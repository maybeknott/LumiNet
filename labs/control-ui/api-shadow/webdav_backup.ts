/**
 * WebDAV Remote Backup Client
 * Ported and refactored from donor WebDavBackup.kt.
 * Provides configuration backup synchronization to Nextcloud/ownCloud/WebDAV servers.
 */

export interface WebDavConfig {
  endpoint: string;
  remoteDir: string;
  username: string;
  password?: string;
  connectTimeoutMs?: number;
  userAgent?: string;
}

export interface BackupManifest {
  version: number;
  createdAtMillis: number;
  profileCount: number;
  sha256: string;
  sourceApp?: string;
}

export interface RemoteBackup {
  name: string;
  href: string;
  size: number;
  lastModifiedMillis: number;
}

export type BackupResult<T> =
  | { success: true; value: T }
  | { success: false; status: number; message: string };

interface NodeBufferShim {
  Buffer?: {
    from(input: string, encoding?: string): { toString(encoding: string): string };
  };
}

function nodeGlobalBuffer() {
  return (globalThis as NodeBufferShim).Buffer;
}

function basicAuthHeader(username: string, password?: string): string {
  const token = username + ':' + (password ?? '');
  if (typeof btoa === 'function') {
    return 'Basic ' + btoa(token);
  }
  const buf = nodeGlobalBuffer();
  if (buf) {
    return 'Basic ' + buf.from(token).toString('base64');
  }
  return 'Basic ' + token;
}

export function parsePropfindXml(xml: string, baseHref: string): RemoteBackup[] {
  const entries: RemoteBackup[] = [];
  const responseRegex = /<(?:\w+:)?response[^>]*>([\s\S]*?)<\/(?:\w+:)?response>/gi;
  let match: RegExpExecArray | null;

  while ((match = responseRegex.exec(xml)) !== null) {
    const body = match[1] ?? '';
    const hrefMatch = /<(?:\w+:)?href[^>]*>([^<]+)<\/(?:\w+:)?href>/i.exec(body);
    if (!hrefMatch) continue;
    const href = hrefMatch[1]!.trim();
    if (href === baseHref || href.replace(/\/+$/, '') === baseHref.replace(/\/+$/, '')) {
      continue;
    }

    const sizeMatch = /<(?:\w+:)?getcontentlength[^>]*>([0-9]+)<\/(?:\w+:)?getcontentlength>/i.exec(body);
    const size = sizeMatch ? parseInt(sizeMatch[1]!, 10) : 0;

    const lmMatch = /<(?:\w+:)?getlastmodified[^>]*>([^<]+)<\/(?:\w+:)?getlastmodified>/i.exec(body);
    let lastModifiedMillis = Date.now();
    if (lmMatch) {
      const parsed = Date.parse(lmMatch[1]!);
      if (!Number.isNaN(parsed)) {
        lastModifiedMillis = parsed;
      }
    }

    const name = href.substring(href.lastIndexOf('/') + 1) || href;
    entries.push({ name, href, size, lastModifiedMillis });
  }

  return entries.sort((a, b) => b.lastModifiedMillis - a.lastModifiedMillis);
}

export class WebDavBackupClient {
  private config: WebDavConfig;

  constructor(config: WebDavConfig) {
    this.config = config;
  }

  private directoryUrl(): string {
    const ep = this.config.endpoint.replace(/\/+$/, '');
    const dir = this.config.remoteDir.startsWith('/') ? this.config.remoteDir : '/' + this.config.remoteDir;
    return ep + dir;
  }

  async ensureDirectory(): Promise<BackupResult<void>> {
    try {
      const url = this.directoryUrl();
      const res = await fetch(url, {
        method: 'MKCOL',
        headers: {
          Authorization: basicAuthHeader(this.config.username, this.config.password),
          'User-Agent': this.config.userAgent ?? 'LumiNet-WebDAV/1.0',
        },
      });

      if (res.status === 201 || res.status === 405) {
        return { success: true, value: undefined };
      }
      return {
        success: false,
        status: res.status,
        message: 'MKCOL failed with HTTP ' + res.status,
      };
    } catch (err) {
      return {
        success: false,
        status: -1,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async uploadBackup(
    filename: string,
    payload: string | Uint8Array,
    manifest: BackupManifest
  ): Promise<BackupResult<RemoteBackup>> {
    try {
      const url = this.directoryUrl().replace(/\/+$/, '') + '/' + encodeURIComponent(filename);
      const res = await fetch(url, {
        method: 'PUT',
        headers: {
          Authorization: basicAuthHeader(this.config.username, this.config.password),
          'Content-Type': 'application/json',
          'X-LumiNet-Manifest': JSON.stringify(manifest),
          'User-Agent': this.config.userAgent ?? 'LumiNet-WebDAV/1.0',
        },
        body: payload as BodyInit,
      });

      if (res.ok) {
        const size = typeof payload === 'string' ? payload.length : payload.byteLength;
        return {
          success: true,
          value: {
            name: filename,
            href: url,
            size,
            lastModifiedMillis: manifest.createdAtMillis,
          },
        };
      }

      return {
        success: false,
        status: res.status,
        message: 'PUT failed with HTTP ' + res.status,
      };
    } catch (err) {
      return {
        success: false,
        status: -1,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async listBackups(): Promise<BackupResult<RemoteBackup[]>> {
    try {
      const url = this.directoryUrl();
      const res = await fetch(url, {
        method: 'PROPFIND',
        headers: {
          Authorization: basicAuthHeader(this.config.username, this.config.password),
          Depth: '1',
          'Content-Type': 'application/xml; charset=utf-8',
          'User-Agent': this.config.userAgent ?? 'LumiNet-WebDAV/1.0',
        },
      });

      if (!res.ok) {
        return {
          success: false,
          status: res.status,
          message: 'PROPFIND failed with HTTP ' + res.status,
        };
      }

      const xml = await res.text();
      const entries = parsePropfindXml(xml, url);
      return { success: true, value: entries };
    } catch (err) {
      return {
        success: false,
        status: -1,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async downloadBackup(name: string): Promise<BackupResult<string>> {
    try {
      const url = this.directoryUrl().replace(/\/+$/, '') + '/' + encodeURIComponent(name);
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: basicAuthHeader(this.config.username, this.config.password),
          'User-Agent': this.config.userAgent ?? 'LumiNet-WebDAV/1.0',
        },
      });

      if (!res.ok) {
        return {
          success: false,
          status: res.status,
          message: 'GET failed with HTTP ' + res.status,
        };
      }

      const text = await res.text();
      return { success: true, value: text };
    } catch (err) {
      return {
        success: false,
        status: -1,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
