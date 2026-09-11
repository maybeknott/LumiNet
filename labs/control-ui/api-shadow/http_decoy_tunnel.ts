/**
 * HTTP Decoy Encrypted Tunnel Protocol API.
 *
 * Unified TypeScript implementation of HTTP request obfuscation, decoy header framing,
 * and tunnel session management .
 */

export type DecoyAction = 'open' | 'request' | 'send' | 'recv' | 'close';

export interface DecoyTunnelConfig {
  token: string;
  fakeUrls: string[];
  methods: string[];
  endpoints: string[];
  userAgent: string;
  httpVersion: string;
  bufferSize: number;
  connectionReuse: boolean;
  tunnelEnable: boolean;
  timeoutSec: number;
  pullTimeoutMs: number;
}

export function defaultDecoyTunnelConfig(): DecoyTunnelConfig {
  return {
    token: 'af445adb-2434-4975-9445-2c1b2231',
    fakeUrls: ['nipo.ciron.net', 'sudoer.ir', 'sudoer.net', 'google.com', 'cloudflare.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    endpoints: ['api', 'login', 'user', 'update'],
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    httpVersion: '1.1',
    bufferSize: 65536,
    connectionReuse: true,
    tunnelEnable: false,
    timeoutSec: 10,
    pullTimeoutMs: 1,
  };
}

export interface DecoyHttpRequest {
  method: string;
  path: string;
  version: string;
  host: string;
  userAgent: string;
  sessionId: string;
  action: DecoyAction;
  contentLength: number;
  keepAlive: boolean;
  headers: Record<string, string>;
  rawBody: string;
}

export interface DecoyHttpResponse {
  version: string;
  statusCode: number;
  statusText: string;
  contentLength: number;
  keepAlive: boolean;
  headers: Record<string, string>;
  rawBody: string;
}

export interface DecoyTunnelSession {
  sessionId: string;
  isConnected: boolean;
  bytesSent: number;
  bytesReceived: number;
  activeAction: DecoyAction;
  createdAt: number;
  lastActive: number;
}

/**
 * Strips protocol schemes and path segments to retrieve a valid Host header.
 */
export function cleanHostHeader(fakeUrl: string): string {
  let host = fakeUrl;
  const schemeIdx = host.indexOf('://');
  if (schemeIdx !== -1) {
    host = host.slice(schemeIdx + 3);
  }
  const slashIdx = host.indexOf('/');
  if (slashIdx !== -1) {
    host = host.slice(0, slashIdx);
  }
  return host;
}

export function selectFakeUrl(config: DecoyTunnelConfig, seed: number): string {
  if (!config.fakeUrls.length) return 'cloudflare.com';
  const idx = Math.abs(seed) % config.fakeUrls.length;
  return config.fakeUrls[idx]!;
}

export function selectMethod(config: DecoyTunnelConfig, seed: number): string {
  if (!config.methods.length) return 'POST';
  const idx = Math.abs(seed) % config.methods.length;
  return config.methods[idx]!;
}

export function selectEndpoint(config: DecoyTunnelConfig, seed: number): string {
  if (!config.endpoints.length) return 'api';
  const idx = Math.abs(seed) % config.endpoints.length;
  return config.endpoints[idx]!;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const trimmed = hex.trim();
  if (trimmed.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const len = trimmed.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

export function base64Decode(str: string): Uint8Array {
  const binary = atob(str.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Formats a decoy HTTP request from an agent to the server.
 */
export function formatDecoyAgentRequest(
  config: DecoyTunnelConfig,
  sessionId: string,
  action: DecoyAction,
  b64Body: string,
  seed = 0,
): string {
  const fakeUrl = selectFakeUrl(config, seed);
  const hostHeader = cleanHostHeader(fakeUrl);
  const method = selectMethod(config, seed);
  const endpoint = selectEndpoint(config, seed);
  const conn = config.connectionReuse || action === 'open' ? 'keep-alive' : 'close';

  return (
    `${method} /${endpoint} HTTP/${config.httpVersion}\r\n` +
    `Host: ${hostHeader}\r\n` +
    `User-Agent: ${config.userAgent}\r\n` +
    `Accept: */*\r\n` +
    `Content-Type: application/text\r\n` +
    `X-Nipo-Session: ${sessionId}\r\n` +
    `X-Nipo-Action: ${action}\r\n` +
    `Content-Length: ${b64Body.length}\r\n` +
    `Connection: ${conn}\r\n` +
    `\r\n` +
    b64Body
  );
}

/**
 * Parses an inbound decoy HTTP request on the server side.
 */
export function parseDecoyServerRequest(rawHttp: string): DecoyHttpRequest {
  const headerEnd = rawHttp.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    throw new Error('Incomplete HTTP request: missing header terminator');
  }

  const headerPart = rawHttp.substring(0, headerEnd);
  const bodyPart = rawHttp.substring(headerEnd + 4);

  const lines = headerPart.split('\r\n');
  if (!lines.length || !lines[0]) {
    throw new Error('Empty HTTP request');
  }

  const reqParts = lines[0].split(' ');
  if (reqParts.length < 3) {
    throw new Error(`Invalid HTTP request line: ${lines[0]}`);
  }

  const method = reqParts[0];
  const path = reqParts[1];
  const version = reqParts[2]!.replace('HTTP/', '');

  const headers: Record<string, string> = {};
  let host = '';
  let userAgent = '';
  let sessionId = '';
  let action: DecoyAction = 'open';
  let contentLength = 0;
  let keepAlive = true;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line!.indexOf(':');
    if (colonIdx !== -1) {
      const name = line!.substring(0, colonIdx).trim().toLowerCase();
      const val = line!.substring(colonIdx + 1).trim();
      headers[name] = val;

      switch (name) {
        case 'host':
          host = val;
          break;
        case 'user-agent':
          userAgent = val;
          break;
        case 'x-nipo-session':
          sessionId = val;
          break;
        case 'x-nipo-action':
          action = val.toLowerCase() as DecoyAction;
          break;
        case 'content-length':
          contentLength = parseInt(val, 10) || 0;
          break;
        case 'connection':
          keepAlive = val.toLowerCase().includes('keep-alive');
          break;
      }
    }
  }

  const actualBody =
    contentLength > 0 && bodyPart.length > contentLength
      ? bodyPart.substring(0, contentLength)
      : bodyPart;

  return {
    method: method!,
    path: path!,
    version,
    host,
    userAgent,
    sessionId,
    action,
    contentLength,
    keepAlive,
    headers,
    rawBody: actualBody,
  };
}

/**
 * Parses an inbound decoy HTTP response on the agent side.
 */
export function parseDecoyAgentResponse(rawHttp: string): DecoyHttpResponse {
  const headerEnd = rawHttp.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    throw new Error('Incomplete HTTP response: missing header terminator');
  }

  const headerPart = rawHttp.substring(0, headerEnd);
  const bodyPart = rawHttp.substring(headerEnd + 4);

  const lines = headerPart.split('\r\n');
  if (!lines.length || !lines[0]) {
    throw new Error('Empty HTTP response');
  }

  const statusParts = lines[0].split(' ');
  if (statusParts.length < 2) {
    throw new Error(`Invalid HTTP status line: ${lines[0]}`);
  }

  const version = statusParts[0]!.replace('HTTP/', '');
  const statusCode = parseInt(statusParts[1]!, 10) || 200;
  const statusText = statusParts.slice(2).join(' ') || 'OK';

  const headers: Record<string, string> = {};
  let contentLength = 0;
  let keepAlive = true;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line!.indexOf(':');
    if (colonIdx !== -1) {
      const name = line!.substring(0, colonIdx).trim().toLowerCase();
      const val = line!.substring(colonIdx + 1).trim();
      headers[name] = val;

      switch (name) {
        case 'content-length':
          contentLength = parseInt(val, 10) || 0;
          break;
        case 'connection':
          keepAlive = val.toLowerCase().includes('keep-alive');
          break;
      }
    }
  }

  const actualBody =
    contentLength > 0 && bodyPart.length > contentLength
      ? bodyPart.substring(0, contentLength)
      : bodyPart;

  return {
    version,
    statusCode,
    statusText,
    contentLength,
    keepAlive,
    headers,
    rawBody: actualBody,
  };
}

/**
 * Tunnel manager tracking active sessions and telemetry metrics.
 */
export class DecoyTunnelManager {
  private config: DecoyTunnelConfig;
  private sessions: Map<string, DecoyTunnelSession> = new Map();

  constructor(config: DecoyTunnelConfig = defaultDecoyTunnelConfig()) {
    this.config = config;
  }

  public getConfig(): DecoyTunnelConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<DecoyTunnelConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  public getOrCreateSession(sessionId: string): DecoyTunnelSession {
    let session = this.sessions.get(sessionId);
    if (!session) {
      const now = Date.now();
      session = {
        sessionId,
        isConnected: false,
        bytesSent: 0,
        bytesReceived: 0,
        activeAction: 'open',
        createdAt: now,
        lastActive: now,
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  public markConnected(sessionId: string): void {
    const session = this.getOrCreateSession(sessionId);
    session.isConnected = true;
    session.activeAction = 'send';
    session.lastActive = Date.now();
  }

  public recordTraffic(sessionId: string, sentBytes: number, receivedBytes: number): void {
    const session = this.getOrCreateSession(sessionId);
    session.bytesSent += sentBytes;
    session.bytesReceived += receivedBytes;
    session.lastActive = Date.now();
  }

  public closeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.isConnected = false;
      session.activeAction = 'close';
      session.lastActive = Date.now();
    }
  }

  public listSessions(): DecoyTunnelSession[] {
    return Array.from(this.sessions.values());
  }
}
