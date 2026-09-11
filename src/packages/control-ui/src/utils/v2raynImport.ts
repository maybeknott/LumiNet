// SPDX-License-Identifier: MIT
//
// v2rayN export-JSON import (roadmap item 6, design
// C# v2rayN client). v2rayN exports profile lists whose entries carry a
// numeric `configType` plus connection fields. We normalise the shape
// LumiNet cares about and skip anything non-mappable with a reason, so
// pasted v2rayN JSON produces an actionable preview instead of a parse
// error. Protocol mapping follows v2rayN 6.x/7.x ConfigType enum.

import { computeProfileKey } from './profileKey.js';

export interface V2rayNImportItem {
  name: string;
  /** Normalised protocol id (vmess/vless/trojan/shadowsocks/socks/hysteria2/tuic). */
  protocol: string;
  server: string;
  port: number;
  /** Raw v2rayN configType number (when present). */
  configType?: number | undefined;
  /** Content-derived stable profile fingerprint. */
  profileKey?: string | undefined;
}

export interface V2rayNImportResult {
  items: V2rayNImportItem[];
  skipped: { index: number; reason: string }[];
}

const CONFIG_TYPE_PROTOCOL: Record<number, string> = {
  1: 'vmess',
  3: 'shadowsocks',
  4: 'socks',
  5: 'vless',
  6: 'trojan',
  7: 'hysteria2',
  8: 'tuic',
};

function readString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function readNumber(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : NaN;
}

/** Parse pasted v2rayN export JSON (single item, array, or nested list). */
export function parseV2rayNExport(text: string): V2rayNImportResult {
  const items: V2rayNImportItem[] = [];
  const skipped: { index: number; reason: string }[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { items, skipped: [{ index: 0, reason: 'input is not valid JSON' }] };
  }

  let entries: unknown[] = [];
  if (Array.isArray(parsed)) {
    entries = parsed;
  } else if (parsed && typeof parsed === 'object') {
    const record = parsed as Record<string, unknown>;
    // v2rayN full-config exports wrap profile items in known keys.
    for (const key of ['servers', 'profileItems', 'items']) {
      if (Array.isArray(record[key])) {
        entries = record[key] as unknown[];
        break;
      }
    }
    if (entries.length === 0 && record.configType !== undefined) {
      entries = [record];
    }
  }

  entries.forEach((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      skipped.push({ index, reason: 'not an object' });
      return;
    }
    const e = entry as Record<string, unknown>;
    const configType = readNumber(e.configType);
    const protocol = CONFIG_TYPE_PROTOCOL[configType];
    if (!protocol) {
      skipped.push({
        index,
        reason: Number.isNaN(configType)
          ? 'missing configType'
          : `unsupported configType ${configType}`,
      });
      return;
    }
    const server = readString(e.address);
    const port = readNumber(e.port);
    if (server === '' || Number.isNaN(port) || port <= 0 || port > 65535) {
      skipped.push({ index, reason: 'missing address or port' });
      return;
    }
    let profileKey: string | undefined;
    try {
      const pk = computeProfileKey({
        protocol,
        host: server,
        port,
        uuid: readString(e.id) || undefined,
        password: readString(e.password) || undefined,
        network: readString(e.net) || undefined,
        tls: readString(e.security) || undefined,
        path: readString(e.path) || undefined,
        sni: readString(e.sni) || undefined,
      });
      profileKey = pk.hash;
    } catch {
      // Ignore key computation failure for partial configs
    }

    items.push({
      name: readString(e.remarks) || `${protocol}-${server}`,
      protocol,
      server,
      port,
      configType,
      profileKey,
    });
  });

  return { items, skipped };
}

/** Human-facing hint for the import textarea. Empty when not v2rayN JSON. */
export function v2raynImportHint(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith('[') && !trimmed.startsWith('{')) {
    return '';
  }
  const { items, skipped } = parseV2rayNExport(trimmed);
  if (items.length === 0 && skipped.length === 0) {
    return '';
  }
  const parts: string[] = [`${items.length} v2rayN profile(s) recognised`];
  if (skipped.length > 0) {
    parts.push(`${skipped.length} skipped`);
  }
  return parts.join(', ') + '.';
}
