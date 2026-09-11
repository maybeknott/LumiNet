/**
 * RFC 8484 DNS-over-HTTPS & SNI Fragment Forwarder API
 * Originates from SlipNet-main and adapted for LumiNet unified network plane.
 */

export const DOH_CONTENT_TYPE = 'application/dns-message';

export interface DohClientConfig {
  endpoint_url: string;
  custom_sni?: string;
  timeout_ms: number;
  max_idle_connections: number;
  fragmentation_strategy: 'sni_split' | 'half' | 'multi';
}

export const DEFAULT_DOH_CLIENT_CONFIG: DohClientConfig = {
  endpoint_url: 'https://cloudflare-dns.com/dns-query',
  custom_sni: 'cloudflare-dns.com',
  timeout_ms: 5000,
  max_idle_connections: 16,
  fragmentation_strategy: 'sni_split',
};

/**
 * Validates whether incoming payload is a valid RFC 1035 DNS response.
 */
export function validateDohResponse(body: Uint8Array): boolean {
  if (body.length < 12) return false;
  const flags = (body[2]! << 8) | body[3]!;
  return (flags & 0x8000) !== 0; // QR bit must be 1
}

/**
 * Scans a TLS ClientHello packet to locate the byte offset and length of the SNI hostname.
 */
export function findSniHostnameOffset(data: Uint8Array): [number, number] | null {
  if (data.length < 44 || data[0] !== 0x16) {
    return null;
  }

  let pos = 5 + 4 + 2 + 32; // record (5) + handshake (4) + version (2) + random (32)
  if (pos >= data.length) return null;

  const sessionIdLen = data[pos]!;
  pos += 1 + sessionIdLen;

  if (pos + 2 > data.length) return null;
  const cipherSuitesLen = (data[pos]! << 8) | data[pos + 1]!;
  pos += 2 + cipherSuitesLen;

  if (pos + 1 > data.length) return null;
  const compMethodsLen = data[pos]!;
  pos += 1 + compMethodsLen;

  if (pos + 2 > data.length) return null;
  const extensionsLen = (data[pos]! << 8) | data[pos + 1]!;
  pos += 2;
  const extensionsEnd = Math.min(pos + extensionsLen, data.length);

  while (pos + 4 <= extensionsEnd) {
    const extType = (data[pos]! << 8) | data[pos + 1]!;
    const extLen = (data[pos + 2]! << 8) | data[pos + 3]!;
    pos += 4;

    if (extType === 0x0000 && extLen > 0) {
      if (pos + 5 <= extensionsEnd) {
        const hostLen = (data[pos + 3]! << 8) | data[pos + 4]!;
        const hostStart = pos + 5;
        if (hostStart + hostLen <= data.length) {
          return [hostStart, hostLen];
        }
      }
    }
    pos += extLen;
  }

  return null;
}

/**
 * Splits a TLS ClientHello packet across TCP segment boundaries.
 */
export function splitClientHello(
  data: Uint8Array,
  strategy: 'sni_split' | 'half' | 'multi' = 'sni_split',
): Uint8Array[] {
  if (strategy === 'sni_split') {
    const found = findSniHostnameOffset(data);
    if (found) {
      const [offset, hostLen] = found;
      let mid =
        hostLen > 0
          ? offset + Math.floor(hostLen / 2)
          : offset + Math.floor((data.length - offset) / 2);
      mid = Math.max(1, Math.min(mid, data.length - 1));
      return [data.slice(0, mid), data.slice(mid)];
    }
    return splitHalf(data);
  }
  if (strategy === 'multi') {
    return splitMulti(data, 24);
  }
  return splitHalf(data);
}

function splitHalf(data: Uint8Array): Uint8Array[] {
  if (data.length <= 1) return [data.slice()];
  const mid = Math.floor(data.length / 2);
  return [data.slice(0, mid), data.slice(mid)];
}

function splitMulti(data: Uint8Array, chunkSize = 24): Uint8Array[] {
  const size = chunkSize <= 0 ? 24 : chunkSize;
  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < data.length) {
    const end = Math.min(offset + size, data.length);
    chunks.push(data.slice(offset, end));
    offset = end;
  }
  return chunks;
}
