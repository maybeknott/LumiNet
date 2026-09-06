/**
 * Multi-Protocol Inbound Proxy Demultiplexer & Framer API.
 *
 * Ported and unified from `proxy-main`.
 * Multiplexes HTTP, HTTPS CONNECT, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h on a single listener port
 * by analyzing initial wire handshake bytes.
 */

export type ProxyProtocolKind = 'http' | 'socks4' | 'socks5';

export const SOCKS4_VERSION = 0x04;
export const SOCKS4_CMD_CONNECT = 0x01;
export const SOCKS4_CMD_BIND = 0x02;

export const SOCKS4_STATUS_GRANTED = 0x5a;
export const SOCKS4_STATUS_REJECTED = 0x5b;
export const SOCKS4_STATUS_NO_IDENTD = 0x5c;
export const SOCKS4_STATUS_INVALID_USER = 0x5d;

export const SOCKS5_VERSION = 0x05;
export const SOCKS5_AUTH_NONE = 0x00;
export const SOCKS5_AUTH_NO_ACCEPTABLE = 0xff;

export const SOCKS5_CMD_CONNECT = 0x01;
export const SOCKS5_CMD_BIND = 0x02;
export const SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

export const SOCKS5_ATYP_IPV4 = 0x01;
export const SOCKS5_ATYP_DOMAIN = 0x03;
export const SOCKS5_ATYP_IPV6 = 0x04;

export const SOCKS5_REP_SUCCESS = 0x00;
export const SOCKS5_REP_GENERAL_FAILURE = 0x01;
export const SOCKS5_REP_CONNECTION_NOT_ALLOWED = 0x02;
export const SOCKS5_REP_NETWORK_UNREACHABLE = 0x03;
export const SOCKS5_REP_HOST_UNREACHABLE = 0x04;
export const SOCKS5_REP_CONNECTION_REFUSED = 0x05;
export const SOCKS5_REP_TTL_EXPIRED = 0x06;
export const SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07;
export const SOCKS5_REP_ADDR_NOT_SUPPORTED = 0x08;

/**
 * Detects protocol family from the opening byte.
 */
export function detectProxyProtocol(firstByte: number): ProxyProtocolKind {
  switch (firstByte) {
    case SOCKS5_VERSION:
      return 'socks5';
    case SOCKS4_VERSION:
      return 'socks4';
    default:
      return 'http';
  }
}

export interface Socks4Request {
  command: number;
  port: number;
  ip: string;
  userId: string;
  domain?: string | undefined;
  isSocks4a: boolean;
  targetHost: string;
}

/**
 * Parses SOCKS4 / SOCKS4a request wire frame.
 */
export function parseSocks4Request(buf: Uint8Array): {
  req: Socks4Request;
  totalLen: number;
} {
  if (buf.length < 8) {
    throw new Error(`Buffer too short for SOCKS4 header: ${buf.length} < 8`);
  }
  if (buf[0] !== SOCKS4_VERSION) {
    throw new Error(`Invalid SOCKS4 version: 0x${buf[0]!.toString(16)}`);
  }

  const command = buf[1];
  const port = (buf[2]! << 8) | buf[3]!;
  const ip = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
  const isSocks4a = buf[4] === 0 && buf[5] === 0 && buf[6] === 0 && buf[7] !== 0;

  let idx = 8;
  while (idx < buf.length && buf[idx] !== 0) {
    idx++;
  }
  if (idx >= buf.length) {
    throw new Error('Unterminated userId string in SOCKS4');
  }
  const decoder = new TextDecoder();
  const userId = decoder.decode(buf.subarray(8, idx));
  idx++; // Skip null byte

  let domain: string | undefined;
  if (isSocks4a) {
    const domainStart = idx;
    while (idx < buf.length && buf[idx] !== 0) {
      idx++;
    }
    if (idx >= buf.length) {
      throw new Error('Unterminated domain string in SOCKS4a');
    }
    domain = decoder.decode(buf.subarray(domainStart, idx));
    idx++; // Skip null byte
  }

  const targetHost = domain || ip;
  return {
    req: {
      command: command!,
      port: port!,
      ip,
      userId,
      domain,
      isSocks4a,
      targetHost,
    },
    totalLen: idx,
  };
}

/**
 * Builds 8-byte standard SOCKS4 response.
 */
export function buildSocks4Reply(
  status: number,
  bndPort: number,
  bndIp: number[] = [0, 0, 0, 0],
): Uint8Array {
  const resp = new Uint8Array(8);
  resp[0] = 0x00;
  resp[1] = status;
  resp[2] = (bndPort >> 8) & 0xff;
  resp[3] = bndPort & 0xff;
  for (let i = 0; i < 4; i++) {
    resp[4 + i] = bndIp[i] || 0;
  }
  return resp;
}

export interface Socks5Greeting {
  methods: number[];
}

/**
 * Parses SOCKS5 greeting method negotiation.
 */
export function parseSocks5Greeting(buf: Uint8Array): {
  greeting: Socks5Greeting;
  totalLen: number;
} {
  if (buf.length < 2) {
    throw new Error(`Buffer too short for SOCKS5 greeting: ${buf.length} < 2`);
  }
  if (buf[0] !== SOCKS5_VERSION) {
    throw new Error(`Invalid SOCKS5 version: 0x${buf[0]!.toString(16)}`);
  }
  const nmethods = buf[1]!;
  const totalLen = 2 + nmethods;
  if (buf.length < totalLen) {
    throw new Error(`Buffer too short for SOCKS5 methods: ${buf.length} < ${totalLen}`);
  }
  const methods = Array.from(buf.subarray(2, totalLen));
  return { greeting: { methods }, totalLen };
}

/**
 * Builds SOCKS5 greeting response frame.
 */
export function buildSocks5GreetingReply(method: number): Uint8Array {
  return new Uint8Array([SOCKS5_VERSION, method]);
}

export interface Socks5Request {
  command: number;
  targetHost: string;
  targetPort: number;
  addressType: number;
}

/**
 * Parses SOCKS5 command request.
 */
export function parseSocks5Request(buf: Uint8Array): {
  req: Socks5Request;
  totalLen: number;
} {
  if (buf.length < 4) {
    throw new Error(`Buffer too short for SOCKS5 request: ${buf.length} < 4`);
  }
  if (buf[0] !== SOCKS5_VERSION) {
    throw new Error(`Invalid SOCKS5 version: 0x${buf[0]!.toString(16)}`);
  }

  const command = buf[1];
  const atyp = buf[3]!;
  let idx = 4;
  let targetHost: string;

  switch (atyp) {
    case SOCKS5_ATYP_IPV4: {
      if (buf.length < idx + 4 + 2) throw new Error('Buffer too short for IPv4 address');
      targetHost = `${buf[idx]}.${buf[idx + 1]}.${buf[idx + 2]}.${buf[idx + 3]}`;
      idx += 4;
      break;
    }
    case SOCKS5_ATYP_DOMAIN: {
      if (buf.length < idx + 1) throw new Error('Buffer too short for domain length');
      const dlen = buf[idx]!;
      idx += 1;
      if (buf.length < idx + dlen + 2) throw new Error('Buffer too short for domain string');
      const decoder = new TextDecoder();
      targetHost = decoder.decode(buf.subarray(idx, idx + dlen));
      idx += dlen;
      break;
    }
    case SOCKS5_ATYP_IPV6: {
      if (buf.length < idx + 16 + 2) throw new Error('Buffer too short for IPv6 address');
      const parts: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(((buf[idx + i]! << 8) | buf[idx + i + 1]!).toString(16));
      }
      targetHost = parts.join(':');
      idx += 16;
      break;
    }
    default:
      throw new Error(`Unsupported address type: 0x${atyp.toString(16)}`);
  }

  if (buf.length < idx + 2) {
    throw new Error('Buffer too short for target port');
  }
  const targetPort = (buf[idx]! << 8) | buf[idx + 1]!;
  idx += 2;

  return {
    req: {
      command: command!,
      targetHost,
      targetPort,
      addressType: atyp,
    },
    totalLen: idx,
  };
}

/**
 * Builds standard 10-byte IPv4 SOCKS5 command reply.
 */
export function buildSocks5Reply(
  rep: number,
  bndPort: number,
  bndIp: number[] = [127, 0, 0, 1],
): Uint8Array {
  const resp = new Uint8Array(10);
  resp[0] = SOCKS5_VERSION;
  resp[1] = rep;
  resp[2] = 0x00;
  resp[3] = SOCKS5_ATYP_IPV4;
  for (let i = 0; i < 4; i++) {
    resp[4 + i] = bndIp[i] || 0;
  }
  resp[8] = (bndPort >> 8) & 0xff;
  resp[9] = bndPort & 0xff;
  return resp;
}

export interface HttpProxyRequest {
  method: string;
  host: string;
  port: number;
  path: string;
  isConnect: boolean;
}

/**
 * Parses HTTP request header line.
 */
export function parseHttpProxyRequest(header: string): HttpProxyRequest {
  const firstLine = header.split(/\r?\n/)[0]?.trim();
  if (!firstLine) {
    throw new Error('Malformed HTTP request header');
  }
  const parts = firstLine.split(/\s+/);
  if (parts.length < 2) {
    throw new Error(`Invalid HTTP request line: ${firstLine}`);
  }

  const method = parts[0]!.toUpperCase();
  const rawUri = parts[1]!;

  if (method === 'CONNECT') {
    const colonIdx = rawUri.lastIndexOf(':');
    const host = colonIdx >= 0 ? rawUri.substring(0, colonIdx).replace(/^\[|\]$/g, '') : rawUri;
    const port = colonIdx >= 0 ? parseInt(rawUri.substring(colonIdx + 1), 10) : 443;
    return {
      method,
      host,
      port: isNaN(port) ? 443 : port,
      path: '',
      isConnect: true,
    };
  }

  const clean = rawUri.replace(/^https?:\/\//, '');
  const slashIdx = clean.indexOf('/');
  const hostPart = slashIdx >= 0 ? clean.substring(0, slashIdx) : clean;
  const pathPart = slashIdx >= 0 ? clean.substring(slashIdx) : '/';

  const colonIdx = hostPart.lastIndexOf(':');
  const host = colonIdx >= 0 ? hostPart.substring(0, colonIdx).replace(/^\[|\]$/g, '') : hostPart;
  const port = colonIdx >= 0 ? parseInt(hostPart.substring(colonIdx + 1), 10) : 80;

  return {
    method,
    host,
    port: isNaN(port) ? 80 : port,
    path: pathPart,
    isConnect: false,
  };
}

/**
 * Standard HTTP 200 Connection Established response for CONNECT requests.
 */
export function buildHttpConnectOkResponse(): string {
  return 'HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet-Mixed-Proxy/1.0\r\n\r\n';
}

export interface MixedProxyConfig {
  bind: string;
  port: number;
  enableHttp: boolean;
  enableSocks4: boolean;
  enableSocks5: boolean;
}

export function defaultMixedProxyConfig(): MixedProxyConfig {
  return {
    bind: '127.0.0.1',
    port: 1080,
    enableHttp: true,
    enableSocks4: true,
    enableSocks5: true,
  };
}
