/**
 * Raw Packet Evasion Transport API & Wire Protocol.
 *
 * Ported and unified from `paqet-master`.
 * Provides raw TCP packet crafting framing, TCP flag bitfield encoding/decoding,
 * KCP transport profile presets, and tunnel multiplexing messages.
 */

export const RAW_PACKET_MAGIC = 0x50; // 'P'
export const RAW_PACKET_VERSION = 0x01;

export const MSG_PING = 0x01;
export const MSG_PONG = 0x02;
export const MSG_TCPF = 0x03;
export const MSG_TCP = 0x04;
export const MSG_UDP = 0x05;

export const HEADER_LEN = 5;
export const MAX_HOST_LEN = 253;
export const MAX_TCPF_COUNT = 64;
export const MAX_BODY_LEN = 4096;

export const FLAG_FIN = 1 << 0;
export const FLAG_SYN = 1 << 1;
export const FLAG_RST = 1 << 2;
export const FLAG_PSH = 1 << 3;
export const FLAG_ACK = 1 << 4;
export const FLAG_URG = 1 << 5;
export const FLAG_ECE = 1 << 6;
export const FLAG_CWR = 1 << 7;
export const FLAG_NS = 1 << 8;

export interface RawTcpFlags {
  fin?: boolean;
  syn?: boolean;
  rst?: boolean;
  psh?: boolean;
  ack?: boolean;
  urg?: boolean;
  ece?: boolean;
  cwr?: boolean;
  ns?: boolean;
}

/**
 * Encodes structured TCP flags into 16-bit integer bitfield.
 */
export function encodeRawTcpFlags(f: RawTcpFlags): number {
  let v = 0;
  if (f.fin) v |= FLAG_FIN;
  if (f.syn) v |= FLAG_SYN;
  if (f.rst) v |= FLAG_RST;
  if (f.psh) v |= FLAG_PSH;
  if (f.ack) v |= FLAG_ACK;
  if (f.urg) v |= FLAG_URG;
  if (f.ece) v |= FLAG_ECE;
  if (f.cwr) v |= FLAG_CWR;
  if (f.ns) v |= FLAG_NS;
  return v;
}

/**
 * Decodes 16-bit wire bitfield into structured TCP flags.
 */
export function decodeRawTcpFlags(v: number): RawTcpFlags {
  return {
    fin: (v & FLAG_FIN) !== 0,
    syn: (v & FLAG_SYN) !== 0,
    rst: (v & FLAG_RST) !== 0,
    psh: (v & FLAG_PSH) !== 0,
    ack: (v & FLAG_ACK) !== 0,
    urg: (v & FLAG_URG) !== 0,
    ece: (v & FLAG_ECE) !== 0,
    cwr: (v & FLAG_CWR) !== 0,
    ns: (v & FLAG_NS) !== 0,
  };
}

/**
 * Parses a flag string like "PA", "SA", "FA", "FSRPAUECN".
 */
export function parseRawTcpFlags(s: string): RawTcpFlags {
  const flags: RawTcpFlags = {};
  for (const ch of s) {
    switch (ch) {
      case 'F':
      case 'f':
        flags.fin = true;
        break;
      case 'S':
      case 's':
        flags.syn = true;
        break;
      case 'R':
      case 'r':
        flags.rst = true;
        break;
      case 'P':
      case 'p':
        flags.psh = true;
        break;
      case 'A':
      case 'a':
        flags.ack = true;
        break;
      case 'U':
      case 'u':
        flags.urg = true;
        break;
      case 'E':
      case 'e':
        flags.ece = true;
        break;
      case 'C':
      case 'c':
        flags.cwr = true;
        break;
      case 'N':
      case 'n':
        flags.ns = true;
        break;
      default:
        throw new Error(`Invalid TCP flag character: '${ch}'`);
    }
  }
  return flags;
}

/**
 * Formats TCP flags into canonical string representation.
 */
export function formatRawTcpFlags(f: RawTcpFlags): string {
  let s = '';
  if (f.fin) s += 'F';
  if (f.syn) s += 'S';
  if (f.rst) s += 'R';
  if (f.psh) s += 'P';
  if (f.ack) s += 'A';
  if (f.urg) s += 'U';
  if (f.ece) s += 'E';
  if (f.cwr) s += 'C';
  if (f.ns) s += 'N';
  return s;
}

export interface TargetEndpoint {
  host: string;
  port: number;
}

export type RawPacketMessage =
  | { type: 'ping' }
  | { type: 'pong' }
  | { type: 'tcp'; target: TargetEndpoint }
  | { type: 'udp'; target: TargetEndpoint }
  | { type: 'tcpf'; flags: RawTcpFlags[] };

/**
 * Serializes RawPacketMessage to wire byte array.
 */
export function encodeRawPacketMessage(msg: RawPacketMessage): Uint8Array {
  let msgType: number;
  let body: Uint8Array;

  switch (msg.type) {
    case 'ping':
      msgType = MSG_PING;
      body = new Uint8Array(0);
      break;
    case 'pong':
      msgType = MSG_PONG;
      body = new Uint8Array(0);
      break;
    case 'tcp':
    case 'udp': {
      msgType = msg.type === 'tcp' ? MSG_TCP : MSG_UDP;
      const encoder = new TextEncoder();
      const hostBytes = encoder.encode(msg.target.host);
      if (hostBytes.length > MAX_HOST_LEN) {
        throw new Error(`Host length ${hostBytes.length} exceeds maximum ${MAX_HOST_LEN}`);
      }
      body = new Uint8Array(1 + hostBytes.length + 2);
      body[0] = hostBytes.length;
      body.set(hostBytes, 1);
      const portOffset = 1 + hostBytes.length;
      body[portOffset] = (msg.target.port >> 8) & 0xff;
      body[portOffset + 1] = msg.target.port & 0xff;
      break;
    }
    case 'tcpf': {
      msgType = MSG_TCPF;
      if (msg.flags.length > MAX_TCPF_COUNT) {
        throw new Error(`TCPF count ${msg.flags.length} exceeds maximum ${MAX_TCPF_COUNT}`);
      }
      body = new Uint8Array(1 + msg.flags.length * 2);
      body[0] = msg.flags.length;
      for (let i = 0; i < msg.flags.length; i++) {
        const val = encodeRawTcpFlags(msg.flags[i]!);
        body[1 + i * 2] = (val >> 8) & 0xff;
        body[1 + i * 2 + 1] = val & 0xff;
      }
      break;
    }
    default:
      throw new Error('Unknown message type');
  }

  if (body.length > MAX_BODY_LEN) {
    throw new Error(`Body length ${body.length} exceeds maximum ${MAX_BODY_LEN}`);
  }

  const out = new Uint8Array(HEADER_LEN + body.length);
  out[0] = RAW_PACKET_MAGIC;
  out[1] = RAW_PACKET_VERSION;
  out[2] = msgType;
  out[3] = (body.length >> 8) & 0xff;
  out[4] = body.length & 0xff;
  out.set(body, HEADER_LEN);
  return out;
}

/**
 * Deserializes RawPacketMessage from wire bytes.
 */
export function decodeRawPacketMessage(buf: Uint8Array): {
  msg: RawPacketMessage;
  totalLen: number;
} {
  if (buf.length < HEADER_LEN) {
    throw new Error(`Buffer too short: ${buf.length} < ${HEADER_LEN}`);
  }
  if (buf[0] !== RAW_PACKET_MAGIC) {
    throw new Error(`Bad magic byte: 0x${buf[0]!.toString(16)}`);
  }
  if (buf[1] !== RAW_PACKET_VERSION) {
    throw new Error(`Unsupported version: 0x${buf[1]!.toString(16)}`);
  }

  const msgType = buf[2]!;
  const bodyLen = (buf[3]! << 8) | buf[4]!;
  const totalLen = HEADER_LEN + bodyLen;
  if (buf.length < totalLen) {
    throw new Error('Buffer too short for complete message');
  }

  const body = buf.subarray(HEADER_LEN, totalLen);

  switch (msgType) {
    case MSG_PING:
      return { msg: { type: 'ping' }, totalLen };
    case MSG_PONG:
      return { msg: { type: 'pong' }, totalLen };
    case MSG_TCP:
    case MSG_UDP: {
      if (body.length < 3) {
        throw new Error('Truncated address body');
      }
      const hostLen = body[0]!;
      if (hostLen > MAX_HOST_LEN || 1 + hostLen + 2 !== body.length) {
        throw new Error(`Invalid host length: ${hostLen}`);
      }
      const decoder = new TextDecoder();
      const host = decoder.decode(body.subarray(1, 1 + hostLen));
      const port = (body[1 + hostLen]! << 8) | body[1 + hostLen + 1]!;
      const target: TargetEndpoint = { host, port };
      return {
        msg: msgType === MSG_TCP ? { type: 'tcp', target } : { type: 'udp', target },
        totalLen,
      };
    }
    case MSG_TCPF: {
      if (body.length < 1) {
        throw new Error('Truncated TCPF body');
      }
      const count = body[0]!;
      if (count > MAX_TCPF_COUNT || 1 + count * 2 !== body.length) {
        throw new Error(`Invalid TCPF count: ${count}`);
      }
      const flags: RawTcpFlags[] = [];
      for (let i = 0; i < count; i++) {
        const val = (body[1 + i * 2]! << 8) | body[1 + i * 2 + 1]!;
        flags.push(decodeRawTcpFlags(val));
      }
      return { msg: { type: 'tcpf', flags }, totalLen };
    }
    default:
      throw new Error(`Unknown message type: 0x${msgType.toString(16)}`);
  }
}

/**
 * RFC 1071 Internet Checksum calculation.
 */
export function computeInternetChecksum(data: Uint8Array): number {
  let sum = 0;
  let i = 0;
  while (i + 1 < data.length) {
    const word = (data[i]! << 8) | data[i + 1]!;
    sum += word;
    i += 2;
  }
  if (i < data.length) {
    sum += data[i]! << 8;
  }
  while (sum >> 16 > 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}

export interface KcpTransportProfile {
  mode: string;
  noDelay: number;
  interval: number;
  resend: number;
  noCongestion: number;
  wDelay: boolean;
  ackNoDelay: boolean;
  mtu: number;
  sndwnd: number;
  rcvwnd: number;
  dscp: number;
}

/**
 * Returns KCP transport parameters according to mode preset.
 */
export function getKcpTransportProfile(mode: string): KcpTransportProfile {
  switch (mode.toLowerCase().trim()) {
    case 'fast':
      return {
        mode: 'fast',
        noDelay: 0,
        interval: 30,
        resend: 2,
        noCongestion: 1,
        wDelay: true,
        ackNoDelay: false,
        mtu: 1350,
        sndwnd: 128,
        rcvwnd: 512,
        dscp: 46,
      };
    case 'fast2':
      return {
        mode: 'fast2',
        noDelay: 1,
        interval: 20,
        resend: 2,
        noCongestion: 1,
        wDelay: false,
        ackNoDelay: true,
        mtu: 1350,
        sndwnd: 128,
        rcvwnd: 512,
        dscp: 46,
      };
    case 'fast3':
      return {
        mode: 'fast3',
        noDelay: 1,
        interval: 10,
        resend: 2,
        noCongestion: 1,
        wDelay: false,
        ackNoDelay: true,
        mtu: 1350,
        sndwnd: 128,
        rcvwnd: 512,
        dscp: 46,
      };
    case 'normal':
    default:
      return {
        mode: 'normal',
        noDelay: 0,
        interval: 40,
        resend: 2,
        noCongestion: 1,
        wDelay: true,
        ackNoDelay: false,
        mtu: 1350,
        sndwnd: 128,
        rcvwnd: 512,
        dscp: 46,
      };
  }
}
