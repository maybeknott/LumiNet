/**
 * WebRTC DataChannel & ICE Proxy Transport API.
 */

export const PPID_DCEP = 50;
export const PPID_STRING = 51;
export const PPID_BINARY = 53;
export const PPID_STRING_EMPTY = 56;
export const PPID_BINARY_EMPTY = 57;

export interface DataChannelFrame {
  ppid: number;
  payload: Uint8Array;
}

export interface ICEProxyConfig {
  proxyUrl: string;
  targetTurnAddr?: string;
  username?: string;
  password?: string;
  timeoutMs?: number;
}

export interface WebRTCProxySessionState {
  connected: boolean;
  iceState: 'new' | 'checking' | 'connected' | 'completed' | 'failed' | 'disconnected' | 'closed';
  dataChannelState: 'connecting' | 'open' | 'closing' | 'closed';
  bytesSent: number;
  bytesReceived: number;
  rttMs: number;
}

/**
 * Encodes a DataChannel frame into 4-byte big-endian PPID + payload bytes.
 */
export function encodeDataChannelFrame(frame: DataChannelFrame): Uint8Array {
  const out = new Uint8Array(4 + frame.payload.length);
  out[0] = (frame.ppid >> 24) & 0xff;
  out[1] = (frame.ppid >> 16) & 0xff;
  out[2] = (frame.ppid >> 8) & 0xff;
  out[3] = frame.ppid & 0xff;
  out.set(frame.payload, 4);
  return out;
}

/**
 * Decodes a DataChannel frame from raw bytes.
 */
export function decodeDataChannelFrame(src: Uint8Array): DataChannelFrame {
  if (src.length < 4) {
    throw new Error('Buffer too short for WebRTC DataChannel frame');
  }
  const ppid = ((src[0]! << 24) | (src[1]! << 16) | (src[2]! << 8) | src[3]!) >>> 0;
  const payload = src.slice(4);
  return { ppid, payload };
}

/**
 * Creates a binary data frame helper.
 */
export function createBinaryFrame(data: Uint8Array): DataChannelFrame {
  return {
    ppid: data.length === 0 ? PPID_BINARY_EMPTY : PPID_BINARY,
    payload: data,
  };
}

/**
 * Creates a text string frame helper.
 */
export function createStringFrame(text: string): DataChannelFrame {
  const data = new TextEncoder().encode(text);
  return {
    ppid: data.length === 0 ? PPID_STRING_EMPTY : PPID_STRING,
    payload: data,
  };
}
