/**
 * Relay stream network types.
 */
export type RelayNetwork = 'tcp' | 'udp';

/**
 * Relay stream header defining egress tunnel destination.
 * Directly mirrors lumicore::relay::relay_stream_codec.
 */
export interface RelayStreamHeader {
  network: RelayNetwork;
  host: string;
  port: number;
}

/**
 * Encodes into ASCII delimiter format: `<network>@<host>$<port>\r`.
 */
export function encodeRelayV1(header: RelayStreamHeader): Uint8Array {
  const s = `${header.network}@${header.host}$${header.port}\r`;
  return new TextEncoder().encode(s);
}

/**
 * Decodes an ASCII delimiter formatted relay header.
 */
export function decodeRelayV1(src: Uint8Array): {
  header: RelayStreamHeader;
  bytesConsumed: number;
} {
  if (src.length === 0) {
    throw new Error('Empty buffer');
  }

  let crPos = -1;
  for (let i = 0; i < src.length; i++) {
    if (src[i] === 0x0d) {
      // '\r'
      crPos = i;
      break;
    }
  }
  if (crPos === -1) {
    throw new Error('Missing delimiter \\r');
  }

  const text = new TextDecoder().decode(src.subarray(0, crPos));
  const atPos = text.indexOf('@');
  if (atPos === -1) {
    throw new Error('Missing delimiter @');
  }

  const netStr = text.substring(0, atPos).toLowerCase();
  if (netStr !== 'tcp' && netStr !== 'udp') {
    throw new Error(`Invalid relay network: ${netStr}`);
  }

  const rest = text.substring(atPos + 1);
  const dollarPos = rest.indexOf('$');
  if (dollarPos === -1) {
    throw new Error('Missing delimiter $');
  }

  const host = rest.substring(0, dollarPos);
  const portStr = rest.substring(dollarPos + 1);
  const port = parseInt(portStr, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${portStr}`);
  }

  return {
    header: {
      network: netStr,
      host,
      port,
    },
    bytesConsumed: crPos + 1,
  };
}

/**
 * Encodes into compact binary wire format:
 * Magic [0x52, 0x32] ('R2') + NetByte (1=TCP, 2=UDP) + Port (uint16 BE) + HostLen (uint8) + HostBytes
 */
export function encodeRelayV2(header: RelayStreamHeader): Uint8Array {
  const hostBytes = new TextEncoder().encode(header.host);
  const clampedLen = Math.min(hostBytes.length, 255);
  const out = new Uint8Array(6 + clampedLen);

  out[0] = 0x52; // 'R'
  out[1] = 0x32; // '2'
  out[2] = header.network === 'tcp' ? 1 : 2;
  out[3] = (header.port >> 8) & 0xff;
  out[4] = header.port & 0xff;
  out[5] = clampedLen;
  out.set(hostBytes.subarray(0, clampedLen), 6);

  return out;
}

/**
 * Decodes a compact binary relay header.
 */
export function decodeRelayV2(src: Uint8Array): {
  header: RelayStreamHeader;
  bytesConsumed: number;
} {
  if (src.length < 6) {
    throw new Error('Buffer too short for relay v2 header');
  }

  if (src[0] !== 0x52 || src[1] !== 0x32) {
    throw new Error('Invalid relay v2 magic bytes');
  }

  const netByte = src[2];
  let network: RelayNetwork;
  if (netByte === 1) {
    network = 'tcp';
  } else if (netByte === 2) {
    network = 'udp';
  } else {
    throw new Error(`Unknown network byte: ${netByte}`);
  }

  const port = (src[3]! << 8) | src[4]!;
  const hostLen = src[5]!;
  const totalLen = 6 + hostLen;

  if (src.length < totalLen) {
    throw new Error('Buffer truncated for relay v2 host');
  }

  const host = new TextDecoder().decode(src.subarray(6, totalLen));

  return {
    header: {
      network,
      host,
      port,
    },
    bytesConsumed: totalLen,
  };
}
