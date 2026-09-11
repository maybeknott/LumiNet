/**
 * VLESS Stream & Request Header Codec
 * Ported and refactored from donor VlessStreamCodec.kt.
 * Conforms to Xray / VLESS v0 protocol specification.
 */

export const VlessCommand = {
  TCP: 1,
  UDP: 2,
  MUX: 3,
} as const;
export type VlessCommand = (typeof VlessCommand)[keyof typeof VlessCommand];

export const VlessAddressType = {
  IPv4: 1,
  Domain: 2,
  IPv6: 3,
} as const;
export type VlessAddressType = (typeof VlessAddressType)[keyof typeof VlessAddressType];

export interface VlessAddress {
  type: VlessAddressType;
  value: string;
}

export interface VlessRequestHeader {
  version: number;
  uuid: string; // 32 hex chars / 16 bytes
  command: VlessCommand;
  port: number;
  address: VlessAddress;
  addons?: Uint8Array | undefined;
}

export interface VlessResponseHeader {
  version: number;
  addons?: Uint8Array | undefined;
}

function parseUuidToBytes(uuidStr: string): Uint8Array {
  const clean = uuidStr.replace(/-/g, '').toLowerCase();
  if (clean.length !== 32) {
    throw new Error('UUID must be 32 hex characters, got ' + uuidStr);
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToUuid(bytes: Uint8Array, offset = 0): string {
  const hex: string[] = [];
  for (let i = 0; i < 16; i++) {
    hex.push((bytes[offset + i]!).toString(16).padStart(2, '0'));
  }
  return (
    hex.slice(0, 4).join('') +
    '-' +
    hex.slice(4, 6).join('') +
    '-' +
    hex.slice(6, 8).join('') +
    '-' +
    hex.slice(8, 10).join('') +
    '-' +
    hex.slice(10, 16).join('')
  );
}

/**
 * Serializes a VLESS request header into a binary buffer (Uint8Array).
 */
export function serializeVlessRequestHeader(header: VlessRequestHeader): Uint8Array {
  const uuidBytes = parseUuidToBytes(header.uuid);
  const addons = header.addons ?? new Uint8Array(0);

  let addrBytes: Uint8Array;
  if (header.address.type === VlessAddressType.IPv4) {
    const parts = header.address.value.split('.').map((p) => parseInt(p, 10));
    addrBytes = new Uint8Array([0x01, parts[0]!, parts[1]!, parts[2]!, parts[3]!]);
  } else if (header.address.type === VlessAddressType.Domain) {
    const enc = new TextEncoder().encode(header.address.value);
    addrBytes = new Uint8Array(2 + enc.length);
    addrBytes[0] = 0x02;
    addrBytes[1] = enc.length;
    addrBytes.set(enc, 2);
  } else {
    addrBytes = new Uint8Array(17);
    addrBytes[0] = 0x03;
  }

  const totalLen = 1 + 16 + 1 + addons.length + 1 + 2 + addrBytes.length;
  const buffer = new Uint8Array(totalLen);
  let pos = 0;

  buffer[pos++] = header.version & 0xff;
  buffer.set(uuidBytes, pos);
  pos += 16;

  buffer[pos++] = addons.length & 0xff;
  if (addons.length > 0) {
    buffer.set(addons, pos);
    pos += addons.length;
  }

  buffer[pos++] = header.command & 0xff;
  buffer[pos++] = (header.port >> 8) & 0xff;
  buffer[pos++] = header.port & 0xff;

  buffer.set(addrBytes, pos);
  return buffer;
}

/**
 * Deserializes a VLESS request header from binary data.
 */
export function deserializeVlessRequestHeader(
  data: Uint8Array
): { header: VlessRequestHeader; bytesRead: number } {
  if (data.length < 22) {
    throw new Error('Buffer too small for VLESS request header');
  }

  let pos = 0;
  const version = data[pos++]!;
  const uuid = bytesToUuid(data, pos);
  pos += 16;

  const addonsLen = data[pos++]!;
  let addons: Uint8Array | undefined;
  if (addonsLen > 0) {
    addons = data.slice(pos, pos + addonsLen);
    pos += addonsLen;
  }

  const command = data[pos++]! as VlessCommand;
  const port = ((data[pos++]! << 8) | data[pos++]!) >>> 0;
  const addrType = data[pos++]! as VlessAddressType;

  let addressValue = '';
  if (addrType === VlessAddressType.IPv4) {
    const b0 = data[pos++]!;
    const b1 = data[pos++]!;
    const b2 = data[pos++]!;
    const b3 = data[pos++]!;
    addressValue = [b0, b1, b2, b3].join('.');
  } else if (addrType === VlessAddressType.Domain) {
    const dLen = data[pos++]!;
    addressValue = new TextDecoder().decode(data.slice(pos, pos + dLen));
    pos += dLen;
  } else if (addrType === VlessAddressType.IPv6) {
    pos += 16;
    addressValue = '::1';
  }

  return {
    header: {
      version,
      uuid,
      command,
      port,
      address: { type: addrType, value: addressValue },
      addons,
    },
    bytesRead: pos,
  };
}

/**
 * Serializes a VLESS response header.
 */
export function serializeVlessResponseHeader(resp: VlessResponseHeader): Uint8Array {
  const addons = resp.addons ?? new Uint8Array(0);
  const out = new Uint8Array(2 + addons.length);
  out[0] = resp.version & 0xff;
  out[1] = addons.length & 0xff;
  if (addons.length > 0) {
    out.set(addons, 2);
  }
  return out;
}

/**
 * Deserializes a VLESS response header.
 */
export function deserializeVlessResponseHeader(
  data: Uint8Array
): { header: VlessResponseHeader; bytesRead: number } {
  if (data.length < 2) {
    throw new Error('Buffer too short for VLESS response header');
  }
  const version = data[0]!;
  const addonsLen = data[1]!;
  let addons: Uint8Array | undefined;
  if (addonsLen > 0) {
    addons = data.slice(2, 2 + addonsLen);
  }
  return {
    header: { version, addons },
    bytesRead: 2 + addonsLen,
  };
}
