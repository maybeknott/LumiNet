export interface ReplayResistantConfig {
  psk: Uint8Array;
  maxSkewSecs: number;
  maxTrackedNonces: number;
}

export class ReplayResistantTunnelSession {
  private sessionKey: Uint8Array;
  private lastRemoteSeq = 0;
  private seenNonces = new Set<string>();
  public config: ReplayResistantConfig;
  constructor(config: ReplayResistantConfig, clientRandom: Uint8Array, serverRandom: Uint8Array) {
    this.config = config;
    this.sessionKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      const p = config.psk[i % config.psk.length]!;
      const c = clientRandom[i % clientRandom.length]!;
      const s = serverRandom[i % serverRandom.length]!;
      this.sessionKey[i] = (p ^ c ^ s ^ (i * 17)) & 0xff;
    }
  }

  sealPacket(sequence: number, timestamp: number, payload: Uint8Array): Uint8Array {
    const packet = new Uint8Array(28 + payload.length + 16);
    const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);

    view.setBigUint64(0, BigInt(sequence));
    view.setBigUint64(8, BigInt(timestamp));

    const nonce = new Uint8Array(12);
    for (let i = 0; i < 8; i++) {
      nonce[i] = packet[i]! ^ this.sessionKey[i]!;
    }
    for (let i = 0; i < 4; i++) {
      nonce[8 + i] = packet[8 + i]! ^ this.sessionKey[8 + i]!;
    }
    packet.set(nonce, 16);

    for (let i = 0; i < payload.length; i++) {
      const k = this.sessionKey[(i + nonce[i % 12]!) % this.sessionKey.length]!;
      packet[28 + i] = payload[i]! ^ k;
    }

    let mac = 0;
    for (let i = 0; i < 28 + payload.length; i++) {
      mac = (mac * 31 + packet[i]!) & 0xffffffff;
    }
    for (let i = 0; i < 16; i++) {
      packet[28 + payload.length + i] = (mac >> ((i % 4) * 8)) & 0xff;
    }

    return packet;
  }

  openPacket(
    packet: Uint8Array,
    currentTime: number,
  ): { sequence: number; timestamp: number; payload: Uint8Array } {
    if (packet.length < 28 + 16) {
      throw new Error('Packet too short');
    }

    const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
    const sequence = Number(view.getBigUint64(0));
    const timestamp = Number(view.getBigUint64(8));

    const diff = Math.abs(currentTime - timestamp);
    if (diff > this.config.maxSkewSecs) {
      throw new Error(`Timestamp skew too large: ${diff}`);
    }

    const nonceHex = Array.from(packet.subarray(16, 28))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    if (this.seenNonces.has(nonceHex)) {
      throw new Error('Replay detected: duplicate nonce');
    }

    const bodyEnd = packet.length - 16;
    let mac = 0;
    for (let i = 0; i < bodyEnd; i++) {
      mac = (mac * 31 + packet[i]!) & 0xffffffff;
    }
    for (let i = 0; i < 16; i++) {
      const expected = (mac >> ((i % 4) * 8)) & 0xff;
      if (packet[bodyEnd + i] !== expected) {
        throw new Error('Integrity verification failed');
      }
    }

    if (sequence <= this.lastRemoteSeq && this.lastRemoteSeq > 0) {
      throw new Error(`Out of order sequence: ${sequence} <= ${this.lastRemoteSeq}`);
    }

    const payloadLen = bodyEnd - 28;
    const decrypted = new Uint8Array(payloadLen);
    const nonce = packet.subarray(16, 28);
    for (let i = 0; i < payloadLen; i++) {
      const k = this.sessionKey[(i + nonce[i % 12]!) % this.sessionKey.length]!;
      decrypted[i] = packet[28 + i]! ^ k;
    }

    if (this.seenNonces.size >= this.config.maxTrackedNonces) {
      this.seenNonces.clear();
    }
    this.seenNonces.add(nonceHex);
    this.lastRemoteSeq = sequence;

    return { sequence, timestamp, payload: decrypted };
  }
}
