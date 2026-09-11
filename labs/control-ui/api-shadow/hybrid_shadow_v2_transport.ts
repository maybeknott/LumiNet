export const HybridShadowCipher = {
  AeadAes256Gcm: 'AEAD_AES_256_GCM',
  AeadChacha20Poly1305: 'AEAD_CHACHA20_POLY1305',
} as const;
export type HybridShadowCipher = (typeof HybridShadowCipher)[keyof typeof HybridShadowCipher];

export interface HybridShadowConfig {
  cipher?: HybridShadowCipher;
  psk: Uint8Array;
  saltLength?: number;
  replayWindowSecs?: number;
}

export class HybridShadowV2Transport {
  public config: Required<HybridShadowConfig>;
  private saltHistory: Map<string, number> = new Map();

  constructor(config: HybridShadowConfig) {
    if (config.psk.length < 16) {
      throw new Error('PSK must be at least 16 bytes');
    }
    this.config = {
      cipher: config.cipher ?? HybridShadowCipher.AeadAes256Gcm,
      psk: config.psk,
      saltLength: config.saltLength ?? 32,
      replayWindowSecs: config.replayWindowSecs ?? 120,
    };
  }

  generateSalt(): Uint8Array {
    const salt = new Uint8Array(this.config.saltLength);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(salt);
    } else {
      for (let i = 0; i < salt.length; i++) {
        salt[i] = Math.floor(Math.random() * 256);
      }
    }
    return salt;
  }

  deriveSubkey(salt: Uint8Array): Uint8Array {
    const subkey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      const pskByte = this.config.psk[i % this.config.psk.length]!;
      const saltByte = salt[i % salt.length]!;
      subkey[i] = (pskByte ^ saltByte ^ (i * 7 + 13)) & 0xff;
    }
    return subkey;
  }

  registerSalt(salt: Uint8Array, nowSecs: number): boolean {
    const cutoff = nowSecs - this.config.replayWindowSecs;
    for (const [key, ts] of this.saltHistory.entries()) {
      if (ts < cutoff) {
        this.saltHistory.delete(key);
      }
    }

    const hex = Array.from(salt)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (this.saltHistory.has(hex)) {
      return false; // Replay detected
    }

    this.saltHistory.set(hex, nowSecs);
    return true;
  }

  framePayload(salt: Uint8Array, payload: Uint8Array): Uint8Array {
    const frame = new Uint8Array(1 + salt.length + 2 + payload.length);
    frame[0] = salt.length;
    frame.set(salt, 1);
    const pLen = payload.length;
    frame[1 + salt.length] = (pLen >> 8) & 0xff;
    frame[2 + salt.length] = pLen & 0xff;
    frame.set(payload, 3 + salt.length);
    return frame;
  }

  unframePayload(data: Uint8Array): { salt: Uint8Array; payload: Uint8Array } | null {
    if (data.length < 3) return null;
    const saltLen = data[0]!;
    if (data.length < 1 + saltLen + 2) return null;

    const salt = data.slice(1, 1 + saltLen);
    const pLen = (data[1 + saltLen]! << 8) | data[2 + saltLen]!;
    const start = 3 + saltLen;
    if (data.length < start + pLen) return null;

    const payload = data.slice(start, start + pLen);
    return { salt, payload };
  }
}
