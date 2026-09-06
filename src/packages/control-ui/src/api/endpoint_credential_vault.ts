export interface StoredProfile {
  profileId: string;
  serverHost: string;
  serverPort: number;
  username: string;
  encryptedSecret: Uint8Array;
  createdAtSec: number;
  expiresAtSec: number;
}

export class EndpointCredentialVault {
  private profiles = new Map<string, StoredProfile>();
  private masterKey: Uint8Array;
  constructor(masterKey: Uint8Array) {
    this.masterKey = masterKey;
  }

  storeProfile(
    profileId: string,
    host: string,
    port: number,
    user: string,
    rawSecret: Uint8Array,
    nowSec: number,
    ttlSec: number,
  ): void {
    const enc = new Uint8Array(rawSecret.length);
    for (let i = 0; i < rawSecret.length; i++) {
      const k = this.masterKey.length > 0 ? this.masterKey[i % this.masterKey.length] : 0;
      enc[i] = rawSecret[i]! ^ k!;
    }

    this.profiles.set(profileId, {
      profileId,
      serverHost: host,
      serverPort: port,
      username: user,
      encryptedSecret: enc,
      createdAtSec: nowSec,
      expiresAtSec: nowSec + ttlSec,
    });
  }

  retrieveSecret(profileId: string, nowSec: number): Uint8Array | undefined {
    const p = this.profiles.get(profileId);
    if (!p || nowSec > p.expiresAtSec) return undefined;

    const dec = new Uint8Array(p.encryptedSecret.length);
    for (let i = 0; i < p.encryptedSecret.length; i++) {
      const k = this.masterKey.length > 0 ? this.masterKey[i % this.masterKey.length] : 0;
      dec[i] = p.encryptedSecret[i]! ^ k!;
    }
    return dec;
  }

  isProfileValid(profileId: string, nowSec: number): boolean {
    const p = this.profiles.get(profileId);
    return !!p && nowSec <= p.expiresAtSec;
  }

  purgeExpired(nowSec: number): number {
    let count = 0;
    for (const [id, p] of this.profiles.entries()) {
      if (nowSec > p.expiresAtSec) {
        this.profiles.delete(id);
        count++;
      }
    }
    return count;
  }
}
