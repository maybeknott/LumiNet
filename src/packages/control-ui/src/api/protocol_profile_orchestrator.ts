export const UiClientProtocol = {
  AmneziaWg: 'amnezia_wg',
  Vless: 'vless',
  Shadowsocks2022: 'shadowsocks_2022',
  Masque: 'masque',
} as const;
export type UiClientProtocol = (typeof UiClientProtocol)[keyof typeof UiClientProtocol];

export interface UiClientProfile {
  profileId: string;
  name: string;
  protocol: UiClientProtocol;
  endpoint: string;
  fallbackOrder: number;
  configPayload: string;
}

export class ProtocolProfileOrchestrator {
  private profiles: Map<string, UiClientProfile> = new Map();
  public activeProfileId: string | null = null;

  addProfile(profile: UiClientProfile): void {
    this.profiles.set(profile.profileId, profile);
    if (!this.activeProfileId) {
      this.activeProfileId = profile.profileId;
    }
  }

  setActiveProfile(profileId: string): boolean {
    if (!this.profiles.has(profileId)) return false;
    this.activeProfileId = profileId;
    return true;
  }

  getActiveProfile(): UiClientProfile | null {
    if (!this.activeProfileId) return null;
    return this.profiles.get(this.activeProfileId) ?? null;
  }

  getFallbackChain(): UiClientProfile[] {
    return Array.from(this.profiles.values()).sort((a, b) => a.fallbackOrder - b.fallbackOrder);
  }

  exportJson(): string {
    return JSON.stringify(Array.from(this.profiles.values()), null, 2);
  }

  importJson(json: string): void {
    const list = JSON.parse(json) as UiClientProfile[];
    for (const p of list) {
      this.profiles.set(p.profileId, p);
    }
    if (!this.activeProfileId && list.length > 0) {
      this.activeProfileId = list[0]!.profileId;
    }
  }

  totalProfiles(): number {
    return this.profiles.size;
  }
}
