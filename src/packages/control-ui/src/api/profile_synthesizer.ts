export const CensorshipRegion = {
  Global: 'global',
  China: 'china',
  Iran: 'iran',
  Russia: 'russia',
} as const;
export type CensorshipRegion = (typeof CensorshipRegion)[keyof typeof CensorshipRegion];

export interface RegionalEvasionProfile {
  region: CensorshipRegion;
  dnsFragmentationEnabled: boolean;
  dnsFragmentSize: number;
  tcpMssClamp: number;
  tlsPaddingMin: number;
  tlsPaddingMax: number;
  parallelDnsQueries: boolean;
  preferredDnsServers: string[];
}

export class CensorshipProfileSynthesizer {
  private profiles: Map<CensorshipRegion, RegionalEvasionProfile> = new Map();

  constructor() {
    this.profiles.set(CensorshipRegion.China, {
      region: CensorshipRegion.China,
      dnsFragmentationEnabled: true,
      dnsFragmentSize: 40,
      tcpMssClamp: 1200,
      tlsPaddingMin: 100,
      tlsPaddingMax: 500,
      parallelDnsQueries: true,
      preferredDnsServers: ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'],
    });

    this.profiles.set(CensorshipRegion.Iran, {
      region: CensorshipRegion.Iran,
      dnsFragmentationEnabled: true,
      dnsFragmentSize: 32,
      tcpMssClamp: 1100,
      tlsPaddingMin: 256,
      tlsPaddingMax: 1024,
      parallelDnsQueries: true,
      preferredDnsServers: [
        'https://sky.rethinkdns.com/dns-query',
        'https://dns.quad9.net/dns-query',
      ],
    });

    this.profiles.set(CensorshipRegion.Russia, {
      region: CensorshipRegion.Russia,
      dnsFragmentationEnabled: false,
      dnsFragmentSize: 0,
      tcpMssClamp: 1300,
      tlsPaddingMin: 64,
      tlsPaddingMax: 256,
      parallelDnsQueries: true,
      preferredDnsServers: ['https://1.1.1.1/dns-query'],
    });

    this.profiles.set(CensorshipRegion.Global, {
      region: CensorshipRegion.Global,
      dnsFragmentationEnabled: false,
      dnsFragmentSize: 0,
      tcpMssClamp: 1460,
      tlsPaddingMin: 0,
      tlsPaddingMax: 0,
      parallelDnsQueries: false,
      preferredDnsServers: ['https://1.1.1.1/dns-query'],
    });
  }

  getProfile(region: CensorshipRegion): RegionalEvasionProfile {
    return this.profiles.get(region) || this.profiles.get(CensorshipRegion.Global)!;
  }
}
