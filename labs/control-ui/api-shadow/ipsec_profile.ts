export interface Ikev2Proposal {
  encryption: string;
  integrity: string;
  dhGroup: string;
  pfsGroup: string;
  lifetimeSec: number;
}

export interface IpsecProfileConfig {
  serverEndpoint: string;
  serverPort?: number;
  pskHex: string;
  leftId: string;
  rightId: string;
  proposal?: Ikev2Proposal;
  natKeepaliveSec?: number;
}

export class IpsecProfile {
  public readonly serverEndpoint: string;
  public readonly serverPort: number;
  public readonly pskHex: string;
  public readonly leftId: string;
  public readonly rightId: string;
  public readonly proposal: Ikev2Proposal;
  public readonly natKeepaliveSec: number;

  constructor(cfg: IpsecProfileConfig) {
    this.serverEndpoint = cfg.serverEndpoint;
    this.serverPort = cfg.serverPort ?? 500;
    this.pskHex = cfg.pskHex;
    this.leftId = cfg.leftId;
    this.rightId = cfg.rightId;
    this.proposal = cfg.proposal ?? {
      encryption: 'aes256gcm128',
      integrity: 'sha256',
      dhGroup: 'modp2048',
      pfsGroup: 'modp2048',
      lifetimeSec: 3600
    };
    this.natKeepaliveSec = cfg.natKeepaliveSec ?? 20;
  }

  public generateSwanctlConf(): string {
    return `connections {
  lumi-${this.leftId} {
    remote_addrs = ${this.serverEndpoint}
    vips = 0.0.0.0,::
    local {
      auth = psk
      id = ${this.leftId}
    }
    remote {
      auth = psk
      id = ${this.rightId}
    }
    children {
      net {
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = ${this.proposal.encryption}-${this.proposal.integrity}-${this.proposal.pfsGroup}
        start_action = start
      }
    }
  }
}`;
  }
}
