export interface KillswitchConfig {
  vpnInterface?: string;
  vpnPort?: number;
  vpnServerIp: string;
  allowedSubnets?: string[];
  blockDnsLeaks?: boolean;
}

export class FirewallKillswitch {
  public readonly vpnInterface: string;
  public readonly vpnPort: number;
  public readonly vpnServerIp: string;
  public readonly allowedSubnets: string[];
  public readonly blockDnsLeaks: boolean;

  constructor(cfg: KillswitchConfig) {
    this.vpnInterface = cfg.vpnInterface ?? 'tun0';
    this.vpnPort = cfg.vpnPort ?? 51820;
    this.vpnServerIp = cfg.vpnServerIp;
    this.allowedSubnets = cfg.allowedSubnets ?? ['127.0.0.1/8', '10.0.0.0/8', '192.168.0.0/16'];
    this.blockDnsLeaks = cfg.blockDnsLeaks ?? true;
  }

  public generateIptables(): string[] {
    const rules = [
      'iptables -F OUTPUT',
      'iptables -P OUTPUT DROP',
      'iptables -A OUTPUT -o lo -j ACCEPT',
      `iptables -A OUTPUT -o ${this.vpnInterface} -j ACCEPT`,
      `iptables -A OUTPUT -d ${this.vpnServerIp} -p udp --dport ${this.vpnPort} -j ACCEPT`
    ];
    for (const subnet of this.allowedSubnets) {
      rules.push(`iptables -A OUTPUT -d ${subnet} -j ACCEPT`);
    }
    if (this.blockDnsLeaks) {
      rules.push(`iptables -A OUTPUT -o ! ${this.vpnInterface} -p udp --dport 53 -j REJECT`);
      rules.push(`iptables -A OUTPUT -o ! ${this.vpnInterface} -p tcp --dport 53 -j REJECT`);
    }
    return rules;
  }
}
