export interface HotspotConfig {
  downstreamIface?: string;
  upstreamVpnIface?: string;
  downstreamSubnet?: string;
  clampMssBytes?: number;
}

export class HotspotNatRepeater {
  public readonly downstreamIface: string;
  public readonly upstreamVpnIface: string;
  public readonly downstreamSubnet: string;
  public readonly clampMssBytes: number;

  constructor(cfg: HotspotConfig = {}) {
    this.downstreamIface = cfg.downstreamIface ?? 'wlan1';
    this.upstreamVpnIface = cfg.upstreamVpnIface ?? 'tun0';
    this.downstreamSubnet = cfg.downstreamSubnet ?? '192.168.43.0/24';
    this.clampMssBytes = cfg.clampMssBytes ?? 1360;
  }

  public generateIptables(): string[] {
    return [
      'echo 1 > /proc/sys/net/ipv4/ip_forward',
      `iptables -A FORWARD -i ${this.downstreamIface} -o ${this.upstreamVpnIface} -j ACCEPT`,
      `iptables -A FORWARD -i ${this.upstreamVpnIface} -o ${this.downstreamIface} -m state --state RELATED,ESTABLISHED -j ACCEPT`,
      `iptables -t nat -A POSTROUTING -s ${this.downstreamSubnet} -o ${this.upstreamVpnIface} -j MASQUERADE`,
      `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${this.clampMssBytes}`
    ];
  }
}
