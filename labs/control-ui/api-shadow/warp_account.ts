export interface WarpProfile {
  accountId: string;
  accessToken: string;
  privateKey: string;
  allocatedV4?: string;
  allocatedV6?: string;
}

export class WarpAccountClient {
  public static synthesizeWireguardConf(
    profile: WarpProfile,
    endpoint = 'engage.cloudflareclient.com:2408',
    peerPubKey = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='
  ): string {
    const v4 = profile.allocatedV4 ?? '172.16.0.2';
    const v6 = profile.allocatedV6 ?? '2606:4700:110:8735:6a4a:2a41:b6b7:b3d3';

    return `[Interface]
PrivateKey = ${profile.privateKey}
Address = ${v4}/32, ${v6}/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = ${peerPubKey}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
  }
}
