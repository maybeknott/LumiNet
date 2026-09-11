export interface ProtocolConfigPreset {
  listenPort: number;
  serverUuid: string;
  sniDest: string;
  transport?: string;
}

export class MultiprotocolSynthesizer {
  public static generateSingboxInbound(preset: ProtocolConfigPreset): string {
    const transport = preset.transport ?? 'tcp-reality';
    return JSON.stringify({
      type: 'vless',
      tag: `in-${transport}`,
      listen_port: preset.listenPort,
      users: [{ uuid: preset.serverUuid }],
      tls: { enabled: true, server_name: preset.sniDest }
    });
  }
}
