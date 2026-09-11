/**
 * Multi-Format Core Configuration Compiler
 */
export interface UnifiedOutboundDefinition {
  tag: string;
  protocol: string;
  server: string;
  serverPort: number;
  uuid: string;
  tlsSni: string;
  transportType: string;
  wsPath: string;
}

export class MultiFormatCompiler {
  static compileSingBox(def: UnifiedOutboundDefinition): string {
    return JSON.stringify({
      type: def.protocol,
      tag: def.tag,
      server: def.server,
      server_port: def.serverPort,
      uuid: def.uuid,
      tls: { enabled: true, server_name: def.tlsSni },
      transport: { type: def.transportType, path: def.wsPath },
    });
  }

  static compileXray(def: UnifiedOutboundDefinition): string {
    return JSON.stringify({
      protocol: def.protocol,
      tag: def.tag,
      settings: {
        vnext: [
          {
            address: def.server,
            port: def.serverPort,
            users: [{ id: def.uuid }],
          },
        ],
      },
      streamSettings: {
        network: def.transportType,
        security: 'tls',
        tlsSettings: { serverName: def.tlsSni },
        wsSettings: { path: def.wsPath },
      },
    });
  }

  static compileClash(def: UnifiedOutboundDefinition): string {
    return `- name: "${def.tag}"\n  type: ${def.protocol}\n  server: ${def.server}\n  port: ${def.serverPort}\n  uuid: ${def.uuid}\n  tls: true\n  servername: ${def.tlsSni}\n  network: ${def.transportType}\n  ws-opts:\n    path: ${def.wsPath}`;
  }
}
