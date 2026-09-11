export interface TlsCertificateBinding {
  certPath: string;
  keyPath: string;
  sniDomain: string;
  alpn: string[];
}

export interface ServerProvisionConfig {
  localAddr?: string;
  localPort?: number;
  remoteFallbackAddr?: string;
  remoteFallbackPort?: number;
  passwords: string[];
  tls: TlsCertificateBinding;
  enableFastOpen?: boolean;
}

export class AutomatedTlsServerConfigurator {
  private servers: Map<string, ServerProvisionConfig> = new Map();

  registerServer(serverId: string, config: ServerProvisionConfig): void {
    this.servers.set(serverId, config);
  }

  generateJsonConfig(serverId: string): string | null {
    const cfg = this.servers.get(serverId);
    if (!cfg) return null;

    const out = {
      run_type: 'server',
      local_addr: cfg.localAddr || '0.0.0.0',
      local_port: cfg.localPort || 443,
      remote_addr: cfg.remoteFallbackAddr || '127.0.0.1',
      remote_port: cfg.remoteFallbackPort || 80,
      password: cfg.passwords,
      ssl: {
        cert: cfg.tls.certPath,
        key: cfg.tls.keyPath,
        sni: cfg.tls.sniDomain,
        alpn: cfg.tls.alpn
      },
      tcp: {
        fast_open: cfg.enableFastOpen ?? true
      }
    };

    return JSON.stringify(out, null, 2);
  }
}
