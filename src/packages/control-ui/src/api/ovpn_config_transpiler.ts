export interface TranspiledOvpnConfig {
  remoteHost: string;
  remotePort: number;
  proto: string;
  dev: string;
  cipher: string;
  auth: string;
  caCert: string;
  clientCert: string;
  clientKey: string;
  routes: string[];
}

export class OvpnConfigTranspiler {
  transpile(raw: string): TranspiledOvpnConfig | null {
    const lines = raw.split('\n');
    const profile: TranspiledOvpnConfig = {
      remoteHost: '',
      remotePort: 1194,
      proto: 'udp',
      dev: 'tun',
      cipher: 'AES-256-GCM',
      auth: 'SHA256',
      caCert: '',
      clientCert: '',
      clientKey: '',
      routes: [],
    };

    let inTag: string | null = null;
    const tagBuffer: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

      if (trimmed.startsWith('<') && trimmed.endsWith('>') && !trimmed.startsWith('</')) {
        inTag = trimmed.slice(1, -1);
        tagBuffer.length = 0;
        continue;
      }

      if (inTag && trimmed === `</${inTag}>`) {
        const content = tagBuffer.join('\n').trim();
        if (inTag === 'ca') profile.caCert = content;
        if (inTag === 'cert') profile.clientCert = content;
        if (inTag === 'key') profile.clientKey = content;
        inTag = null;
        continue;
      }

      if (inTag) {
        tagBuffer.push(trimmed);
        continue;
      }

      const tokens = trimmed.split(/\s+/);
      if (tokens.length === 0) continue;

      switch (tokens[0]) {
        case 'remote':
          if (tokens.length >= 2) profile.remoteHost = tokens[1]!;
          if (tokens.length >= 3) {
            const p = parseInt(tokens[2]!, 10);
            if (!isNaN(p)) profile.remotePort = p;
          }
          if (tokens.length >= 4) profile.proto = tokens[3]!.toLowerCase();
          break;
        case 'proto':
          if (tokens.length >= 2) profile.proto = tokens[1]!.toLowerCase();
          break;
        case 'dev':
          if (tokens.length >= 2) profile.dev = tokens[1]!;
          break;
        case 'cipher':
          if (tokens.length >= 2) profile.cipher = tokens[1]!;
          break;
        case 'auth':
          if (tokens.length >= 2) profile.auth = tokens[1]!;
          break;
        case 'route':
          if (tokens.length >= 2) profile.routes.push(tokens.slice(1).join(' '));
          break;
      }
    }

    if (!profile.remoteHost) return null;
    return profile;
  }
}
