// Control UI TypeScript: Dynamic Proxy Pool Validator API

export type ProxyProtocol = 'http' | 'https' | 'socks4' | 'socks5';
export type AnonymityLevel = 'transparent' | 'anonymous' | 'elite';

export interface ProxyRecord {
  host: string;
  port: number;
  protocol: ProxyProtocol;
  isAlive: boolean;
  latencyMs: number;
  anonymity: AnonymityLevel;
  lastCheckedMs: number;
}

export class DynamicProxyValidator {
  public timeoutMs: number;
  public pool: Map<string, ProxyRecord> = new Map();

  constructor(timeoutMs: number = 5000) {
    this.timeoutMs = timeoutMs;
  }

  public craftSocks5Probe(): Uint8Array {
    return new Uint8Array([0x05, 0x01, 0x00]);
  }

  public craftHttpProbe(host: string): string {
    return `GET http://${host}/generate_204 HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;
  }

  public verifySocks5Response(resp: Uint8Array): boolean {
    return resp.length >= 2 && resp[0] === 0x05 && resp[1] === 0x00;
  }

  public determineAnonymity(headers: Record<string, string>, clientIp: string): AnonymityLevel {
    const keys = ['x-forwarded-for', 'via', 'x-real-ip', 'forwarded'];
    let hasForward = false;

    for (const [k, v] of Object.entries(headers)) {
      if (keys.includes(k.toLowerCase())) {
        hasForward = true;
        if (v.includes(clientIp)) return 'transparent';
      }
    }

    return hasForward ? 'anonymous' : 'elite';
  }

  public recordProbe(
    host: string,
    port: number,
    protocol: ProxyProtocol,
    isAlive: boolean,
    latencyMs: number,
    anonymity: AnonymityLevel,
    nowMs: number
  ): void {
    const key = `${host}:${port}`;
    this.pool.set(key, {
      host,
      port,
      protocol,
      isAlive,
      latencyMs,
      anonymity,
      lastCheckedMs: nowMs,
    });
  }

  public getHealthyProxies(maxLatencyMs: number): ProxyRecord[] {
    return Array.from(this.pool.values())
      .filter(p => p.isAlive && p.latencyMs <= maxLatencyMs)
      .sort((a, b) => a.latencyMs - b.latencyMs);
  }
}
