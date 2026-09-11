/**
 * Desktop Proxy Orchestrator, PAC Script Engine, and Network Telemetry API.
 *
 * Unified TypeScript implementation of system proxy auto-configuration,
 * routing rule parsing, throughput telemetry, and geo/ISP resolvers
 */

export interface DesktopRoutingRule {
  type: 'domain' | 'ip' | 'range' | 'app';
  value: string;
  isWildcard: boolean;
  forceProxy: boolean;
}

export interface NetStatsSnapshot {
  timestamp: number;
  bytesSent: number;
  bytesReceived: number;
  uploadSpeedBps: number;
  downloadSpeedBps: number;
  peakUploadBps: number;
  peakDownloadBps: number;
  totalSent: number;
  totalReceived: number;
}

export interface CloudflareColoLocation {
  airportCode: string;
  countryCode: string;
  countryName: string;
  flagEmoji: string;
}

/**
 * Parses user routing rules string into structured rule directives.
 */
export function parseDesktopRoutingRules(raw: string): DesktopRoutingRule[] {
  const rules: DesktopRoutingRule[] = [];
  if (!raw || !raw.trim()) return rules;

  const cleaned = raw
    .replace(/<br>/g, ',')
    .replace(/\n/g, ',')
    .replace(/\r/g, '');

  const tokens = cleaned.split(',');
  for (const token of tokens) {
    const t = token.trim();
    if (!t || t.startsWith('app:')) continue;

    let ruleType: 'domain' | 'ip' | 'range' | 'app' = 'domain';
    let val = t;

    const colonIdx = t.indexOf(':');
    if (colonIdx !== -1) {
      const typeStr = t.slice(0, colonIdx).trim().toLowerCase();
      val = t.slice(colonIdx + 1).trim();
      if (typeStr === 'domain' || typeStr === 'ip' || typeStr === 'range') {
        ruleType = typeStr;
      }
    }

    let forceProxy = false;
    if (val.startsWith('!')) {
      forceProxy = true;
      val = val.slice(1);
    }

    const isWildcard = val.startsWith('*') || val.includes('*');
    const cleanVal = val.replace(/^\*/, '');

    rules.push({
      type: ruleType,
      value: cleanVal,
      isWildcard,
      forceProxy,
    });
  }

  return rules;
}

/**
 * Evaluates a hostname against the compiled rules offline in TypeScript.
 */
export function evaluateHostPac(
  host: string,
  rules: DesktopRoutingRule[]
): 'DIRECT' | 'PROXY' | 'DEFAULT_PROXY' {
  const hostLower = host.trim().toLowerCase();
  if (
    hostLower === '127.0.0.1' ||
    hostLower === '::1' ||
    hostLower === 'localhost'
  ) {
    return 'DIRECT';
  }

  for (const rule of rules) {
    const ruleValLower = rule.value.toLowerCase();

    if (rule.type === 'domain') {
      if (rule.isWildcard) {
        if (hostLower.endsWith(ruleValLower) || hostLower === ruleValLower) {
          return rule.forceProxy ? 'PROXY' : 'DIRECT';
        }
      } else if (hostLower === ruleValLower) {
        return rule.forceProxy ? 'PROXY' : 'DIRECT';
      }
    } else if (rule.type === 'ip' || rule.type === 'range') {
      if (rule.isWildcard) {
        const prefix = ruleValLower.replace(/\*+$/, '');
        if (hostLower.startsWith(prefix)) {
          return rule.forceProxy ? 'PROXY' : 'DIRECT';
        }
      } else if (hostLower === ruleValLower) {
        return rule.forceProxy ? 'PROXY' : 'DIRECT';
      }
    }
  }

  return 'DEFAULT_PROXY';
}

/**
 * Compiles a Proxy Auto-Configuration (PAC) script conforming to standard browser/OS specs.
 */
export function compilePacScript(
  proxyHost: string,
  proxyPort: number,
  isSocks5: boolean,
  rules: DesktopRoutingRule[]
): string {
  const proxyDirective = isSocks5
    ? `SOCKS5 ${proxyHost}:${proxyPort}; SOCKS ${proxyHost}:${proxyPort}; DIRECT`
    : `PROXY ${proxyHost}:${proxyPort}; DIRECT`;

  let jsRules = '';
  for (const rule of rules) {
    const val = rule.value;
    if (rule.forceProxy && rule.type === 'domain') {
      if (rule.isWildcard) {
        jsRules += `  if (shExpMatch(host, "*${val}")) return "${proxyDirective}";\n`;
      } else {
        jsRules += `  if (host === "${val}") return "${proxyDirective}";\n`;
      }
    } else if (rule.type === 'domain') {
      if (rule.isWildcard) {
        jsRules += `  if (shExpMatch(host, "*${val}")) return "DIRECT";\n`;
      } else {
        jsRules += `  if (host === "${val}") return "DIRECT";\n`;
      }
    } else if (rule.type === 'ip' || rule.type === 'range') {
      if (rule.isWildcard) {
        const prefix = val.replace(/\*+$/, '');
        jsRules += `  if (host.indexOf("${prefix}") === 0) return "DIRECT";\n`;
      } else {
        jsRules += `  if (host === "${val}") return "DIRECT";\n`;
      }
    }
  }

  return (
    `function FindProxyForURL(url, host) {\n` +
    `  "use strict";\n` +
    `  if (isPlainHostName(host) || /^127\\./.test(host) || /^10\\./.test(host) || /^172\\.(1[6-9]|2[0-9]|3[01])\\./.test(host) || /^192\\.168\\./.test(host) || host === "localhost" || host === "::1") {\n` +
    `    return "DIRECT";\n` +
    `  }\n` +
    `${jsRules}` +
    `  return "${proxyDirective}";\n` +
    `}\n`
  );
}

/**
 * Resolves a Cloudflare edge colocation IATA code to its country and emoji flag.
 */
export function resolveColoLocation(iataCode: string): CloudflareColoLocation {
  const code = iataCode.trim().toUpperCase();

  const map: Record<string, CloudflareColoLocation> = {
    FRA: { airportCode: 'FRA', countryCode: 'DE', countryName: 'Germany', flagEmoji: '🇩🇪' },
    LHR: { airportCode: 'LHR', countryCode: 'GB', countryName: 'United Kingdom', flagEmoji: '🇬🇧' },
    AMS: { airportCode: 'AMS', countryCode: 'NL', countryName: 'Netherlands', flagEmoji: '🇳🇱' },
    CDG: { airportCode: 'CDG', countryCode: 'FR', countryName: 'France', flagEmoji: '🇫🇷' },
    DOH: { airportCode: 'DOH', countryCode: 'QA', countryName: 'Qatar', flagEmoji: '🇶🇦' },
    DXB: { airportCode: 'DXB', countryCode: 'AE', countryName: 'United Arab Emirates', flagEmoji: '🇦🇪' },
    IST: { airportCode: 'IST', countryCode: 'TR', countryName: 'Turkey', flagEmoji: '🇹🇷' },
    NRT: { airportCode: 'NRT', countryCode: 'JP', countryName: 'Japan', flagEmoji: '🇯🇵' },
    SIN: { airportCode: 'SIN', countryCode: 'SG', countryName: 'Singapore', flagEmoji: '🇸🇬' },
    HKG: { airportCode: 'HKG', countryCode: 'HK', countryName: 'Hong Kong', flagEmoji: '🇭🇰' },
    LAX: { airportCode: 'LAX', countryCode: 'US', countryName: 'United States', flagEmoji: '🇺🇸' },
    JFK: { airportCode: 'JFK', countryCode: 'US', countryName: 'United States', flagEmoji: '🇺🇸' },
    ORD: { airportCode: 'ORD', countryCode: 'US', countryName: 'United States', flagEmoji: '🇺🇸' },
    ARN: { airportCode: 'ARN', countryCode: 'SE', countryName: 'Sweden', flagEmoji: '🇸🇪' },
    HEL: { airportCode: 'HEL', countryCode: 'FI', countryName: 'Finland', flagEmoji: '🇫🇮' },
    VIE: { airportCode: 'VIE', countryCode: 'AT', countryName: 'Austria', flagEmoji: '🇦🇹' },
    ZRH: { airportCode: 'ZRH', countryCode: 'CH', countryName: 'Switzerland', flagEmoji: '🇨🇭' },
  };

  return map[code] || {
    airportCode: code,
    countryCode: 'XX',
    countryName: 'Global Edge',
    flagEmoji: '🌐',
  };
}

/**
 * Resolves an Autonomous System Number (ASN) to an ISP display name.
 */
export function resolveIspName(asn: number): string {
  const map: Record<number, string> = {
    197207: 'MCI (Mobile Telecommunication Co of Iran)',
    44244: 'Irancell (MTN Irancell Telecommunications)',
    57218: 'Rightel',
    58224: 'TCI (Telecommunication Company of Iran)',
    25184: 'Afranet',
    48159: 'Shatel',
    31549: 'Pars Online',
    16322: 'Asiatech',
    13335: 'Cloudflare, Inc.',
    15169: 'Google LLC',
    16509: 'Amazon.com, Inc.',
    14061: 'DigitalOcean, LLC',
    24940: 'Hetzner Online GmbH',
    16276: 'OVH SAS',
  };

  return map[asn] || `AS${asn}`;
}

/**
 * Formats raw bytes into human-readable strings (e.g. "1.25 MB").
 */
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Formats bandwidth in bits per second (e.g. "10.5 Mbps").
 */
export function formatBitrate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits === 0) return '0 bps';
  const k = 1000;
  const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  const i = Math.floor(Math.log(bits) / Math.log(k));
  return `${parseFloat((bits / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Real-time network statistics sampler tracking speed and traffic deltas.
 */
export class NetStatsTracker {
  private lastTime = Date.now();
  private lastSent = 0;
  private lastRecv = 0;
  private totalSent = 0;
  private totalRecv = 0;
  private peakUpload = 0;
  private peakDownload = 0;

  public recordSample(currentSent: number, currentRecv: number): NetStatsSnapshot {
    const now = Date.now();
    let elapsedSec = (now - this.lastTime) / 1000;
    if (elapsedSec <= 0) elapsedSec = 1.0;

    const deltaSent = currentSent >= this.lastSent ? currentSent - this.lastSent : currentSent;
    const deltaRecv = currentRecv >= this.lastRecv ? currentRecv - this.lastRecv : currentRecv;

    const uploadSpeed = deltaSent / elapsedSec;
    const downloadSpeed = deltaRecv / elapsedSec;

    if (uploadSpeed > this.peakUpload) this.peakUpload = uploadSpeed;
    if (downloadSpeed > this.peakDownload) this.peakDownload = downloadSpeed;

    this.totalSent += deltaSent;
    this.totalRecv += deltaRecv;

    this.lastSent = currentSent;
    this.lastRecv = currentRecv;
    this.lastTime = now;

    return {
      timestamp: now,
      bytesSent: deltaSent,
      bytesReceived: deltaRecv,
      uploadSpeedBps: uploadSpeed,
      downloadSpeedBps: downloadSpeed,
      peakUploadBps: this.peakUpload,
      peakDownloadBps: this.peakDownload,
      totalSent: this.totalSent,
      totalReceived: this.totalRecv,
    };
  }

  public reset(): void {
    this.lastTime = Date.now();
    this.lastSent = 0;
    this.lastRecv = 0;
    this.totalSent = 0;
    this.totalRecv = 0;
    this.peakUpload = 0;
    this.peakDownload = 0;
  }
}
