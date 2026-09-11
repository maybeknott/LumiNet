/**
 * Adblock Hosts & Domain List Parser
 * Ported and refactored from donor AdblockHostsParser.kt.
 * Extracts blocked domains from standard hosts file blocklists (0.0.0.0 / 127.0.0.1).
 */

const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const WILDCARD_REGEX = /[*?]/;
const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

const HOSTS_PREFIXES = new Set(['0.0.0.0', '127.0.0.1', '::1', '::0', '::']);
const SKIP_NAMES = new Set([
  'localhost',
  'local',
  'broadcasthost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
]);

/**
 * Parses raw text from a hosts file or domain blocklist into clean, normalized domain strings.
 */
export function parseAdblockHosts(text: string): string[] {
  const seen = new Set<string>();
  const domains: string[] = [];

  const lines = text.split(/\r?\n/);
  for (let rawLine of lines) {
    rawLine = rawLine.trim();
    if (!rawLine || rawLine.startsWith('#')) continue;

    const commentIdx = rawLine.indexOf(' #');
    if (commentIdx !== -1) {
      rawLine = rawLine.substring(0, commentIdx).trim();
    }

    const parts = rawLine.split(/\s+/).filter(Boolean);
    let domain: string;

    if (parts.length >= 2 && HOSTS_PREFIXES.has(parts[0]!)) {
      domain = parts[1]!.toLowerCase().replace(/\.+$/, '');
    } else if (parts.length === 1) {
      domain = parts[0]!.toLowerCase().replace(/\.+$/, '');
    } else {
      continue;
    }

    if (WILDCARD_REGEX.test(domain)) continue;
    if (SKIP_NAMES.has(domain)) continue;
    if (IPV4_REGEX.test(domain) || domain.includes(':')) continue;
    if (!DOMAIN_REGEX.test(domain)) continue;

    if (!seen.has(domain)) {
      seen.add(domain);
      domains.push(domain);
    }
  }

  return domains;
}
