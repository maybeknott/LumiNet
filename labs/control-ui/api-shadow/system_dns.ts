/**
 * DNS Anti-Poisoning, Rescue Scanner, and Windows Adapter DNS Management API
 * Originates from RedCloud Windows core and adapted for LumiNet unified network plane.
 */

export interface DnsProbeResult {
  server_ip: string;
  latency_ms: number;
  resolved_ips: string[];
  is_poisoned: boolean;
  poison_reason?: string;
  success: boolean;
}

export interface VerifiedDnsRecord {
  ip: string;
  latency_ms: number;
  verified_at: number;
  provider_label: string;
  consecutive_successes: number;
  is_clean: boolean;
}

export interface AdapterDnsConfig {
  adapter_alias: string;
  dns_servers: string[];
  is_dhcp: boolean;
}

/**
 * Client-side detection of Iranian censorship redirect pages (10.10.34.0/24),
 * private addresses, loopback, or invalid address spaces returned by hostile DNS filtering.
 */
export function checkPoisonedIPv4(ipStr: string): {
  isPoisoned: boolean;
  reason?: string;
} {
  const parts = ipStr.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return { isPoisoned: true, reason: 'Invalid IPv4 address format' };
  }

  // Iranian national filtering redirect page: 10.10.34.0/24
  if (parts[0] === 10 && parts[1] === 10 && parts[2] === 34) {
    return {
      isPoisoned: true,
      reason: 'Iranian Censorship Redirect Page (10.10.34.0/24)',
    };
  }

  // RFC 1918 Class A: 10.0.0.0/8
  if (parts[0] === 10) {
    return {
      isPoisoned: true,
      reason: 'Bogus Private RFC 1918 Class A (10.0.0.0/8)',
    };
  }

  // Loopback: 127.0.0.0/8
  if (parts[0] === 127) {
    return { isPoisoned: true, reason: 'Bogus Loopback Address (127.0.0.0/8)' };
  }

  // Unspecified: 0.0.0.0/8
  if (parts[0] === 0) {
    return {
      isPoisoned: true,
      reason: 'Bogus Unspecified Address (0.0.0.0/8)',
    };
  }

  // RFC 1918 Class C: 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) {
    return {
      isPoisoned: true,
      reason: 'Bogus Private RFC 1918 Class C (192.168.0.0/16)',
    };
  }

  // RFC 1918 Class B: 172.16.0.0 - 172.31.255.255
  if (parts[0]! === 172 && parts[1]! >= 16 && parts[1]! <= 31) {
    return {
      isPoisoned: true,
      reason: 'Bogus Private RFC 1918 Class B (172.16.0.0/12)',
    };
  }

  // CGNAT: 100.64.0.0/10
  if (parts[0]! === 100 && parts[1]! >= 64 && parts[1]! <= 127) {
    return { isPoisoned: true, reason: 'Bogus CGNAT RFC 6598 (100.64.0.0/10)' };
  }

  // Link-local: 169.254.0.0/16
  if (parts[0] === 169 && parts[1] === 254) {
    return {
      isPoisoned: true,
      reason: 'Bogus Link-Local RFC 3927 (169.254.0.0/16)',
    };
  }

  // Benchmarking: 198.18.0.0/15
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) {
    return {
      isPoisoned: true,
      reason: 'Bogus Benchmarking RFC 2544 (198.18.0.0/15)',
    };
  }

  // Broadcast & Multicast
  if (parts[0] === 255 && parts[1] === 255 && parts[2] === 255 && parts[3] === 255) {
    return {
      isPoisoned: true,
      reason: 'Bogus Broadcast Address (255.255.255.255)',
    };
  }
  if (parts[0]! >= 224 && parts[0]! <= 239) {
    return {
      isPoisoned: true,
      reason: 'Bogus Multicast Address (224.0.0.0/4)',
    };
  }

  return { isPoisoned: false };
}

/**
 * Retrieves the current list of clean DNS resolvers from the daemon's DnsVault.
 */
export async function fetchCleanDnsVault(): Promise<VerifiedDnsRecord[]> {
  const resp = await fetch('/api/v1/dns/vault');
  if (!resp.ok) {
    throw new Error(`Failed to fetch clean DNS vault: ${resp.statusText}`);
  }
  return await resp.json();
}

/**
 * Triggers a live DNS rescue scan against candidate resolvers.
 */
export async function triggerDnsRescueScan(candidateIps?: string[]): Promise<DnsProbeResult[]> {
  const resp = await fetch('/api/v1/dns/rescue-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ candidates: candidateIps ?? [] }),
  });
  if (!resp.ok) {
    throw new Error(`Failed to trigger DNS rescue scan: ${resp.statusText}`);
  }
  return await resp.json();
}

/**
 * Configures static DNS servers on a local network adapter.
 */
export async function setAdapterDns(adapterAlias: string, dnsServers: string[]): Promise<boolean> {
  const resp = await fetch('/api/v1/dns/system-adapter', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      adapter_alias: adapterAlias,
      dns_servers: dnsServers,
    }),
  });
  return resp.ok;
}

/**
 * Resets local network adapter DNS to automatic DHCP.
 */
export async function resetAdapterDns(adapterAlias: string): Promise<boolean> {
  const resp = await fetch('/api/v1/dns/system-adapter/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ adapter_alias: adapterAlias }),
  });
  return resp.ok;
}

/**
 * Clears the local OS DNS resolver cache.
 */
export async function flushLocalDnsCache(): Promise<boolean> {
  const resp = await fetch('/api/v1/dns/flush-cache', {
    method: 'POST',
  });
  return resp.ok;
}
