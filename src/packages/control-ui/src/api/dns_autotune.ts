export type AutoTunePresetStability = 'Stable' | 'Aggressive';

export interface AutoTunePreset {
  id: string;
  label: string;
  minUploadMtu: number;
  maxUploadMtu: number;
  minDownloadMtu: number;
  maxDownloadMtu: number;
  resolverTimeoutMs: number;
  dnsFragCapacity: number;
  uploadDuplication: number;
  downloadDuplication: number;
  uploadCompression: number;
  downloadCompression: number;
  stability: AutoTunePresetStability;
}

export const AUTO_TUNE_PRESETS: AutoTunePreset[] = [
  {
    id: 'iran-average',
    label: 'Iran Default',
    minUploadMtu: 40,
    maxUploadMtu: 140,
    minDownloadMtu: 300,
    maxDownloadMtu: 3000,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 3,
    downloadDuplication: 7,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-low-mtu-scan',
    label: 'Iran Low MTU Scan',
    minUploadMtu: 20,
    maxUploadMtu: 120,
    minDownloadMtu: 160,
    maxDownloadMtu: 768,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 3,
    downloadDuplication: 7,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-fast-low-mtu',
    label: 'Iran Fast Low MTU',
    minUploadMtu: 20,
    maxUploadMtu: 325,
    minDownloadMtu: 100,
    maxDownloadMtu: 1270,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 100,
    uploadDuplication: 5,
    downloadDuplication: 10,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-compact-fixed',
    label: 'Iran Compact Fixed',
    minUploadMtu: 62,
    maxUploadMtu: 62,
    minDownloadMtu: 414,
    maxDownloadMtu: 414,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 384,
    uploadDuplication: 6,
    downloadDuplication: 8,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-fixed-64-balanced',
    label: 'Iran Fixed 64 Balanced',
    minUploadMtu: 64,
    maxUploadMtu: 64,
    minDownloadMtu: 756,
    maxDownloadMtu: 756,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 8,
    downloadDuplication: 8,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-mid-reliable',
    label: 'Iran Mid Reliable',
    minUploadMtu: 120,
    maxUploadMtu: 160,
    minDownloadMtu: 652,
    maxDownloadMtu: 1110,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 5,
    downloadDuplication: 11,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-download-heavy',
    label: 'Iran Download Heavy',
    minUploadMtu: 104,
    maxUploadMtu: 139,
    minDownloadMtu: 394,
    maxDownloadMtu: 1000,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 8,
    downloadDuplication: 30,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Stable',
  },
  {
    id: 'iran-fixed-64-aggressive',
    label: 'Iran Fixed 64 Wide',
    minUploadMtu: 64,
    maxUploadMtu: 64,
    minDownloadMtu: 756,
    maxDownloadMtu: 1317,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 230,
    uploadDuplication: 14,
    downloadDuplication: 30,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Aggressive',
  },
  {
    id: 'iran-large-download-aggressive',
    label: 'Iran No Compression Max',
    minUploadMtu: 100,
    maxUploadMtu: 600,
    minDownloadMtu: 800,
    maxDownloadMtu: 6500,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 640,
    uploadDuplication: 23,
    downloadDuplication: 30,
    uploadCompression: 0,
    downloadCompression: 0,
    stability: 'Aggressive',
  },
  {
    id: 'iran-wide-range-aggressive',
    label: 'Iran Wide Range Max',
    minUploadMtu: 100,
    maxUploadMtu: 1000,
    minDownloadMtu: 200,
    maxDownloadMtu: 2667,
    resolverTimeoutMs: 2500,
    dnsFragCapacity: 256,
    uploadDuplication: 15,
    downloadDuplication: 30,
    uploadCompression: 2,
    downloadCompression: 2,
    stability: 'Aggressive',
  },
];

export function getPresetById(id: string): AutoTunePreset | undefined {
  return AUTO_TUNE_PRESETS.find((p) => p.id === id);
}

export function chunkResolversRoundRobin(
  resolvers: string[],
  requestedWorkers: number,
): string[][] {
  const clean = resolvers.map((r) => r.trim()).filter((r) => r.length > 0);
  if (clean.length === 0) return [];

  const workerCount = Math.max(1, Math.min(requestedWorkers, clean.length));
  const chunks: string[][] = Array.from({ length: workerCount }, () => []);

  clean.forEach((resolver, index) => {
    chunks[index % workerCount]!.push(resolver);
  });

  return chunks;
}

export interface DnsProfileRecord {
  name: string;
  domain: string;
  encryptionKey: string;
  encryptionMethod: number;
  engine: string;
}

export function encodeDnsProfileLink(record: DnsProfileRecord): string {
  if (!record.domain.trim() || !record.encryptionKey.trim()) {
    throw new Error('Domain and encryption key are required');
  }

  const wire = {
    schema: 'whitedns.profile',
    version: 1,
    profile: {
      name: record.name.trim() || record.domain.trim(),
      server: {
        domain: record.domain.trim().replace(/\.+$/, ''),
        encryption_key: record.encryptionKey.trim(),
        encryption_method: Math.max(0, Math.min(5, record.encryptionMethod)),
      },
    },
  };

  const jsonStr = JSON.stringify(wire);
  const b64 = btoa(jsonStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const scheme = record.engine.trim().toLowerCase() || 'stormdns';
  return `${scheme}://${b64}`;
}

export function decodeDnsProfileLink(link: string): DnsProfileRecord {
  const parts = link.split('://');
  if (parts.length !== 2) {
    throw new Error('Invalid profile URI format');
  }

  const engine = parts[0]!.toLowerCase();
  let payload = parts[1]!.split(/[#?]/)[0]!.trim();
  if (!payload) {
    throw new Error('Empty profile payload');
  }

  const jsonStr = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
  const wire = JSON.parse(jsonStr);

  if (wire.schema !== 'whitedns.profile') {
    throw new Error(`Unsupported profile schema: ${wire.schema}`);
  }

  return {
    name: wire.profile.name,
    domain: wire.profile.server.domain,
    encryptionKey: wire.profile.server.encryption_key,
    encryptionMethod: wire.profile.server.encryption_method,
    engine,
  };
}
