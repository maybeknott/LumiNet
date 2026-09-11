export interface NeighborHost {
  ip: string;
  port: number;
  rttMs: number;
  gateway: boolean;
}

export function scanSubnetNeighborsUI(baseIp: string, port = 443, count = 8): NeighborHost[] {
  const hosts: NeighborHost[] = [];
  for (let i = 1; i <= Math.min(count, 254); i++) {
    const ip = `${baseIp}.${i}`;
    const rttMs = 12 + ((i * 17) % 75);
    hosts.push({
      ip,
      port,
      rttMs,
      gateway: i === 1,
    });
  }
  return hosts.sort((a, b) => a.rttMs - b.rttMs);
}
