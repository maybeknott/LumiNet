export interface ScoutedTarget {
  ip: string;
  rttMs: number;
  isClean: boolean;
}

export interface SubnetScoutReport {
  subnet: string;
  testedCount: number;
  cleanCount: number;
  bestTargets: ScoutedTarget[];
}

export function scoutSubnetRange(baseSubnet: string, count: number = 8, thresholdMs: number = 200): SubnetScoutReport {
  const targets: ScoutedTarget[] = [];
  let clean = 0;

  for (let i = 1; i <= Math.min(count, 254); i++) {
    const ip = `${baseSubnet}.${i}`;
    const rttMs = 15 + ((i * 13) % 180);
    const isClean = rttMs <= thresholdMs;
    if (isClean) clean++;
    targets.push({ ip, rttMs, isClean });
  }

  targets.sort((a, b) => a.rttMs - b.rttMs);

  return {
    subnet: `${baseSubnet}.0/24`,
    testedCount: targets.length,
    cleanCount: clean,
    bestTargets: targets.slice(0, 5),
  };
}
