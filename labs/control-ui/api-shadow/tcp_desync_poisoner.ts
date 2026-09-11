export type DesyncStrategyUI = "NONE" | "SPLIT" | "FAKE_TTL" | "DISORDER";

export interface DesyncSegmentUI {
  ttl: number;
  payload: Uint8Array;
  isFake: boolean;
}

export function planDesyncSegments(
  strategy: DesyncStrategyUI,
  data: Uint8Array,
  splitOffset: number = 2
): DesyncSegmentUI[] {
  if (data.length === 0) return [];
  const offset = Math.max(1, Math.min(splitOffset, data.length - 1));

  const p1 = data.slice(0, offset);
  const p2 = data.slice(offset);

  switch (strategy) {
    case "SPLIT":
      return [
        { ttl: 64, payload: p1, isFake: false },
        { ttl: 64, payload: p2, isFake: false },
      ];
    case "DISORDER":
      return [
        { ttl: 64, payload: p2, isFake: false },
        { ttl: 64, payload: p1, isFake: false },
      ];
    case "FAKE_TTL":
      const fake = new Uint8Array(offset);
      fake.fill(0x58);
      return [
        { ttl: 3, payload: fake, isFake: true },
        { ttl: 64, payload: p1, isFake: false },
        { ttl: 64, payload: p2, isFake: false },
      ];
    default:
      return [{ ttl: 64, payload: data, isFake: false }];
  }
}
