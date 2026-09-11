export type ProxyChainSlot = "before" | "base" | "after";
export type ProxyChainHopMode = "off" | "automatic" | "fixed";

export interface ProxyProfileRef {
  subscriptionId: string;
  fingerprint: string;
  name: string;
}

export interface ProxyChainHop {
  slot: ProxyChainSlot;
  mode: ProxyChainHopMode;
  fixedRef?: ProxyProfileRef;
}

export interface ProxyChainSettings {
  enabled: boolean;
  before: ProxyChainHop;
  after: ProxyChainHop;
}

export interface ProxyChainResolvedRoute {
  hops: ProxyProfileRef[];
  isChained: boolean;
}

export function resolveProxyChain(
  base: ProxyProfileRef,
  settings: ProxyChainSettings,
  available: ProxyProfileRef[] = []
): ProxyChainResolvedRoute {
  if (!settings.enabled) {
    return {
      hops: [base],
      isChained: false,
    };
  }

  const hops: ProxyProfileRef[] = [];
  let beforeResolved: ProxyProfileRef | null = null;

  // 1. Resolve Before Hop
  if (settings.before.mode === "fixed") {
    if (!settings.before.fixedRef) {
      throw new Error("Fixed before hop missing profile reference");
    }
    if (settings.before.fixedRef.fingerprint === base.fingerprint) {
      throw new Error(`Loop detected: before hop duplicates base fingerprint ${base.fingerprint}`);
    }
    beforeResolved = settings.before.fixedRef;
    hops.push(beforeResolved);
  } else if (settings.before.mode === "automatic") {
    const candidate = available.find((p) => p.fingerprint !== base.fingerprint);
    if (!candidate) {
      throw new Error("No distinct candidates available for before hop");
    }
    beforeResolved = candidate;
    hops.push(candidate);
  }

  // 2. Add Base Hop
  hops.push(base);

  // 3. Resolve After Hop
  if (settings.after.mode === "fixed") {
    if (!settings.after.fixedRef) {
      throw new Error("Fixed after hop missing profile reference");
    }
    if (settings.after.fixedRef.fingerprint === base.fingerprint) {
      throw new Error(`Loop detected: after hop duplicates base fingerprint ${base.fingerprint}`);
    }
    if (beforeResolved && settings.after.fixedRef.fingerprint === beforeResolved.fingerprint) {
      throw new Error(`Loop detected: after hop duplicates before hop ${beforeResolved.fingerprint}`);
    }
    hops.push(settings.after.fixedRef);
  } else if (settings.after.mode === "automatic") {
    const candidate = available.find(
      (p) =>
        p.fingerprint !== base.fingerprint &&
        (!beforeResolved || p.fingerprint !== beforeResolved.fingerprint)
    );
    if (!candidate) {
      throw new Error("No distinct candidates available for after hop");
    }
    hops.push(candidate);
  }

  return {
    hops,
    isChained: hops.length > 1,
  };
}
