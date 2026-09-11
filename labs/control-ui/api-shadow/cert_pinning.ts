/**
 * Certificate & SPKI SHA-256 Pinning Engine
 * Ported and refactored from donor CertPinningFlow.kt.
 * Provides v2rayNG/Xray compatible certificate verification.
 */

export interface CertPin {
  subject: string;
  issuer: string;
  certSha256: string;
  spkiSha256: string;
  notAfterMillis: number;
}

export interface PinningConfig {
  profileId: string;
  leafPins: string[];
  intermediatePins?: string[];
  backupPins?: string[];
  expiresAtMillis?: number;
  policy: 'strict' | 'lenient' | 'off';
}

export type PinResult =
  | { status: 'ok'; matched: string }
  | { status: 'mismatch'; expected: string[]; actual: string }
  | { status: 'expired'; expiresAtMillis: number }
  | { status: 'disabled' }
  | { status: 'no_peer_certificates' };

export function normalizePin(pin: string): string {
  const cleaned = pin.replace(/[:\s-]/g, '').toLowerCase();
  if (cleaned.length !== 64 || !/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new Error('Invalid SHA-256 pin: expected 64 hex characters, got ' + pin);
  }
  return cleaned;
}

export function verifyCertPins(
  observedSha256List: string[],
  config: PinningConfig
): PinResult {
  if (config.policy === 'off') {
    return { status: 'disabled' };
  }

  if (config.expiresAtMillis && config.expiresAtMillis > 0 && Date.now() > config.expiresAtMillis) {
    return { status: 'expired', expiresAtMillis: config.expiresAtMillis };
  }

  if (!observedSha256List || observedSha256List.length === 0) {
    return { status: 'no_peer_certificates' };
  }

  const normalizedObserved = observedSha256List.map((h) => h.toLowerCase().replace(/[:\s-]/g, ''));
  const leafPin = normalizedObserved[0]!;

  const expectedLeaf = config.leafPins.map((h) => h.toLowerCase().replace(/[:\s-]/g, ''));
  if (expectedLeaf.includes(leafPin)) {
    return { status: 'ok', matched: leafPin };
  }

  const expectedIntermediate = (config.intermediatePins ?? []).map((h) => h.toLowerCase().replace(/[:\s-]/g, ''));
  for (let i = 1; i < normalizedObserved.length; i++) {
    const inter = normalizedObserved[i]!;
    if (expectedIntermediate.includes(inter)) {
      return { status: 'ok', matched: inter };
    }
  }

  const expectedBackup = (config.backupPins ?? []).map((h) => h.toLowerCase().replace(/[:\s-]/g, ''));
  for (const obs of normalizedObserved) {
    if (expectedBackup.includes(obs)) {
      return { status: 'ok', matched: obs };
    }
  }

  if (config.policy === 'lenient') {
    return { status: 'ok', matched: leafPin };
  }

  return {
    status: 'mismatch',
    expected: [...expectedLeaf, ...expectedIntermediate, ...expectedBackup],
    actual: leafPin,
  };
}

export function createPinningConfig(
  profileId: string,
  primarySpkiSha256: string,
  backupPins: string[] = [],
  validityDays = 30
): PinningConfig {
  const leafPins = [normalizePin(primarySpkiSha256)];
  const normBackups = backupPins.map(normalizePin);
  const expiresAtMillis = Date.now() + validityDays * 24 * 60 * 60 * 1000;

  return {
    profileId,
    leafPins,
    backupPins: normBackups,
    expiresAtMillis,
    policy: 'strict',
  };
}
