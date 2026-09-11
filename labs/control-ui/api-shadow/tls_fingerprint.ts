/**
 * Browser TLS ClientHello fingerprint mimicry profile.
 * Absorbed and unified from utls-master and lumicore::evasion::fingerprint.
 */
export type TlsFingerprintProfile =
  | 'chrome'
  | 'chrome120'
  | 'chrome131'
  | 'chrome133'
  | 'firefox'
  | 'firefox105'
  | 'firefox120'
  | 'safari'
  | 'safari16'
  | 'edge'
  | 'edge106'
  | 'ios'
  | 'ios14'
  | 'android_okhttp'
  | 'randomized'
  | 'randomized_alpn'
  | 'randomized_no_alpn';

/**
 * Configuration options for TLS fingerprint emulation.
 */
export interface TlsFingerprintOptions {
  profile: TlsFingerprintProfile;
  grease: boolean;
  permuteExtensions: boolean;
  requiredAlpn: string[];
}

/**
 * Resolves the latest version-specific fingerprint profile for a given browser family.
 */
export function resolveLatestFingerprint(browser: string): TlsFingerprintProfile {
  switch (browser.toLowerCase().trim()) {
    case 'chrome':
      return 'chrome133';
    case 'firefox':
      return 'firefox120';
    case 'safari':
      return 'safari16';
    case 'edge':
      return 'edge106';
    case 'ios':
      return 'ios14';
    case 'android':
      return 'android_okhttp';
    default:
      return 'chrome133';
  }
}

/**
 * Returns the list of standard supported fingerprint profile identifiers.
 */
export function getAvailableFingerprintProfiles(): TlsFingerprintProfile[] {
  return [
    'chrome',
    'chrome120',
    'chrome131',
    'chrome133',
    'firefox',
    'firefox105',
    'firefox120',
    'safari',
    'safari16',
    'edge',
    'edge106',
    'ios',
    'ios14',
    'android_okhttp',
    'randomized',
    'randomized_alpn',
    'randomized_no_alpn',
  ];
}
