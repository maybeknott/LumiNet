// SPDX-License-Identifier: MIT
//
// Domain Fronting & MITM Routing Manager.
// Ported and unified from donor MitmFrontingManager.kt.

export interface DomainFrontingConfig {
  frontDomain: string;
  originHost: string;
  path?: string | undefined;
  headers?: Record<string, string> | undefined;
}

export interface PreparedFrontedRequest {
  sni: string;
  hostHeader: string;
  path: string;
  rawHeaderString: string;
}

export function buildFrontedRequest(config: DomainFrontingConfig): PreparedFrontedRequest {
  if (!config.frontDomain) throw new Error('frontDomain is required');
  if (!config.originHost) throw new Error('originHost is required');

  const path = config.path || '/';
  let raw = `GET ${path} HTTP/1.1\r\nHost: ${config.originHost}\r\n`;
  if (config.headers) {
    for (const [k, v] of Object.entries(config.headers)) {
      if (k.toLowerCase() !== 'host') {
        raw += `${k}: ${v}\r\n`;
      }
    }
  }
  raw += '\r\n';

  return {
    sni: config.frontDomain,
    hostHeader: config.originHost,
    path,
    rawHeaderString: raw,
  };
}

export const MitmActionKind = {
  Direct: 'direct',
  Block: 'block',
  RedirectToMitm: 'redirect_mitm',
  RepackFronted: 'repack_fronted',
} as const;
export type MitmActionKind = (typeof MitmActionKind)[keyof typeof MitmActionKind];

export interface MitmAction {
  kind: MitmActionKind;
  port?: number | undefined;
  frontedSni?: string | undefined;
  allowedSans?: string[] | undefined;
  redirectEndpoint?: string | undefined;
  alpn?: string[] | undefined;
}

export interface FrontingProfile {
  name: string;
  frontedSni: string;
  allowedSans: string[];
  redirectEndpoint?: string | undefined;
  alpn: string[];
}

export const GOOGLE_VIDEO_PROFILE: FrontingProfile = {
  name: 'google-video',
  frontedSni: 'www.google.com',
  allowedSans: [
    'www.google.com',
    '*.google.com',
    'dns.google',
    'www.googlevideo.com',
    '*.googlevideo.com',
    'www.youtube.com',
    '*.youtube.com',
  ],
  alpn: ['http/1.1'],
};

export const GOOGLE_PROFILE: FrontingProfile = {
  name: 'google',
  frontedSni: 'www.google.com',
  allowedSans: [
    'www.google.com',
    '*.google.com',
    'dns.google',
    'www.googlevideo.com',
    '*.googlevideo.com',
    'www.youtube.com',
    '*.youtube.com',
  ],
  alpn: ['h2', 'http/1.1'],
};

export const FASTLY_PROFILE: FrontingProfile = {
  name: 'fastly',
  frontedSni: 'github.githubassets.com',
  redirectEndpoint: 'github.githubassets.com:443',
  allowedSans: [
    'github.githubassets.com',
    'githubassets.com',
    '*.githubassets.com',
    'github.com',
    '*.github.com',
    'fastly.com',
    '*.fastly.com',
    'reddit.com',
    '*.reddit.com',
    'pypi.org',
    '*.python.org',
  ],
  alpn: ['h2', 'http/1.1'],
};

export const META_PROFILE: FrontingProfile = {
  name: 'meta',
  frontedSni: 'www.microsoft.com',
  allowedSans: [
    'www.whatsapp.com',
    '*.whatsapp.com',
    '*.whatsapp.net',
    'www.facebook.com',
    '*.facebook.com',
    '*.fbcdn.net',
    'www.instagram.com',
    '*.instagram.com',
    '*.cdninstagram.com',
    '*.meta.com',
  ],
  alpn: ['h2', 'http/1.1'],
};

export const CANONICAL_FRONTING_PROFILES: readonly FrontingProfile[] = [
  GOOGLE_VIDEO_PROFILE,
  GOOGLE_PROFILE,
  FASTLY_PROFILE,
  META_PROFILE,
];

/**
 * Checks whether a host matches an allowed Subject Alternative Name pattern.
 */
export function matchesSan(host: string, sanPattern: string): boolean {
  const h = host.toLowerCase().trim();
  const p = sanPattern.toLowerCase().trim();

  if (h === p) return true;

  if (p.startsWith('*.')) {
    const rootDomain = p.substring(2);
    // Matches subdomain.domain.com or exactly domain.com
    return h.endsWith(`.${rootDomain}`) || h === rootDomain;
  }

  return false;
}

/**
 * Evaluates target host against known fronting profiles to determine the MitmAction.
 */
export function resolveMitmAction(
  targetHost: string,
  targetPort: number = 443,
  customProfiles: readonly FrontingProfile[] = CANONICAL_FRONTING_PROFILES,
): MitmAction {
  const host = targetHost.toLowerCase().trim();

  for (const profile of customProfiles) {
    for (const san of profile.allowedSans) {
      if (matchesSan(host, san)) {
        return {
          kind: MitmActionKind.RepackFronted,
          frontedSni: profile.frontedSni,
          allowedSans: profile.allowedSans,
          redirectEndpoint: profile.redirectEndpoint,
          alpn: profile.alpn,
        };
      }
    }
  }

  return {
    kind: MitmActionKind.Direct,
    port: targetPort,
  };
}
