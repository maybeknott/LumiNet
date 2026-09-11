export type NavigationSection = 'Overview' | 'Observe' | 'Network policy' | 'Operations' | 'System';

export const navigationItems = [
  { path: '/', label: 'Dashboard', section: 'Overview', keywords: ['overview', 'status', 'metrics', 'ping'] },
  { path: '/connections', label: 'Connections', section: 'Observe', keywords: ['flows', 'network', 'sessions', 'traffic'] },
  { path: '/health', label: 'Health', section: 'Observe', keywords: ['doctor', 'readiness', 'diagnostics', 'bundle', 'timeline'] },
  { path: '/logs', label: 'Logs', section: 'Observe', keywords: ['logs', 'events', 'console'] },
  { path: '/rules', label: 'Rules & Routing', section: 'Network policy', keywords: ['rules', 'routes', 'policy'] },
  { path: '/dns', label: 'DNS & Security', section: 'Network policy', keywords: ['dns', 'resolver', 'security', 'blocklist', 'dns leak', 'clean ip', 'resolver health', 'poisoning', 'injection', 'udp tcp dns'] },
  { path: '/profiles', label: 'Profiles', section: 'Network policy', keywords: ['subscriptions', 'profiles', 'import', 'export', 'subscription node', 'local socks', 'hidden node', 'provider feed', 'subscription health', 'certificate failure'] },
  { path: '/operations', label: 'Operations', section: 'Operations', keywords: ['doctor', 'engines', 'diagnostics', 'updates', 'planner', 'transport truth', 'fec', 'arq', 'packet loss', 'egress country'] },
  { path: '/deployment', label: 'Deployment & Remote', section: 'Operations', keywords: ['deployment', 'cloudflare', 'worker', 'warp', 'tailnet', 'rollout', 'remote'] },
  { path: '/capabilities', label: 'Capabilities', section: 'System', keywords: ['coverage', 'runtime', 'availability'] },
  { path: '/settings', label: 'Settings', section: 'System', keywords: ['configuration', 'preferences', 'appearance', 'evasion', 'utls'] },
] as const;

export const navigationSections: NavigationSection[] = ['Overview', 'Observe', 'Network policy', 'Operations', 'System'];

export type NavigationItem = (typeof navigationItems)[number];
export type NavigationPath = NavigationItem['path'];
