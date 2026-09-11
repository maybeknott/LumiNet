export interface DnsWizardConfig {
  profileName: string;
  dnsServer: string;
  rootDomain: string;
  obfuscationKey: string;
  compression: boolean;
  port?: number;
}

export interface DnsWizardResult {
  id: string;
  uri: string;
  ready: boolean;
}

export function generateDnsWizardProfile(config: DnsWizardConfig): DnsWizardResult {
  if (!config.profileName) throw new Error("profileName is required");
  if (!config.dnsServer) throw new Error("dnsServer is required");
  if (!config.rootDomain) throw new Error("rootDomain is required");

  const port = config.port && config.port > 0 ? config.port : 53;
  const uri = `dnsvpn://${config.obfuscationKey}@${config.dnsServer}:${port}?domain=${config.rootDomain}&comp=${config.compression}`;
  const id = `dns-wiz-${config.profileName.toLowerCase().replace(/\s+/g, '-')}`;

  return { id, uri, ready: true };
}
