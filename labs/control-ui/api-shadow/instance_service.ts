/**
 * Multi-Instance Tunnel Daemon and Resolver Scanner Client API
 * 
 * Provides management operations for multiple tunnel daemon instances
 * and fast concurrent UDP DNS resolver scanning.
 */

export interface InstanceConfig {
  DOMAINS: string[];
  ENCRYPTION_KEY: string;
  LISTEN_PORT?: number;
  DATA_ENCRYPTION_METHOD?: number;
  SOCKS5_AUTH?: boolean;
  [key: string]: unknown;
}

export interface InstanceProfile {
  name: string;
  configure: InstanceConfig;
  resolver: string[];
}

export interface InstanceStatus {
  status: 'success' | 'error';
  unit: string;
  unitFile: string;
  enabled: string;
  returnCode: number;
  output: string;
  cpu?: number;
  memory?: number;
  uptimeSeconds?: number;
}

export interface ResolverScanOptions {
  resolvers: string[];
  domain?: string;
  expectedIp?: string;
  ports?: number[];
  timeout?: number;
  concurrency?: number;
  numSockets?: number;
}

export interface ResolverScanResult {
  status: string;
  mode: string;
  domain: string;
  scanned: number;
  foundCount: number;
  invalidCount: number;
  durationSeconds: number;
  ratePerSecond: number;
  foundResolvers: string[];
  invalidInputs: string[];
}

export class InstanceService {
  private static baseUrl = '/api/v1';

  static async listInstances(): Promise<InstanceProfile[]> {
    const res = await fetch(`${this.baseUrl}/instances`);
    if (!res.ok) throw new Error(`Failed to list instances: ${res.statusText}`);
    return res.json();
  }

  static async createInstance(profile: InstanceProfile): Promise<{ status: string; unit: string }> {
    const res = await fetch(`${this.baseUrl}/instances`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(profile),
    });
    if (!res.ok) throw new Error(`Failed to create instance: ${res.statusText}`);
    return res.json();
  }

  static async startInstance(name: string): Promise<{ status: string; unit: string }> {
    const res = await fetch(`${this.baseUrl}/service/${encodeURIComponent(name)}/start`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Failed to start service ${name}: ${res.statusText}`);
    return res.json();
  }

  static async stopInstance(name: string): Promise<{ status: string; unit: string }> {
    const res = await fetch(`${this.baseUrl}/service/${encodeURIComponent(name)}/stop`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Failed to stop service ${name}: ${res.statusText}`);
    return res.json();
  }

  static async restartInstance(name: string): Promise<{ status: string; unit: string }> {
    const res = await fetch(`${this.baseUrl}/service/${encodeURIComponent(name)}/restart`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Failed to restart service ${name}: ${res.statusText}`);
    return res.json();
  }

  static async getInstanceStatus(name: string): Promise<InstanceStatus> {
    const res = await fetch(`${this.baseUrl}/service/${encodeURIComponent(name)}/status`);
    if (!res.ok) throw new Error(`Failed to get status for ${name}: ${res.statusText}`);
    return res.json();
  }

  static async getInstanceLogs(name: string, lines = 100): Promise<{ output: string }> {
    const res = await fetch(`${this.baseUrl}/service/${encodeURIComponent(name)}/logs?lines=${lines}`);
    if (!res.ok) throw new Error(`Failed to get logs for ${name}: ${res.statusText}`);
    return res.json();
  }

  static async deleteInstance(name: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}/instances/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error(`Failed to delete instance ${name}: ${res.statusText}`);
  }

  static async runResolverScan(options: ResolverScanOptions): Promise<ResolverScanResult> {
    const res = await fetch(`${this.baseUrl}/resolver-scanner/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resolvers: options.resolvers,
        domain: options.domain ?? 'example.com',
        expected_ip: options.expectedIp,
        ports: options.ports ?? [53],
        timeout: options.timeout ?? 3.0,
        concurrency: options.concurrency ?? 500,
        numSockets: options.numSockets ?? 10,
      }),
    });
    if (!res.ok) throw new Error(`Failed to run resolver scan: ${res.statusText}`);
    return res.json();
  }
}
