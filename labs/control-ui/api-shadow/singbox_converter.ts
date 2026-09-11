/**
 * Multi-Protocol Proxy to Sing-Box Converter Client API
 *
 */

export interface SingboxExportOptions {
  listen?: string;
  mixedPort?: number;
  tunEnabled?: boolean;
  tunMtu?: number;
  autoUrlTest?: boolean;
  testUrl?: string;
  experimentalClashApi?: boolean;
  clashApiPort?: number;
}

export interface SingboxConvertResult {
  config: Record<string, unknown>;
  nodeCount: number;
  warnings: string[];
}

export class SingboxConverterService {
  private static baseUrl = '/api/v1/sub';

  /**
   * Compiles raw multi-protocol subscription text into a production-grade sing-box JSON configuration.
   */
  static async convertSubscription(
    rawSubscription: string,
    options: SingboxExportOptions = {}
  ): Promise<SingboxConvertResult> {
    const res = await fetch(`${this.baseUrl}/convert/singbox`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        subscription: rawSubscription,
        options: {
          listen: options.listen ?? '127.0.0.1',
          mixed_port: options.mixedPort ?? 2080,
          tun_enabled: options.tunEnabled ?? false,
          tun_mtu: options.tunMtu ?? 9000,
          auto_urltest: options.autoUrlTest ?? true,
          test_url: options.testUrl ?? 'https://www.gstatic.com/generate_204',
          experimental_clash_api: options.experimentalClashApi ?? true,
          clash_api_port: options.clashApiPort ?? 9090,
        },
      }),
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`Sing-box conversion failed (${res.status}): ${errorText}`);
    }

    return await res.json();
  }

  /**
   * Directly exports formatted sing-box client configuration JSON string.
   */
  static async exportConfigJson(
    rawSubscription: string,
    options: SingboxExportOptions = {}
  ): Promise<string> {
    const result = await this.convertSubscription(rawSubscription, options);
    return JSON.stringify(result.config, null, 2);
  }
}
