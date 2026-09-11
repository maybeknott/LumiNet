/**
 * Android SagerNet / NekoBox / Matsuri Native Plugin Bridge API.
 *
 * Ported and unified from `nekobepass-main`.
 * Provides external plugin process configuration, CLI argument formatting,
 * environment variable formulation, and IPC contract definitions.
 */

export const ACTION_NATIVE_PLUGIN =
  'io.nekohasekai.sagernet.plugin.ACTION_NATIVE_PLUGIN';
export const EXTRA_ENTRY = 'io.nekohasekai.sagernet.plugin.EXTRA_ENTRY';
export const METADATA_KEY_ID = 'io.nekohasekai.sagernet.plugin.id';
export const METADATA_KEY_EXECUTABLE_PATH =
  'io.nekohasekai.sagernet.plguin.executable_path';
export const METHOD_GET_EXECUTABLE = 'sagernet:getExecutable';
export const DEFAULT_PLUGIN_PERMS = 0o755; // 0b111101101 (rwxr-xr-x)

export interface NativePluginDescriptor {
  id: string;
  name: string;
  executablePath: string;
  fileMode?: number;
  environmentArgs?: string[];
}

export interface PluginCommandConfig {
  bindAddress?: string;
  bindPort?: number;
  remoteDns?: string;
  sni?: string;
  dohUrl?: string;
  splitSni?: boolean;
  udpMode?: boolean;
}

/**
 * Builds CLI argument list passed to external plugin executable.
 */
export function buildPluginCliArgs(cfg: PluginCommandConfig): string[] {
  const bind = cfg.bindAddress || '127.0.0.1';
  const port = cfg.bindPort || 10808;
  const dns = cfg.remoteDns || '1.1.1.1';

  const args: string[] = ['-l', `${bind}:${port}`, '-d', dns];

  if (cfg.sni && cfg.sni.trim().length > 0) {
    args.push('-s', cfg.sni.trim());
  }

  if (cfg.dohUrl && cfg.dohUrl.trim().length > 0) {
    args.push('--doh', cfg.dohUrl.trim());
  }

  if (cfg.splitSni) {
    args.push('--split-sni');
  }

  if (cfg.udpMode !== false) {
    args.push('-u');
  }

  return args;
}

/**
 * Generates environment variable mappings for external plugin execution.
 */
export function formatPluginEnvironment(
  desc: NativePluginDescriptor
): Record<string, string> {
  const env: Record<string, string> = {
    SAGARNET_PLUGIN_ID: desc.id,
    SAGARNET_PLUGIN_NAME: desc.name,
    SAGARNET_PLUGIN_EXEC: desc.executablePath,
  };

  if (desc.environmentArgs) {
    for (const arg of desc.environmentArgs) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx > 0) {
        const k = arg.substring(0, eqIdx).trim();
        const v = arg.substring(eqIdx + 1).trim();
        if (k.length > 0) {
          env[k] = v;
        }
      }
    }
  }

  return env;
}
