/**
 * SNI Spoofing and DPI Bypass Decoy Injection API
 * Originates from SNI-Spoofing-Go-main and adapted for LumiNet unified network plane.
 */

export interface SniSpoofConfig {
  listen_host: string;
  listen_port: number;
  connect_ip: string;
  connect_port: number;
  fake_sni: string;
  bypass_method: 'wrong_seq' | 'seq_overlap' | 'split_hello';
}

export interface DecoyInjectionStatus {
  active_connections: number;
  decoys_injected: number;
  decoys_acknowledged: number;
  handshakes_completed: number;
  last_injected_at?: number;
}

/**
 * Calculates the out-of-window sequence number so the packet precedes the receiver's window:
 * Formula: (ISN + 1 - payload_len) & 0xFFFFFFFF
 */
export function computeOutOfWindowSeq(isn: number, payloadLen: number): number {
  const diff = (isn + 1 - payloadLen) >>> 0;
  return diff;
}

/**
 * Wraps early client application data in a TLS ChangeCipherSpec + ApplicationData envelope.
 */
export function wrapClientResponse(appData: Uint8Array): Uint8Array {
  const changeCipher = new Uint8Array([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
  const appDataHdr = new Uint8Array([0x17, 0x03, 0x03]);
  const out = new Uint8Array(11 + appData.length);
  out.set(changeCipher, 0);
  out.set(appDataHdr, 6);
  out[9] = (appData.length >>> 8) & 0xff;
  out[10] = appData.length & 0xff;
  out.set(appData, 11);
  return out;
}


/**
 * Validates that an SNI is a valid RFC-compliant DNS hostname suitable for decoy synthesis.
 */
export function isValidSni(sni: string): boolean {
  if (!sni || sni.length > 219 || sni.startsWith('.') || sni.endsWith('.')) {
    return false;
  }
  const labels = sni.split('.');
  for (const label of labels) {
    if (!label || label.length > 63 || label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    if (!/^[a-zA-Z0-9-]+$/.test(label)) {
      return false;
    }
  }
  return true;
}

/**
 * Retrieves the current SNI spoofing runtime configuration.
 */
export async function fetchSniSpoofConfig(): Promise<SniSpoofConfig> {
  const resp = await fetch('/api/v1/evasion/sni-spoof');
  if (!resp.ok) {
    throw new Error(`Failed to fetch SNI spoof config: ${resp.statusText}`);
  }
  return await resp.json();
}

/**
 * Updates the SNI spoofing configuration.
 */
export async function updateSniSpoofConfig(config: Partial<SniSpoofConfig>): Promise<boolean> {
  const resp = await fetch('/api/v1/evasion/sni-spoof', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  return resp.ok;
}

/**
 * Retrieves live telemetry metrics for out-of-window decoy injections.
 */
export async function fetchSniSpoofMetrics(): Promise<DecoyInjectionStatus> {
  const resp = await fetch('/api/v1/evasion/sni-spoof/metrics');
  if (!resp.ok) {
    throw new Error(`Failed to fetch SNI spoof metrics: ${resp.statusText}`);
  }
  return await resp.json();
}
