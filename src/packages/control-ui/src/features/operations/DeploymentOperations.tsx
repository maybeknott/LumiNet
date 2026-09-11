import { useState } from 'react';
import { Cloud, Copy, Download, Key, Play, RefreshCw, ShieldAlert } from 'lucide-react';
import { controlTransport } from '../../api/ControlTransport';
import {
  errorMessage,
  parseWarpParams,
  parseWarpScanResults,
  type WarpParams,
  type WarpScanResult,
} from '../../api/contracts';
import {
  parseBrowserProxyHandoffPlan,
  parseTailnetTransactionPlan,
  parseUpdateRolloutPlan,
  type BrowserProxyHandoffPlan,
  type TailnetTransactionPlan,
  type UpdateRolloutPlan,
} from '../../api/planners';

const DEFAULT_WORKER_SCRIPT = `// Generic Cloudflare Worker upload template.
// This template is intentionally not presented as a VLESS implementation.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }
    return new Response("LumiNet custom Worker online", { status: 200 });
  }
};`;

export function CloudflareWorkerUpload() {
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [accountID, setAccountID] = useState('');
  const [workerName, setWorkerName] = useState('luminet-worker');
  const [scriptBody, setScriptBody] = useState(DEFAULT_WORKER_SCRIPT);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const upload = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request('/api/system/cloudflare-deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token, account_id: accountID, name: workerName, script: scriptBody }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      const serverMessage = typeof payload === 'object' && payload !== null && 'message' in payload ? String(payload.message) : 'Cloudflare accepted the Worker script upload.';
      setMessage(`${serverMessage} This action does not verify VLESS, WebSocket, or other runtime protocol behavior.`);
    } catch (caught) {
      setError(errorMessage(caught, 'Cloudflare Worker upload failed.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card space-y-4" aria-labelledby="worker-upload-title">
      <div className="flex flex-col justify-between gap-3 border-b border-border-color pb-3 sm:flex-row sm:items-center">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-warning">External mutation · Cloudflare</p>
          <h3 id="worker-upload-title" className="m-0 mt-1 flex items-center gap-2 text-lg text-text-primary"><Cloud size={18} className="text-warning" aria-hidden="true" /> Custom Cloudflare Worker upload</h3>
        </div>
        <button type="button" disabled={busy} onClick={() => void upload()} className="btn btn-primary px-3 py-1.5">
          {busy ? <RefreshCw size={14} className="animate-spin" aria-hidden="true" /> : <Play size={14} aria-hidden="true" />} Upload Script
        </button>
      </div>
      <p className="m-0 text-xs leading-relaxed text-text-secondary">Uploads the exact JavaScript shown below. Success means Cloudflare accepted source; LumiNet deliberately makes no protocol-readiness claim from HTTP upload success alone.</p>
      <div className="grid grid-cols-1 gap-4 text-xs md:grid-cols-3">
        <label className="space-y-1"><span className="text-text-secondary">Auth Email</span><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="user@example.com" className="field-input" /></label>
        <label className="space-y-1"><span className="text-text-secondary">API Token</span><input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="Paste API token…" autoComplete="off" className="field-input" /></label>
        <label className="space-y-1"><span className="text-text-secondary">Account ID</span><input value={accountID} onChange={(event) => setAccountID(event.target.value)} placeholder="Paste Account ID…" className="field-input" /></label>
      </div>
      <div className="space-y-2 text-xs">
        <label className="flex items-center justify-between gap-3"><span className="font-semibold text-text-secondary">Worker script name</span><input value={workerName} onChange={(event) => setWorkerName(event.target.value)} className="field-input mono w-56" /></label>
        <label className="block space-y-1"><span className="font-semibold text-text-secondary">Worker JavaScript source</span><textarea value={scriptBody} onChange={(event) => setScriptBody(event.target.value)} className="mono h-40 w-full rounded border border-border-color bg-bg-secondary p-2 text-[11px] text-text-primary outline-none" /></label>
      </div>
      {error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</div>}
      {message && <div role="status" aria-live="polite" className="rounded border border-success/30 bg-success/10 p-3 text-xs text-text-primary">{message}</div>}
    </section>
  );
}

export function WarpOperations() {
  const [params, setParams] = useState<WarpParams | null>(null);
  const [registering, setRegistering] = useState(false);
  const [privateKeyVisible, setPrivateKeyVisible] = useState(false);
  const [scanResults, setScanResults] = useState<WarpScanResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanCount, setScanCount] = useState(30);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const best = scanResults[0] ?? null;
  const medianRTT = scanResults.length > 0 ? scanResults[Math.floor(scanResults.length / 2)]?.rttMilliseconds ?? 0 : 0;

  const register = async () => {
    setRegistering(true); setError(null); setMessage(null);
    try {
      const profile = await controlTransport.json('/api/system/warp-register', parseWarpParams, { method: 'POST' });
      setPrivateKeyVisible(false); setParams(profile); setMessage('Successfully registered a new Cloudflare WARP account profile.');
    } catch (caught) { setError(errorMessage(caught, 'WARP registration failed.')); }
    finally { setRegistering(false); }
  };
  const scan = async () => {
    setScanning(true); setError(null); setMessage(null);
    try {
      setScanResults(await controlTransport.json('/api/system/warp-scan', parseWarpScanResults, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ count: scanCount, concurrency: 15, timeout_ms: 1000 }),
      }));
    } catch (caught) { setError(errorMessage(caught, 'WARP endpoint scan failed.')); }
    finally { setScanning(false); }
  };
  const copyBest = async () => {
    if (!best) return;
    try { await navigator.clipboard.writeText(best.endpoint); setMessage(`Copied best observed WARP endpoint: ${best.endpoint}`); }
    catch (caught) { setError(errorMessage(caught, 'Could not copy the WARP endpoint.')); }
  };
  const exportEvidence = () => {
    if (scanResults.length === 0) return;
    const payload = JSON.stringify({ generated_at: new Date().toISOString(), authority: 'observed scan evidence only; does not modify active WARP configuration', results: scanResults.map((row, rank) => ({ rank: rank + 1, endpoint: row.endpoint, rtt_ms: Number(row.rttMilliseconds.toFixed(3)) })) }, null, 2);
    const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'luminet-warp-scan-evidence.json'; anchor.click(); URL.revokeObjectURL(url);
  };

  return (
    <section className="grid grid-cols-1 gap-6 xl:grid-cols-2" aria-label="Cloudflare WARP operations">
      <div className="card space-y-4">
        <div className="flex items-center justify-between gap-3 border-b border-border-color pb-3"><h3 className="m-0 flex items-center gap-2 text-lg text-text-primary"><Key size={18} className="text-purple" /> Cloudflare WARP profile</h3><button type="button" disabled={registering} onClick={() => void register()} className="btn btn-secondary px-3 py-1.5">{registering ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} Register</button></div>
        <p className="m-0 text-xs leading-relaxed text-text-secondary">Creates a new remote WARP account profile. Treat returned WireGuard private-key material as a secret.</p>
        {params ? <div className="space-y-2 rounded-md border border-border-color bg-bg-secondary/40 p-3 text-xs"><div><span className="text-text-muted">IPv4 Address</span><p className="mono m-0 mt-0.5 font-semibold text-text-primary">{params.ipv4}</p></div><div><span className="text-text-muted">IPv6 Address</span><p className="mono m-0 mt-0.5 truncate font-semibold text-text-primary">{params.ipv6}</p></div><div><div className="flex items-center justify-between gap-2"><span className="text-text-muted">WireGuard Private Key</span><button type="button" onClick={() => setPrivateKeyVisible((visible) => !visible)} className="text-accent hover:underline">{privateKeyVisible ? 'Hide' : 'Reveal'}</button></div><p className="mono m-0 mt-0.5 truncate font-semibold text-text-primary">{privateKeyVisible ? params.privateKey : '••••••••••••••••'}</p></div><div><span className="text-text-muted">Reserved Traffic Bytes</span><p className="mono m-0 mt-0.5 font-semibold text-text-primary">[{params.reserved.join(', ')}]</p></div></div> : <div className="rounded-md border border-dashed border-border-color py-8 text-center text-sm text-text-muted">No generated WARP credentials in this view.</div>}
      </div>

      <div className="card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-color pb-3"><h3 className="m-0 flex items-center gap-2 text-lg text-text-primary"><ShieldAlert size={18} className="text-cyan" /> WARP endpoint scanner</h3><div className="flex items-center gap-2"><label className="text-xs text-text-muted">Candidates <input aria-label="WARP scan candidate count" type="number" value={scanCount} onChange={(event) => setScanCount(Math.max(1, Number(event.target.value) || 30))} className="field-input ml-1 w-20" /></label><button type="button" disabled={scanning} onClick={() => void scan()} className="btn btn-primary px-3 py-1.5">{scanning ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} Scan</button></div></div>
        <p className="m-0 text-xs leading-relaxed text-text-secondary">Performs concurrent UDP observations over candidate WARP endpoints. Ranking is evidence only and does not activate or persist an endpoint.</p>
        {scanResults.length > 0 ? <div className="space-y-3"><div className="grid grid-cols-1 gap-3 sm:grid-cols-3"><div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Best observed</p><p className="mono m-0 mt-1 text-xs text-success">{best?.endpoint}</p><p className="m-0 mt-1 text-[10px] text-text-muted">{best?.rttMilliseconds.toFixed(1)} ms</p></div><div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Median RTT</p><p className="mono m-0 mt-1 text-lg text-text-primary">{medianRTT.toFixed(1)} ms</p><p className="m-0 mt-1 text-[10px] text-text-muted">{scanResults.length} successful observations</p></div><div className="flex items-center justify-end gap-2 rounded border border-border-color bg-bg-primary/60 p-3"><button type="button" className="btn btn-secondary px-3 py-1.5 text-xs" onClick={() => void copyBest()}><Copy size={13} /> Copy best</button><button type="button" className="btn btn-secondary px-3 py-1.5 text-xs" onClick={exportEvidence}><Download size={13} /> Export</button></div></div><div className="max-h-[250px] overflow-y-auto rounded border border-border-color"><table className="w-full border-collapse text-xs"><thead className="sticky top-0 bg-bg-tertiary text-left text-text-muted"><tr><th className="px-3 py-2">Rank</th><th className="px-3 py-2">Endpoint</th><th className="px-3 py-2 text-right">RTT</th></tr></thead><tbody className="divide-y divide-border-color">{scanResults.map((row, index) => <tr key={row.endpoint} className="bg-bg-secondary/40"><td className="mono px-3 py-2 text-text-muted">#{index + 1}</td><td className="mono px-3 py-2 text-text-primary">{row.endpoint}</td><td className="mono px-3 py-2 text-right text-success">{row.rttMilliseconds.toFixed(1)} ms</td></tr>)}</tbody></table></div></div> : <div className="rounded-md bg-bg-secondary/20 py-12 text-center text-sm text-text-muted">{scanning ? 'Scanning WARP candidates…' : 'No endpoint scan evidence yet.'}</div>}
        {error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</div>}
        {message && <div role="status" className="rounded border border-success/30 bg-success/10 p-3 text-xs text-text-primary">{message}</div>}
      </div>
    </section>
  );
}

export function RemotePlanningOperations() {
  const [tailnetOperation, setTailnetOperation] = useState('dns-patch');
  const [etag, setETag] = useState('rev-7');
  const [tailnetPlan, setTailnetPlan] = useState<TailnetTransactionPlan | null>(null);
  const [tailnetError, setTailnetError] = useState<string | null>(null);
  const [browserPlan, setBrowserPlan] = useState<BrowserProxyHandoffPlan | null>(null);
  const [browserError, setBrowserError] = useState<string | null>(null);
  const [profileID, setProfileID] = useState('default');
  const [proxyURL, setProxyURL] = useState('socks5://127.0.0.1:1080');
  const [browserFamily, setBrowserFamily] = useState('chrome');
  const [extensionID, setExtensionID] = useState('abcdefghijklmnopabcdefghijklmnop');
  const [version, setVersion] = useState('229.0.0');
  const [rollout, setRollout] = useState(0.25);
  const [sequence, setSequence] = useState(42);
  const [highest, setHighest] = useState(41);
  const [rolloutPlan, setRolloutPlan] = useState<UpdateRolloutPlan | null>(null);
  const [rolloutError, setRolloutError] = useState<string | null>(null);

  async function planTailnet() {
    setTailnetError(null); setTailnetPlan(null);
    try { setTailnetPlan(await controlTransport.json('/api/system/tailnet-transaction-plan', parseTailnetTransactionPlan, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operation: tailnetOperation, etag, target_id: tailnetOperation === 'device-route' ? 'device-preview' : undefined }) })); }
    catch (caught) { setTailnetError(errorMessage(caught, 'Tailnet transaction planning failed.')); }
  }
  async function planBrowser() {
    setBrowserError(null); setBrowserPlan(null);
    try { setBrowserPlan(await controlTransport.json('/api/system/browser-proxy-handoff-plan', parseBrowserProxyHandoffPlan, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile_id: profileID, proxy_url: proxyURL, permissions: ['nativeMessaging', 'proxy', 'storage'], native_message_bytes: 4096, native_host_installed: true, browser_family: browserFamily, extension_id: extensionID }) })); }
    catch (caught) { setBrowserError(errorMessage(caught, 'Browser proxy handoff planning failed.')); }
  }
  async function planRollout() {
    setRolloutError(null); setRolloutPlan(null);
    try { setRolloutPlan(await controlTransport.json('/api/system/update-rollout-plan', parseUpdateRolloutPlan, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ version, rollout, cohort_seed: 20260821, metadata_sequence: sequence, highest_seen_sequence: highest }) })); }
    catch (caught) { setRolloutError(errorMessage(caught, 'Update rollout planning failed.')); }
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
      <section className="card space-y-4" aria-labelledby="remote-planning-title">
        <div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · no remote mutation</p><h3 id="remote-planning-title" className="m-0 mt-1 text-lg text-text-primary">Tailnet & browser handoff planning</h3><p className="m-0 mt-1 text-xs text-text-muted">Preview CAS/ETag transaction semantics and profile-isolated loopback browser handoff. These planners make no Tailnet API request, register no native host, and change no browser proxy.</p></div>
        <div className="space-y-3 rounded border border-border-color bg-bg-primary/50 p-3"><div className="grid grid-cols-2 gap-2"><select aria-label="Tailnet operation" value={tailnetOperation} onChange={(event) => setTailnetOperation(event.target.value)} className="field-input"><option value="acl-validate">ACL validate</option><option value="dns-patch">DNS patch</option><option value="dns-replace">DNS replace</option><option value="device-route">device route</option><option value="key-create">key create</option><option value="webhook-secret-rotate">webhook secret rotate</option></select><input aria-label="Tailnet ETag or revision" value={etag} onChange={(event) => setETag(event.target.value)} placeholder="ETag/revision" className="field-input mono" /></div><button type="button" onClick={() => void planTailnet()} className="btn btn-secondary">Plan Tailnet transaction</button>{tailnetError && <p role="alert" className="m-0 text-xs text-error">{tailnetError}</p>}{tailnetPlan && <div className="text-xs text-text-muted"><p className="m-0">{tailnetPlan.operation} · ETag {tailnetPlan.requiresETag ? 'required' : 'not required'} · API request {tailnetPlan.makesAPIRequest ? 'yes' : 'no'} · credentials accepted {tailnetPlan.credentialAccepted ? 'yes' : 'no'}</p><ol className="mb-0 mt-2 list-decimal space-y-1 pl-5">{tailnetPlan.steps.map((step) => <li key={step}>{step}</li>)}</ol></div>}</div>
        <div className="space-y-3 rounded border border-border-color bg-bg-primary/50 p-3"><div className="grid grid-cols-2 gap-2"><input aria-label="Browser profile ID" value={profileID} onChange={(event) => setProfileID(event.target.value)} placeholder="profile" className="field-input" /><input aria-label="Browser proxy URL" value={proxyURL} onChange={(event) => setProxyURL(event.target.value)} className="field-input mono" /><select aria-label="Browser family" value={browserFamily} onChange={(event) => setBrowserFamily(event.target.value)} className="field-input"><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="generic">Generic</option></select><input aria-label="Browser extension ID" value={extensionID} onChange={(event) => setExtensionID(event.target.value)} className="field-input mono" /></div><button type="button" onClick={() => void planBrowser()} className="btn btn-secondary">Check handoff readiness</button>{browserError && <p role="alert" className="m-0 text-xs text-error">{browserError}</p>}{browserPlan && <div className="space-y-1 text-xs text-text-muted"><p className="m-0">state <strong className="text-text-primary">{browserPlan.state}</strong> · {browserPlan.browserFamily} · {browserPlan.proxyHost}:{browserPlan.proxyPort}</p><p className="m-0">missing permissions {browserPlan.missingPermissions.join(', ') || 'none'} · registers host {browserPlan.registersHost ? 'yes' : 'no'} · changes proxy {browserPlan.changesBrowserProxy ? 'yes' : 'no'}</p></div>}</div>
      </section>

      <section className="card space-y-3" aria-labelledby="update-rollout-title">
        <div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · signed-update companion</p><h3 id="update-rollout-title" className="m-0 mt-1 text-lg text-text-primary">Update rollout & metadata replay posture</h3><p className="m-0 mt-1 text-xs text-text-muted">Preview deterministic cohort eligibility and monotonic signed-metadata sequence checks. This planner persists no high-water mark and installs nothing.</p></div>
        <div className="grid gap-2 md:grid-cols-2"><label className="text-xs text-text-muted">Version<input className="field-input mt-1" value={version} onChange={(event) => setVersion(event.target.value)} /></label><label className="text-xs text-text-muted">Rollout 0..1<input type="number" min={0} max={1} step={0.05} className="field-input mt-1" value={rollout} onChange={(event) => setRollout(Number(event.target.value))} /></label><label className="text-xs text-text-muted">Metadata sequence<input type="number" min={1} className="field-input mt-1" value={sequence} onChange={(event) => setSequence(Math.max(1, Number(event.target.value) || 1))} /></label><label className="text-xs text-text-muted">Highest seen<input type="number" min={0} className="field-input mt-1" value={highest} onChange={(event) => setHighest(Math.max(0, Number(event.target.value) || 0))} /></label></div>
        <button type="button" className="btn btn-secondary" onClick={() => void planRollout()}>Evaluate rollout</button>
        {rolloutError && <p role="alert" className="m-0 text-xs text-error">{rolloutError}</p>}
        {rolloutPlan && <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{rolloutPlan.eligible ? 'eligible cohort' : 'not eligible'}</strong> · threshold {rolloutPlan.cohortThreshold.toFixed(6)} · sequence {rolloutPlan.sequenceFresh ? 'fresh' : 'stale'} · withdrawn {rolloutPlan.withdrawn ? 'yes' : 'no'}</p><p className="m-0">persisted high-water mark required {rolloutPlan.requiresPersistedHighWaterMark ? 'yes' : 'no'} · persisted here {rolloutPlan.persistsHighWaterMark ? 'yes' : 'no'} · downloads {rolloutPlan.downloadsArtifact ? 'yes' : 'no'} · installs {rolloutPlan.installsUpdate ? 'yes' : 'no'}</p>{rolloutPlan.reasons.map((reason) => <p key={reason} className="m-0 text-warning">{reason}</p>)}</div>}
      </section>
    </div>
  );
}
