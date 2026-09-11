import { useEffect, useState } from 'react';
import { Monitor, Moon, Settings as SettingsIcon, Sun } from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import { errorMessage, parseEvasionSettings } from '../api/contracts';
import { useAppearance } from '../hooks/useAppearance';

export function Settings() {
  const [appearance, setAppearance] = useAppearance();
  const [evasionEnabled, setEvasionEnabled] = useState(false);
  const [splitBytes, setSplitBytes] = useState(2);
  const [delayMs, setDelayMs] = useState(10);
  const [mutateHost, setMutateHost] = useState(false);
  const [fakePacketInject, setFakePacketInject] = useState(false);
  const [wsUseUtls, setWsUseUtls] = useState(false);
  const [wsFingerprint, setWsFingerprint] = useState('firefox');
  const [savingEvasion, setSavingEvasion] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchEvasionStatus = async () => {
    try {
      const data = await controlTransport.json('/api/system/evasion-tunnel', parseEvasionSettings);
      setEvasionEnabled(data.running);
      setSplitBytes(data.splitBytes);
      setDelayMs(data.delayMs);
      setMutateHost(data.mutateHost);
      setFakePacketInject(data.fakePacketInject);
      setWsUseUtls(data.wsUseUtls);
      setWsFingerprint(data.wsFingerprint || 'firefox');
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to load evasion settings.'));
    }
  };

  useEffect(() => {
    void fetchEvasionStatus();
  }, []);

  const applyEvasionSettings = async () => {
    setSavingEvasion(true);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request('/api/system/evasion-tunnel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: evasionEnabled,
          split_bytes: splitBytes,
          delay_ms: delayMs,
          mutate_host: mutateHost,
          fake_packet_inject: fakePacketInject,
          ws_use_utls: wsUseUtls,
          ws_fingerprint: wsFingerprint,
        }),
      });
      if (!response.ok) throw new Error(`evasion configuration returned HTTP ${response.status}`);
      setMessage('Evasion and uTLS parameters successfully updated.');
    } catch (caught) {
      setError(errorMessage(caught, 'Error saving evasion settings.'));
    } finally {
      setSavingEvasion(false);
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <p className="mono m-0 text-xs uppercase tracking-[0.16em] text-accent">System · preferences</p>
        <h2 className="m-0 mt-1 text-2xl font-display text-text-primary">Settings</h2>
        <p className="m-0 mt-2 max-w-3xl text-sm text-text-secondary">
          Display preferences and local runtime configuration. Remote deployment, WARP registration/scanning, and rollout planning are intentionally owned by Operations.
        </p>
      </header>

      {error && <div role="alert" aria-live="assertive" className="rounded-md border border-error/50 bg-error/20 p-4 text-sm text-text-primary">{error}</div>}
      {message && <div role="status" aria-live="polite" className="rounded-md border border-success/50 bg-success/20 p-4 text-sm text-text-primary">{message}</div>}

      <section className="card space-y-4" aria-labelledby="appearance-heading">
        <div className="border-b border-border-color pb-3">
          <h3 id="appearance-heading" className="m-0 flex items-center gap-2 text-lg text-text-primary"><Monitor size={18} className="text-accent" aria-hidden="true" /> Appearance</h3>
          <p className="mb-0 mt-1 text-xs text-text-secondary">A local-only display preference. System follows your operating-system theme; it never changes daemon configuration.</p>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Appearance preference">
          {([
            ['system', 'System', <Monitor key="system-icon" size={16} aria-hidden="true" />],
            ['dark', 'Dark', <Moon key="dark-icon" size={16} aria-hidden="true" />],
            ['light', 'Light', <Sun key="light-icon" size={16} aria-hidden="true" />],
          ] as const).map(([value, label, icon]) => (
            <button key={value} type="button" role="radio" aria-checked={appearance === value} onClick={() => setAppearance(value)} className={`btn justify-start px-3 py-2 ${appearance === value ? 'border-accent bg-accent/10 text-accent' : 'btn-secondary'}`}>
              {icon}{label}
            </button>
          ))}
        </div>
      </section>

      <section className="card space-y-4" aria-labelledby="evasion-settings-title">
        <div className="flex flex-col justify-between gap-3 border-b border-border-color pb-3 sm:flex-row sm:items-center">
          <div>
            <h3 id="evasion-settings-title" className="m-0 flex items-center gap-2 text-lg text-text-primary"><SettingsIcon size={18} className="text-accent" aria-hidden="true" /> DPI evasion & uTLS configuration</h3>
            <p className="m-0 mt-1 text-xs text-text-secondary">Mutates local runtime behavior only. Unsupported combinations are rejected by the daemon capability contract.</p>
          </div>
          <button type="button" disabled={savingEvasion} onClick={() => void applyEvasionSettings()} className="btn btn-primary px-3 py-1.5">{savingEvasion ? 'Applying…' : 'Apply Config'}</button>
        </div>

        <div className="space-y-4 text-sm">
          <label className="flex cursor-pointer items-center justify-between rounded-md p-2 hover:bg-bg-secondary">
            <span><span className="block font-semibold text-text-primary">Enable Active Desync</span><span className="mt-0.5 block text-xs text-text-secondary">Use active packet fragmentation and sequence spoofing.</span></span>
            <input type="checkbox" checked={evasionEnabled} onChange={(event) => setEvasionEnabled(event.target.checked)} className="h-4 w-4 accent-accent" />
          </label>

          <label className="block">
            <span className="mb-1 flex justify-between"><span className="text-text-secondary">ClientHello Split Offset</span><span className="mono text-cyan">{splitBytes} bytes</span></span>
            <input type="range" min="1" max="10" value={splitBytes} onChange={(event) => setSplitBytes(Number(event.target.value))} className="w-full accent-accent" />
          </label>

          <label className="block">
            <span className="mb-1 flex justify-between"><span className="text-text-secondary">Inter-packet Desync Delay</span><span className="mono text-cyan">{delayMs} ms</span></span>
            <input type="range" min="0" max="100" value={delayMs} onChange={(event) => setDelayMs(Number(event.target.value))} className="w-full accent-accent" />
          </label>

          <label className="flex cursor-pointer items-center justify-between rounded-md p-2 hover:bg-bg-secondary">
            <span><span className="block font-semibold text-text-primary">Mangle HTTP Host Case</span><span className="mt-0.5 block text-xs text-text-secondary">Randomize HTTP Host casing to disrupt parser matching.</span></span>
            <input type="checkbox" checked={mutateHost} onChange={(event) => setMutateHost(event.target.checked)} className="h-4 w-4 accent-accent" />
          </label>

          <label className="flex cursor-pointer items-center justify-between rounded-md p-2 hover:bg-bg-secondary">
            <span><span className="block font-semibold text-text-primary">Inject Out-of-Window Decoys</span><span className="mt-0.5 block text-xs text-text-secondary">Request bounded decoy injection when the active platform/runtime supports it.</span></span>
            <input type="checkbox" checked={fakePacketInject} onChange={(event) => setFakePacketInject(event.target.checked)} className="h-4 w-4 accent-accent" />
          </label>

          <label className="flex cursor-pointer items-center justify-between rounded-md border-t border-border-color p-2 pt-4 hover:bg-bg-secondary">
            <span><span className="block font-semibold text-text-primary">Use uTLS ClientHello Spoofing</span><span className="mt-0.5 block text-xs text-text-secondary">Mimic a supported browser signature on applicable TLS handshakes.</span></span>
            <input type="checkbox" checked={wsUseUtls} onChange={(event) => setWsUseUtls(event.target.checked)} className="h-4 w-4 accent-accent" />
          </label>

          {wsUseUtls && (
            <label className="block space-y-1 p-2">
              <span className="text-text-secondary">Browser Fingerprint Type</span>
              <select value={wsFingerprint} onChange={(event) => setWsFingerprint(event.target.value)} className="field-input">
                <option value="chrome">Chrome 120</option>
                <option value="firefox">Firefox 120</option>
                <option value="safari">Safari 17</option>
                <option value="edge">Edge 120</option>
                <option value="randomized">Randomized</option>
              </select>
            </label>
          )}
        </div>
      </section>
    </div>
  );
}
