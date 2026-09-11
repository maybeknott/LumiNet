import { useState } from 'react';
import { RefreshCw, ShieldCheck } from 'lucide-react';
import { controlTransport } from '../../api/ControlTransport';
import {
  parseEndpointDispatchPlan,
  parseMultiplexPolicyPlan,
  parseWebSocketReadinessPlan,
  type EndpointDispatchPlan,
  type MultiplexPolicyPlan,
  type WebSocketReadinessPlan,
} from '../../api/planners';
import { errorText } from './format';

export function EndpointDispatchPlanner() {
  const [dispatchInput, setDispatchInput] = useState('');
  const [dispatchStrategy, setDispatchStrategy] = useState('quality-first');
  const [dispatchPlan, setDispatchPlan] = useState<EndpointDispatchPlan | null>(null);
  const [dispatchBusy, setDispatchBusy] = useState(false);
  const [dispatchError, setDispatchError] = useState<string | null>(null);

  const analyzeEndpointDispatch = async () => {
    setDispatchBusy(true);
    setDispatchError(null);
    setDispatchPlan(null);
    try {
      const endpoints = dispatchInput.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
        const parts = line.split(',').map((part) => part.trim());
        if (parts.length < 3 || parts.length > 7) throw new Error(`Endpoint line ${index + 1} must use endpoint,successes,failures[,latency_ms,health,capacity,in_flight].`);
        const [endpoint, successesRaw, failuresRaw, latencyRaw = '0', health = 'unknown', capacityRaw = '0', inflightRaw = '0'] = parts;
        const successes = Number(successesRaw), failures = Number(failuresRaw), latency = Number(latencyRaw), capacity = Number(capacityRaw), inflight = Number(inflightRaw);
        if (![successes, failures, latency, capacity, inflight].every(Number.isFinite)) throw new Error(`Endpoint line ${index + 1} contains invalid numeric evidence.`);
        return { endpoint, successes, failures, latency_ms: latency, health_state: health, capacity, in_flight: inflight };
      });
      if (endpoints.length === 0) throw new Error('Enter at least one endpoint evidence row.');
      setDispatchPlan(await controlTransport.json('/api/system/endpoint-pool-plan', parseEndpointDispatchPlan, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoints, strategy: dispatchStrategy, scope: 'connections-page' }),
      }));
    } catch (caught) {
      setDispatchError(errorText(caught, 'Endpoint dispatch analysis failed.'));
    } finally {
      setDispatchBusy(false);
    }
  };

  return (
    <section className="card space-y-4" aria-labelledby="endpoint-dispatch-title">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · health-aware dispatch</p>
          <h3 id="endpoint-dispatch-title" className="m-0 mt-1 text-lg text-text-primary">Endpoint dispatch evidence</h3>
          <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Rank caller-supplied success, latency, health and capacity evidence. Unhealthy, circuit-open, disabled or full endpoints remain ineligible; load/sticky strategies may only reorder near-equivalent quality candidates.</p>
        </div>
        <button type="button" className="btn btn-secondary" disabled={dispatchBusy} onClick={() => void analyzeEndpointDispatch()}>{dispatchBusy ? 'Analyzing…' : 'Analyze dispatch'}</button>
      </div>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_14rem]">
        <label className="text-xs text-text-muted">One endpoint per line: <span className="mono">endpoint,successes,failures[,latency_ms,health,capacity,in_flight]</span>
          <textarea value={dispatchInput} onChange={(event) => setDispatchInput(event.target.value)} rows={4} placeholder={'relay-a.example:443,20,1,110,healthy,100,12\nrelay-b.example:443,18,2,90,degraded,100,5'} className="mono mt-1 w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Strategy
          <select value={dispatchStrategy} onChange={(event) => setDispatchStrategy(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="quality-first">quality first</option><option value="least-loaded">least loaded</option><option value="weighted-quality">weighted quality</option><option value="sticky">sticky</option></select>
          <span className="mt-2 block text-[11px] text-text-muted">Secondary strategy never promotes a materially worse endpoint outside the bounded quality band.</span>
        </label>
      </div>
      {dispatchError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{dispatchError}</div>}
      {dispatchPlan && <div className="space-y-3"><div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{dispatchPlan.ranked.slice(0, 9).map((rank) => <div key={rank.endpoint} className="rounded border border-border-color bg-bg-primary/60 p-3 text-xs"><div className="flex justify-between gap-2"><strong className="mono truncate text-text-primary">{rank.endpoint}</strong><span className={rank.eligible ? 'text-success' : 'text-warning'}>{rank.eligible ? rank.quality : 'ineligible'}</span></div><div className="mt-1 text-text-muted">score {rank.score.toFixed(1)} · {rank.healthState}{rank.loadPct !== undefined ? ` · load ${rank.loadPct.toFixed(0)}%` : ''}{rank.circuitOpen ? ' · circuit open' : ''}</div></div>)}</div><p className="m-0 text-xs text-text-muted">Dispatch: <span className="mono text-text-primary">{dispatchPlan.dispatchOrder.join(' → ') || 'none'}</span> · warm pool {dispatchPlan.warmPool} · basis {dispatchPlan.selectionBasis.join(', ') || 'quality evidence'}</p></div>}
    </section>
  );
}

export function MultiplexPolicyPlanner() {
  const [muxProtocol, setMuxProtocol] = useState<'smux' | 'yamux' | 'h2mux'>('smux');
  const [muxConnections, setMuxConnections] = useState(2);
  const [muxStreams, setMuxStreams] = useState(32);
  const [muxPadding, setMuxPadding] = useState(false);
  const [muxPaddingBytes, setMuxPaddingBytes] = useState(256);
  const [muxPlan, setMuxPlan] = useState<MultiplexPolicyPlan | null>(null);
  const [muxBusy, setMuxBusy] = useState(false);
  const [muxError, setMuxError] = useState<string | null>(null);

  const analyzeMultiplexPolicy = async () => {
    setMuxBusy(true);
    setMuxError(null);
    try {
      const plan = await controlTransport.json('/api/system/multiplex-policy-plan', parseMultiplexPolicyPlan, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          protocol: muxProtocol,
          version: 1,
          max_connections: muxConnections,
          max_streams_per_connection: muxStreams,
          session_selection: 'least-loaded',
          padding: muxPadding,
          max_padding_bytes: muxPadding ? muxPaddingBytes : 0,
        }),
      });
      setMuxPlan(plan);
    } catch (caught) {
      setMuxError(errorText(caught, 'Multiplex policy analysis failed.'));
    } finally {
      setMuxBusy(false);
    }
  };

  return (
    <section className="card space-y-4" aria-labelledby="mux-policy-title">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Read-only · session admission</p>
          <h3 id="mux-policy-title" className="m-0 mt-1 text-lg text-text-primary">Multiplex capacity policy</h3>
          <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Evaluate stream/session limits before changing runtime configuration. LumiNet keeps one live SMUX owner; yamux and h2mux remain comparison-only unless a runtime explicitly reports support.</p>
        </div>
        <button type="button" className="btn btn-secondary" disabled={muxBusy} onClick={() => void analyzeMultiplexPolicy()}>
          {muxBusy ? <RefreshCw size={14} className="animate-spin" /> : <ShieldCheck size={14} />} Analyze admission
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <label className="text-xs text-text-muted">Protocol
          <select value={muxProtocol} onChange={(event) => setMuxProtocol(event.target.value as 'smux' | 'yamux' | 'h2mux')} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary">
            <option value="smux">SMUX</option><option value="yamux">Yamux</option><option value="h2mux">H2Mux</option>
          </select>
        </label>
        <label className="text-xs text-text-muted">Connections
          <input type="number" min={1} max={32} value={muxConnections} onChange={(event) => setMuxConnections(Math.max(1, Number(event.target.value) || 1))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Streams / connection
          <input type="number" min={1} max={4096} value={muxStreams} onChange={(event) => setMuxStreams(Math.max(1, Number(event.target.value) || 1))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Max padding bytes
          <input type="number" min={0} max={4096} disabled={!muxPadding} value={muxPaddingBytes} onChange={(event) => setMuxPaddingBytes(Math.max(0, Number(event.target.value) || 0))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary disabled:opacity-50" />
        </label>
        <label className="flex min-h-11 items-center gap-2 self-end rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-secondary">
          <input type="checkbox" checked={muxPadding} onChange={(event) => setMuxPadding(event.target.checked)} /> Bounded padding
        </label>
      </div>

      {muxError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{muxError}</div>}
      {muxPlan && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <div className="rounded border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Runtime truth</p>
            <p className={`m-0 mt-1 text-sm font-semibold ${muxPlan.runtimeSupported ? 'text-success' : 'text-warning'}`}>{muxPlan.protocol} · {muxPlan.runtimeSupported ? 'supported' : 'planning only'}</p>
            <p className="m-0 mt-1 text-xs text-text-muted">{muxPlan.sessionSelection} selection · v{muxPlan.version}</p>
          </div>
          <div className="rounded border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Bounded capacity</p>
            <p className="mono m-0 mt-1 text-lg text-text-primary">{muxPlan.estimatedMaxConcurrentStreams} streams</p>
            <p className="m-0 mt-1 text-xs text-text-muted">{muxPlan.maxConnections} × {muxPlan.maxStreamsPerConnection}</p>
          </div>
          <div className="rounded border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Framing guards</p>
            <p className="m-0 mt-1 text-sm text-text-primary">padding {muxPlan.padding ? `≤ ${muxPlan.maxPaddingBytes ?? 0} B` : 'disabled'}</p>
            <p className="m-0 mt-1 text-xs text-text-muted">First Write counts application bytes; peer padding is bounded before skip/allocation.</p>
          </div>
        </div>
      )}
      {muxPlan && (muxPlan.warnings.length > 0 || muxPlan.invariants.length > 0) && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <ul className="m-0 space-y-1 pl-5 text-xs text-warning">{muxPlan.warnings.map((item) => <li key={item}>{item}</li>)}</ul>
          <ul className="m-0 space-y-1 pl-5 text-xs text-text-secondary">{muxPlan.invariants.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
    </section>
  );
}

export function WebSocketReadinessPlanner() {
  const [status, setStatus] = useState(101);
  const [tlsVerified, setTLSVerified] = useState(true);
  const [plan, setPlan] = useState<WebSocketReadinessPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = 'MDEyMzQ1Njc4OWFiY2RlZg==';
  const accept = 'BACScCJPNqyz+UBoqMH89VmURoA=';

  async function analyze() {
    setError(null);
    setPlan(null);
    try {
      setPlan(await controlTransport.json('/api/system/websocket-readiness-plan', parseWebSocketReadinessPlan, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tcp_reachable: true,
          status_code: status,
          headers: { Upgrade: 'websocket', Connection: 'keep-alive, Upgrade', 'Sec-WebSocket-Accept': accept },
          sec_websocket_key: key,
          tls_expected: true,
          tls_verified: tlsVerified,
        }),
      }));
    } catch (caught) {
      setError(errorText(caught, 'WebSocket readiness planning failed.'));
    }
  }

  return (
    <section className="card space-y-4" aria-labelledby="websocket-readiness-title">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Protocol evidence · no probe performed</p>
          <h3 id="websocket-readiness-title" className="m-0 mt-1 text-lg text-text-primary">WebSocket backend readiness</h3>
          <p className="m-0 mt-1 text-xs text-text-muted">An open TCP port is not enough. Readiness requires an HTTP 101 upgrade, Upgrade/Connection evidence, the correct Sec-WebSocket-Accept, and verified TLS when expected.</p>
        </div>
        <button type="button" onClick={() => void analyze()} className="btn btn-secondary">Classify handshake</button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-text-muted">Observed HTTP status
          <input type="number" min={100} max={599} value={status} onChange={(event) => setStatus(Number(event.target.value) || 0)} className="field-input mt-1" />
        </label>
        <label className="flex items-center gap-2 self-end pb-2 text-xs text-text-muted">
          <input type="checkbox" checked={tlsVerified} onChange={(event) => setTLSVerified(event.target.checked)} /> Strict TLS verification observed
        </label>
      </div>
      {error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</div>}
      {plan && (
        <div className={`rounded border p-3 text-xs ${plan.ready ? 'border-success/30 bg-success/10' : 'border-warning/30 bg-warning/10'}`}>
          <strong>{plan.ready ? 'WebSocket ready' : 'Not WebSocket ready'}</strong>
          <p className="mb-0 mt-1 text-text-muted">101/Upgrade {plan.upgradeValid ? 'ok' : 'missing'} · Connection {plan.connectionValid ? 'ok' : 'missing'} · Accept {plan.acceptValid ? 'ok' : 'invalid'} · TLS {plan.tlsValid ? 'ok' : 'unverified'} · network I/O {plan.performsNetworkIO ? 'yes' : 'no'}</p>
          {plan.reasons.length > 0 && <p className="mb-0 mt-2 text-warning">{plan.reasons.join(' · ')}</p>}
        </div>
      )}
    </section>
  );
}
