import { Cable, CircleCheck, ShieldCheck } from 'lucide-react';
import type { FlowCoverage, FlowListResponse, NetworkInterfaceState, NetworkMonitorStatus } from '../../api/flows';

function capabilityBadge(enabled: boolean, label: string) {
  return (
    <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${enabled ? 'border-success/25 bg-success/10 text-success' : 'border-border-color bg-bg-primary text-text-muted'}`}>
      {label}
    </span>
  );
}

function CoverageRow({ coverage }: { coverage: FlowCoverage }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-primary/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="mono m-0 text-sm font-semibold text-text-primary">{coverage.owner}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Runtime-owned publication contract</p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {capabilityBadge(coverage.visible, 'visible')}
          {capabilityBadge(coverage.closeable, 'close')}
          {capabilityBadge(coverage.byteCounters, 'bytes')}
          {capabilityBadge(coverage.processAttribution, 'process')}
          {capabilityBadge(coverage.destinationMetadata, 'destination')}
        </div>
      </div>
      {coverage.notes.length > 0 && (
        <ul className="mb-0 mt-3 space-y-1 pl-5 text-xs text-text-secondary">
          {coverage.notes.map((note) => <li key={note}>{note}</li>)}
        </ul>
      )}
    </div>
  );
}

interface NetworkStatePanelProps {
  data: FlowListResponse | null;
  networkState: NetworkMonitorStatus | null;
  activeInterfaces: NetworkInterfaceState[];
}

export function NetworkStatePanel({ data, networkState, activeInterfaces }: NetworkStatePanelProps) {
  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
      <section className="card space-y-4" aria-labelledby="coverage-title">
        <div className="flex items-start gap-3">
          <ShieldCheck size={20} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
          <div>
            <h3 id="coverage-title" className="m-0 text-lg text-text-primary">Runtime coverage truth</h3>
            <p className="m-0 mt-1 text-xs text-text-muted">Model: {data?.coverageModel || 'unavailable'} · complete: {data?.coverageComplete ? 'yes' : 'no'}</p>
          </div>
        </div>
        <div className="space-y-3">
          {data?.coverage.map((coverage) => <CoverageRow key={coverage.owner} coverage={coverage} />)}
          {(!data || data.coverage.length === 0) && <p className="m-0 text-sm text-text-muted">No runtime owners have declared flow publication capability yet.</p>}
        </div>
      </section>

      <section className="card space-y-4" aria-labelledby="network-title">
        <div className="flex items-start gap-3">
          <Cable size={20} className="mt-0.5 shrink-0 text-purple" aria-hidden="true" />
          <div>
            <h3 id="network-title" className="m-0 text-lg text-text-primary">Passive network state</h3>
            <p className="m-0 mt-1 text-xs text-text-muted">Epoch changes only when interface/default-egress truth changes.</p>
          </div>
        </div>

        {networkState?.lastError && (
          <div className="rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning">Latest capture error: {networkState.lastError}. Last known-good state is retained.</div>
        )}

        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <dt className="text-[10px] uppercase tracking-wide text-text-muted">IPv4 egress</dt>
            <dd className="mono m-0 mt-1 text-xs text-text-primary">{networkState?.current.defaultIPv4Interface || 'unknown'}</dd>
            <dd className="mono m-0 mt-1 text-[11px] text-text-muted">{networkState?.current.defaultIPv4LocalIP || 'no observed local IP'}</dd>
          </div>
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <dt className="text-[10px] uppercase tracking-wide text-text-muted">IPv6 egress</dt>
            <dd className="mono m-0 mt-1 text-xs text-text-primary">{networkState?.current.defaultIPv6Interface || 'unknown'}</dd>
            <dd className="mono m-0 mt-1 text-[11px] text-text-muted">{networkState?.current.defaultIPv6LocalIP || 'no observed local IP'}</dd>
          </div>
        </dl>

        <div>
          <p className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Active interfaces</p>
          <div className="space-y-2">
            {activeInterfaces.map((iface) => (
              <div key={`${iface.index}-${iface.name}`} className="rounded-md border border-border-color bg-bg-primary/60 p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="mono text-xs font-semibold text-text-primary">{iface.name}</span>
                  <span className="mono text-[10px] text-text-muted">MTU {iface.mtu}</span>
                </div>
                <p className="mono m-0 mt-1 break-all text-[10px] text-text-muted">{iface.addresses.join(' · ') || 'no addresses'}</p>
              </div>
            ))}
            {activeInterfaces.length === 0 && <p className="m-0 text-xs text-text-muted">No non-loopback active interface is currently observed.</p>}
          </div>
        </div>

        <div>
          <p className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Recent handoffs</p>
          <div className="space-y-2">
            {[...(networkState?.history ?? [])].reverse().map((change) => (
              <div key={change.revision} className="flex items-start justify-between gap-4 rounded-md border border-border-color bg-bg-primary/60 p-3">
                <div>
                  <p className="mono m-0 text-xs font-semibold text-text-primary">epoch #{change.revision}</p>
                  <p className="m-0 mt-1 text-[11px] text-text-muted">{change.kinds.join(', ')}</p>
                </div>
                <span className="mono shrink-0 text-[10px] text-text-muted">{new Date(change.observedAt).toLocaleTimeString()}</span>
              </div>
            ))}
            {(networkState?.history.length ?? 0) === 0 && (
              <div className="flex items-center gap-2 rounded-md border border-border-color bg-bg-primary/60 p-3 text-xs text-text-muted">
                <CircleCheck size={14} className="text-success" /> No observed network handoff in retained history.
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
