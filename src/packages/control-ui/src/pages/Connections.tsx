import { useMemo } from 'react';
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  CircleAlert,
  Network,
  RefreshCw,
  X,
} from 'lucide-react';
import { FlowTable } from '../features/connections/FlowTable';
import { NetworkStatePanel } from '../features/connections/NetworkStatePanel';
import {
  EndpointDispatchPlanner,
  MultiplexPolicyPlanner,
  WebSocketReadinessPlanner,
} from '../features/connections/PlannerPanels';
import { formatBytes } from '../features/connections/format';
import {
  VISIBLE_FLOW_STEP,
  useConnectionsFeed,
} from '../features/connections/useConnectionsFeed';
import { useFlowMutations } from '../features/connections/useFlowMutations';

function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
      <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mono m-0 mt-1 text-lg font-semibold text-text-primary">{value}</p>
      <p className="m-0 mt-1 text-[10px] text-text-muted">{detail}</p>
    </div>
  );
}

export function Connections() {
  const feed = useConnectionsFeed();
  const visibleFlows = useMemo(
    () => feed.data?.flows.slice(0, feed.visibleFlowLimit) ?? [],
    [feed.data, feed.visibleFlowLimit],
  );
  const mutations = useFlowMutations({
    flows: feed.data?.flows ?? [],
    visibleFlows,
    reload: () => feed.load(false),
    reportError: feed.setError,
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="mono m-0 text-xs uppercase tracking-[0.16em] text-accent">Cross-runtime observability</p>
          <h2 className="m-0 mt-1 text-2xl text-text-primary">Connections & network epochs</h2>
          <p className="m-0 mt-2 max-w-3xl text-sm text-text-secondary">
            Runtime owners publish only what they can prove. Missing coverage is shown explicitly; it is never interpreted as proof that the host has no other connections.
          </p>
        </div>
        <button type="button" className="btn btn-secondary" disabled={feed.loading} onClick={() => void feed.load(true)}>
          <RefreshCw size={16} className={feed.loading ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
        </button>
      </header>

      {feed.error && (
        <div role="alert" className="flex items-start gap-3 rounded-md border border-error/30 bg-error/10 p-4 text-sm text-error">
          <CircleAlert size={18} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span className="flex-1">{feed.error}</span>
          <button type="button" className="border-0 bg-transparent p-1 text-error" aria-label="Dismiss error" onClick={() => feed.setError(null)}><X size={15} /></button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><Activity size={14} /> Registered flows</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-text-primary">{feed.data?.stats.active ?? 0}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">{feed.data?.stats.closing ?? 0} closing · capacity {feed.data?.stats.capacity ?? 0}</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><ArrowUpFromLine size={14} /> Confirmed upload</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-cyan">{formatBytes(feed.data?.stats.uploadBytes ?? 0)}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Participating owners only</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><ArrowDownToLine size={14} /> Confirmed download</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-success">{formatBytes(feed.data?.stats.downloadBytes ?? 0)}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Monotonic per-flow counters</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><Network size={14} /> Network epoch</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-purple">#{feed.currentEpoch}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">{feed.networkState?.running ? 'passive monitor live' : 'snapshot only'}</p>
        </div>
      </div>

      <section className="card space-y-4" aria-labelledby="path-intelligence-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Derived · passive · local-only</p>
            <h3 id="path-intelligence-title" className="m-0 mt-1 text-lg text-text-primary">Path intelligence</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Synthesized from owner-published flows, network epochs, and the active provider prefix corpus. No DNS, GeoIP fetch, scan, route mutation, or runtime mutation occurs here.</p>
          </div>
          <div className={`rounded border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${feed.intelligence?.providerCorpusStale ? 'border-warning/30 bg-warning/10 text-warning' : feed.intelligence?.providerCorpusReady ? 'border-success/25 bg-success/10 text-success' : 'border-border-color bg-bg-primary text-text-muted'}`}>
            {feed.intelligence?.providerCorpusReady ? `provider corpus ${feed.intelligence.providerCorpusStale ? 'stale' : 'ready'}` : 'provider corpus unavailable'}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
          <MetricCard label="Pre-handoff" value={String(feed.intelligence?.preHandoffFlows ?? 0)} detail="flows from older network epochs" />
          <MetricCard label="Unknown epoch" value={String(feed.intelligence?.unknownEpochFlows ?? 0)} detail="owner did not publish epoch" />
          <MetricCard label="Providers" value={String(feed.intelligence?.distinctProviders ?? 0)} detail={`${feed.intelligence?.unattributedFlows ?? 0} unattributed`} />
          <MetricCard label="Protocols" value={String(feed.intelligence?.distinctProtocols ?? 0)} detail="participating flows only" />
          <MetricCard label="Interfaces" value={String(feed.intelligence?.activeInterfaces ?? 0)} detail={`${feed.intelligence?.retainedHandoffs ?? 0} retained handoffs`} />
          <MetricCard label="Coverage" value={feed.intelligence?.coverageComplete ? 'complete' : 'partial'} detail={feed.intelligence?.coverageModel || 'unavailable'} />
        </div>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-xs font-semibold uppercase tracking-wide text-text-muted">Provider distribution</p>
            <div className="mt-2 space-y-2">
              {(feed.intelligence?.providers ?? []).slice(0, 8).map((provider) => (
                <div key={`${provider.providerID}-${provider.displayName}`} className="flex items-center justify-between gap-4 text-xs">
                  <span className="truncate text-text-primary" title={provider.displayName || provider.providerID}>{provider.displayName || provider.providerID || 'unnamed provider'}</span>
                  <span className="mono shrink-0 text-text-muted">{provider.flows} flow{provider.flows === 1 ? '' : 's'} · ↑{formatBytes(provider.uploadBytes)} ↓{formatBytes(provider.downloadBytes)}</span>
                </div>
              ))}
              {(feed.intelligence?.providers.length ?? 0) === 0 && <p className="m-0 text-xs text-text-muted">No currently registered numeric destination matches the active local provider corpus.</p>}
            </div>
          </div>
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-xs font-semibold uppercase tracking-wide text-text-muted">Owner path state</p>
            <div className="mt-2 space-y-2">
              {(feed.intelligence?.owners ?? []).map((entry) => (
                <div key={entry.owner} className="flex items-center justify-between gap-4 text-xs">
                  <span className="mono truncate text-text-primary">{entry.owner}</span>
                  <span className="mono shrink-0 text-text-muted">{entry.active} active · {entry.preHandoff} old epoch · {entry.unknownEpoch} unknown</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <WebSocketReadinessPlanner />
      <EndpointDispatchPlanner />
      <MultiplexPolicyPlanner />

      <FlowTable
        data={feed.data}
        visibleFlows={visibleFlows}
        currentEpoch={feed.currentEpoch}
        query={feed.query}
        onQueryChange={feed.setQuery}
        owner={feed.owner}
        onOwnerChange={feed.setOwner}
        owners={feed.owners}
        selected={mutations.selected}
        busyIDs={mutations.busyIDs}
        allVisibleSelected={mutations.allVisibleSelected}
        onSetFlowSelected={mutations.setFlowSelected}
        onSetAllVisibleSelected={mutations.setAllVisibleSelected}
        onCloseOne={mutations.closeOne}
        onCloseSelected={mutations.closeSelected}
        onShowMore={() => feed.setVisibleFlowLimit((current) => Math.min(current + VISIBLE_FLOW_STEP, feed.data?.flows.length ?? current))}
      />

      <NetworkStatePanel data={feed.data} networkState={feed.networkState} activeInterfaces={feed.activeInterfaces} />
    </div>
  );
}
