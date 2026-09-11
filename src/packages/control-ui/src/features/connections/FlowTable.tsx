import { Clock3, RefreshCw, Search, Unplug } from 'lucide-react';
import type { FlowListResponse, FlowSnapshot } from '../../api/flows';
import { FLOW_FETCH_LIMIT, VISIBLE_FLOW_STEP } from './useConnectionsFeed';
import { formatAge, formatBytes } from './format';

function FlowEndpoint({ flow }: { flow: FlowSnapshot }) {
  const destination = flow.destination || flow.host || 'unknown destination';
  return (
    <div className="min-w-0">
      <p className="mono m-0 truncate text-xs font-semibold text-text-primary" title={destination}>{destination}</p>
      <p className="mono m-0 mt-1 truncate text-[11px] text-text-muted" title={flow.source || 'unknown source'}>
        {flow.source || 'source unavailable'}
      </p>
      {flow.destinationProvider && (
        <p className="m-0 mt-1 truncate text-[11px] text-purple" title={`${flow.destinationProvider.displayName} · ${flow.destinationProvider.prefix} · corpus ${flow.destinationProvider.corpusID}${flow.destinationProvider.corpusStale ? ' (stale)' : ''}`}>
          {flow.destinationProvider.displayName} · {flow.destinationProvider.prefix} · {flow.destinationProvider.confidence || 'unrated'}{flow.destinationProvider.corpusStale ? ' · stale corpus' : ''}
        </p>
      )}
      {flow.chain.length > 0 && <p className="m-0 mt-1 truncate text-[11px] text-accent">{flow.chain.join(' → ')}</p>}
    </div>
  );
}

interface FlowTableProps {
  data: FlowListResponse | null;
  visibleFlows: FlowSnapshot[];
  currentEpoch: number;
  query: string;
  onQueryChange: (value: string) => void;
  owner: string;
  onOwnerChange: (value: string) => void;
  owners: string[];
  selected: Set<string>;
  busyIDs: Set<string>;
  allVisibleSelected: boolean;
  onSetFlowSelected: (id: string, checked: boolean) => void;
  onSetAllVisibleSelected: (checked: boolean) => void;
  onCloseOne: (flow: FlowSnapshot) => Promise<void>;
  onCloseSelected: () => Promise<void>;
  onShowMore: () => void;
}

export function FlowTable({
  data,
  visibleFlows,
  currentEpoch,
  query,
  onQueryChange,
  owner,
  onOwnerChange,
  owners,
  selected,
  busyIDs,
  allVisibleSelected,
  onSetFlowSelected,
  onSetAllVisibleSelected,
  onCloseOne,
  onCloseSelected,
  onShowMore,
}: FlowTableProps) {
  return (
    <section className="card space-y-4" aria-labelledby="flow-table-title">
      <div className="flex flex-col justify-between gap-3 xl:flex-row xl:items-end">
        <div>
          <h3 id="flow-table-title" className="m-0 text-lg text-text-primary">Live owner-published flows</h3>
          <p className="m-0 mt-1 text-xs text-text-muted">{data?.matched ?? 0} matched · {data?.returned ?? 0} returned</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative min-w-64 text-xs text-text-muted">
            <span className="sr-only">Search connections</span>
            <Search size={15} className="pointer-events-none absolute left-3 top-3.5 text-text-muted" aria-hidden="true" />
            <input className="field-input pl-9" value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search host, process, source, rule…" />
          </label>
          <label className="text-xs text-text-muted">
            <span className="sr-only">Runtime owner filter</span>
            <select className="field-input min-w-48" value={owner} onChange={(event) => onOwnerChange(event.target.value)}>
              <option value="">All declared owners</option>
              {owners.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border-color bg-bg-primary/60 px-3 py-2">
        <label className="flex min-h-11 cursor-pointer items-center gap-2 text-xs text-text-secondary">
          <input type="checkbox" checked={allVisibleSelected} onChange={(event) => onSetAllVisibleSelected(event.target.checked)} />
          Select closeable visible flows
        </label>
        <button type="button" className="btn btn-secondary" disabled={selected.size === 0} onClick={() => void onCloseSelected()}>
          <Unplug size={15} aria-hidden="true" /> Close selected ({selected.size})
        </button>
      </div>

      <div className="overflow-x-auto rounded-md border border-border-color">
        <table className="w-full min-w-[1040px] border-collapse text-left text-xs">
          <thead className="bg-bg-primary text-text-muted">
            <tr>
              <th className="w-10 px-3 py-3"><span className="sr-only">Select</span></th>
              <th className="px-3 py-3 font-medium">Runtime / protocol</th>
              <th className="px-3 py-3 font-medium">Endpoint</th>
              <th className="px-3 py-3 font-medium">Process / rule</th>
              <th className="px-3 py-3 font-medium">Transfer</th>
              <th className="px-3 py-3 font-medium">Age / epoch</th>
              <th className="px-3 py-3 text-right font-medium">Owner action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-color">
            {visibleFlows.map((flow) => {
              const busy = busyIDs.has(flow.id);
              const staleEpoch = currentEpoch > 0 && flow.networkEpoch > 0 && flow.networkEpoch < currentEpoch;
              return (
                <tr key={flow.id} className="bg-bg-secondary/40 align-top hover:bg-bg-tertiary/60">
                  <td className="px-3 py-3">
                    <input
                      type="checkbox"
                      aria-label={`Select ${flow.id}`}
                      disabled={!flow.closeable || busy}
                      checked={selected.has(flow.id)}
                      onChange={(event) => onSetFlowSelected(flow.id, event.target.checked)}
                    />
                  </td>
                  <td className="px-3 py-3">
                    <p className="mono m-0 font-semibold text-text-primary">{flow.owner}</p>
                    <p className="mono m-0 mt-1 text-[11px] text-accent">{flow.protocol || flow.network || 'unspecified'}</p>
                    <p className="mono m-0 mt-1 text-[10px] text-text-muted">{flow.id}</p>
                  </td>
                  <td className="max-w-80 px-3 py-3"><FlowEndpoint flow={flow} /></td>
                  <td className="max-w-72 px-3 py-3">
                    <p className="m-0 truncate text-text-primary" title={flow.processPath}>{flow.process || 'process attribution unavailable'}</p>
                    <p className="m-0 mt-1 truncate text-[11px] text-text-muted" title={flow.rulePayload}>{flow.rule ? `${flow.rule}${flow.rulePayload ? ` · ${flow.rulePayload}` : ''}` : 'no routing rule metadata'}</p>
                  </td>
                  <td className="px-3 py-3">
                    <p className="mono m-0 text-cyan">↑ {formatBytes(flow.uploadBytes)}</p>
                    <p className="mono m-0 mt-1 text-success">↓ {formatBytes(flow.downloadBytes)}</p>
                  </td>
                  <td className="px-3 py-3">
                    <p className="m-0 flex items-center gap-1 text-text-primary"><Clock3 size={12} /> {formatAge(flow.startedAt)}</p>
                    <p className={`mono m-0 mt-1 text-[11px] ${staleEpoch ? 'text-warning' : 'text-text-muted'}`}>epoch #{flow.networkEpoch || 0}{staleEpoch ? ' · pre-handoff' : ''}</p>
                  </td>
                  <td className="px-3 py-3 text-right">
                    <button type="button" className="btn btn-secondary min-h-9 px-3 py-1.5 text-xs" disabled={!flow.closeable || busy || flow.state === 'closing'} onClick={() => void onCloseOne(flow)}>
                      {busy || flow.state === 'closing' ? <RefreshCw size={13} className="animate-spin" /> : <Unplug size={13} />}
                      {flow.closeable ? (flow.state === 'closing' ? 'Closing' : 'Close') : 'Observe only'}
                    </button>
                  </td>
                </tr>
              );
            })}
            {(!data || data.flows.length === 0) && (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-sm text-text-muted">No participating runtime owner currently publishes a matching flow.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {data && data.flows.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-text-muted">
          <span>
            Rendering {Math.min(visibleFlows.length, data.flows.length)} of {data.returned} fetched flows
            {data.matched > data.returned ? ` · ${data.matched} match the current filters; refine filters to inspect beyond the ${FLOW_FETCH_LIMIT}-flow fetch cap.` : '.'}
          </span>
          {visibleFlows.length < data.flows.length && (
            <button type="button" className="btn btn-secondary min-h-9 px-3 py-1.5 text-xs" onClick={onShowMore}>
              Show {Math.min(VISIBLE_FLOW_STEP, data.flows.length - visibleFlows.length)} more
            </button>
          )}
        </div>
      )}
    </section>
  );
}
