import { Activity, Network, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';

/**
 * The historical 3D cockpit rendered authored sample topology as if it were
 * measured daemon evidence. That is intentionally retired. Keep this component
 * as an explicit unavailable-state document for old imports/deep links until a
 * future implementation has a real telemetry contract.
 */
export const NetworkCockpit = () => (
  <div className="space-y-6">
    <header>
      <div className="flex items-center gap-3">
        <Network className="h-7 w-7 text-accent" aria-hidden="true" />
        <div>
          <p className="mono m-0 text-xs font-semibold uppercase tracking-[0.16em] text-warning">Unavailable</p>
          <h1 className="m-0 text-2xl font-display text-text-primary">Network topology view</h1>
        </div>
      </div>
      <p className="mt-2 max-w-3xl text-sm text-text-secondary">
        LumiNet does not currently have an authoritative daemon contract for global POP topology, cable transit,
        geographic RTT, or middlebox location. This screen therefore does not synthesize or imply those values.
      </p>
    </header>

    <section className="card space-y-4" aria-labelledby="cockpit-evidence-heading">
      <div className="flex items-start gap-3">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-warning" aria-hidden="true" />
        <div>
          <h2 id="cockpit-evidence-heading" className="m-0 text-base font-semibold text-text-primary">Evidence contract required</h2>
          <p className="mb-0 mt-1 text-sm text-text-secondary">
            A future spatial view may return only when each displayed node, path, latency, and interference claim has
            provenance from a live, cached, or explicitly simulated source. Until then this route is not part of primary navigation.
          </p>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-3" aria-label="Topology evidence requirements">
        <EvidenceRequirement title="Topology" detail="Authoritative node and path source" />
        <EvidenceRequirement title="Measurements" detail="Timestamped RTT and reachability evidence" />
        <EvidenceRequirement title="Interference" detail="Probe-backed detection with confidence and method" />
      </div>
    </section>

    <section className="card" aria-labelledby="cockpit-alternative-heading">
      <h2 id="cockpit-alternative-heading" className="m-0 flex items-center gap-2 text-base font-semibold text-text-primary">
        <Activity className="h-5 w-5 text-cyan" aria-hidden="true" />
        Use measured connection evidence
      </h2>
      <p className="mt-2 text-sm text-text-secondary">
        Connections is the current observation surface backed by daemon flow data and explicitly describes its coverage limits.
      </p>
      <Link to="/connections" className="btn btn-primary inline-flex no-underline">
        Open Connections
      </Link>
    </section>
  </div>
);

function EvidenceRequirement({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-secondary p-3">
      <p className="m-0 text-sm font-semibold text-text-primary">{title}</p>
      <p className="mb-0 mt-1 text-xs text-text-secondary">{detail}</p>
    </div>
  );
}
