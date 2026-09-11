import { Cloud, Gauge, RotateCcw, SlidersHorizontal } from 'lucide-react';
import { DiagnosticsOperations } from '../features/operations/DiagnosticsOperations';
import { RecoveryOperations } from '../features/operations/RecoveryOperations';
import {
  CloudflareWorkerUpload,
  RemotePlanningOperations,
  WarpOperations,
} from '../features/operations/DeploymentOperations';

const sections = [
  { id: 'diagnostics', label: 'Diagnostics', icon: Gauge },
  { id: 'recovery', label: 'Recovery', icon: RotateCcw },
  { id: 'deployment', label: 'Deployment', icon: Cloud },
  { id: 'planning', label: 'Planning', icon: SlidersHorizontal },
] as const;

function revealSection(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'auto', block: 'start' });
}

export function Operations() {
  return (
    <div className="space-y-6">
      <header className="space-y-3">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.16em] text-accent">Operate · explicit behavioral ownership</p>
          <h1 className="m-0 mt-1 text-2xl font-semibold text-text-primary">Operations</h1>
          <p className="mb-0 mt-2 max-w-4xl text-sm leading-relaxed text-text-secondary">
            Runtime diagnostics, interrupted-job recovery, external deployment, and read-only planning are separated by ownership. Each feature manages its own requests, cancellation, mutation state, errors, and evidence instead of sharing one page-level controller.
          </p>
        </div>
        <nav aria-label="Operations sections" className="flex flex-wrap gap-2">
          {sections.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" onClick={() => revealSection(id)} className="btn btn-secondary px-3 py-1.5 text-xs">
              <Icon size={14} aria-hidden="true" /> {label}
            </button>
          ))}
        </nav>
      </header>

      <section id="diagnostics" className="scroll-mt-6" aria-label="Diagnostics">
        <DiagnosticsOperations />
      </section>

      <section id="recovery" className="scroll-mt-6" aria-label="Recovery">
        <RecoveryOperations />
      </section>

      <section id="deployment" className="scroll-mt-6 space-y-6" aria-labelledby="deployment-title">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-warning">Deploy · remote mutation</p>
          <h2 id="deployment-title" className="m-0 mt-1 text-xl text-text-primary">External deployment</h2>
          <p className="mb-0 mt-1 text-xs text-text-secondary">Remote mutations stay distinct from application Settings and report only verified outcomes.</p>
        </div>
        <CloudflareWorkerUpload />
        <WarpOperations />
      </section>

      <section id="planning" className="scroll-mt-6 space-y-4" aria-labelledby="planning-title">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Investigate · read-only</p>
          <h2 id="planning-title" className="m-0 mt-1 text-xl text-text-primary">Remote planning</h2>
          <p className="mb-0 mt-1 text-xs text-text-secondary">Planning surfaces remain explicitly read-only and do not masquerade as deployed runtime capability.</p>
        </div>
        <RemotePlanningOperations />
      </section>
    </div>
  );
}
