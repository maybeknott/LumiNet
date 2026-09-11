import {
  CloudflareWorkerUpload,
  RemotePlanningOperations,
  WarpOperations,
} from '../features/operations/DeploymentOperations';

export function Deployment() {
  return (
    <div className="space-y-6">
      <header>
        <p className="mono m-0 text-xs uppercase tracking-[0.16em] text-accent">Operations · external systems</p>
        <h2 className="m-0 mt-1 text-2xl font-display text-text-primary">Deployment & remote network operations</h2>
        <p className="m-0 mt-2 max-w-3xl text-sm text-text-secondary">
          Remote mutations and evidence-gathering workflows live here rather than in preferences. Each surface states whether it mutates an external system or only computes a plan.
        </p>
      </header>
      <CloudflareWorkerUpload />
      <WarpOperations />
      <RemotePlanningOperations />
    </div>
  );
}
