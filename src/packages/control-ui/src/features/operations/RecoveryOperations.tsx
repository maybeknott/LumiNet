import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, RotateCcw, Search } from 'lucide-react';
import { controlTransport } from '../../api/ControlTransport';
import { errorMessage } from '../../api/contracts';
import {
  parseInterruptedJobHistory,
  parseRecoveryInfo,
  parseRecoveryRequeueResult,
  type InterruptedJobSummary,
  type RecoveryInfo,
  type RecoveryRequeueResult,
} from '../../api/recovery';

export function RecoveryOperations() {
  const [interruptedJobs, setInterruptedJobs] = useState<InterruptedJobSummary[]>([]);
  const [jobID, setJobID] = useState('');
  const [info, setInfo] = useState<RecoveryInfo | null>(null);
  const [result, setResult] = useState<RecoveryRequeueResult | null>(null);
  const [busy, setBusy] = useState<'list' | 'inspect' | 'requeue' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadCandidates = useCallback(async () => {
    setBusy('list');
    setError(null);
    try {
      const jobs = await controlTransport.json('/api/history', parseInterruptedJobHistory);
      setInterruptedJobs(jobs);
      setJobID((current) => current || jobs[0]?.id || '');
    } catch (caught) {
      setError(errorMessage(caught, 'Interrupted job history is unavailable.'));
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => { void loadCandidates(); }, [loadCandidates]);

  const inspect = async (candidate = jobID) => {
    const id = candidate.trim();
    if (!id) return;
    setBusy('inspect');
    setError(null);
    setResult(null);
    try {
      setInfo(await controlTransport.json(`/api/jobs/${encodeURIComponent(id)}/recovery`, parseRecoveryInfo));
      setJobID(id);
    } catch (caught) {
      setInfo(null);
      setError(errorMessage(caught, 'Recovery inspection failed.'));
    } finally {
      setBusy(null);
    }
  };

  const requeue = async () => {
    if (!info?.requeueAvailable || !info.requiresConfirmation) return;
    const confirmed = window.confirm(`Create and start a NEW ${info.jobType} execution recovered from ${info.jobID}? The interrupted source record will remain unchanged.`);
    if (!confirmed) return;

    setBusy('requeue');
    setError(null);
    try {
      const next = await controlTransport.json(`/api/jobs/${encodeURIComponent(info.jobID)}/requeue`, parseRecoveryRequeueResult, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      const [refreshedInfo, jobs] = await Promise.all([
        controlTransport.json(`/api/jobs/${encodeURIComponent(info.jobID)}/recovery`, parseRecoveryInfo),
        controlTransport.json('/api/history', parseInterruptedJobHistory),
      ]);
      setInfo(refreshedInfo);
      setInterruptedJobs(jobs);
      setResult(next);
    } catch (caught) {
      setError(errorMessage(caught, 'Recovery requeue failed.'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="card space-y-4" aria-labelledby="recovery-title">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border-color pb-3">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-warning">Recover · explicit confirmation</p>
          <h2 id="recovery-title" className="m-0 mt-1 flex items-center gap-2 text-lg text-text-primary"><RotateCcw size={18} aria-hidden="true" /> Interrupted jobs</h2>
        </div>
        <button type="button" className="btn btn-secondary px-3 py-1.5" disabled={busy !== null} onClick={() => void loadCandidates()}><RefreshCw size={14} className={busy === 'list' ? 'animate-spin' : ''} aria-hidden="true" /> Refresh</button>
      </div>
      <p className="m-0 text-xs leading-relaxed text-text-secondary">Inspects persisted interrupted-job evidence first. Requeue creates a new execution only after an explicit confirmation; the source record is preserved.</p>
      {error && <p role="alert" className="m-0 rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</p>}

      <div className="grid gap-3 md:grid-cols-[1fr_auto]">
        <label className="text-xs text-text-muted">Interrupted job
          <select value={jobID} onChange={(event) => setJobID(event.target.value)} className="field-input mt-1 w-full">
            <option value="">Select or enter a job below</option>
            {interruptedJobs.map((job) => <option key={job.id} value={job.id}>{job.type} · {job.id}</option>)}
          </select>
        </label>
        <button type="button" className="btn btn-secondary self-end" disabled={!jobID.trim() || busy !== null} onClick={() => void inspect()}><Search size={14} aria-hidden="true" /> Inspect</button>
      </div>
      <label className="block text-xs text-text-muted">Job ID<input value={jobID} onChange={(event) => setJobID(event.target.value)} className="field-input mono mt-1 w-full" placeholder="job id" /></label>

      {info && (
        <div className="space-y-2 rounded border border-border-color bg-bg-primary/60 p-3 text-xs text-text-secondary">
          <p className="m-0"><strong className="text-text-primary">{info.jobType}</strong> · policy {info.policy || 'unspecified'}</p>
          <p className="m-0">Interrupted {info.interrupted ? 'yes' : 'no'} · reconstructible {info.reconstructible ? 'yes' : 'no'} · requeue {info.requeueAvailable ? 'available' : 'unavailable'}</p>
          {info.reason && <p className="m-0 text-text-muted">{info.reason}</p>}
          {info.activeDescendant && <p className="m-0 text-warning">Active descendant: {info.activeDescendant}</p>}
          <button type="button" className="btn btn-primary mt-2" disabled={!info.requeueAvailable || !info.requiresConfirmation || busy !== null} onClick={() => void requeue()}><RotateCcw size={14} aria-hidden="true" /> {busy === 'requeue' ? 'Requeueing…' : 'Confirm and requeue as new job'}</button>
        </div>
      )}
      {result && <div role="status" aria-live="polite" className="rounded border border-success/30 bg-success/10 p-3 text-xs text-text-primary">Created recovery job <span className="mono">{result.jobID}</span> from <span className="mono">{result.recoveredFrom}</span>; status {result.status}.</div>}
    </section>
  );
}
