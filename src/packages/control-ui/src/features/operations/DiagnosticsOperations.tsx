import { useCallback, useEffect, useRef, useState } from 'react';
import { Activity, Download, Gauge, Play, RefreshCw, Stethoscope } from 'lucide-react';
import { controlTransport } from '../../api/ControlTransport';
import {
  errorMessage,
  parseDiagnosticPhases,
  parseDiagnosticStatus,
  parseDoctorReport,
  parsePortPreflight,
  parseRuntimeEngines,
  type DiagnosticPhase,
  type DiagnosticStatus,
  type DoctorReport,
  type RuntimeEngineStatus,
} from '../../api/contracts';

const terminalDiagnosticStates = new Set(['completed', 'failed', 'cancelled', 'canceled']);

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

function EvidenceBlock({ value }: { value: unknown }) {
  return (
    <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-border-color bg-bg-primary/60 p-3 text-[11px] leading-relaxed text-text-secondary">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function DiagnosticsOperations() {
  const [doctor, setDoctor] = useState<DoctorReport | null>(null);
  const [phases, setPhases] = useState<DiagnosticPhase[]>([]);
  const [engines, setEngines] = useState<RuntimeEngineStatus[]>([]);
  const [overviewBusy, setOverviewBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const overviewController = useRef<AbortController | null>(null);

  const [diagnosticTarget, setDiagnosticTarget] = useState('1.1.1.1');
  const [diagnosticType, setDiagnosticType] = useState('connectivity');
  const [diagnosticID, setDiagnosticID] = useState<string | null>(null);
  const [lastDiagnosticID, setLastDiagnosticID] = useState<string | null>(null);
  const [diagnosticStatus, setDiagnosticStatus] = useState<DiagnosticStatus | null>(null);
  const [diagnosticBusy, setDiagnosticBusy] = useState(false);

  const [preflightHost, setPreflightHost] = useState('127.0.0.1');
  const [preflightPort, setPreflightPort] = useState(1080);
  const [preflightResult, setPreflightResult] = useState<ReturnType<typeof parsePortPreflight> | null>(null);
  const [preflightBusy, setPreflightBusy] = useState(false);

  const loadOverview = useCallback(async () => {
    overviewController.current?.abort();
    const controller = new AbortController();
    overviewController.current = controller;
    setOverviewBusy(true);
    setError(null);

    try {
      const doctorTask = (async () => {
        const response = await controlTransport.request('/api/doctor', { signal: controller.signal });
        if (!response.ok) throw new Error(`doctor request failed (${response.status})`);
        return parseDoctorReport(await response.json() as unknown);
      })();
      const phasesTask = controlTransport.json('/api/diagnostics/phases', parseDiagnosticPhases, { signal: controller.signal });
      const enginesTask = controlTransport.json('/api/system/engines', parseRuntimeEngines, { signal: controller.signal });
      const [doctorResult, phasesResult, enginesResult] = await Promise.allSettled([doctorTask, phasesTask, enginesTask]);
      if (controller.signal.aborted) return;

      const unavailable: string[] = [];
      if (doctorResult.status === 'fulfilled') setDoctor(doctorResult.value);
      else unavailable.push(`doctor: ${errorMessage(doctorResult.reason, 'unavailable')}`);
      if (phasesResult.status === 'fulfilled') setPhases(phasesResult.value);
      else unavailable.push(`diagnostics: ${errorMessage(phasesResult.reason, 'unavailable')}`);
      if (enginesResult.status === 'fulfilled') setEngines(enginesResult.value);
      else unavailable.push(`engines: ${errorMessage(enginesResult.reason, 'unavailable')}`);
      if (unavailable.length > 0) setError(`Some operations evidence is unavailable. ${unavailable.join(' · ')}`);
    } finally {
      if (overviewController.current === controller) {
        overviewController.current = null;
        setOverviewBusy(false);
      }
    }
  }, []);

  useEffect(() => {
    void loadOverview();
    return () => overviewController.current?.abort();
  }, [loadOverview]);

  useEffect(() => {
    if (!diagnosticID) return undefined;
    const controller = new AbortController();
    let timer: number | undefined;

    const poll = async () => {
      try {
        const status = await controlTransport.json(
          `/api/diagnostics/${encodeURIComponent(diagnosticID)}`,
          parseDiagnosticStatus,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setDiagnosticStatus(status);
        if (terminalDiagnosticStates.has(status.status.toLowerCase())) {
          setDiagnosticBusy(false);
          setDiagnosticID(null);
          return;
        }
        timer = window.setTimeout(() => void poll(), 900);
      } catch (caught) {
        if (controller.signal.aborted || isAbortError(caught)) return;
        setError(errorMessage(caught, 'Failed to poll diagnostic job.'));
        setDiagnosticBusy(false);
        setDiagnosticID(null);
      }
    };

    void poll();
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [diagnosticID]);

  const runDiagnostic = async () => {
    setDiagnosticBusy(true);
    setDiagnosticStatus(null);
    setError(null);
    try {
      const id = await controlTransport.executeDiagnosticRun(diagnosticType, diagnosticTarget.trim());
      setDiagnosticID(id);
      setLastDiagnosticID(id);
      setDiagnosticStatus({ status: 'running', progress: 0, results: null });
    } catch (caught) {
      setDiagnosticBusy(false);
      setError(errorMessage(caught, 'Failed to start diagnostic run.'));
    }
  };

  const exportDiagnostic = async () => {
    if (!lastDiagnosticID) return;
    setError(null);
    try {
      const response = await controlTransport.request(`/api/diagnostics/${encodeURIComponent(lastDiagnosticID)}/export`);
      if (!response.ok) throw new Error(`diagnostic export failed (${response.status})`);
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `luminet-diagnostic-${lastDiagnosticID}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to export diagnostic report.'));
    }
  };

  const runPreflight = async () => {
    setPreflightBusy(true);
    setError(null);
    try {
      setPreflightResult(await controlTransport.json('/api/system/port-preflight', parsePortPreflight, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: preflightHost.trim(), port: preflightPort }),
      }));
    } catch (caught) {
      setError(errorMessage(caught, 'Port preflight failed.'));
    } finally {
      setPreflightBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="card space-y-4" aria-labelledby="operations-evidence-title">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border-color pb-3">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Observe · authoritative runtime evidence</p>
            <h2 id="operations-evidence-title" className="m-0 mt-1 flex items-center gap-2 text-lg text-text-primary"><Gauge size={18} aria-hidden="true" /> Runtime overview</h2>
          </div>
          <button type="button" className="btn btn-secondary px-3 py-1.5" onClick={() => void loadOverview()} disabled={overviewBusy}>
            <RefreshCw size={14} className={overviewBusy ? 'animate-spin' : ''} aria-hidden="true" /> Refresh evidence
          </button>
        </div>
        {error && <p role="alert" className="m-0 rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</p>}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <article><h3 className="text-sm text-text-primary">Doctor report</h3>{doctor ? <EvidenceBlock value={doctor} /> : <p className="text-xs text-text-muted">No doctor evidence loaded.</p>}</article>
          <article><h3 className="text-sm text-text-primary">Diagnostic phases</h3>{phases.length > 0 ? <EvidenceBlock value={phases} /> : <p className="text-xs text-text-muted">No phase evidence loaded.</p>}</article>
          <article><h3 className="text-sm text-text-primary">Runtime engines</h3>{engines.length > 0 ? <EvidenceBlock value={engines} /> : <p className="text-xs text-text-muted">No engine evidence loaded.</p>}</article>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-2" aria-label="Diagnostic operations">
        <div className="card space-y-4">
          <h2 className="m-0 flex items-center gap-2 text-lg text-text-primary"><Stethoscope size={18} aria-hidden="true" /> Diagnostic run</h2>
          <p className="m-0 text-xs text-text-secondary">Runs a daemon diagnostic and polls it serially. Starting a new run never shares polling state with an older run.</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-xs text-text-muted">Type<select value={diagnosticType} onChange={(event) => setDiagnosticType(event.target.value)} className="field-input mt-1"><option value="connectivity">Connectivity</option><option value="dns">DNS</option><option value="routing">Routing</option><option value="proxy">Proxy</option></select></label>
            <label className="text-xs text-text-muted">Target<input value={diagnosticTarget} onChange={(event) => setDiagnosticTarget(event.target.value)} className="field-input mono mt-1" /></label>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn btn-primary" disabled={diagnosticBusy || !diagnosticTarget.trim()} onClick={() => void runDiagnostic()}><Play size={15} aria-hidden="true" /> {diagnosticBusy ? 'Running…' : 'Run diagnostic'}</button>
            <button type="button" className="btn btn-secondary" disabled={!lastDiagnosticID} onClick={() => void exportDiagnostic()}><Download size={15} aria-hidden="true" /> Export last run</button>
          </div>
          {diagnosticStatus && <div role="status" aria-live="polite"><EvidenceBlock value={diagnosticStatus} /></div>}
        </div>

        <div className="card space-y-4">
          <h2 className="m-0 flex items-center gap-2 text-lg text-text-primary"><Activity size={18} aria-hidden="true" /> Port preflight</h2>
          <p className="m-0 text-xs text-text-secondary">Checks daemon-side bind/readiness evidence before a local listener mutation.</p>
          <div className="grid gap-3 sm:grid-cols-[1fr_9rem]">
            <label className="text-xs text-text-muted">Host<input value={preflightHost} onChange={(event) => setPreflightHost(event.target.value)} className="field-input mono mt-1" /></label>
            <label className="text-xs text-text-muted">Port<input type="number" min={1} max={65535} value={preflightPort} onChange={(event) => setPreflightPort(Math.min(65535, Math.max(1, Number(event.target.value) || 1)))} className="field-input mono mt-1" /></label>
          </div>
          <button type="button" className="btn btn-secondary" disabled={preflightBusy || !preflightHost.trim()} onClick={() => void runPreflight()}>{preflightBusy ? <RefreshCw size={15} className="animate-spin" aria-hidden="true" /> : <Play size={15} aria-hidden="true" />} Check port</button>
          {preflightResult && <EvidenceBlock value={preflightResult} />}
        </div>
      </section>
    </div>
  );
}
