import { useEffect, useMemo, useState } from 'react';
import { controlTransport } from '../../api/ControlTransport';
import type { FlowSnapshot } from '../../api/flows';
import { errorText } from './format';

interface FlowMutationOptions {
  flows: FlowSnapshot[];
  visibleFlows: FlowSnapshot[];
  reload: () => Promise<void>;
  reportError: (message: string | null) => void;
}

export function useFlowMutations({ flows, visibleFlows, reload, reportError }: FlowMutationOptions) {
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busyIDs, setBusyIDs] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    const live = new Set(flows.map((flow) => flow.id));
    setSelected((previous) => new Set([...previous].filter((id) => live.has(id))));
  }, [flows]);

  const setBusy = (ids: string[], busy: boolean) => {
    setBusyIDs((previous) => {
      const next = new Set(previous);
      ids.forEach((id) => busy ? next.add(id) : next.delete(id));
      return next;
    });
  };

  const closeOne = async (flow: FlowSnapshot) => {
    if (!flow.closeable || busyIDs.has(flow.id)) return;
    if (!window.confirm(`Close ${flow.owner} flow ${flow.id}? The owning runtime will tear down the connection.`)) return;
    setBusy([flow.id], true);
    try {
      const response = await controlTransport.request(`/api/system/flows/${encodeURIComponent(flow.id)}`, { method: 'DELETE' });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      setSelected((previous) => {
        const next = new Set(previous);
        next.delete(flow.id);
        return next;
      });
      await reload();
    } catch (caught) {
      reportError(errorText(caught, 'Flow close failed.'));
    } finally {
      setBusy([flow.id], false);
    }
  };

  const closeSelected = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    if (!window.confirm(`Close ${ids.length} explicitly selected flow${ids.length === 1 ? '' : 's'}? Each owning runtime will perform its own teardown.`)) return;
    setBusy(ids, true);
    try {
      const response = await controlTransport.request('/api/system/flows/close', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true, ids }),
      });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      const payload: unknown = await response.json();
      if (typeof payload === 'object' && payload !== null && 'failed' in payload && Number(payload.failed) > 0) {
        reportError(`${String(payload.failed)} selected flow close request(s) failed; successful owner teardowns were retained.`);
      } else {
        reportError(null);
      }
      setSelected(new Set());
      await reload();
    } catch (caught) {
      reportError(errorText(caught, 'Bulk flow close failed.'));
    } finally {
      setBusy(ids, false);
    }
  };

  const allVisibleSelected = useMemo(
    () => visibleFlows.some((flow) => flow.closeable) && visibleFlows.filter((flow) => flow.closeable).every((flow) => selected.has(flow.id)),
    [selected, visibleFlows],
  );

  const setFlowSelected = (id: string, checked: boolean) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  };

  const setAllVisibleSelected = (checked: boolean) => {
    setSelected(checked ? new Set(visibleFlows.filter((flow) => flow.closeable).map((flow) => flow.id)) : new Set());
  };

  return {
    selected,
    busyIDs,
    allVisibleSelected,
    setFlowSelected,
    setAllVisibleSelected,
    closeOne,
    closeSelected,
  };
}
