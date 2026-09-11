import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { controlTransport } from '../../api/ControlTransport';
import {
  parseFlowList,
  parseNetworkIntelligence,
  parseNetworkStatus,
  type FlowListResponse,
  type NetworkIntelligence,
  type NetworkMonitorStatus,
} from '../../api/flows';
import { errorText } from './format';

export const POLL_MS = 1500;
export const FLOW_FETCH_LIMIT = 512;
export const INITIAL_VISIBLE_FLOWS = 100;
export const VISIBLE_FLOW_STEP = 100;

export interface ConnectionsFeed {
  data: FlowListResponse | null;
  networkState: NetworkMonitorStatus | null;
  intelligence: NetworkIntelligence | null;
  query: string;
  setQuery: (value: string) => void;
  owner: string;
  setOwner: (value: string) => void;
  owners: string[];
  loading: boolean;
  error: string | null;
  setError: (value: string | null) => void;
  load: (foreground?: boolean) => Promise<void>;
  currentEpoch: number;
  activeInterfaces: NetworkMonitorStatus['current']['interfaces'];
  visibleFlowLimit: number;
  setVisibleFlowLimit: (value: number | ((current: number) => number)) => void;
}

export function useConnectionsFeed(): ConnectionsFeed {
  const [data, setData] = useState<FlowListResponse | null>(null);
  const [networkState, setNetworkState] = useState<NetworkMonitorStatus | null>(null);
  const [intelligence, setIntelligence] = useState<NetworkIntelligence | null>(null);
  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [visibleFlowLimit, setVisibleFlowLimit] = useState(INITIAL_VISIBLE_FLOWS);
  const requestSequence = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);

  const load = useCallback(async (foreground = false) => {
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    if (foreground) setLoading(true);
    else setLoading(false);

    try {
      const params = new URLSearchParams({ limit: String(FLOW_FETCH_LIMIT) });
      if (owner) params.set('owner', owner);
      if (query.trim()) params.set('q', query.trim());
      const requestInit: RequestInit = { signal: controller.signal };
      const [flows, net, intel] = await Promise.all([
        controlTransport.json(`/api/system/flows?${params.toString()}`, parseFlowList, requestInit),
        controlTransport.json('/api/system/network-state?history=12', parseNetworkStatus, requestInit),
        controlTransport.json('/api/system/network-intelligence', parseNetworkIntelligence, requestInit),
      ]);
      if (controller.signal.aborted || sequence !== requestSequence.current) return;

      setData(flows);
      setNetworkState(net);
      setIntelligence(intel);
      setError(null);
    } catch (caught) {
      if (controller.signal.aborted || sequence !== requestSequence.current) return;
      setError(errorText(caught, 'Flow observability is unavailable.'));
    } finally {
      if (sequence === requestSequence.current) {
        if (activeRequest.current === controller) activeRequest.current = null;
        if (foreground) setLoading(false);
      }
    }
  }, [owner, query]);

  useEffect(() => {
    setVisibleFlowLimit(INITIAL_VISIBLE_FLOWS);
  }, [owner, query]);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;

    const stopTimer = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = undefined;
    };
    const schedule = () => {
      stopTimer();
      if (stopped || document.hidden) return;
      timer = window.setTimeout(() => void poll(false), POLL_MS);
    };
    const poll = async (foreground: boolean) => {
      if (stopped || document.hidden) return;
      await load(foreground);
      schedule();
    };
    const visibility = () => {
      if (document.hidden) {
        stopTimer();
        activeRequest.current?.abort();
        return;
      }
      void poll(false);
    };

    void poll(true);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      stopped = true;
      stopTimer();
      requestSequence.current += 1;
      activeRequest.current?.abort();
      activeRequest.current = null;
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [load]);

  const owners = useMemo(() => {
    const values = new Set<string>();
    data?.coverage.forEach((item) => values.add(item.owner));
    data?.flows.forEach((flow) => values.add(flow.owner));
    return [...values].sort();
  }, [data]);

  return {
    data,
    networkState,
    intelligence,
    query,
    setQuery,
    owner,
    setOwner,
    owners,
    loading,
    error,
    setError,
    load,
    currentEpoch: networkState?.current.revision ?? data?.networkRevision ?? 0,
    activeInterfaces: networkState?.current.interfaces ?? [],
    visibleFlowLimit,
    setVisibleFlowLimit,
  };
}
