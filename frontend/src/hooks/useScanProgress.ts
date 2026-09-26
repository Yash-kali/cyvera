import { useState, useEffect, useRef, useCallback } from 'react';
import { getScanStatusApi, getScanDetailsApi, getScanWebSocketUrl, ScanProgressResponse, Scan } from '../api/scans';
import { getWebSocketTicketApi } from '../api/auth';

export interface LogEntry {
  id: string;
  timestamp: string;
  stage: string;
  message: string;
  progress: number;
  level: 'info' | 'recon' | 'vuln' | 'ai' | 'report' | 'success' | 'error';
}

export interface LiveAsset {
  asset_id?: number | string;
  asset_type?: string;
  url: string;
  http_method?: string;
  status_code?: number;
  evidence?: string;
}

export interface LiveFinding {
  finding_id?: number | string;
  title: string;
  category?: string;
  severity?: string;
  confidence?: string;
  affected_url?: string;
  cvss_score?: number;
}

export interface ScanTimelineStep {
  key: string;
  title: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  detail?: string;
}

export interface UseScanProgressReturn {
  progress: number;
  state: string;
  stage: string;
  message: string;
  status: string;
  logs: LogEntry[];
  isConnected: boolean;
  isPolling: boolean;
  error: string | null;
  requestsUsed: number;
  requestsRemaining: number;
  requestsTotal: number;
  discoveredAssets: LiveAsset[];
  activeFindings: LiveFinding[];
  score: { score: number | null; grade: string | null; risk: string | null };
  heartbeatSecondsAgo: number | null;
  isWorkerAlive: boolean;
  timeline: ScanTimelineStep[];
  reconnect: () => void;
}

const STAGE_ORDER = [
  { key: 'VALIDATING_TARGET', title: 'Target Validation' },
  { key: 'RECON', title: 'Network Reconnaissance' },
  { key: 'DISCOVERY', title: 'Attack Surface Discovery' },
  { key: 'SECURITY_TESTING', title: 'Security Testing' },
  { key: 'SCORING', title: 'Risk Scoring' },
  { key: 'REPORTING', title: 'Report Generation' },
  { key: 'COMPLETED', title: 'Audit Completed' },
];

export const useScanProgress = (scanId?: number): UseScanProgressReturn => {
  const [progress, setProgress] = useState<number>(0);
  const [state, setState] = useState<string>('PENDING');
  const [stage, setStage] = useState<string>('Scan Initializing');
  const [message, setMessage] = useState<string>('Connecting to real-time scan stream...');
  const [status, setStatus] = useState<string>('Pending');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [requestsUsed, setRequestsUsed] = useState<number>(0);
  const [requestsRemaining, setRequestsRemaining] = useState<number>(150);
  const [requestsTotal] = useState<number>(150);

  const [discoveredAssets, setDiscoveredAssets] = useState<LiveAsset[]>([]);
  const [activeFindings, setActiveFindings] = useState<LiveFinding[]>([]);
  const [score, setScore] = useState<{ score: number | null; grade: string | null; risk: string | null }>({
    score: null,
    grade: null,
    risk: null,
  });

  const [lastHeartbeatTimestamp, setLastHeartbeatTimestamp] = useState<number | null>(null);
  const [heartbeatSecondsAgo, setHeartbeatSecondsAgo] = useState<number | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  const pingTimerRef = useRef<NodeJS.Timeout | null>(null);
  const lastLogMsgRef = useRef<string>('');

  const mapStageToLevel = (stageName: string, statusName: string): LogEntry['level'] => {
    if (statusName === 'Failed' || stageName.includes('Failed')) return 'error';
    if (statusName === 'Completed' || stageName.includes('Completed')) return 'success';
    if (stageName.includes('Recon')) return 'recon';
    if (stageName.includes('Testing') || stageName.includes('Finding') || stageName.includes('Vuln')) return 'vuln';
    if (stageName.includes('Scoring') || stageName.includes('Score') || stageName.includes('AI')) return 'ai';
    if (stageName.includes('Report')) return 'report';
    return 'info';
  };

  const addLogEntry = useCallback((stageName: string, msg: string, pct: number, statusName: string, ts?: string) => {
    if (!msg) return;
    const formattedTs = ts ? new Date(ts).toLocaleTimeString() : new Date().toLocaleTimeString();
    const logKey = `${formattedTs}-${stageName}-${msg}`;
    if (lastLogMsgRef.current === logKey) return;
    lastLogMsgRef.current = logKey;

    const level = mapStageToLevel(stageName, statusName);
    const newEntry: LogEntry = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      timestamp: formattedTs,
      stage: stageName,
      message: msg,
      progress: pct,
      level,
    };

    setLogs((prev) => [...prev.slice(-150), newEntry]);
  }, []);

  // Compute timeline steps
  const computeTimeline = useCallback((): ScanTimelineStep[] => {
    const isTermCompleted = status === 'Completed' || state === 'COMPLETED';
    const isTermFailed = status === 'Failed' || state === 'FAILED';
    const isTermCancelled = status === 'Cancelled' || state === 'CANCELLED';

    const currentIndex = STAGE_ORDER.findIndex((s) => s.key === state);

    return STAGE_ORDER.map((item, idx) => {
      if (isTermCompleted) {
        return { key: item.key, title: item.title, status: 'completed' };
      }
      if (isTermFailed && idx === currentIndex) {
        return { key: item.key, title: item.title, status: 'failed' };
      }
      if (isTermCancelled && idx === currentIndex) {
        return { key: item.key, title: item.title, status: 'cancelled' };
      }
      if (idx < currentIndex) {
        return { key: item.key, title: item.title, status: 'completed' };
      }
      if (idx === currentIndex) {
        return { key: item.key, title: item.title, status: 'in_progress' };
      }
      return { key: item.key, title: item.title, status: 'pending' };
    });
  }, [state, status]);

  // Handle Canonical WebSocket and Polling Payloads
  const handlePayload = useCallback((payload: any) => {
    if (!payload) return;

    // 1. Progress and State updates
    const pct = typeof payload.progress_percent === 'number' ? payload.progress_percent : payload.progress;
    if (typeof pct === 'number') {
      setProgress(pct);
    }

    if (payload.state) {
      setState(payload.state);
    }
    if (payload.stage) {
      setStage(payload.stage);
    }
    if (payload.message) {
      setMessage(payload.message);
    }
    if (payload.status) {
      setStatus(payload.status);
    }

    // 2. Budget metrics
    const data = payload.data || {};
    if (typeof data.requests_used === 'number') {
      setRequestsUsed(data.requests_used);
    }
    if (typeof data.requests_remaining === 'number') {
      setRequestsRemaining(data.requests_remaining);
    }

    // 3. Event-specific handlers
    const evType = payload.type;

    if (evType === 'scan.connected') {
      setLastHeartbeatTimestamp(Date.now());
      if (Array.isArray(data.discovered_assets) && data.discovered_assets.length > 0) {
        setDiscoveredAssets(data.discovered_assets);
      }
      if (Array.isArray(data.active_findings) && data.active_findings.length > 0) {
        setActiveFindings(data.active_findings);
      }
    } else if (evType === 'scan.asset_discovered' && data.asset) {
      setDiscoveredAssets((prev) => {
        const url = data.asset.url;
        if (prev.some((a) => a.url === url)) return prev;
        return [...prev, data.asset];
      });
    } else if (evType === 'scan.finding_discovered' && data.finding) {
      setActiveFindings((prev) => {
        const title = data.finding.title;
        if (prev.some((f) => f.title === title)) return prev;
        return [...prev, data.finding];
      });
    } else if (evType === 'scan.score_updated' || evType === 'scan.completed') {
      if (typeof data.score === 'number' || typeof data.score === 'string') {
        setScore({
          score: Number(data.score),
          grade: data.grade || null,
          risk: data.risk || null,
        });
      }
    } else if (evType === 'scan.heartbeat') {
      setLastHeartbeatTimestamp(Date.now());
    }

    // Add activity log
    addLogEntry(
      payload.stage || state || 'Scan Progress',
      payload.message || '',
      typeof pct === 'number' ? pct : 0,
      payload.status || status || 'Running',
      payload.timestamp
    );
  }, [addLogEntry, state, status]);

  // Reconcile authoritative persisted state from DB
  const reconcileFromDatabase = useCallback(async (id: number) => {
    try {
      const scanData: Scan = await getScanDetailsApi(id);
      if (scanData) {
        if (typeof scanData.progress === 'number' && scanData.progress > 0) {
          setProgress(scanData.progress);
        }
        if (scanData.current_phase) {
          setState(scanData.current_phase);
          setStage(scanData.current_phase.replace(/_/g, ' '));
        }
        if (scanData.status) {
          setStatus(scanData.status);
        }
        if (scanData.security_score !== null && scanData.security_score !== undefined) {
          setScore({
            score: scanData.security_score,
            grade: scanData.security_grade || null,
            risk: scanData.risk_level || null,
          });
        }
        if ((scanData as any).score_details?.requests_used !== undefined) {
          const reqs = Number((scanData as any).score_details.requests_used);
          setRequestsUsed(reqs);
          setRequestsRemaining(Math.max(0, 150 - reqs));
        }
      }
    } catch (e) {
      console.warn('Could not reconcile scan state from DB:', e);
    }
  }, []);

  // HTTP Polling Fallback
  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    setIsPolling(false);
  }, []);

  const startPolling = useCallback((id: number) => {
    if (pollTimerRef.current) return;
    setIsPolling(true);

    const poll = async () => {
      try {
        const data: ScanProgressResponse = await getScanStatusApi(id);
        handlePayload(data);
        if (data.status === 'Completed' || data.status === 'Failed' || data.status === 'Cancelled') {
          stopPolling();
        }
      } catch (err: any) {
        console.warn('Scan status polling error:', err);
      }
    };

    poll();
    pollTimerRef.current = setInterval(poll, 3000);
  }, [handlePayload, stopPolling]);

  // WebSocket Connection Handler
  const connectWebSocket = useCallback(async () => {
    if (!scanId) return;

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    let wsToken: string | undefined = undefined;
    try {
      wsToken = await getWebSocketTicketApi();
    } catch {
      // Graceful fallback to session token if ticket endpoint unreachable
    }

    const wsUrl = getScanWebSocketUrl(scanId, wsToken);

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setError(null);
        stopPolling();
        setLastHeartbeatTimestamp(Date.now());

        // Setup ping keepalive every 15 seconds
        if (pingTimerRef.current) clearInterval(pingTimerRef.current);
        pingTimerRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        if (event.data === 'pong') {
          setLastHeartbeatTimestamp(Date.now());
          return;
        }
        try {
          const data = JSON.parse(event.data);
          handlePayload(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onerror = (evt) => {
        console.warn(`WebSocket error on scan #${scanId}:`, evt);
        setIsConnected(false);
      };

      ws.onclose = (evt) => {
        setIsConnected(false);
        wsRef.current = null;
        if (pingTimerRef.current) {
          clearInterval(pingTimerRef.current);
          pingTimerRef.current = null;
        }

        // Handle authentication or forbidden closure
        if (evt.code === 4401) {
          setError('WebSocket authentication failed. Please log in.');
          return;
        }
        if (evt.code === 4403) {
          setError('Access denied: Tenant scan isolation enforced.');
          return;
        }

        // Reconcile and start polling fallback if scan is still active
        reconcileFromDatabase(scanId);
        if (status !== 'Completed' && status !== 'Failed' && status !== 'Cancelled') {
          startPolling(scanId);
        }
      };
    } catch (err: any) {
      console.error('Failed to instantiate WebSocket:', err);
      setIsConnected(false);
      setError('WebSocket connection error. Falling back to HTTP polling.');
      reconcileFromDatabase(scanId);
      startPolling(scanId);
    }
  }, [scanId, handlePayload, startPolling, stopPolling, status, reconcileFromDatabase]);

  // Heartbeat Timer ticker
  useEffect(() => {
    const ticker = setInterval(() => {
      if (lastHeartbeatTimestamp) {
        const secs = Math.floor((Date.now() - lastHeartbeatTimestamp) / 1000);
        setHeartbeatSecondsAgo(secs);
      }
    }, 1000);

    return () => clearInterval(ticker);
  }, [lastHeartbeatTimestamp]);

  // Initial connect & reconcile
  useEffect(() => {
    if (!scanId) return;

    reconcileFromDatabase(scanId);
    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      if (pingTimerRef.current) {
        clearInterval(pingTimerRef.current);
        pingTimerRef.current = null;
      }
      stopPolling();
    };
  }, [scanId, connectWebSocket, stopPolling, reconcileFromDatabase]);

  const isWorkerAlive = isConnected && (heartbeatSecondsAgo === null || heartbeatSecondsAgo < 15);

  return {
    progress,
    state,
    stage,
    message,
    status,
    logs,
    isConnected,
    isPolling,
    error,
    requestsUsed,
    requestsRemaining,
    requestsTotal,
    discoveredAssets,
    activeFindings,
    score,
    heartbeatSecondsAgo,
    isWorkerAlive,
    timeline: computeTimeline(),
    reconnect: connectWebSocket,
  };
};
