import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { getScanHistoryApi, getScanWebSocketUrl, Scan } from '../api/scans';
import { getSecurityScoreApi } from '../api/securityScore';
import { soundEngine } from '../utils/soundEffects';

export interface ScanProgressState {
  stage: string;
  progress: number;
  status: string;
}

export interface ScanContextType {
  scans: Scan[];
  isLoading: boolean;
  error: string | null;
  runningScansCount: number;
  activeScanId: number | null;
  activeScanProgress: ScanProgressState | null;
  latestScan: Scan | null;
  latestCompletedScan: Scan | null;
  securityScore: number | null;
  securityGrade: string | null;
  riskLevel: string | null;
  refreshScans: (showLoader?: boolean) => Promise<void>;
  setActiveScanId: (id: number | null) => void;
  setActiveScanProgress: React.Dispatch<React.SetStateAction<ScanProgressState | null>>;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { isAuthenticated, token } = useAuth();

  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [activeScanProgress, setActiveScanProgress] = useState<ScanProgressState | null>(null);

  const refreshScans = useCallback(
    async (showLoader = false) => {
      if (!isAuthenticated || !token) {
        setScans([]);
        setIsLoading(false);
        return;
      }

      if (showLoader) setIsLoading(true);
      setError(null);

      try {
        const userScans = await getScanHistoryApi();
        setScans(userScans);

        // Check if any scan is actively running
        const runningScan = userScans.find((s) => s.status?.toLowerCase() === 'running');
        if (runningScan) {
          setActiveScanId(runningScan.id);
        } else {
          setActiveScanId(null);
          setActiveScanProgress(null);
        }

        // If the latest completed scan doesn't have a computed score in its record, fetch and persist it
        const latestComp = userScans.find((s) => s.status?.toLowerCase() === 'completed');
        if (latestComp && (latestComp.security_score === null || latestComp.security_score === undefined)) {
          try {
            const calculated = await getSecurityScoreApi(latestComp.id);
            setScans((prev) =>
              prev.map((s) =>
                s.id === latestComp.id
                  ? {
                      ...s,
                      security_score: calculated.score,
                      security_grade: calculated.grade,
                      risk_level: calculated.risk_level,
                    }
                  : s
              )
            );
          } catch {
            // Ignore if calculation not ready
          }
        }
      } catch (err: any) {
        console.error('Failed to load scan telemetry:', err);
        setError(err.message || 'Error communicating with security operations backend.');
      } finally {
        if (showLoader) setIsLoading(false);
      }
    },
    [isAuthenticated, token]
  );

  // Initial fetch on authentication state change
  useEffect(() => {
    if (isAuthenticated) {
      refreshScans(true);
    } else {
      setScans([]);
      setActiveScanId(null);
      setActiveScanProgress(null);
      setIsLoading(false);
    }
  }, [isAuthenticated, refreshScans]);

  // Real-time WebSocket connection to track running scans
  useEffect(() => {
    if (!activeScanId) return;

    const wsUrl = getScanWebSocketUrl(activeScanId);
    let socket: WebSocket | null = null;
    let isClosed = false;

    try {
      socket = new WebSocket(wsUrl);

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setActiveScanProgress({
            stage: data.stage || 'Vulnerability Scan Progress',
            progress: typeof data.progress === 'number' ? data.progress : 0,
            status: data.status || 'Running',
          });

          if (data.status === 'Completed' || data.status === 'Failed') {
            soundEngine.playScanCompleted();
            setActiveScanId(null);
            // Refresh telemetry silently to update statuses, scores, and findings
            refreshScans(false);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket progress payload:', e);
        }
      };

      socket.onerror = () => {
        console.warn(`WebSocket connection warning for scan #${activeScanId}`);
      };

      socket.onclose = () => {
        if (!isClosed) {
          // Closed normally
        }
      };
    } catch (err) {
      console.warn('Could not establish WebSocket connection:', err);
    }

    return () => {
      isClosed = true;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [activeScanId, refreshScans]);

  // Derived telemetry metrics strictly from actual backend state
  const runningScansCount = scans.filter((s) => s.status?.toLowerCase() === 'running').length;
  const latestScan = scans.length > 0 ? scans[0] : null;
  const latestCompletedScan = scans.find((s) => s.status?.toLowerCase() === 'completed') || null;

  // The displayed security score is derived strictly from the latest completed scan (or null if none exist)
  const securityScore = latestCompletedScan?.security_score ?? null;
  const securityGrade = latestCompletedScan?.security_grade ?? null;
  const riskLevel = latestCompletedScan?.risk_level ?? null;

  return (
    <ScanContext.Provider
      value={{
        scans,
        isLoading,
        error,
        runningScansCount,
        activeScanId,
        activeScanProgress,
        latestScan,
        latestCompletedScan,
        securityScore,
        securityGrade,
        riskLevel,
        refreshScans,
        setActiveScanId,
        setActiveScanProgress,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export const useScanTelemetry = (): ScanContextType => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScanTelemetry must be used within a ScanProvider');
  }
  return context;
};
