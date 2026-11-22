import type { ConnectionState } from './device';

export type SubsystemStatus = 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | 'IDLE';

export interface SystemHealthSnapshot {
  databaseStatus: SubsystemStatus;
  transportStatus: ConnectionState;
  syncStatus: SubsystemStatus;
  pendingCount: number;
  inProgressCount: number;
  syncedCount: number;
  failedCount: number;
  lastSuccessfulConnectionAt: number | null;
  lastSuccessfulSyncAt: number | null;
  lastError: {
    code: string;
    source: string;
    message: string;
    timestamp: number;
  } | null;
  checkedAt: number;
}
