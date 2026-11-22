export type SyncEventStatus = 'PENDING' | 'IN_PROGRESS' | 'SYNCED' | 'FAILED';

export interface SyncEvent {
  id: number;
  type: string;
  payload: string;
  createdAt: number;
  status: SyncEventStatus;
  retryCount: number;
  nextRetryAt: number | null;
  idempotencyKey: string;
  notificationKey?: string;
  payloadHash?: string;
  encrypted: boolean;
  lastError?: string | null;
  syncedAt?: number | null;
}

export interface NotificationPayload {
  packageName: string;
  title: string;
  text: string;
  postedAt: number;
}

export interface SyncDispatchAck {
  acknowledged: boolean;
  acceptedIds: number[];
  duplicateIds: number[];
  serverTimestamp: number;
  error?: string;
}

export interface SyncRunSummary {
  attempted: number;
  synced: number;
  duplicates: number;
  failed: number;
  skippedReason?: 'OFFLINE' | 'SESSION_EXPIRED' | 'UNPAIRED' | 'LOCKED';
  completedAt: number;
}
