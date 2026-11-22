import type { E2eeEnvelope } from './security';

export type SyncEventStatus = 'PENDING' | 'IN_PROGRESS' | 'SYNCED' | 'FAILED';

export type SyncDeliveryPolicy = 'PEER_CONFIRMED' | 'RELAY_QUEUED';

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
  /** True only when encrypted at rest locally with AES-256-GCM */
  encrypted: boolean;
  /** True only when actually encrypted/verified via E2EE ECDH+HKDF+AES-256-GCM */
  e2eeProtected?: boolean;
  targetDeviceId?: string | null;
  sourceDeviceId?: string | null;
  e2eeEnvelope?: E2eeEnvelope;
  relayAcceptedAt?: number | null;
  deliveredAt?: number | null;
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
  deliveredIds?: number[];
  serverTimestamp: number;
  error?: string;
}

export interface SyncRunSummary {
  attempted: number;
  synced: number;
  awaitingPeerAck: number;
  duplicates: number;
  failed: number;
  skippedReason?: 'OFFLINE' | 'SESSION_EXPIRED' | 'UNPAIRED' | 'LOCKED';
  completedAt: number;
}
