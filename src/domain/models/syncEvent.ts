import type { E2eeEnvelope } from './security';

export type SyncEventStatus = 'PENDING' | 'IN_PROGRESS' | 'SYNCED' | 'FAILED';

export type SyncDeliveryPolicy = 'PEER_CONFIRMED' | 'RELAY_QUEUED';

export type RelayDeliveryState = 'QUEUED_AT_RELAY' | 'DELIVERED';

/**
 * Shared SyncEvent domain & wire contract:
 * - Sender capture/local save: `status = 'PENDING'`, `encrypted` reflects local AES-256-GCM rest encryption.
 * - Sender dispatch (`POST /sync`): `status = 'IN_PROGRESS'`, `relayAcceptedAt` set on relay accept.
 *   Under `PEER_CONFIRMED` (default), `status` NEVER becomes `'SYNCED'` until recipient `/sync/ack` arrives.
 * - Relay push/inbox (`sync:event` / `GET /sync/:deviceId/inbox`):
 *   - `status` is `'IN_PROGRESS'` (never `'SYNCED'` before ACK) and `relayDeliveryState` is `'QUEUED_AT_RELAY'`.
 *   - `encrypted: true` (payload is E2EE ciphertext `[E2EE_CIPHERTEXT]`, zero plaintext).
 *   - `localEncrypted: false` (relay holds no local plaintext key).
 *   - `e2eeProtected: false` and `e2eeVerified: false` (relay cannot prove end-to-end AES-GCM decryption;
 *     only `relaySignatureVerified: true` is attested by the relay).
 * - Recipient ingest (`SyncEngine.ingestInboundEvent`):
 *   1. Verifies paired sender + cryptoKeyId + nonce uniqueness + ECDSA signature + AAD + AES-256-GCM decrypt.
 *   2. Persists plaintext locally (encrypted at rest if WebCrypto/Keystore available) with
 *      `e2eeProtected: true`, `e2eeVerified: true`, `e2eeNonce`.
 *   3. ONLY AFTER local persistence succeeds, sends `POST /sync/ack`.
 */
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
  /** True when represented as ciphertext (local AES-256-GCM at rest OR opaque E2EE ciphertext on wire). */
  encrypted: boolean;
  /** True only when encrypted at rest locally with device AES-256-GCM key. */
  localEncrypted?: boolean;
  /** True only when end-to-end encrypted by sender or verified+decrypted via E2EE on recipient. Never true on unverified Relay wire events. */
  e2eeProtected?: boolean;
  /** True only on recipient after ECDSA + AAD + ECDH/HKDF + AES-GCM verification succeeds. */
  e2eeVerified?: boolean;
  /** True when Relay verified the sender ECDSA signature on the E2EE envelope. */
  relaySignatureVerified?: boolean;
  /** Relay queue/delivery sub-state observed by server. */
  relayDeliveryState?: RelayDeliveryState;
  targetDeviceId?: string | null;
  sourceDeviceId?: string | null;
  e2eeEnvelope?: E2eeEnvelope;
  /** Persisted messageNonce from verified inbound E2EE envelope to block cross-restart replays. */
  e2eeNonce?: string | null;
  /** Relay row ID for un-ACKed inbound delivery recovery. */
  relayEventId?: number | null;
  /** True once recipient confirmed POST /sync/ack back to Relay. */
  inboundAckConfirmed?: boolean;
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
