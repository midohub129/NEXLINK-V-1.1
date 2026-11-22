import type {
  ConnectionState,
  DeviceRole,
  LinkedDevice,
  PairingRequest,
} from '../models/device';
import type {
  E2eeEnvelope,
  EncryptedEnvelope,
  RelayServerSession,
} from '../models/security';
import type { SyncDispatchAck, SyncEvent } from '../models/syncEvent';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export interface LogRecord {
  id: number;
  timestamp: number;
  level: LogLevel;
  scope: string;
  traceId: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface ILogger {
  debug(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void;
  info(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void;
  warn(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void;
  error(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void;
  getLogs(): LogRecord[];
  clear(): void;
  subscribe(listener: () => void): () => void;
}

export interface ICryptoProvider {
  isSupported(): boolean;
  randomHex(byteLength?: number): string;
  encrypt(plaintext: string): Promise<EncryptedEnvelope | null>;
  decrypt(envelope: EncryptedEnvelope): Promise<string | null>;
  sha256Hex(value: string): Promise<string>;
  getOrCreateDeviceKeyPair(): Promise<{
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
    ecdhPublicKeyJwk: JsonWebKey | null;
  }>;
  signPayload(payload: string): Promise<string | null>;
  verifySignatureWithJwk(
    publicKeyJwk: JsonWebKey,
    expectedCryptoKeyId: string,
    payload: string,
    signatureBase64: string
  ): Promise<boolean>;
  encryptForPeer(params: {
    plaintext: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    senderCryptoKeyId: string;
    recipientCryptoKeyId: string;
    recipientEcdhPublicKeyJwk: JsonWebKey;
    sessionId: string;
    idempotencyKey: string;
  }): Promise<E2eeEnvelope>;
  decryptFromPeer(params: {
    envelope: E2eeEnvelope;
    senderEcdsaPublicKeyJwk: JsonWebKey;
    senderEcdhPublicKeyJwk: JsonWebKey;
    expectedRecipientDeviceId: string;
    expectedRecipientCryptoKeyId: string;
  }): Promise<string>;
  verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }>;
}

export interface RelayRegistrationPayload {
  publicId: string;
  cryptoKeyId: string;
  publicKeyJwk: JsonWebKey | null;
  ecdhPublicKeyJwk: JsonWebKey | null;
  role: DeviceRole;
  label: string;
}

export interface ITransportClient {
  getState(): ConnectionState;
  getServerSession(): RelayServerSession | null;
  getLastSuccessfulConnectionAt(): number | null;
  connect(device: RelayRegistrationPayload): Promise<void>;
  disconnect(): Promise<void>;
  revokeServerSession(deviceId: string): Promise<void>;
  createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest>;
  acceptPairingRequest(
    pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<PairingRequest>;
  confirmPairingRequest(
    pairingId: string,
    approve: boolean,
    expectedResponderCryptoKeyId?: string
  ): Promise<LinkedDevice | null>;
  fetchPendingPairingApprovals(deviceId: string): Promise<PairingRequest[]>;
  fetchLinkedDevices(deviceId: string): Promise<LinkedDevice[]>;
  revokeDeviceLink(
    deviceId: string,
    targetDeviceId: string,
    revokeDeviceTrust?: boolean
  ): Promise<void>;
  sendSyncBatch(
    deviceId: string,
    targetDeviceId: string,
    events: SyncEvent[]
  ): Promise<SyncDispatchAck>;
  fetchInboundEvents(deviceId: string): Promise<SyncEvent[]>;
  acknowledgeInboundDelivery(deviceId: string, eventIds: number[]): Promise<void>;
  fetchSyncDeliveryStatus(
    deviceId: string,
    clientEventIds: number[]
  ): Promise<number[]>;
  subscribe(listener: () => void): () => void;
  subscribeEvents(listener: (event: SyncEvent) => void): () => void;
  subscribeDeliveryAcks(
    listener: (deliveredClientEventIds: number[], serverTimestamp: number) => void
  ): () => void;
  subscribePairingUpdates(listener: () => void): () => void;
}

export interface DataSourceAppInfo {
  packageName: string;
  appName: string;
  foregroundTimeMs: number | null;
  sourceKind: 'BROWSER_CAPABILITY' | 'TEST_FIXTURE';
}

export interface DataSourceAvailability {
  installedAppsAvailable: boolean;
  usageStatsAvailable: boolean;
  backgroundNotificationCaptureAvailable: boolean;
  reason?: string;
}

export interface IDataSource {
  readonly mode: 'PRODUCTION' | 'TEST_FIXTURE';
  getAvailability(): DataSourceAvailability;
  getInstalledApps(): Promise<DataSourceAppInfo[]>;
  getUsageStatsLast24h(): Promise<DataSourceAppInfo[]>;
}

export interface ILifecycleParticipant {
  readonly name: string;
  start(): Promise<void>;
  stop(): Promise<void>;
}
