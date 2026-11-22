import type {
  ConnectionState,
  DeviceRole,
  LinkedDevice,
  PairingRequest,
} from '../models/device';
import type { EncryptedEnvelope } from '../models/security';
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
  encrypt(plaintext: string): Promise<EncryptedEnvelope | null>;
  decrypt(envelope: EncryptedEnvelope): Promise<string | null>;
  sha256Hex(value: string): Promise<string>;
  getOrCreateDeviceKeyPair(): Promise<{
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
  }>;
  signPayload(payload: string): Promise<string | null>;
  verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }>;
}

export interface RelayRegistrationPayload {
  publicId: string;
  cryptoKeyId: string;
  publicKeyJwk: JsonWebKey | null;
  role: DeviceRole;
  label: string;
  signature?: string | null;
}

export interface ITransportClient {
  getState(): ConnectionState;
  getLastSuccessfulConnectionAt(): number | null;
  connect(device: RelayRegistrationPayload): Promise<void>;
  disconnect(): Promise<void>;
  createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest>;
  acceptPairingRequest(
    pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<LinkedDevice>;
  fetchLinkedDevices(deviceId: string): Promise<LinkedDevice[]>;
  revokeDeviceLink(deviceId: string, targetDeviceId: string): Promise<void>;
  sendSyncBatch(
    deviceId: string,
    targetDeviceId: string | null,
    events: SyncEvent[]
  ): Promise<SyncDispatchAck>;
  fetchInboundEvents(deviceId: string): Promise<SyncEvent[]>;
  subscribe(listener: () => void): () => void;
  subscribeEvents(listener: (event: SyncEvent) => void): () => void;
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
