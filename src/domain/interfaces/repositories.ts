import type { DeviceIdentityProfile, LinkedDevice } from '../models/device';
import type { SecurityAuditEntry } from '../models/security';
import type { AppSettings } from '../models/settings';
import type { SyncEvent, SyncEventStatus } from '../models/syncEvent';

export interface CreateSyncEventInput {
  type: string;
  payload: string;
  idempotencyKey: string;
  notificationKey?: string;
  payloadHash?: string;
  targetDeviceId?: string | null;
  sourceDeviceId?: string | null;
  e2eeProtected?: boolean;
  createdAt?: number;
}

export interface ISyncEventRepository {
  initialize(): Promise<void>;
  insert(input: CreateSyncEventInput): Promise<SyncEvent>;
  findById(id: number): Promise<SyncEvent | null>;
  findByIdempotencyKey(idempotencyKey: string): Promise<SyncEvent | null>;
  findRecentDuplicate(
    type: string,
    notificationKey: string,
    payloadHash: string,
    windowMs: number,
    nowMs: number
  ): Promise<SyncEvent | null>;
  getAll(): Promise<SyncEvent[]>;
  getByStatus(status: SyncEventStatus): Promise<SyncEvent[]>;
  getDuePendingEvents(nowMs: number): Promise<SyncEvent[]>;
  updateEvent(
    id: number,
    patch: Partial<
      Pick<
        SyncEvent,
        | 'status'
        | 'retryCount'
        | 'nextRetryAt'
        | 'lastError'
        | 'syncedAt'
        | 'relayAcceptedAt'
        | 'deliveredAt'
        | 'targetDeviceId'
        | 'e2eeProtected'
      >
    >
  ): Promise<SyncEvent | null>;
  resetInProgressToPending(): Promise<number>;
  delete(id: number): Promise<boolean>;
  clearAll(): Promise<void>;
  subscribe(listener: () => void): () => void;
}

export interface IDeviceRepository {
  initialize(): Promise<void>;
  getIdentity(): Promise<DeviceIdentityProfile | null>;
  saveIdentity(identity: DeviceIdentityProfile): Promise<void>;
  getLinkedDevices(): Promise<LinkedDevice[]>;
  upsertLinkedDevice(device: LinkedDevice): Promise<void>;
  removeLinkedDevice(publicId: string): Promise<void>;
  subscribe(listener: () => void): () => void;
}

export interface ISecurityAuditRepository {
  initialize(): Promise<void>;
  append(entry: Omit<SecurityAuditEntry, 'id'>): Promise<SecurityAuditEntry>;
  getAll(): Promise<SecurityAuditEntry[]>;
  clear(): Promise<void>;
  subscribe(listener: () => void): () => void;
}

export interface ISettingsRepository {
  initialize(): Promise<void>;
  get(): Promise<AppSettings>;
  save(settings: AppSettings): Promise<void>;
  subscribe(listener: () => void): () => void;
}

export interface BackupArchive {
  schemaVersion: number;
  exportedAt: number;
  checksumSha256: string;
  settings: AppSettings;
  identity: DeviceIdentityProfile | null;
  linkedDevices: LinkedDevice[];
  syncEvents: SyncEvent[];
  auditEntries: SecurityAuditEntry[];
}

export interface IBackupProvider {
  exportBackup(): Promise<BackupArchive>;
  restoreBackup(archive: BackupArchive): Promise<void>;
}
