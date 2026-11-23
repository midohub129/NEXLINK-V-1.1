import { StorageError, ValidationError } from '../../domain/errors/appError';
import type {
  BackupArchive,
  CreateSyncEventInput,
  IBackupProvider,
  IDeviceRepository,
  ISecurityAuditRepository,
  ISettingsRepository,
  ISyncEventRepository,
} from '../../domain/interfaces/repositories';
import type { ICryptoProvider } from '../../domain/interfaces/services';
import type { DeviceIdentityProfile, LinkedDevice } from '../../domain/models/device';
import type {
  EncryptedEnvelope,
  SecurityAuditEntry,
} from '../../domain/models/security';
import { type AppSettings, DEFAULT_APP_SETTINGS } from '../../domain/models/settings';
import type { SyncEvent, SyncEventStatus } from '../../domain/models/syncEvent';
import {
  APP_DB_VERSION,
  IndexedDbDatabase,
  STORES,
  reqToPromise,
} from './indexedDbDatabase';

interface StoredSyncEventRecord {
  id?: number;
  type: string;
  payload: string;
  envelope?: EncryptedEnvelope;
  createdAt: number;
  status: SyncEventStatus;
  retryCount: number;
  nextRetryAt: number | null;
  idempotencyKey: string;
  notificationKey?: string;
  payloadHash?: string;
  encrypted: boolean;
  localEncrypted?: boolean;
  e2eeProtected?: boolean;
  e2eeVerified?: boolean;
  e2eeNonce?: string | null;
  relayEventId?: number | null;
  inboundAckConfirmed?: boolean;
  targetDeviceId?: string | null;
  sourceDeviceId?: string | null;
  relayAcceptedAt?: number | null;
  deliveredAt?: number | null;
  lastError?: string | null;
  syncedAt?: number | null;
}

interface StoredSettingsRecord {
  id: 'app_settings';
  settings: AppSettings;
}

interface StoredIdentityRecord {
  id: 'local_device';
  identity: DeviceIdentityProfile;
}

function canonicalArchivePayload(
  archive: Omit<BackupArchive, 'checksumSha256'>
): string {
  return JSON.stringify({
    schemaVersion: archive.schemaVersion,
    exportedAt: archive.exportedAt,
    settings: archive.settings,
    identity: archive.identity,
    linkedDevices: archive.linkedDevices,
    syncEvents: archive.syncEvents,
    auditEntries: archive.auditEntries,
  });
}

export class IndexedDbSyncEventRepository implements ISyncEventRepository {
  private readonly db: IndexedDbDatabase;
  private readonly crypto: ICryptoProvider;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase, crypto: ICryptoProvider) {
    this.db = db;
    this.crypto = crypto;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  private async toDomainEvent(record: StoredSyncEventRecord): Promise<SyncEvent> {
    let plaintext = record.payload;
    if (record.encrypted && record.envelope) {
      const decrypted = await this.crypto.decrypt(record.envelope);
      if (decrypted !== null) {
        plaintext = decrypted;
      }
    }

    return {
      id: record.id ?? 0,
      type: record.type,
      payload: plaintext,
      createdAt: record.createdAt,
      status: record.status,
      retryCount: record.retryCount,
      nextRetryAt: record.nextRetryAt,
      idempotencyKey: record.idempotencyKey,
      notificationKey: record.notificationKey,
      payloadHash: record.payloadHash,
      encrypted: record.encrypted,
      localEncrypted: record.localEncrypted ?? record.encrypted,
      e2eeProtected: record.e2eeProtected ?? false,
      e2eeVerified: record.e2eeVerified ?? false,
      e2eeNonce: record.e2eeNonce ?? null,
      relayEventId: record.relayEventId ?? null,
      inboundAckConfirmed: record.inboundAckConfirmed ?? false,
      targetDeviceId: record.targetDeviceId ?? null,
      sourceDeviceId: record.sourceDeviceId ?? null,
      relayAcceptedAt: record.relayAcceptedAt ?? null,
      deliveredAt: record.deliveredAt ?? null,
      lastError: record.lastError ?? null,
      syncedAt: record.syncedAt ?? null,
    };
  }

  async insert(input: CreateSyncEventInput): Promise<SyncEvent> {
    const envelope = this.crypto.isSupported()
      ? await this.crypto.encrypt(input.payload)
      : null;

    const record: StoredSyncEventRecord = {
      type: input.type,
      payload: envelope ? '[ENCRYPTED_AES_256_GCM]' : input.payload,
      envelope: envelope ?? undefined,
      createdAt: input.createdAt ?? Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: input.idempotencyKey,
      notificationKey: input.notificationKey,
      payloadHash: input.payloadHash,
      encrypted: Boolean(envelope),
      localEncrypted: Boolean(envelope),
      e2eeProtected: input.e2eeProtected ?? false,
      e2eeVerified: input.e2eeVerified ?? false,
      e2eeNonce: input.e2eeNonce ?? null,
      relayEventId: input.relayEventId ?? null,
      inboundAckConfirmed: input.inboundAckConfirmed ?? false,
      targetDeviceId: input.targetDeviceId ?? null,
      sourceDeviceId: input.sourceDeviceId ?? null,
      relayAcceptedAt: null,
      deliveredAt: null,
      lastError: null,
      syncedAt: null,
    };

    let generatedId: IDBValidKey;
    try {
      generatedId = await this.db.add(STORES.SYNC_EVENTS, record);
    } catch (err) {
      if (err instanceof Error && err.name === 'ConstraintError') {
        throw new StorageError(
          'DUPLICATE_IDEMPOTENCY_KEY',
          'حدث مكرر بمفتاح عدم التكرار نفسه.',
          `Duplicate idempotencyKey ${input.idempotencyKey}`,
          err
        );
      }
      throw err;
    }
    const savedRecord: StoredSyncEventRecord = {
      ...record,
      id: Number(generatedId),
    };
    this.notify();
    return {
      ...(await this.toDomainEvent(savedRecord)),
      payload: input.payload,
    };
  }

  async findById(id: number): Promise<SyncEvent | null> {
    const rec = await this.db.readOne<StoredSyncEventRecord>(STORES.SYNC_EVENTS, id);
    return rec ? this.toDomainEvent(rec) : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<SyncEvent | null> {
    const rec = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readonly',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        if (store.indexNames.contains('by_idempotencyKey')) {
          const found = (await reqToPromise(
            store.index('by_idempotencyKey').get(idempotencyKey)
          )) as StoredSyncEventRecord | undefined;
          return found ?? null;
        }
        const all = (await reqToPromise(store.getAll())) as StoredSyncEventRecord[];
        return all.find((r) => r.idempotencyKey === idempotencyKey) ?? null;
      }
    );
    return rec ? this.toDomainEvent(rec) : null;
  }

  async findRecentDuplicate(
    type: string,
    notificationKey: string,
    payloadHash: string,
    windowMs: number,
    nowMs: number
  ): Promise<SyncEvent | null> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    const cutoff = nowMs - windowMs;
    const match = records.find(
      (r) =>
        r.type === type &&
        r.notificationKey === notificationKey &&
        r.payloadHash === payloadHash &&
        r.createdAt >= cutoff
    );
    return match ? this.toDomainEvent(match) : null;
  }

  async getAll(): Promise<SyncEvent[]> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    records.sort((a, b) => b.createdAt - a.createdAt || (b.id ?? 0) - (a.id ?? 0));
    return Promise.all(records.map((r) => this.toDomainEvent(r)));
  }

  async getByStatus(status: SyncEventStatus): Promise<SyncEvent[]> {
    const all = await this.getAll();
    return all.filter((e) => e.status === status);
  }

  async getDuePendingEvents(nowMs: number): Promise<SyncEvent[]> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    const due = records
      .filter(
        (r) =>
          r.status === 'PENDING' && (r.nextRetryAt === null || r.nextRetryAt <= nowMs)
      )
      .sort((a, b) => a.createdAt - b.createdAt || (a.id ?? 0) - (b.id ?? 0));
    return Promise.all(due.map((r) => this.toDomainEvent(r)));
  }

  async updateEvent(
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
        | 'e2eeVerified'
        | 'inboundAckConfirmed'
      >
    >
  ): Promise<SyncEvent | null> {
    const updatedRecord = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readwrite',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        const existing = (await reqToPromise(store.get(id))) as
          StoredSyncEventRecord | undefined;
        if (!existing) return null;
        const merged: StoredSyncEventRecord = {
          ...existing,
          ...patch,
        };
        await reqToPromise(store.put(merged));
        return merged;
      }
    );

    if (!updatedRecord) return null;
    this.notify();
    return this.toDomainEvent(updatedRecord);
  }

  async resetInProgressToPending(): Promise<number> {
    const count = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readwrite',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        const all = (await reqToPromise(store.getAll())) as StoredSyncEventRecord[];
        let updated = 0;
        for (const rec of all) {
          if (rec.status === 'IN_PROGRESS') {
            await reqToPromise(
              store.put({
                ...rec,
                status: 'PENDING',
                nextRetryAt: Date.now(),
              })
            );
            updated += 1;
          }
        }
        return updated;
      }
    );
    if (count > 0) this.notify();
    return count;
  }

  async delete(id: number): Promise<boolean> {
    const existing = await this.db.readOne<StoredSyncEventRecord>(
      STORES.SYNC_EVENTS,
      id
    );
    if (!existing) return false;
    await this.db.deleteKey(STORES.SYNC_EVENTS, id);
    this.notify();
    return true;
  }

  async clearAll(): Promise<void> {
    await this.db.clearStore(STORES.SYNC_EVENTS);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbDeviceRepository implements IDeviceRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async getIdentity(): Promise<DeviceIdentityProfile | null> {
    const record = await this.db.readOne<StoredIdentityRecord>(
      STORES.IDENTITY,
      'local_device'
    );
    return record?.identity ?? null;
  }

  async saveIdentity(identity: DeviceIdentityProfile): Promise<void> {
    await this.db.put(STORES.IDENTITY, {
      id: 'local_device',
      identity,
    } satisfies StoredIdentityRecord);
    this.notify();
  }

  async getLinkedDevices(): Promise<LinkedDevice[]> {
    const devices = await this.db.readAll<LinkedDevice>(STORES.LINKED_DEVICES);
    return devices.sort((a, b) => (b.pairedAt ?? 0) - (a.pairedAt ?? 0));
  }

  async upsertLinkedDevice(device: LinkedDevice): Promise<void> {
    await this.db.put(STORES.LINKED_DEVICES, device);
    this.notify();
  }

  async removeLinkedDevice(publicId: string): Promise<void> {
    await this.db.deleteKey(STORES.LINKED_DEVICES, publicId);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbAuditRepository implements ISecurityAuditRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async append(entry: Omit<SecurityAuditEntry, 'id'>): Promise<SecurityAuditEntry> {
    const generatedId = await this.db.add(STORES.SECURITY_AUDIT, entry);
    const saved: SecurityAuditEntry = {
      ...entry,
      id: Number(generatedId),
    };
    this.notify();
    return saved;
  }

  async getAll(): Promise<SecurityAuditEntry[]> {
    const rows = await this.db.readAll<SecurityAuditEntry>(STORES.SECURITY_AUDIT);
    return rows.sort((a, b) => b.timestamp - a.timestamp || b.id - a.id).slice(0, 150);
  }

  async clear(): Promise<void> {
    await this.db.clearStore(STORES.SECURITY_AUDIT);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbSettingsRepository implements ISettingsRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async get(): Promise<AppSettings> {
    const record = await this.db.readOne<StoredSettingsRecord>(
      STORES.SETTINGS,
      'app_settings'
    );
    return record?.settings ?? { ...DEFAULT_APP_SETTINGS };
  }

  async save(settings: AppSettings): Promise<void> {
    await this.db.put(STORES.SETTINGS, {
      id: 'app_settings',
      settings,
    } satisfies StoredSettingsRecord);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbBackupProvider implements IBackupProvider {
  private readonly db: IndexedDbDatabase;
  private readonly crypto: ICryptoProvider;
  private readonly syncRepo: IndexedDbSyncEventRepository;
  private readonly deviceRepo: IndexedDbDeviceRepository;
  private readonly auditRepo: IndexedDbAuditRepository;
  private readonly settingsRepo: IndexedDbSettingsRepository;

  constructor(deps: {
    db: IndexedDbDatabase;
    crypto: ICryptoProvider;
    syncRepo: IndexedDbSyncEventRepository;
    deviceRepo: IndexedDbDeviceRepository;
    auditRepo: IndexedDbAuditRepository;
    settingsRepo: IndexedDbSettingsRepository;
  }) {
    this.db = deps.db;
    this.crypto = deps.crypto;
    this.syncRepo = deps.syncRepo;
    this.deviceRepo = deps.deviceRepo;
    this.auditRepo = deps.auditRepo;
    this.settingsRepo = deps.settingsRepo;
  }

  async exportBackup(): Promise<BackupArchive> {
    const [settings, identity, linkedDevices, syncEvents, auditEntries] =
      await Promise.all([
        this.settingsRepo.get(),
        this.deviceRepo.getIdentity(),
        this.deviceRepo.getLinkedDevices(),
        this.syncRepo.getAll(),
        this.auditRepo.getAll(),
      ]);

    const body: Omit<BackupArchive, 'checksumSha256'> = {
      schemaVersion: APP_DB_VERSION,
      exportedAt: Date.now(),
      settings,
      identity,
      linkedDevices,
      syncEvents,
      auditEntries,
    };

    const checksumSha256 = await this.crypto.sha256Hex(canonicalArchivePayload(body));

    return {
      ...body,
      checksumSha256,
    };
  }

  async restoreBackup(archive: BackupArchive): Promise<void> {
    if (
      !archive ||
      typeof archive.schemaVersion !== 'number' ||
      !Array.isArray(archive.syncEvents) ||
      !Array.isArray(archive.linkedDevices) ||
      !Array.isArray(archive.auditEntries) ||
      !archive.settings
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'بنية ملف النسخة الاحتياطية غير صالحة.',
        'BackupArchive missing required fields'
      );
    }

    const expectedChecksum = await this.crypto.sha256Hex(
      canonicalArchivePayload({
        schemaVersion: archive.schemaVersion,
        exportedAt: archive.exportedAt,
        settings: archive.settings,
        identity: archive.identity,
        linkedDevices: archive.linkedDevices,
        syncEvents: archive.syncEvents,
        auditEntries: archive.auditEntries,
      })
    );

    if (expectedChecksum !== archive.checksumSha256) {
      throw new StorageError(
        'BACKUP_CHECKSUM_MISMATCH',
        'فشل التحقق من بصمة SHA-256 للنسخة الاحتياطية؛ قد يكون الملف تالفاً أو معدّلاً.',
        'Backup SHA-256 checksum mismatch'
      );
    }

    const preparedEvents: StoredSyncEventRecord[] = [];
    for (const evt of archive.syncEvents) {
      const envelope = this.crypto.isSupported()
        ? await this.crypto.encrypt(evt.payload)
        : null;
      preparedEvents.push({
        id: evt.id,
        type: evt.type,
        payload: envelope ? '[ENCRYPTED_AES_256_GCM]' : evt.payload,
        envelope: envelope ?? undefined,
        createdAt: evt.createdAt,
        status: evt.status,
        retryCount: evt.retryCount,
        nextRetryAt: evt.nextRetryAt,
        idempotencyKey: evt.idempotencyKey,
        notificationKey: evt.notificationKey,
        payloadHash: evt.payloadHash,
        encrypted: Boolean(envelope),
        localEncrypted: Boolean(envelope),
        e2eeProtected: evt.e2eeProtected ?? false,
        e2eeVerified: evt.e2eeVerified ?? false,
        e2eeNonce: evt.e2eeNonce ?? null,
        relayEventId: evt.relayEventId ?? null,
        inboundAckConfirmed: evt.inboundAckConfirmed ?? false,
        targetDeviceId: evt.targetDeviceId ?? null,
        sourceDeviceId: evt.sourceDeviceId ?? null,
        relayAcceptedAt: evt.relayAcceptedAt ?? null,
        deliveredAt: evt.deliveredAt ?? null,
        lastError: evt.lastError ?? null,
        syncedAt: evt.syncedAt ?? null,
      });
    }

    await this.db.runTransaction(
      [
        STORES.SETTINGS,
        STORES.IDENTITY,
        STORES.LINKED_DEVICES,
        STORES.SYNC_EVENTS,
        STORES.SECURITY_AUDIT,
      ],
      'readwrite',
      async (tx) => {
        const settingsStore = tx.objectStore(STORES.SETTINGS);
        const identityStore = tx.objectStore(STORES.IDENTITY);
        const devicesStore = tx.objectStore(STORES.LINKED_DEVICES);
        const syncStore = tx.objectStore(STORES.SYNC_EVENTS);
        const auditStore = tx.objectStore(STORES.SECURITY_AUDIT);

        await reqToPromise(settingsStore.clear());
        await reqToPromise(identityStore.clear());
        await reqToPromise(devicesStore.clear());
        await reqToPromise(syncStore.clear());
        await reqToPromise(auditStore.clear());

        await reqToPromise(
          settingsStore.put({
            id: 'app_settings',
            settings: archive.settings,
          } satisfies StoredSettingsRecord)
        );
        if (archive.identity) {
          await reqToPromise(
            identityStore.put({
              id: 'local_device',
              identity: archive.identity,
            } satisfies StoredIdentityRecord)
          );
        }
        for (const device of archive.linkedDevices) {
          await reqToPromise(devicesStore.put(device));
        }
        for (const evt of preparedEvents) {
          await reqToPromise(syncStore.put(evt));
        }
        for (const entry of archive.auditEntries) {
          await reqToPromise(auditStore.put(entry));
        }
      }
    );
  }
}

/* -------------------------------------------------------------------------- */
/* In-Memory Repositories for Deterministic Node Unit & Integration Tests     */
/* -------------------------------------------------------------------------- */

export class InMemorySyncEventRepository implements ISyncEventRepository {
  private events: SyncEvent[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async insert(input: CreateSyncEventInput): Promise<SyncEvent> {
    if (this.events.some((e) => e.idempotencyKey === input.idempotencyKey)) {
      throw new StorageError(
        'DUPLICATE_IDEMPOTENCY_KEY',
        'حدث مكرر بمفتاح عدم التكرار نفسه.',
        `Duplicate idempotencyKey ${input.idempotencyKey}`
      );
    }

    const created: SyncEvent = {
      id: this.nextId++,
      type: input.type,
      payload: input.payload,
      createdAt: input.createdAt ?? Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: input.idempotencyKey,
      notificationKey: input.notificationKey,
      payloadHash: input.payloadHash,
      encrypted: false,
      localEncrypted: false,
      e2eeProtected: input.e2eeProtected ?? false,
      e2eeVerified: input.e2eeVerified ?? false,
      e2eeNonce: input.e2eeNonce ?? null,
      relayEventId: input.relayEventId ?? null,
      inboundAckConfirmed: input.inboundAckConfirmed ?? false,
      targetDeviceId: input.targetDeviceId ?? null,
      sourceDeviceId: input.sourceDeviceId ?? null,
      relayAcceptedAt: null,
      deliveredAt: null,
      lastError: null,
      syncedAt: null,
    };
    this.events.push(created);
    this.listeners.forEach((l) => l());
    return { ...created };
  }

  async findById(id: number): Promise<SyncEvent | null> {
    const found = this.events.find((e) => e.id === id);
    return found ? { ...found } : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<SyncEvent | null> {
    const found = this.events.find((e) => e.idempotencyKey === idempotencyKey);
    return found ? { ...found } : null;
  }

  async findRecentDuplicate(
    type: string,
    notificationKey: string,
    payloadHash: string,
    windowMs: number,
    nowMs: number
  ): Promise<SyncEvent | null> {
    const cutoff = nowMs - windowMs;
    const found = this.events.find(
      (e) =>
        e.type === type &&
        e.notificationKey === notificationKey &&
        e.payloadHash === payloadHash &&
        e.createdAt >= cutoff
    );
    return found ? { ...found } : null;
  }

  async getAll(): Promise<SyncEvent[]> {
    return [...this.events]
      .sort((a, b) => b.createdAt - a.createdAt || b.id - a.id)
      .map((e) => ({ ...e }));
  }

  async getByStatus(status: SyncEventStatus): Promise<SyncEvent[]> {
    return (await this.getAll()).filter((e) => e.status === status);
  }

  async getDuePendingEvents(nowMs: number): Promise<SyncEvent[]> {
    return this.events
      .filter(
        (e) =>
          e.status === 'PENDING' && (e.nextRetryAt === null || e.nextRetryAt <= nowMs)
      )
      .sort((a, b) => a.createdAt - b.createdAt || a.id - b.id)
      .map((e) => ({ ...e }));
  }

  async updateEvent(
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
        | 'e2eeVerified'
        | 'inboundAckConfirmed'
      >
    >
  ): Promise<SyncEvent | null> {
    const idx = this.events.findIndex((e) => e.id === id);
    if (idx === -1) return null;
    this.events[idx] = { ...this.events[idx], ...patch };
    this.listeners.forEach((l) => l());
    return { ...this.events[idx] };
  }

  async resetInProgressToPending(): Promise<number> {
    let count = 0;
    this.events = this.events.map((e) => {
      if (e.status === 'IN_PROGRESS') {
        count += 1;
        return { ...e, status: 'PENDING', nextRetryAt: Date.now() };
      }
      return e;
    });
    if (count > 0) this.listeners.forEach((l) => l());
    return count;
  }

  async delete(id: number): Promise<boolean> {
    const before = this.events.length;
    this.events = this.events.filter((e) => e.id !== id);
    if (this.events.length !== before) {
      this.listeners.forEach((l) => l());
      return true;
    }
    return false;
  }

  async clearAll(): Promise<void> {
    this.events = [];
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemoryDeviceRepository implements IDeviceRepository {
  private identity: DeviceIdentityProfile | null = null;
  private linked = new Map<string, LinkedDevice>();
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async getIdentity(): Promise<DeviceIdentityProfile | null> {
    return this.identity ? { ...this.identity } : null;
  }

  async saveIdentity(identity: DeviceIdentityProfile): Promise<void> {
    this.identity = { ...identity };
    this.listeners.forEach((l) => l());
  }

  async getLinkedDevices(): Promise<LinkedDevice[]> {
    return Array.from(this.linked.values()).map((d) => ({ ...d }));
  }

  async upsertLinkedDevice(device: LinkedDevice): Promise<void> {
    this.linked.set(device.publicId, { ...device });
    this.listeners.forEach((l) => l());
  }

  async removeLinkedDevice(publicId: string): Promise<void> {
    this.linked.delete(publicId);
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemoryAuditRepository implements ISecurityAuditRepository {
  private entries: SecurityAuditEntry[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async append(entry: Omit<SecurityAuditEntry, 'id'>): Promise<SecurityAuditEntry> {
    const created: SecurityAuditEntry = { ...entry, id: this.nextId++ };
    this.entries = [created, ...this.entries];
    this.listeners.forEach((l) => l());
    return created;
  }

  async getAll(): Promise<SecurityAuditEntry[]> {
    return [...this.entries];
  }

  async clear(): Promise<void> {
    this.entries = [];
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemorySettingsRepository implements ISettingsRepository {
  private current: AppSettings = { ...DEFAULT_APP_SETTINGS };
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async get(): Promise<AppSettings> {
    return {
      ...this.current,
      selectedNotificationApps: [...this.current.selectedNotificationApps],
    };
  }

  async save(settings: AppSettings): Promise<void> {
    this.current = {
      ...settings,
      selectedNotificationApps: [...settings.selectedNotificationApps],
    };
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
