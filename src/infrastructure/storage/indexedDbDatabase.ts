import { StorageError } from '../../domain/errors/appError';

export const APP_DB_NAME = 'nexlink_app_db';
export const APP_DB_VERSION = 3;

export const STORES = {
  MIGRATIONS: 'schema_migrations',
  SETTINGS: 'settings',
  IDENTITY: 'device_identity',
  LINKED_DEVICES: 'linked_devices',
  SYNC_EVENTS: 'sync_events',
  SECURITY_AUDIT: 'security_audit',
} as const;

export type AppStoreName = (typeof STORES)[keyof typeof STORES];

export interface SchemaMigrationRecord {
  version: number;
  name: string;
  appliedAt: number;
}

const MIGRATION_DEFINITIONS: Array<{
  version: number;
  name: string;
  apply: (db: IDBDatabase, tx: IDBTransaction) => void;
}> = [
  {
    version: 1,
    name: 'v1_core_stores',
    apply: (db) => {
      if (!db.objectStoreNames.contains(STORES.MIGRATIONS)) {
        db.createObjectStore(STORES.MIGRATIONS, { keyPath: 'version' });
      }
      if (!db.objectStoreNames.contains(STORES.SETTINGS)) {
        db.createObjectStore(STORES.SETTINGS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORES.SYNC_EVENTS)) {
        const syncStore = db.createObjectStore(STORES.SYNC_EVENTS, {
          keyPath: 'id',
          autoIncrement: true,
        });
        syncStore.createIndex('by_status', 'status', { unique: false });
        syncStore.createIndex('by_createdAt', 'createdAt', { unique: false });
      }
    },
  },
  {
    version: 2,
    name: 'v2_device_identity_and_audit',
    apply: (db) => {
      if (!db.objectStoreNames.contains(STORES.IDENTITY)) {
        db.createObjectStore(STORES.IDENTITY, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORES.LINKED_DEVICES)) {
        db.createObjectStore(STORES.LINKED_DEVICES, { keyPath: 'publicId' });
      }
      if (!db.objectStoreNames.contains(STORES.SECURITY_AUDIT)) {
        const auditStore = db.createObjectStore(STORES.SECURITY_AUDIT, {
          keyPath: 'id',
          autoIncrement: true,
        });
        auditStore.createIndex('by_timestamp', 'timestamp', { unique: false });
      }
    },
  },
  {
    version: 3,
    name: 'v3_sync_idempotency_and_dedup_indexes',
    apply: (_db, tx) => {
      const syncStore = tx.objectStore(STORES.SYNC_EVENTS);
      if (!syncStore.indexNames.contains('by_idempotencyKey')) {
        syncStore.createIndex('by_idempotencyKey', 'idempotencyKey', {
          unique: true,
        });
      }
      if (!syncStore.indexNames.contains('by_notificationKey')) {
        syncStore.createIndex('by_notificationKey', 'notificationKey', {
          unique: false,
        });
      }
    },
  },
];

function reqToPromise<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
  });
}

/**
 * Reliable browser storage engine using IndexedDB with:
 * - Versioned migrations (tracked in `schema_migrations`)
 * - Serialized write queue to guarantee safe concurrent mutations
 * - Atomic multi-store transactions
 */
export class IndexedDbDatabase {
  private readonly dbName: string;
  private db: IDBDatabase | null = null;
  private initPromise: Promise<IDBDatabase> | null = null;
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(dbName = APP_DB_NAME) {
    this.dbName = dbName;
  }

  async initialize(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      if (typeof indexedDB === 'undefined') {
        throw new StorageError(
          'INDEXEDDB_UNAVAILABLE',
          'قاعدة البيانات المحلية غير متاحة في هذه البيئة.',
          'global indexedDB is undefined'
        );
      }

      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(this.dbName, APP_DB_VERSION);

        request.onupgradeneeded = (event) => {
          const upgradedDb = request.result;
          const tx = request.transaction;
          if (!tx) return;
          const oldVersion = event.oldVersion;

          for (const migration of MIGRATION_DEFINITIONS) {
            if (migration.version > oldVersion) {
              migration.apply(upgradedDb, tx);
              const migStore = tx.objectStore(STORES.MIGRATIONS);
              migStore.put({
                version: migration.version,
                name: migration.name,
                appliedAt: Date.now(),
              } satisfies SchemaMigrationRecord);
            }
          }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
          reject(
            new StorageError(
              'INDEXEDDB_OPEN_FAILED',
              'تعذّر فتح قاعدة البيانات المحلية.',
              request.error?.message ?? 'Failed to open IndexedDB',
              request.error
            )
          );
      });

      this.db = db;
      this.cleanupLegacyLocalStorage();
      return db;
    })();

    return this.initPromise;
  }

  /**
   * Removes deprecated legacy keys/secrets from localStorage if left over from v1.0.
   */
  private cleanupLegacyLocalStorage(): void {
    if (typeof window === 'undefined' || !window.localStorage) return;
    try {
      const legacyKeys = [
        'nexlink_device_id',
        'nexlink_device_role',
        'nexlink_selected_apps',
        'nexlink_service_running',
        'nexlink_notification_access',
        'nexlink_usage_access',
        'nexlink_sync_events',
        'nexlink_security_audit_log',
        'nexlink_session_meta',
        'nexlink_crypto_fallback_warning',
      ];
      for (const key of legacyKeys) {
        window.localStorage.removeItem(key);
      }
    } catch {
      // Ignore storage access errors in restricted frames
    }
  }

  async getMigrations(): Promise<SchemaMigrationRecord[]> {
    const db = await this.initialize();
    const tx = db.transaction(STORES.MIGRATIONS, 'readonly');
    const records = (await reqToPromise(
      tx.objectStore(STORES.MIGRATIONS).getAll()
    )) as SchemaMigrationRecord[];
    await txDone(tx);
    return records.sort((a, b) => a.version - b.version);
  }

  async readAll<T>(storeName: AppStoreName): Promise<T[]> {
    const db = await this.initialize();
    const tx = db.transaction(storeName, 'readonly');
    const result = (await reqToPromise(tx.objectStore(storeName).getAll())) as T[];
    await txDone(tx);
    return result;
  }

  async readOne<T>(storeName: AppStoreName, key: IDBValidKey): Promise<T | null> {
    const db = await this.initialize();
    const tx = db.transaction(storeName, 'readonly');
    const result = (await reqToPromise(tx.objectStore(storeName).get(key))) as
      T | undefined;
    await txDone(tx);
    return result ?? null;
  }

  enqueueWrite<T>(operation: (db: IDBDatabase) => Promise<T>): Promise<T> {
    const next = this.writeQueue.then(async () => {
      const db = await this.initialize();
      return operation(db);
    });
    this.writeQueue = next.catch(() => undefined);
    return next;
  }

  async put<T>(storeName: AppStoreName, value: T): Promise<IDBValidKey> {
    return this.enqueueWrite(async (db) => {
      const tx = db.transaction(storeName, 'readwrite');
      const key = await reqToPromise(tx.objectStore(storeName).put(value));
      await txDone(tx);
      return key;
    });
  }

  async add<T>(storeName: AppStoreName, value: T): Promise<IDBValidKey> {
    return this.enqueueWrite(async (db) => {
      const tx = db.transaction(storeName, 'readwrite');
      const key = await reqToPromise(tx.objectStore(storeName).add(value));
      await txDone(tx);
      return key;
    });
  }

  async deleteKey(storeName: AppStoreName, key: IDBValidKey): Promise<void> {
    return this.enqueueWrite(async (db) => {
      const tx = db.transaction(storeName, 'readwrite');
      await reqToPromise(tx.objectStore(storeName).delete(key));
      await txDone(tx);
    });
  }

  async clearStore(storeName: AppStoreName): Promise<void> {
    return this.enqueueWrite(async (db) => {
      const tx = db.transaction(storeName, 'readwrite');
      await reqToPromise(tx.objectStore(storeName).clear());
      await txDone(tx);
    });
  }

  async runTransaction<T>(
    stores: AppStoreName[],
    mode: IDBTransactionMode,
    work: (tx: IDBTransaction) => Promise<T>
  ): Promise<T> {
    if (mode === 'readwrite') {
      return this.enqueueWrite(async (db) => {
        const tx = db.transaction(stores, mode);
        const result = await work(tx);
        await txDone(tx);
        return result;
      });
    }
    const db = await this.initialize();
    const tx = db.transaction(stores, mode);
    const result = await work(tx);
    await txDone(tx);
    return result;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initPromise = null;
    }
  }
}

export { reqToPromise, txDone };
