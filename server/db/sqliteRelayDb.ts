import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export interface SqliteMigration {
  version: number;
  name: string;
  up: (db: DatabaseSync) => void;
}

export const RELAY_MIGRATIONS: SqliteMigration[] = [
  {
    version: 1,
    name: 'create_devices_table',
    up: (db) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS devices (
          public_id TEXT PRIMARY KEY,
          crypto_key_id TEXT NOT NULL,
          public_key_jwk TEXT,
          role TEXT NOT NULL CHECK(role IN ('admin', 'basic')),
          label TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL
        );
      `);
    },
  },
  {
    version: 2,
    name: 'create_pairing_and_links_tables',
    up: (db) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS pairing_requests (
          pairing_code TEXT PRIMARY KEY,
          requester_device_id TEXT NOT NULL,
          requester_crypto_key_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACCEPTED', 'EXPIRED')),
          FOREIGN KEY (requester_device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS device_links (
          device_a TEXT NOT NULL,
          device_b TEXT NOT NULL,
          pairing_state TEXT NOT NULL CHECK(pairing_state IN ('PAIRED', 'REVOKED')),
          paired_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          PRIMARY KEY (device_a, device_b),
          FOREIGN KEY (device_a) REFERENCES devices(public_id) ON DELETE CASCADE,
          FOREIGN KEY (device_b) REFERENCES devices(public_id) ON DELETE CASCADE
        );
      `);
    },
  },
  {
    version: 3,
    name: 'create_relay_events_with_idempotency',
    up: (db) => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS relay_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source_device_id TEXT NOT NULL,
          target_device_id TEXT,
          client_event_id INTEGER NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE,
          type TEXT NOT NULL,
          payload TEXT NOT NULL,
          notification_key TEXT,
          payload_hash TEXT,
          created_at INTEGER NOT NULL,
          received_at INTEGER NOT NULL,
          FOREIGN KEY (source_device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_relay_events_target ON relay_events(target_device_id, received_at DESC);
      `);
    },
  },
];

export interface SqliteBackupPayload {
  schemaVersion: number;
  exportedAt: number;
  devices: Record<string, unknown>[];
  deviceLinks: Record<string, unknown>[];
  relayEvents: Record<string, unknown>[];
}

export class SqliteRelayDatabase {
  readonly db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath !== ':memory:') {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    if (dbPath !== ':memory:') {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
    this.runMigrations();
  }

  runMigrations(migrations: SqliteMigration[] = RELAY_MIGRATIONS): number[] {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at INTEGER NOT NULL
      );
    `);

    const appliedRows = this.db
      .prepare('SELECT version FROM schema_migrations')
      .all() as { version: number }[];
    const appliedSet = new Set(appliedRows.map((r) => r.version));
    const newlyApplied: number[] = [];

    for (const migration of [...migrations].sort((a, b) => a.version - b.version)) {
      if (appliedSet.has(migration.version)) continue;

      this.withTransaction(() => {
        migration.up(this.db);
        this.db
          .prepare(
            'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)'
          )
          .run(migration.version, migration.name, Date.now());
      });
      newlyApplied.push(migration.version);
    }

    return newlyApplied;
  }

  getSchemaVersion(): number {
    const row = this.db
      .prepare('SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations')
      .get() as { version: number };
    return row.version;
  }

  withTransaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const result = fn();
      this.db.exec('COMMIT;');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK;');
      throw err;
    }
  }

  upsertDevice(input: {
    publicId: string;
    cryptoKeyId: string;
    publicKeyJwk: string | null;
    role: 'admin' | 'basic';
    label: string;
  }): void {
    const now = Date.now();
    this.withTransaction(() => {
      this.db
        .prepare(
          `INSERT INTO devices (public_id, crypto_key_id, public_key_jwk, role, label, created_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(public_id) DO UPDATE SET
             crypto_key_id = excluded.crypto_key_id,
             public_key_jwk = COALESCE(excluded.public_key_jwk, devices.public_key_jwk),
             role = excluded.role,
             label = excluded.label,
             last_seen_at = excluded.last_seen_at`
        )
        .run(
          input.publicId,
          input.cryptoKeyId,
          input.publicKeyJwk,
          input.role,
          input.label,
          now,
          now
        );
    });
  }

  createPairingRequest(input: {
    pairingCode: string;
    requesterDeviceId: string;
    requesterCryptoKeyId: string;
    expiresAt: number;
  }): void {
    this.withTransaction(() => {
      this.db
        .prepare(
          `INSERT INTO pairing_requests (pairing_code, requester_device_id, requester_crypto_key_id, expires_at, status)
           VALUES (?, ?, ?, ?, 'PENDING')
           ON CONFLICT(pairing_code) DO UPDATE SET
             requester_device_id = excluded.requester_device_id,
             requester_crypto_key_id = excluded.requester_crypto_key_id,
             expires_at = excluded.expires_at,
             status = 'PENDING'`
        )
        .run(
          input.pairingCode,
          input.requesterDeviceId,
          input.requesterCryptoKeyId,
          input.expiresAt
        );
    });
  }

  acceptPairingRequest(
    pairingCode: string,
    responderId: string
  ): {
    requesterDeviceId: string;
    requesterCryptoKeyId: string;
    requesterRole: 'admin' | 'basic';
    requesterLabel: string;
    pairedAt: number;
  } | null {
    const now = Date.now();
    return this.withTransaction(() => {
      const req = this.db
        .prepare(
          `SELECT pr.pairing_code, pr.requester_device_id, pr.requester_crypto_key_id, pr.expires_at, pr.status,
                  d.role AS requester_role, d.label AS requester_label
           FROM pairing_requests pr
           JOIN devices d ON d.public_id = pr.requester_device_id
           WHERE pr.pairing_code = ?`
        )
        .get(pairingCode) as
        | {
            pairing_code: string;
            requester_device_id: string;
            requester_crypto_key_id: string;
            expires_at: number;
            status: string;
            requester_role: 'admin' | 'basic';
            requester_label: string;
          }
        | undefined;

      if (!req || req.status !== 'PENDING' || req.expires_at < now) {
        return null;
      }
      if (req.requester_device_id === responderId) {
        return null;
      }

      const [a, b] = [req.requester_device_id, responderId].sort();
      this.db
        .prepare(
          `UPDATE pairing_requests SET status = 'ACCEPTED' WHERE pairing_code = ?`
        )
        .run(pairingCode);

      this.db
        .prepare(
          `INSERT INTO device_links (device_a, device_b, pairing_state, paired_at, updated_at)
           VALUES (?, ?, 'PAIRED', ?, ?)
           ON CONFLICT(device_a, device_b) DO UPDATE SET
             pairing_state = 'PAIRED',
             updated_at = excluded.updated_at`
        )
        .run(a, b, now, now);

      return {
        requesterDeviceId: req.requester_device_id,
        requesterCryptoKeyId: req.requester_crypto_key_id,
        requesterRole: req.requester_role,
        requesterLabel: req.requester_label,
        pairedAt: now,
      };
    });
  }

  getLinkedDevices(deviceId: string): Array<{
    publicId: string;
    cryptoKeyId: string;
    label: string;
    role: 'admin' | 'basic';
    pairingState: 'PAIRED' | 'REVOKED';
    pairedAt: number;
    lastSeenAt: number;
  }> {
    const rows = this.db
      .prepare(
        `SELECT d.public_id, d.crypto_key_id, d.label, d.role, dl.pairing_state, dl.paired_at, d.last_seen_at
         FROM device_links dl
         JOIN devices d ON d.public_id = CASE WHEN dl.device_a = ? THEN dl.device_b ELSE dl.device_a END
         WHERE dl.device_a = ? OR dl.device_b = ?
         ORDER BY dl.updated_at DESC`
      )
      .all(deviceId, deviceId, deviceId) as Array<{
      public_id: string;
      crypto_key_id: string;
      label: string;
      role: 'admin' | 'basic';
      pairing_state: 'PAIRED' | 'REVOKED';
      paired_at: number;
      last_seen_at: number;
    }>;

    return rows.map((r) => ({
      publicId: r.public_id,
      cryptoKeyId: r.crypto_key_id,
      label: r.label,
      role: r.role,
      pairingState: r.pairing_state,
      pairedAt: r.paired_at,
      lastSeenAt: r.last_seen_at,
    }));
  }

  revokeDeviceLink(deviceId: string, targetDeviceId: string): void {
    const [a, b] = [deviceId, targetDeviceId].sort();
    this.withTransaction(() => {
      this.db
        .prepare(
          `UPDATE device_links SET pairing_state = 'REVOKED', updated_at = ? WHERE device_a = ? AND device_b = ?`
        )
        .run(Date.now(), a, b);
    });
  }

  ingestSyncBatch(
    sourceDeviceId: string,
    targetDeviceId: string | null,
    events: Array<{
      id: number;
      idempotencyKey: string;
      type: string;
      payload: string;
      notificationKey?: string;
      payloadHash?: string;
      createdAt: number;
    }>
  ): {
    acceptedIds: number[];
    duplicateIds: number[];
    insertedRows: Array<{
      sourceDeviceId: string;
      targetDeviceId: string | null;
      clientEventId: number;
      idempotencyKey: string;
      type: string;
      payload: string;
      notificationKey: string | null;
      payloadHash: string | null;
      createdAt: number;
    }>;
  } {
    const now = Date.now();
    return this.withTransaction(() => {
      const acceptedIds: number[] = [];
      const duplicateIds: number[] = [];
      const insertedRows: Array<{
        sourceDeviceId: string;
        targetDeviceId: string | null;
        clientEventId: number;
        idempotencyKey: string;
        type: string;
        payload: string;
        notificationKey: string | null;
        payloadHash: string | null;
        createdAt: number;
      }> = [];

      const findStmt = this.db.prepare(
        'SELECT id FROM relay_events WHERE idempotency_key = ?'
      );
      const insertStmt = this.db.prepare(
        `INSERT INTO relay_events
          (source_device_id, target_device_id, client_event_id, idempotency_key, type, payload, notification_key, payload_hash, created_at, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      for (const evt of events) {
        const existing = findStmt.get(evt.idempotencyKey) as { id: number } | undefined;
        if (existing) {
          duplicateIds.push(evt.id);
          continue;
        }
        insertStmt.run(
          sourceDeviceId,
          targetDeviceId,
          evt.id,
          evt.idempotencyKey,
          evt.type,
          evt.payload,
          evt.notificationKey ?? null,
          evt.payloadHash ?? null,
          evt.createdAt,
          now
        );
        acceptedIds.push(evt.id);
        insertedRows.push({
          sourceDeviceId,
          targetDeviceId,
          clientEventId: evt.id,
          idempotencyKey: evt.idempotencyKey,
          type: evt.type,
          payload: evt.payload,
          notificationKey: evt.notificationKey ?? null,
          payloadHash: evt.payloadHash ?? null,
          createdAt: evt.createdAt,
        });
      }

      return { acceptedIds, duplicateIds, insertedRows };
    });
  }

  getInboundEvents(targetDeviceId: string): Array<{
    id: number;
    type: string;
    payload: string;
    createdAt: number;
    idempotencyKey: string;
    notificationKey: string | null;
    payloadHash: string | null;
  }> {
    const rows = this.db
      .prepare(
        `SELECT id, type, payload, created_at, idempotency_key, notification_key, payload_hash
         FROM relay_events
         WHERE target_device_id = ?
         ORDER BY created_at DESC
         LIMIT 100`
      )
      .all(targetDeviceId) as Array<{
      id: number;
      type: string;
      payload: string;
      created_at: number;
      idempotency_key: string;
      notification_key: string | null;
      payload_hash: string | null;
    }>;

    return rows.map((r) => ({
      id: r.id,
      type: r.type,
      payload: r.payload,
      createdAt: r.created_at,
      idempotencyKey: r.idempotency_key,
      notificationKey: r.notification_key,
      payloadHash: r.payload_hash,
    }));
  }

  exportBackup(): SqliteBackupPayload {
    return {
      schemaVersion: this.getSchemaVersion(),
      exportedAt: Date.now(),
      devices: this.db.prepare('SELECT * FROM devices').all() as Record<
        string,
        unknown
      >[],
      deviceLinks: this.db.prepare('SELECT * FROM device_links').all() as Record<
        string,
        unknown
      >[],
      relayEvents: this.db.prepare('SELECT * FROM relay_events').all() as Record<
        string,
        unknown
      >[],
    };
  }

  close(): void {
    this.db.close();
  }
}
