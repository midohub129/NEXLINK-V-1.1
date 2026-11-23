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
  {
    version: 4,
    name: 'add_auth_sessions_nonces_tickets_and_mutual_pairing',
    up: (db) => {
      db.exec(`
        ALTER TABLE devices ADD COLUMN ecdh_public_key_jwk TEXT;
        ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED'));

        DROP TABLE IF EXISTS pairing_requests;
        CREATE TABLE pairing_requests (
          pairing_id TEXT PRIMARY KEY,
          pairing_code TEXT NOT NULL,
          requester_device_id TEXT NOT NULL,
          requester_crypto_key_id TEXT NOT NULL,
          requester_ecdh_jwk TEXT,
          responder_device_id TEXT,
          responder_crypto_key_id TEXT,
          responder_ecdsa_jwk TEXT,
          responder_ecdh_jwk TEXT,
          responder_label TEXT,
          failed_attempts INTEGER NOT NULL DEFAULT 0,
          expires_at INTEGER NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PENDING', 'AWAITING_REQUESTER_CONFIRMATION', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'LOCKED')),
          FOREIGN KEY (requester_device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );
        CREATE INDEX idx_pairing_code ON pairing_requests(pairing_code);

        CREATE TABLE IF NOT EXISTS auth_challenges (
          challenge TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          FOREIGN KEY (device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS device_sessions (
          session_id TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          crypto_key_id TEXT NOT NULL,
          token_hash TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked_at INTEGER,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS used_nonces (
          nonce_key TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ws_tickets (
          ticket TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          FOREIGN KEY (device_id) REFERENCES devices(public_id) ON DELETE CASCADE
        );
      `);
    },
  },
  {
    version: 5,
    name: 'add_e2ee_metadata_and_delivery_acks',
    up: (db) => {
      db.exec(`
        ALTER TABLE relay_events ADD COLUMN sender_crypto_key_id TEXT;
        ALTER TABLE relay_events ADD COLUMN recipient_crypto_key_id TEXT;
        ALTER TABLE relay_events ADD COLUMN message_nonce TEXT;
        ALTER TABLE relay_events ADD COLUMN delivered_at INTEGER;
        CREATE INDEX IF NOT EXISTS idx_relay_events_source_client ON relay_events(source_device_id, client_event_id);
      `);
    },
  },
];

export interface RegisteredDeviceRecord {
  publicId: string;
  cryptoKeyId: string;
  publicKeyJwk: string | null;
  ecdhPublicKeyJwk: string | null;
  role: 'admin' | 'basic';
  label: string;
  status: 'ACTIVE' | 'REVOKED';
  createdAt: number;
  lastSeenAt: number;
}

export interface PairingRequestRecord {
  pairingId: string;
  pairingCode: string;
  requesterDeviceId: string;
  requesterCryptoKeyId: string;
  responderDeviceId: string | null;
  responderCryptoKeyId: string | null;
  responderLabel: string | null;
  failedAttempts: number;
  expiresAt: number;
  status:
    | 'PENDING'
    | 'AWAITING_REQUESTER_CONFIRMATION'
    | 'ACCEPTED'
    | 'REJECTED'
    | 'EXPIRED'
    | 'LOCKED';
}

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

  getDevice(publicId: string): RegisteredDeviceRecord | null {
    const row = this.db
      .prepare(
        `SELECT public_id, crypto_key_id, public_key_jwk, ecdh_public_key_jwk, role, label, status, created_at, last_seen_at
         FROM devices WHERE public_id = ?`
      )
      .get(publicId) as
      | {
          public_id: string;
          crypto_key_id: string;
          public_key_jwk: string | null;
          ecdh_public_key_jwk: string | null;
          role: 'admin' | 'basic';
          label: string;
          status: 'ACTIVE' | 'REVOKED';
          created_at: number;
          last_seen_at: number;
        }
      | undefined;

    if (!row) return null;
    return {
      publicId: row.public_id,
      cryptoKeyId: row.crypto_key_id,
      publicKeyJwk: row.public_key_jwk,
      ecdhPublicKeyJwk: row.ecdh_public_key_jwk,
      role: row.role,
      label: row.label,
      status: row.status,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
    };
  }

  registerDevice(input: {
    publicId: string;
    cryptoKeyId: string;
    publicKeyJwk: string;
    ecdhPublicKeyJwk: string | null;
    role: 'admin' | 'basic';
    label: string;
  }): { ok: true } | { ok: false; reason: 'IDENTITY_CONFLICT' | 'DEVICE_REVOKED' } {
    const now = Date.now();
    return this.withTransaction(() => {
      const existing = this.db
        .prepare('SELECT crypto_key_id, status FROM devices WHERE public_id = ?')
        .get(input.publicId) as
        { crypto_key_id: string; status: 'ACTIVE' | 'REVOKED' } | undefined;

      if (existing) {
        if (existing.crypto_key_id !== input.cryptoKeyId) {
          return { ok: false, reason: 'IDENTITY_CONFLICT' } as const;
        }
        if (existing.status === 'REVOKED') {
          return { ok: false, reason: 'DEVICE_REVOKED' } as const;
        }
        this.db
          .prepare(
            `UPDATE devices
             SET public_key_jwk = ?,
                 ecdh_public_key_jwk = COALESCE(?, ecdh_public_key_jwk),
                 role = ?,
                 label = ?,
                 last_seen_at = ?
             WHERE public_id = ?`
          )
          .run(
            input.publicKeyJwk,
            input.ecdhPublicKeyJwk,
            input.role,
            input.label,
            now,
            input.publicId
          );
        return { ok: true } as const;
      }

      this.db
        .prepare(
          `INSERT INTO devices
            (public_id, crypto_key_id, public_key_jwk, ecdh_public_key_jwk, role, label, status, created_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`
        )
        .run(
          input.publicId,
          input.cryptoKeyId,
          input.publicKeyJwk,
          input.ecdhPublicKeyJwk,
          input.role,
          input.label,
          now,
          now
        );
      return { ok: true } as const;
    });
  }

  /** Helper preserved for DB tests / admin seeding */
  upsertDevice(input: {
    publicId: string;
    cryptoKeyId: string;
    publicKeyJwk: string | null;
    ecdhPublicKeyJwk?: string | null;
    role: 'admin' | 'basic';
    label: string;
  }): void {
    const now = Date.now();
    this.withTransaction(() => {
      this.db
        .prepare(
          `INSERT INTO devices
            (public_id, crypto_key_id, public_key_jwk, ecdh_public_key_jwk, role, label, status, created_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
           ON CONFLICT(public_id) DO UPDATE SET
             crypto_key_id = excluded.crypto_key_id,
             public_key_jwk = COALESCE(excluded.public_key_jwk, devices.public_key_jwk),
             ecdh_public_key_jwk = COALESCE(excluded.ecdh_public_key_jwk, devices.ecdh_public_key_jwk),
             role = excluded.role,
             label = excluded.label,
             last_seen_at = excluded.last_seen_at`
        )
        .run(
          input.publicId,
          input.cryptoKeyId,
          input.publicKeyJwk,
          input.ecdhPublicKeyJwk ?? null,
          input.role,
          input.label,
          now,
          now
        );
    });
  }

  consumeNonce(
    nonceKey: string,
    deviceId: string,
    expiresAt: number,
    now = Date.now()
  ): boolean {
    return this.withTransaction(() => {
      this.db.prepare('DELETE FROM used_nonces WHERE expires_at < ?').run(now);
      const existing = this.db
        .prepare('SELECT nonce_key FROM used_nonces WHERE nonce_key = ?')
        .get(nonceKey) as { nonce_key: string } | undefined;
      if (existing) {
        return false;
      }
      this.db
        .prepare(
          'INSERT INTO used_nonces (nonce_key, device_id, expires_at) VALUES (?, ?, ?)'
        )
        .run(nonceKey, deviceId, expiresAt);
      return true;
    });
  }

  createAuthChallenge(challenge: string, deviceId: string, expiresAt: number): void {
    this.withTransaction(() => {
      this.db
        .prepare(
          'INSERT INTO auth_challenges (challenge, device_id, expires_at, used_at) VALUES (?, ?, ?, NULL)'
        )
        .run(challenge, deviceId, expiresAt);
    });
  }

  consumeAuthChallenge(challenge: string, deviceId: string, now = Date.now()): boolean {
    return this.withTransaction(() => {
      const row = this.db
        .prepare(
          'SELECT device_id, expires_at, used_at FROM auth_challenges WHERE challenge = ?'
        )
        .get(challenge) as
        { device_id: string; expires_at: number; used_at: number | null } | undefined;
      if (
        !row ||
        row.device_id !== deviceId ||
        row.used_at !== null ||
        row.expires_at < now
      ) {
        return false;
      }
      this.db
        .prepare('UPDATE auth_challenges SET used_at = ? WHERE challenge = ?')
        .run(now, challenge);
      return true;
    });
  }

  createDeviceSession(input: {
    sessionId: string;
    deviceId: string;
    cryptoKeyId: string;
    tokenHash: string;
    expiresAt: number;
  }): void {
    const now = Date.now();
    this.withTransaction(() => {
      this.db
        .prepare(
          `INSERT INTO device_sessions (session_id, device_id, crypto_key_id, token_hash, expires_at, revoked_at, created_at)
           VALUES (?, ?, ?, ?, ?, NULL, ?)`
        )
        .run(
          input.sessionId,
          input.deviceId,
          input.cryptoKeyId,
          input.tokenHash,
          input.expiresAt,
          now
        );
    });
  }

  getValidSession(
    sessionId: string,
    tokenHash: string,
    now = Date.now()
  ): {
    sessionId: string;
    deviceId: string;
    cryptoKeyId: string;
    role: 'admin' | 'basic';
    publicKeyJwk: string | null;
    expiresAt: number;
  } | null {
    const row = this.db
      .prepare(
        `SELECT s.session_id, s.device_id, s.crypto_key_id, s.token_hash, s.expires_at, s.revoked_at,
                d.role, d.public_key_jwk, d.status AS device_status
         FROM device_sessions s
         JOIN devices d ON d.public_id = s.device_id
         WHERE s.session_id = ?`
      )
      .get(sessionId) as
      | {
          session_id: string;
          device_id: string;
          crypto_key_id: string;
          token_hash: string;
          expires_at: number;
          revoked_at: number | null;
          role: 'admin' | 'basic';
          public_key_jwk: string | null;
          device_status: 'ACTIVE' | 'REVOKED';
        }
      | undefined;

    if (
      !row ||
      row.revoked_at !== null ||
      row.expires_at <= now ||
      row.token_hash !== tokenHash ||
      row.device_status !== 'ACTIVE'
    ) {
      return null;
    }

    return {
      sessionId: row.session_id,
      deviceId: row.device_id,
      cryptoKeyId: row.crypto_key_id,
      role: row.role,
      publicKeyJwk: row.public_key_jwk,
      expiresAt: row.expires_at,
    };
  }

  revokeDeviceSessions(deviceId: string, revokeDeviceAccount = false): void {
    const now = Date.now();
    this.withTransaction(() => {
      this.db
        .prepare(
          'UPDATE device_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE device_id = ?'
        )
        .run(now, deviceId);
      if (revokeDeviceAccount) {
        this.db
          .prepare("UPDATE devices SET status = 'REVOKED' WHERE public_id = ?")
          .run(deviceId);
      }
    });
  }

  createWsTicket(ticket: string, deviceId: string, expiresAt: number): void {
    this.withTransaction(() => {
      this.db
        .prepare(
          'INSERT INTO ws_tickets (ticket, device_id, expires_at, used_at) VALUES (?, ?, ?, NULL)'
        )
        .run(ticket, deviceId, expiresAt);
    });
  }

  consumeWsTicket(ticket: string, now = Date.now()): string | null {
    return this.withTransaction(() => {
      const row = this.db
        .prepare(
          `SELECT t.device_id, t.expires_at, t.used_at, d.status AS device_status
           FROM ws_tickets t
           JOIN devices d ON d.public_id = t.device_id
           WHERE t.ticket = ?`
        )
        .get(ticket) as
        | {
            device_id: string;
            expires_at: number;
            used_at: number | null;
            device_status: 'ACTIVE' | 'REVOKED';
          }
        | undefined;

      if (
        !row ||
        row.used_at !== null ||
        row.expires_at < now ||
        row.device_status !== 'ACTIVE'
      ) {
        return null;
      }

      this.db
        .prepare('UPDATE ws_tickets SET used_at = ? WHERE ticket = ?')
        .run(now, ticket);
      return row.device_id;
    });
  }

  createPairingRequest(input: {
    pairingId: string;
    pairingCode: string;
    requesterDeviceId: string;
    requesterCryptoKeyId: string;
    requesterEcdhJwk: string | null;
    expiresAt: number;
  }): void {
    this.withTransaction(() => {
      // Expire any stale PENDING requests from same requester
      this.db
        .prepare(
          `UPDATE pairing_requests SET status = 'EXPIRED'
           WHERE requester_device_id = ? AND status = 'PENDING'`
        )
        .run(input.requesterDeviceId);

      this.db
        .prepare(
          `INSERT INTO pairing_requests
            (pairing_id, pairing_code, requester_device_id, requester_crypto_key_id, requester_ecdh_jwk, failed_attempts, expires_at, status)
           VALUES (?, ?, ?, ?, ?, 0, ?, 'PENDING')`
        )
        .run(
          input.pairingId,
          input.pairingCode,
          input.requesterDeviceId,
          input.requesterCryptoKeyId,
          input.requesterEcdhJwk,
          input.expiresAt
        );
    });
  }

  submitPairingAcceptance(input: {
    pairingCode: string;
    responderDeviceId: string;
    responderCryptoKeyId: string;
    responderEcdsaJwk: string | null;
    responderEcdhJwk: string | null;
    responderLabel: string;
  }):
    | {
        ok: true;
        pairing: PairingRequestRecord;
      }
    | {
        ok: false;
        reason:
          'NOT_FOUND' | 'EXPIRED' | 'LOCKED' | 'ALREADY_CONSUMED' | 'SELF_PAIRING';
      } {
    const now = Date.now();
    return this.withTransaction(() => {
      const req = this.db
        .prepare(
          `SELECT * FROM pairing_requests
           WHERE pairing_code = ?
           ORDER BY expires_at DESC
           LIMIT 1`
        )
        .get(input.pairingCode) as
        | {
            pairing_id: string;
            pairing_code: string;
            requester_device_id: string;
            requester_crypto_key_id: string;
            responder_device_id: string | null;
            responder_crypto_key_id: string | null;
            responder_label: string | null;
            failed_attempts: number;
            expires_at: number;
            status: PairingRequestRecord['status'];
          }
        | undefined;

      if (!req) {
        return { ok: false, reason: 'NOT_FOUND' } as const;
      }
      if (req.status === 'LOCKED' || req.failed_attempts >= 5) {
        return { ok: false, reason: 'LOCKED' } as const;
      }
      if (req.expires_at < now) {
        this.db
          .prepare(
            "UPDATE pairing_requests SET status = 'EXPIRED' WHERE pairing_id = ?"
          )
          .run(req.pairing_id);
        return { ok: false, reason: 'EXPIRED' } as const;
      }
      if (req.status !== 'PENDING') {
        return { ok: false, reason: 'ALREADY_CONSUMED' } as const;
      }
      if (req.requester_device_id === input.responderDeviceId) {
        return { ok: false, reason: 'SELF_PAIRING' } as const;
      }

      this.db
        .prepare(
          `UPDATE pairing_requests
           SET responder_device_id = ?,
               responder_crypto_key_id = ?,
               responder_ecdsa_jwk = ?,
               responder_ecdh_jwk = ?,
               responder_label = ?,
               status = 'AWAITING_REQUESTER_CONFIRMATION'
           WHERE pairing_id = ?`
        )
        .run(
          input.responderDeviceId,
          input.responderCryptoKeyId,
          input.responderEcdsaJwk,
          input.responderEcdhJwk,
          input.responderLabel,
          req.pairing_id
        );

      return {
        ok: true,
        pairing: {
          pairingId: req.pairing_id,
          pairingCode: req.pairing_code,
          requesterDeviceId: req.requester_device_id,
          requesterCryptoKeyId: req.requester_crypto_key_id,
          responderDeviceId: input.responderDeviceId,
          responderCryptoKeyId: input.responderCryptoKeyId,
          responderLabel: input.responderLabel,
          failedAttempts: req.failed_attempts,
          expiresAt: req.expires_at,
          status: 'AWAITING_REQUESTER_CONFIRMATION',
        },
      } as const;
    });
  }

  recordFailedPairingAttemptOnActive(now = Date.now()): void {
    this.withTransaction(() => {
      this.db
        .prepare(
          `UPDATE pairing_requests
           SET failed_attempts = failed_attempts + 1,
               status = CASE WHEN failed_attempts + 1 >= 5 THEN 'LOCKED' ELSE status END
           WHERE status = 'PENDING' AND expires_at >= ?`
        )
        .run(now);
    });
  }

  getPendingPairingApprovals(
    requesterDeviceId: string,
    now = Date.now()
  ): PairingRequestRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM pairing_requests
         WHERE requester_device_id = ?
           AND status = 'AWAITING_REQUESTER_CONFIRMATION'
           AND expires_at >= ?
         ORDER BY expires_at DESC`
      )
      .all(requesterDeviceId, now) as Array<{
      pairing_id: string;
      pairing_code: string;
      requester_device_id: string;
      requester_crypto_key_id: string;
      responder_device_id: string | null;
      responder_crypto_key_id: string | null;
      responder_label: string | null;
      failed_attempts: number;
      expires_at: number;
      status: PairingRequestRecord['status'];
    }>;

    return rows.map((r) => ({
      pairingId: r.pairing_id,
      pairingCode: r.pairing_code,
      requesterDeviceId: r.requester_device_id,
      requesterCryptoKeyId: r.requester_crypto_key_id,
      responderDeviceId: r.responder_device_id,
      responderCryptoKeyId: r.responder_crypto_key_id,
      responderLabel: r.responder_label,
      failedAttempts: r.failed_attempts,
      expiresAt: r.expires_at,
      status: r.status,
    }));
  }

  confirmPairingRequest(input: {
    pairingId: string;
    requesterDeviceId: string;
    approve: boolean;
    expectedResponderCryptoKeyId?: string;
  }):
    | {
        ok: true;
        approved: boolean;
        pairedAt: number;
        requester: RegisteredDeviceRecord;
        responder: RegisteredDeviceRecord;
      }
    | {
        ok: false;
        reason:
          | 'NOT_FOUND'
          | 'FORBIDDEN_OWNERSHIP'
          | 'INVALID_STATE'
          | 'EXPIRED'
          | 'KEY_FINGERPRINT_MISMATCH';
      } {
    const now = Date.now();
    return this.withTransaction(() => {
      const req = this.db
        .prepare('SELECT * FROM pairing_requests WHERE pairing_id = ?')
        .get(input.pairingId) as
        | {
            pairing_id: string;
            requester_device_id: string;
            responder_device_id: string | null;
            responder_crypto_key_id: string | null;
            expires_at: number;
            status: PairingRequestRecord['status'];
          }
        | undefined;

      if (!req) return { ok: false, reason: 'NOT_FOUND' } as const;
      if (req.requester_device_id !== input.requesterDeviceId) {
        return { ok: false, reason: 'FORBIDDEN_OWNERSHIP' } as const;
      }
      if (req.expires_at < now) {
        this.db
          .prepare(
            "UPDATE pairing_requests SET status = 'EXPIRED' WHERE pairing_id = ?"
          )
          .run(req.pairing_id);
        return { ok: false, reason: 'EXPIRED' } as const;
      }
      if (
        req.status !== 'AWAITING_REQUESTER_CONFIRMATION' ||
        !req.responder_device_id
      ) {
        return { ok: false, reason: 'INVALID_STATE' } as const;
      }
      if (
        input.expectedResponderCryptoKeyId &&
        req.responder_crypto_key_id !== input.expectedResponderCryptoKeyId
      ) {
        return { ok: false, reason: 'KEY_FINGERPRINT_MISMATCH' } as const;
      }

      const requester = this.getDevice(req.requester_device_id);
      const responder = this.getDevice(req.responder_device_id);
      if (!requester || !responder) {
        return { ok: false, reason: 'NOT_FOUND' } as const;
      }

      if (!input.approve) {
        this.db
          .prepare(
            "UPDATE pairing_requests SET status = 'REJECTED' WHERE pairing_id = ?"
          )
          .run(req.pairing_id);
        return {
          ok: true,
          approved: false,
          pairedAt: now,
          requester,
          responder,
        } as const;
      }

      this.db
        .prepare("UPDATE pairing_requests SET status = 'ACCEPTED' WHERE pairing_id = ?")
        .run(req.pairing_id);

      const [a, b] = [requester.publicId, responder.publicId].sort();
      this.db
        .prepare(
          `INSERT INTO device_links (device_a, device_b, pairing_state, paired_at, updated_at)
           VALUES (?, ?, 'PAIRED', ?, ?)
           ON CONFLICT(device_a, device_b) DO UPDATE SET
             pairing_state = 'PAIRED',
             paired_at = excluded.paired_at,
             updated_at = excluded.updated_at`
        )
        .run(a, b, now, now);

      return {
        ok: true,
        approved: true,
        pairedAt: now,
        requester,
        responder,
      } as const;
    });
  }

  isLinkPaired(deviceA: string, deviceB: string): boolean {
    const [a, b] = [deviceA, deviceB].sort();
    const row = this.db
      .prepare(
        `SELECT dl.pairing_state, d1.status AS s1, d2.status AS s2
         FROM device_links dl
         JOIN devices d1 ON d1.public_id = dl.device_a
         JOIN devices d2 ON d2.public_id = dl.device_b
         WHERE dl.device_a = ? AND dl.device_b = ?`
      )
      .get(a, b) as { pairing_state: string; s1: string; s2: string } | undefined;
    return (
      row?.pairing_state === 'PAIRED' && row.s1 === 'ACTIVE' && row.s2 === 'ACTIVE'
    );
  }

  getLinkedDevices(deviceId: string): Array<{
    publicId: string;
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
    ecdhPublicKeyJwk: JsonWebKey | null;
    label: string;
    role: 'admin' | 'basic';
    pairingState: 'PAIRED' | 'REVOKED';
    pairedAt: number;
    lastSeenAt: number;
  }> {
    const rows = this.db
      .prepare(
        `SELECT d.public_id, d.crypto_key_id, d.public_key_jwk, d.ecdh_public_key_jwk,
                d.label, d.role, dl.pairing_state, dl.paired_at, d.last_seen_at
         FROM device_links dl
         JOIN devices d ON d.public_id = CASE WHEN dl.device_a = ? THEN dl.device_b ELSE dl.device_a END
         WHERE dl.device_a = ? OR dl.device_b = ?
         ORDER BY dl.updated_at DESC`
      )
      .all(deviceId, deviceId, deviceId) as Array<{
      public_id: string;
      crypto_key_id: string;
      public_key_jwk: string | null;
      ecdh_public_key_jwk: string | null;
      label: string;
      role: 'admin' | 'basic';
      pairing_state: 'PAIRED' | 'REVOKED';
      paired_at: number;
      last_seen_at: number;
    }>;

    return rows.map((r) => ({
      publicId: r.public_id,
      cryptoKeyId: r.crypto_key_id,
      publicKeyJwk: r.public_key_jwk
        ? (JSON.parse(r.public_key_jwk) as JsonWebKey)
        : null,
      ecdhPublicKeyJwk: r.ecdh_public_key_jwk
        ? (JSON.parse(r.ecdh_public_key_jwk) as JsonWebKey)
        : null,
      label: r.label,
      role: r.role,
      pairingState: r.pairing_state,
      pairedAt: r.paired_at,
      lastSeenAt: r.last_seen_at,
    }));
  }

  revokeDeviceLink(
    deviceId: string,
    targetDeviceId: string,
    revokeTargetTrust = false
  ): boolean {
    const [a, b] = [deviceId, targetDeviceId].sort();
    return this.withTransaction(() => {
      const existing = this.db
        .prepare(
          'SELECT pairing_state FROM device_links WHERE device_a = ? AND device_b = ?'
        )
        .get(a, b) as { pairing_state: string } | undefined;
      if (!existing) {
        return false;
      }

      const now = Date.now();
      this.db
        .prepare(
          `UPDATE device_links SET pairing_state = 'REVOKED', updated_at = ? WHERE device_a = ? AND device_b = ?`
        )
        .run(now, a, b);

      if (revokeTargetTrust) {
        this.db
          .prepare(
            'UPDATE device_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE device_id = ?'
          )
          .run(now, targetDeviceId);
        this.db
          .prepare("UPDATE devices SET status = 'REVOKED' WHERE public_id = ?")
          .run(targetDeviceId);
      }
      return true;
    });
  }

  hasUsedMessageNonce(
    sourceDeviceId: string,
    messageNonce: string,
    excludingIdempotencyKey?: string
  ): boolean {
    const row = excludingIdempotencyKey
      ? (this.db
          .prepare(
            `SELECT id FROM relay_events
             WHERE source_device_id = ? AND message_nonce = ? AND idempotency_key != ?
             LIMIT 1`
          )
          .get(sourceDeviceId, messageNonce, excludingIdempotencyKey) as
          { id: number } | undefined)
      : (this.db
          .prepare(
            `SELECT id FROM relay_events
             WHERE source_device_id = ? AND message_nonce = ?
             LIMIT 1`
          )
          .get(sourceDeviceId, messageNonce) as { id: number } | undefined);
    return Boolean(row);
  }

  ingestSyncBatch(
    sourceDeviceId: string,
    targetDeviceId: string,
    events: Array<{
      id: number;
      idempotencyKey: string;
      type: string;
      payload: string;
      senderCryptoKeyId?: string;
      recipientCryptoKeyId?: string;
      messageNonce?: string;
      notificationKey?: string;
      payloadHash?: string;
      createdAt: number;
    }>
  ): {
    acceptedIds: number[];
    duplicateIds: number[];
    deliveredIds: number[];
    insertedRows: Array<{
      relayEventId: number;
      sourceDeviceId: string;
      targetDeviceId: string;
      clientEventId: number;
      idempotencyKey: string;
      type: string;
      payload: string;
      notificationKey: string | null;
      payloadHash: string | null;
      createdAt: number;
      receivedAt: number;
    }>;
  } {
    const now = Date.now();
    return this.withTransaction(() => {
      const acceptedIds: number[] = [];
      const duplicateIds: number[] = [];
      const deliveredIds: number[] = [];
      const insertedRows: Array<{
        relayEventId: number;
        sourceDeviceId: string;
        targetDeviceId: string;
        clientEventId: number;
        idempotencyKey: string;
        type: string;
        payload: string;
        notificationKey: string | null;
        payloadHash: string | null;
        createdAt: number;
        receivedAt: number;
      }> = [];

      const findStmt = this.db.prepare(
        'SELECT id, delivered_at FROM relay_events WHERE idempotency_key = ?'
      );
      const insertStmt = this.db.prepare(
        `INSERT INTO relay_events
          (source_device_id, target_device_id, client_event_id, idempotency_key, type, payload, sender_crypto_key_id, recipient_crypto_key_id, message_nonce, notification_key, payload_hash, created_at, received_at, delivered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
      );

      for (const evt of events) {
        const existing = findStmt.get(evt.idempotencyKey) as
          { id: number; delivered_at: number | null } | undefined;
        if (existing) {
          duplicateIds.push(evt.id);
          if (existing.delivered_at !== null) {
            deliveredIds.push(evt.id);
          }
          continue;
        }
        const info = insertStmt.run(
          sourceDeviceId,
          targetDeviceId,
          evt.id,
          evt.idempotencyKey,
          evt.type,
          evt.payload,
          evt.senderCryptoKeyId ?? null,
          evt.recipientCryptoKeyId ?? null,
          evt.messageNonce ?? null,
          evt.notificationKey ?? null,
          evt.payloadHash ?? null,
          evt.createdAt,
          now
        );
        acceptedIds.push(evt.id);
        insertedRows.push({
          relayEventId: Number(info.lastInsertRowid),
          sourceDeviceId,
          targetDeviceId,
          clientEventId: evt.id,
          idempotencyKey: evt.idempotencyKey,
          type: evt.type,
          payload: evt.payload,
          notificationKey: evt.notificationKey ?? null,
          payloadHash: evt.payloadHash ?? null,
          createdAt: evt.createdAt,
          receivedAt: now,
        });
      }

      return { acceptedIds, duplicateIds, deliveredIds, insertedRows };
    });
  }

  acknowledgeDelivery(
    recipientDeviceId: string,
    relayEventIds: number[]
  ): Array<{
    relayEventId: number;
    senderDeviceId: string;
    clientEventId: number;
  }> {
    const uniqueIds = Array.from(
      new Set(
        relayEventIds.filter(
          (id) => typeof id === 'number' && Number.isInteger(id) && id > 0
        )
      )
    );
    const now = Date.now();
    return this.withTransaction(() => {
      const acked: Array<{
        relayEventId: number;
        senderDeviceId: string;
        clientEventId: number;
      }> = [];
      const selectStmt = this.db.prepare(
        `SELECT id, source_device_id, target_device_id, client_event_id, delivered_at
         FROM relay_events WHERE id = ?`
      );
      const updateStmt = this.db.prepare(
        'UPDATE relay_events SET delivered_at = ? WHERE id = ?'
      );

      for (const eventId of uniqueIds) {
        const row = selectStmt.get(eventId) as
          | {
              id: number;
              source_device_id: string;
              target_device_id: string | null;
              client_event_id: number;
              delivered_at: number | null;
            }
          | undefined;
        if (!row || row.target_device_id !== recipientDeviceId) continue;
        if (!this.isLinkPaired(row.source_device_id, recipientDeviceId)) continue;

        if (row.delivered_at === null) {
          updateStmt.run(now, row.id);
        }
        acked.push({
          relayEventId: row.id,
          senderDeviceId: row.source_device_id,
          clientEventId: row.client_event_id,
        });
      }
      return acked;
    });
  }

  getDeliveredClientEventIds(
    sourceDeviceId: string,
    clientEventIds: number[]
  ): number[] {
    if (clientEventIds.length === 0) return [];
    const placeholders = clientEventIds.map(() => '?').join(',');
    const rows = this.db
      .prepare(
        `SELECT client_event_id FROM relay_events
         WHERE source_device_id = ? AND delivered_at IS NOT NULL
           AND client_event_id IN (${placeholders})`
      )
      .all(sourceDeviceId, ...clientEventIds) as Array<{ client_event_id: number }>;
    return rows.map((r) => r.client_event_id);
  }

  getInboundEvents(targetDeviceId: string): Array<{
    id: number;
    sourceDeviceId: string;
    type: string;
    payload: string;
    createdAt: number;
    receivedAt: number;
    deliveredAt: number | null;
    idempotencyKey: string;
    notificationKey: string | null;
    payloadHash: string | null;
  }> {
    const rows = this.db
      .prepare(
        `SELECT r.id, r.source_device_id, r.type, r.payload, r.created_at, r.received_at, r.delivered_at, r.idempotency_key, r.notification_key, r.payload_hash
         FROM relay_events r
         JOIN device_links dl
           ON ((dl.device_a = r.source_device_id AND dl.device_b = r.target_device_id)
            OR (dl.device_b = r.source_device_id AND dl.device_a = r.target_device_id))
         WHERE r.target_device_id = ?
           AND dl.pairing_state = 'PAIRED'
           AND r.delivered_at IS NULL
         ORDER BY r.created_at DESC
         LIMIT 100`
      )
      .all(targetDeviceId) as Array<{
      id: number;
      source_device_id: string;
      type: string;
      payload: string;
      created_at: number;
      received_at: number;
      delivered_at: number | null;
      idempotency_key: string;
      notification_key: string | null;
      payload_hash: string | null;
    }>;

    return rows.map((r) => ({
      id: r.id,
      sourceDeviceId: r.source_device_id,
      type: r.type,
      payload: r.payload,
      createdAt: r.created_at,
      receivedAt: r.received_at,
      deliveredAt: r.delivered_at,
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
