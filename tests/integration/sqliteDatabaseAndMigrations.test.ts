import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { SqliteRelayDatabase } from '../../server/db/sqliteRelayDb';

describe('SQLite Relay Database, Migrations & Transactions Tests', () => {
  it('runs migrations v1-v3 idempotently, persists across restarts, and rolls back invalid FK writes', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'nexlink-db-test-'));
    const dbPath = path.join(dir, 'relay.sqlite');

    try {
      const db1 = new SqliteRelayDatabase(dbPath);
      assert.equal(db1.getSchemaVersion(), 3);

      db1.upsertDevice({
        publicId: 'dev-a',
        cryptoKeyId: 'ecdsa-a',
        publicKeyJwk: null,
        role: 'admin',
        label: 'Device A',
      });

      const batch1 = db1.ingestSyncBatch('dev-a', null, [
        {
          id: 1,
          type: 'notification',
          payload: '{"title":"hello"}',
          createdAt: 1000,
          idempotencyKey: 'idem-1',
        },
        {
          id: 2,
          type: 'notification',
          payload: '{"title":"world"}',
          createdAt: 2000,
          idempotencyKey: 'idem-2',
        },
      ]);
      assert.deepEqual(batch1.acceptedIds, [1, 2]);
      assert.deepEqual(batch1.duplicateIds, []);

      // Re-sending same idempotency keys deduplicates at DB level
      const batchDup = db1.ingestSyncBatch('dev-a', null, [
        {
          id: 1,
          type: 'notification',
          payload: '{"title":"hello"}',
          createdAt: 1000,
          idempotencyKey: 'idem-1',
        },
      ]);
      assert.deepEqual(batchDup.acceptedIds, []);
      assert.deepEqual(batchDup.duplicateIds, [1]);

      // Foreign key rollback test: unregistered requester cannot create pairing request
      assert.throws(() =>
        db1.createPairingRequest({
          pairingCode: '999999',
          requesterDeviceId: 'non-existent-device',
          requesterCryptoKeyId: 'none',
          expiresAt: Date.now() + 60_000,
        })
      );

      db1.close();

      // Restart against same file preserves data & schema version
      const db2 = new SqliteRelayDatabase(dbPath);
      assert.equal(db2.getSchemaVersion(), 3);
      const backup = db2.exportBackup();
      assert.equal(backup.schemaVersion, 3);
      assert.equal(backup.devices.length, 1);
      assert.equal(backup.relayEvents.length, 2);
      db2.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
