import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SecurityError, StorageError, ValidationError } from '../../src/domain/errors/appError';
import {
  BACKUP_KDF_MAX_ITERATIONS,
  BACKUP_KDF_MIN_ITERATIONS,
  BACKUP_MAX_SYNC_EVENTS,
  ENCRYPTED_BACKUP_FORMAT_ID,
  ENCRYPTED_BACKUP_FORMAT_VERSION,
  type EncryptedBackupArchiveV2,
} from '../../src/domain/models/backup';
import { DEFAULT_APP_SETTINGS } from '../../src/domain/models/settings';
import { WebCryptoProvider } from '../../src/infrastructure/security/webCryptoProvider';
import { APP_DB_VERSION, IndexedDbDatabase, STORES } from '../../src/infrastructure/storage/indexedDbDatabase';
import {
  IndexedDbAuditRepository,
  IndexedDbBackupProvider,
  IndexedDbDeviceRepository,
  IndexedDbSettingsRepository,
  IndexedDbSyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { InMemoryIndexedDbHarness } from '../helpers/inMemoryIndexedDb';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

const STRONG_PASSPHRASE = 'Correct-Backup-Passphrase-2026!';
const WRONG_PASSPHRASE = 'Wrong-Backup-Passphrase-9999!';

async function createRealWebCryptoStack(dbName: string, harness: InMemoryIndexedDbHarness) {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB = harness.createFactory();
  const crypto = new WebCryptoProvider();
  const db = new IndexedDbDatabase(dbName);
  await db.initialize();

  const settingsRepo = new IndexedDbSettingsRepository(db);
  const deviceRepo = new IndexedDbDeviceRepository(db);
  const auditRepo = new IndexedDbAuditRepository(db);
  const syncRepo = new IndexedDbSyncEventRepository(db, crypto);
  const backup = new IndexedDbBackupProvider({
    db,
    crypto,
    syncRepo,
    deviceRepo,
    auditRepo,
    settingsRepo,
  });

  const keys = await crypto.getOrCreateDeviceKeyPair();
  await deviceRepo.saveIdentity({
    publicId: `dev-${crypto.randomHex(6)}`,
    cryptoKeyId: keys.cryptoKeyId,
    publicKeyJwk: keys.publicKeyJwk,
    ecdhPublicKeyJwk: keys.ecdhPublicKeyJwk,
    createdAt: Date.now(),
  });

  await settingsRepo.save({
    ...DEFAULT_APP_SETTINGS,
    role: 'admin',
    relayEndpoint: '/api/relay',
  });

  return { crypto, db, settingsRepo, deviceRepo, auditRepo, syncRepo, backup };
}

describe('Encrypted Backup v2 Unit & Cryptographic Verification (Real WebCrypto Subtle + IDB Harness)', () => {
  it('exports v2 archive with zero plaintext/secrets, unique salt & IV per export, and restores cleanly via real WebCrypto', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-export-v2', harness);

    const secretTitle = 'Secret OTP Alert Title';
    const secretText = 'Verification code is 739104 for bank';
    await stack.syncRepo.insert({
      type: 'notification',
      payload: JSON.stringify({
        packageName: 'com.bank.app',
        title: secretTitle,
        text: secretText,
        postedAt: 1700000000000,
      }),
      idempotencyKey: 'idem-secret-1',
      notificationKey: 'com.bank.app|otp',
      payloadHash: 'hash-1',
    });

    const summary1 = await stack.backup.exportBackup(STRONG_PASSPHRASE);
    const summary2 = await stack.backup.exportBackup(STRONG_PASSPHRASE);
    const raw1 = JSON.stringify(summary1.archive);

    // 1-4: Outer envelope checks (no plaintext, no notification text, no passphrase, no private key)
    assert.equal(summary1.archive.format, ENCRYPTED_BACKUP_FORMAT_ID);
    assert.equal(summary1.archive.formatVersion, ENCRYPTED_BACKUP_FORMAT_VERSION);
    assert.equal(summary1.archive.schemaVersion, APP_DB_VERSION);
    assert.equal(summary1.archive.kdf.algorithm, 'PBKDF2-HMAC-SHA-256');
    assert.equal(summary1.archive.encryption.algorithm, 'AES-256-GCM');
    assert.ok(!raw1.includes(secretTitle));
    assert.ok(!raw1.includes(secretText));
    assert.ok(!raw1.includes('com.bank.app'));
    assert.ok(!raw1.includes(STRONG_PASSPHRASE));
    assert.ok(!raw1.includes('privateKey'));

    // 5: Unique salt & IV per export
    assert.notEqual(summary1.archive.kdf.salt, summary2.archive.kdf.salt);
    assert.notEqual(summary1.archive.encryption.iv, summary2.archive.encryption.iv);
    assert.notEqual(summary1.archive.ciphertext, summary2.archive.ciphertext);

    // Clear sync events & verify real restore recovers decrypted payload
    await stack.syncRepo.clearAll();
    assert.equal((await stack.syncRepo.getAll()).length, 0);

    const restoreRes = await stack.backup.restoreBackup(raw1, STRONG_PASSPHRASE);
    assert.equal(restoreRes.restoredEvents, 1);

    const restoredEvents = await stack.syncRepo.getAll();
    assert.equal(restoredEvents.length, 1);
    assert.ok(restoredEvents[0].payload.includes(secretTitle));
    assert.ok(restoredEvents[0].payload.includes(secretText));

    // Interoperability check: NodeTestCryptoProvider must decrypt WebCryptoProvider output
    const nodeCrypto = new NodeTestCryptoProvider();
    const decryptedByNode = await nodeCrypto.decryptBackupPayload({
      archive: summary1.archive,
      passphrase: STRONG_PASSPHRASE,
    });
    assert.ok(decryptedByNode.includes(secretTitle));
  });

  it('fails export cleanly when a local encrypted event cannot be decrypted (no silent placeholder export)', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-decrypt-fail-export', harness);

    // Insert a corrupted local encrypted record missing/invalidating envelope
    await stack.db.add(STORES.SYNC_EVENTS, {
      type: 'notification',
      payload: '[ENCRYPTED_AES_256_GCM]',
      envelope: {
        algorithm: 'AES-256-GCM',
        iv: Buffer.from(new Uint8Array(12)).toString('base64'),
        ciphertext: Buffer.from('corrupted-ciphertext-tag-bytes').toString('base64'),
      },
      createdAt: Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-corrupt-local',
      encrypted: true,
      localEncrypted: true,
    });

    await assert.rejects(
      () => stack.backup.exportBackup(STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof StorageError && err.code === 'BACKUP_EVENT_DECRYPTION_FAILED'
    );

    // Also test missing envelope on encrypted record
    await stack.syncRepo.clearAll();
    await stack.db.add(STORES.SYNC_EVENTS, {
      type: 'notification',
      payload: '[ENCRYPTED_AES_256_GCM]',
      createdAt: Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-missing-envelope',
      encrypted: true,
      localEncrypted: true,
    });

    await assert.rejects(
      () => stack.backup.exportBackup(STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof StorageError && err.code === 'BACKUP_EVENT_DECRYPTION_FAILED'
    );
  });

  it('rejects wrong passphrase, tampered ciphertext/AAD/headers, invalid KDF/salt/IV bounds, and leaves DB untouched', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-reject-all', harness);

    await stack.syncRepo.insert({
      type: 'notification',
      payload: 'baseline-untouched-event',
      idempotencyKey: 'idem-baseline',
    });
    const exported = await stack.backup.exportBackup(STRONG_PASSPHRASE);

    // Mutate DB after export so we can verify DB remains untouched on rejected restores
    await stack.syncRepo.insert({
      type: 'notification',
      payload: 'newer-live-event-must-survive',
      idempotencyKey: 'idem-newer-live',
    });

    const verifyDbUntouched = async () => {
      const current = await stack.syncRepo.getAll();
      assert.equal(current.length, 2);
      assert.ok(current.some((e) => e.idempotencyKey === 'idem-newer-live'));
    };

    // 8. Wrong passphrase
    await assert.rejects(
      () => stack.backup.restoreBackup(JSON.stringify(exported.archive), WRONG_PASSPHRASE),
      (err: unknown) => err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
    );
    await verifyDbUntouched();

    // 9. Tampered ciphertext
    const tamperedCipher: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    const cipherBytes = Buffer.from(tamperedCipher.ciphertext, 'base64');
    cipherBytes[0] = cipherBytes[0] ^ 0xff;
    tamperedCipher.ciphertext = cipherBytes.toString('base64');
    await assert.rejects(
      () => stack.backup.restoreBackup(tamperedCipher, STRONG_PASSPHRASE),
      (err: unknown) => err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
    );
    await verifyDbUntouched();

    // Tampered header metadata (exportedAt changed)
    const tamperedHeader: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    tamperedHeader.exportedAt += 1;
    await assert.rejects(
      () => stack.backup.restoreBackup(tamperedHeader, STRONG_PASSPHRASE),
      (err: unknown) => err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
    );

    // 10. Invalid IV length & invalid salt length
    const badIv: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    badIv.encryption.iv = Buffer.from([1, 2, 3]).toString('base64');
    await assert.rejects(
      () => stack.backup.restoreBackup(badIv, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'INVALID_BACKUP_CRYPTO_PARAMS'
    );

    const badSalt: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    badSalt.kdf.salt = Buffer.from([1, 2, 3, 4]).toString('base64');
    await assert.rejects(
      () => stack.backup.restoreBackup(badSalt, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'INVALID_BACKUP_CRYPTO_PARAMS'
    );

    // 11. KDF parameters outside safe bounds (too low / too high / negative)
    const lowKdf: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    lowKdf.kdf.iterations = BACKUP_KDF_MIN_ITERATIONS - 1;
    await assert.rejects(
      () => stack.backup.restoreBackup(lowKdf, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'INVALID_BACKUP_KDF_PARAMS'
    );

    const highKdf: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    highKdf.kdf.iterations = BACKUP_KDF_MAX_ITERATIONS + 1;
    await assert.rejects(
      () => stack.backup.restoreBackup(highKdf, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'INVALID_BACKUP_KDF_PARAMS'
    );

    // 12. Unsupported formatVersion & unsupported schemaVersion
    const badFormatVersion = {
      ...structuredClone(exported.archive),
      formatVersion: 99,
    };
    await assert.rejects(
      () =>
        stack.backup.restoreBackup(
          JSON.stringify(badFormatVersion),
          STRONG_PASSPHRASE
        ),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'UNSUPPORTED_BACKUP_VERSION'
    );

    const futureSchema = {
      ...structuredClone(exported.archive),
      schemaVersion: APP_DB_VERSION + 10,
    };
    await assert.rejects(
      () => stack.backup.restoreBackup(JSON.stringify(futureSchema), STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'UNSUPPORTED_SCHEMA_VERSION'
    );

    // 13. Corrupt JSON
    await assert.rejects(
      () => stack.backup.restoreBackup('{not-valid-json', STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_CORRUPT_JSON'
    );

    // 14. Missing inner fields & oversized lists (using real WebCrypto encryption of invalid inner payload)
    const missingInnerArchive = await stack.crypto.encryptBackupPayload({
      plaintext: JSON.stringify({ payloadVersion: 2, schemaVersion: APP_DB_VERSION }),
      passphrase: STRONG_PASSPHRASE,
      schemaVersion: APP_DB_VERSION,
    });
    await assert.rejects(
      () => stack.backup.restoreBackup(missingInnerArchive, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'INVALID_BACKUP_SCHEMA'
    );

    const oversizedEventsArchive = await stack.crypto.encryptBackupPayload({
      plaintext: JSON.stringify({
        payloadVersion: 2,
        schemaVersion: APP_DB_VERSION,
        exportedAt: 1700000000000,
        sourceDevice: null,
        settings: { ...DEFAULT_APP_SETTINGS, role: 'admin' },
        linkedDevices: [],
        syncEvents: new Array(BACKUP_MAX_SYNC_EVENTS + 1).fill({}),
        auditEntries: [],
      }),
      passphrase: STRONG_PASSPHRASE,
      schemaVersion: APP_DB_VERSION,
      exportedAt: 1700000000000,
    });
    await assert.rejects(
      () => stack.backup.restoreBackup(oversizedEventsArchive, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_LIMIT_EXCEEDED'
    );

    await verifyDbUntouched();
  });

  it('rolls back atomically if IndexedDB transaction fails mid-restore without partial data loss', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-rollback-test', harness);

    await stack.syncRepo.insert({
      type: 'notification',
      payload: 'pre-existing-event',
      idempotencyKey: 'idem-pre-existing',
    });
    const archiveToRestore = await stack.backup.exportBackup(STRONG_PASSPHRASE);

    await stack.syncRepo.insert({
      type: 'notification',
      payload: 'second-event-must-survive-rollback',
      idempotencyKey: 'idem-second-survives',
    });

    // Simulate failure inside STORES.SYNC_EVENTS AFTER settings/devices clear occurred in tx
    harness.failOnPutStore = STORES.SYNC_EVENTS;

    await assert.rejects(() =>
      stack.backup.restoreBackup(archiveToRestore.archive, STRONG_PASSPHRASE)
    );

    harness.failOnPutStore = null;
    const afterRollback = await stack.syncRepo.getAll();
    assert.equal(afterRollback.length, 2);
    assert.ok(afterRollback.some((e) => e.idempotencyKey === 'idem-second-survives'));
    const settingsAfter = await stack.settingsRepo.get();
    assert.equal(settingsAfter.role, 'admin');
  });
});
