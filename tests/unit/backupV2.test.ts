import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  executeRestoreWithPostCommitRecovery,
  type RestoreRecoveryDeps,
} from '../../src/application/container';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { ErrorManager } from '../../src/application/errors/errorManager';
import { HealthMonitor } from '../../src/application/health/healthMonitor';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import { SyncEngine } from '../../src/application/sync/syncEngine';
import {
  AppError,
  type ErrorSource,
  SecurityError,
  StorageError,
  ValidationError,
} from '../../src/domain/errors/appError';
import type { ITransportClient } from '../../src/domain/interfaces/services';
import {
  BACKUP_KDF_MAX_ITERATIONS,
  BACKUP_KDF_MIN_ITERATIONS,
  BACKUP_MAX_AUDIT_ENTRIES,
  BACKUP_MAX_LINKED_DEVICES,
  BACKUP_MAX_SELECTED_APPS,
  BACKUP_MAX_SYNC_EVENTS,
  ENCRYPTED_BACKUP_FORMAT_ID,
  ENCRYPTED_BACKUP_FORMAT_VERSION,
  type EncryptedBackupArchiveV2,
  type LegacyBackupArchiveV1,
} from '../../src/domain/models/backup';
import type { ConnectionState, PairingRequest } from '../../src/domain/models/device';
import { DEFAULT_APP_SETTINGS } from '../../src/domain/models/settings';
import { WebCryptoProvider } from '../../src/infrastructure/security/webCryptoProvider';
import {
  APP_DB_VERSION,
  IndexedDbDatabase,
  STORES,
} from '../../src/infrastructure/storage/indexedDbDatabase';
import {
  IndexedDbAuditRepository,
  IndexedDbBackupProvider,
  IndexedDbDeviceRepository,
  IndexedDbSettingsRepository,
  IndexedDbSyncEventRepository,
  InMemoryAuditRepository,
  InMemoryDeviceRepository,
  InMemorySettingsRepository,
  InMemorySyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { InMemoryIndexedDbHarness } from '../helpers/inMemoryIndexedDb';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

const STRONG_PASSPHRASE = 'Correct-Backup-Passphrase-2026!';
const WRONG_PASSPHRASE = 'Wrong-Backup-Passphrase-9999!';

async function createRealWebCryptoStack(
  dbName: string,
  harness: InMemoryIndexedDbHarness
) {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    harness.createFactory();
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
      () =>
        stack.backup.restoreBackup(JSON.stringify(exported.archive), WRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
    );
    await verifyDbUntouched();

    // 9. Tampered ciphertext
    const tamperedCipher: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    const cipherBytes = Buffer.from(tamperedCipher.ciphertext, 'base64');
    cipherBytes[0] = cipherBytes[0] ^ 0xff;
    tamperedCipher.ciphertext = cipherBytes.toString('base64');
    await assert.rejects(
      () => stack.backup.restoreBackup(tamperedCipher, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
    );
    await verifyDbUntouched();

    // Tampered header metadata (exportedAt changed)
    const tamperedHeader: EncryptedBackupArchiveV2 = structuredClone(exported.archive);
    tamperedHeader.exportedAt += 1;
    await assert.rejects(
      () => stack.backup.restoreBackup(tamperedHeader, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'BACKUP_AUTH_FAILED'
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
        stack.backup.restoreBackup(JSON.stringify(badFormatVersion), STRONG_PASSPHRASE),
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

  it('preserves target device role across restore in both directions while restoring allowed settings and preserving role on failure', async () => {
    const harness = new InMemoryIndexedDbHarness();

    // Source device A is admin with custom allowed settings
    const sourceAdmin = await createRealWebCryptoStack('db-role-src-admin', harness);
    await sourceAdmin.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'admin',
      sessionTimeoutMinutes: 45,
      syncIntervalMs: 15000,
      maxSyncRetries: 8,
      selectedNotificationApps: ['com.whatsapp', 'com.signal'],
      syncDeliveryPolicy: 'RELAY_QUEUED',
    });
    const adminBackup = await sourceAdmin.backup.exportBackup(STRONG_PASSPHRASE);

    // 1. Target device B is 'basic' restoring backup from 'admin' -> MUST remain 'basic'
    const targetBasic = await createRealWebCryptoStack('db-role-tgt-basic', harness);
    await targetBasic.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'basic',
      sessionTimeoutMinutes: 10,
      syncIntervalMs: 5000,
    });
    const resBasic = await targetBasic.backup.restoreBackup(
      adminBackup.archive,
      STRONG_PASSPHRASE
    );
    assert.equal(resBasic.restoredRole, 'basic');
    const basicSettingsAfter = await targetBasic.settingsRepo.get();
    assert.equal(basicSettingsAfter.role, 'basic');
    // Allowed settings ARE restored
    assert.equal(basicSettingsAfter.sessionTimeoutMinutes, 45);
    assert.equal(basicSettingsAfter.syncIntervalMs, 15000);
    assert.equal(basicSettingsAfter.maxSyncRetries, 8);
    assert.deepEqual(basicSettingsAfter.selectedNotificationApps, [
      'com.whatsapp',
      'com.signal',
    ]);
    assert.equal(basicSettingsAfter.syncDeliveryPolicy, 'RELAY_QUEUED');

    // Failure during restore leaves target role & settings untouched
    await assert.rejects(() =>
      targetBasic.backup.restoreBackup(adminBackup.archive, WRONG_PASSPHRASE)
    );
    assert.equal((await targetBasic.settingsRepo.get()).role, 'basic');

    // 2. Target device C is 'admin' restoring backup from 'basic' -> MUST remain 'admin'
    const sourceBasic = await createRealWebCryptoStack('db-role-src-basic', harness);
    await sourceBasic.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'basic',
      sessionTimeoutMinutes: 90,
      maxSyncRetries: 12,
    });
    const basicBackup = await sourceBasic.backup.exportBackup(STRONG_PASSPHRASE);

    const targetAdmin = await createRealWebCryptoStack('db-role-tgt-admin', harness);
    await targetAdmin.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'admin',
      sessionTimeoutMinutes: 20,
    });
    const resAdmin = await targetAdmin.backup.restoreBackup(
      basicBackup.archive,
      STRONG_PASSPHRASE
    );
    assert.equal(resAdmin.restoredRole, 'admin');
    const adminSettingsAfter = await targetAdmin.settingsRepo.get();
    assert.equal(adminSettingsAfter.role, 'admin');
    assert.equal(adminSettingsAfter.sessionTimeoutMinutes, 90);
    assert.equal(adminSettingsAfter.maxSyncRetries, 12);
  });

  it('preserves local audit entries (including REVOKED), avoids ID collisions, ignores spoofed archive provenance, and rolls back atomically on failure', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-audit-provenance', harness);

    // Local device records local audit entries with IDs 1 and 2 (including DEVICE_REVOKED)
    const localRevoked = await stack.auditRepo.append({
      timestamp: 1700000001000,
      action: 'DEVICE_REVOKED',
      actorRole: 'admin',
      deviceId: 'local-device-1',
      outcome: 'ALLOWED',
      details: 'سحب ثقة جهاز محلي مهم يجب عدم حذفه',
    });
    const localRole = await stack.auditRepo.append({
      timestamp: 1700000002000,
      action: 'ROLE_ASSIGNED',
      actorRole: 'admin',
      deviceId: 'local-device-1',
      outcome: 'ALLOWED',
      details: 'تعيين دور محلي أصلي',
    });
    assert.equal(localRevoked.origin, 'LOCAL');
    assert.equal(localRole.origin, 'LOCAL');

    // Craft an archive from another device claiming colliding IDs (1, 2) and spoofed origin='LOCAL'
    const craftedInner = {
      payloadVersion: 2,
      schemaVersion: APP_DB_VERSION,
      exportedAt: 1700000010000,
      sourceDevice: {
        publicId: 'archive-source-dev-99',
        cryptoKeyId: 'ecdsa-source-99',
      },
      settings: { ...DEFAULT_APP_SETTINGS, role: 'basic' },
      linkedDevices: [],
      syncEvents: [
        {
          id: 1,
          type: 'notification',
          payload: 'restored-event-1',
          createdAt: 1700000005000,
          status: 'SYNCED',
          retryCount: 0,
          nextRetryAt: null,
          idempotencyKey: 'idem-audit-evt-1',
          encrypted: true,
        },
      ],
      auditEntries: [
        {
          id: localRevoked.id, // Collides with local ID 1
          timestamp: 1700000003000,
          action: 'ROLE_CHANGED',
          actorRole: 'admin',
          deviceId: 'archive-source-dev-99',
          outcome: 'ALLOWED',
          details: 'سجل مستورد يحاول تزوير provenance المحلي',
          origin: 'LOCAL', // Spoofed provenance!
          importedAt: null,
          importedFromDeviceId: 'spoofed-local',
        },
        {
          id: localRole.id, // Collides with local ID 2
          timestamp: 1700000004000,
          action: 'VAULT_VERIFIED',
          actorRole: 'admin',
          deviceId: 'archive-source-dev-99',
          outcome: 'ALLOWED',
          details: 'سجل مستورد ثانٍ بمعرّف متصادم',
          origin: 'LOCAL',
        },
      ],
    };

    const archive = await stack.crypto.encryptBackupPayload({
      plaintext: JSON.stringify(craftedInner),
      passphrase: STRONG_PASSPHRASE,
      schemaVersion: APP_DB_VERSION,
      exportedAt: craftedInner.exportedAt,
    });

    // 1. Rollback test: fail mid-restore inside SYNC_EVENTS -> local audits untouched, zero imported added
    harness.failOnPutStore = STORES.SYNC_EVENTS;
    await assert.rejects(() => stack.backup.restoreBackup(archive, STRONG_PASSPHRASE));
    harness.failOnPutStore = null;

    const auditsAfterFail = await stack.auditRepo.getAll();
    assert.equal(auditsAfterFail.length, 2);
    assert.ok(auditsAfterFail.every((a) => a.origin === 'LOCAL'));

    // 2. Successful restore -> local entries preserved, imported entries appended with new IDs & BACKUP_IMPORT
    await stack.backup.restoreBackup(archive, STRONG_PASSPHRASE);
    const auditsAfterRestore = await stack.auditRepo.getAll();
    assert.equal(auditsAfterRestore.length, 4);

    const preservedRevoked = auditsAfterRestore.find((a) => a.id === localRevoked.id)!;
    const preservedRole = auditsAfterRestore.find((a) => a.id === localRole.id)!;
    assert.equal(preservedRevoked.origin, 'LOCAL');
    assert.equal(preservedRevoked.action, 'DEVICE_REVOKED');
    assert.equal(preservedRevoked.importedAt, null);
    assert.equal(preservedRole.origin, 'LOCAL');
    assert.equal(preservedRole.action, 'ROLE_ASSIGNED');

    const importedEntries = auditsAfterRestore.filter(
      (a) => a.origin === 'BACKUP_IMPORT'
    );
    assert.equal(importedEntries.length, 2);
    for (const imp of importedEntries) {
      assert.ok(imp.id !== localRevoked.id && imp.id !== localRole.id);
      assert.equal(imp.origin, 'BACKUP_IMPORT');
      assert.equal(imp.importedFromDeviceId, 'archive-source-dev-99');
      assert.equal(typeof imp.importedAt, 'number');
    }

    // Re-exporting after restore retains explicit provenance on both local and imported rows
    const reExported = await stack.backup.exportBackup(STRONG_PASSPHRASE);
    const reDecrypted = JSON.parse(
      await stack.crypto.decryptBackupPayload({
        archive: reExported.archive,
        passphrase: STRONG_PASSPHRASE,
      })
    );
    assert.equal(reDecrypted.auditEntries.length, 4);
    assert.equal(
      reDecrypted.auditEntries.filter((a: { origin: string }) => a.origin === 'LOCAL')
        .length,
      2
    );
    assert.equal(
      reDecrypted.auditEntries.filter(
        (a: { origin: string }) => a.origin === 'BACKUP_IMPORT'
      ).length,
      2
    );
  });

  it('migrates existing IndexedDB v3 security_audit records to v4 with origin=LOCAL and zero data loss', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const factory = harness.createFactory();
    (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB = factory;

    // Seed an existing v3 IndexedDB database with legacy audit entries lacking `origin`
    const dbName = 'db-v3-to-v4-migration';
    await new Promise<void>((resolve, reject) => {
      const openReq = factory.open(dbName, 3);
      openReq.onupgradeneeded = () => {
        const db = openReq.result;
        db.createObjectStore(STORES.MIGRATIONS, { keyPath: 'version' });
        db.createObjectStore(STORES.SETTINGS, { keyPath: 'id' });
        db.createObjectStore(STORES.IDENTITY, { keyPath: 'id' });
        db.createObjectStore(STORES.LINKED_DEVICES, { keyPath: 'publicId' });
        const syncStore = db.createObjectStore(STORES.SYNC_EVENTS, {
          keyPath: 'id',
          autoIncrement: true,
        });
        syncStore.createIndex('by_status', 'status', { unique: false });
        syncStore.createIndex('by_createdAt', 'createdAt', { unique: false });
        syncStore.createIndex('by_idempotencyKey', 'idempotencyKey', { unique: true });
        syncStore.createIndex('by_notificationKey', 'notificationKey', {
          unique: false,
        });

        const auditStore = db.createObjectStore(STORES.SECURITY_AUDIT, {
          keyPath: 'id',
          autoIncrement: true,
        });
        auditStore.createIndex('by_timestamp', 'timestamp', { unique: false });
        auditStore.put({
          id: 10,
          timestamp: 1700000000100,
          action: 'DEVICE_REVOKED',
          actorRole: 'admin',
          deviceId: 'v3-device',
          outcome: 'ALLOWED',
          details: 'Legacy v3 revocation record without origin field',
        });
      };
      openReq.onsuccess = () => {
        openReq.result.close();
        resolve();
      };
      openReq.onerror = () => reject(openReq.error);
    });

    // Initialize IndexedDbDatabase (upgrades v3 -> v4)
    const db = new IndexedDbDatabase(dbName);
    await db.initialize();
    const migrations = await db.getMigrations();
    assert.ok(
      migrations.some((m) => m.version === 4 && m.name === 'v4_audit_origin_provenance')
    );

    const auditRepo = new IndexedDbAuditRepository(db);
    const migratedRows = await auditRepo.getAll();
    assert.equal(migratedRows.length, 1);
    assert.equal(migratedRows[0].id, 10);
    assert.equal(migratedRows[0].action, 'DEVICE_REVOKED');
    assert.equal(migratedRows[0].origin, 'LOCAL');
    assert.equal(migratedRows[0].importedAt, null);
  });

  it('isolates legacy v1 migration from migrating device state, freezes pending events, and blocks forged identity replay', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const migratingStack = await createRealWebCryptoStack(
      'db-v1-migrating-host',
      harness
    );
    await migratingStack.deviceRepo.saveIdentity({
      publicId: 'host-migrator-id',
      cryptoKeyId: 'host-migrator-key',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      createdAt: 1700000000000,
    });
    // Migrating host has its own locally revoked peer that must NOT leak into v1->v2 output
    await migratingStack.deviceRepo.upsertLinkedDevice({
      publicId: 'host-local-revoked-secret-peer',
      cryptoKeyId: 'ecdsa-host-revoked',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      label: 'Host Secret Revoked Peer',
      role: 'basic',
      pairingState: 'REVOKED',
      pairedAt: null,
      lastSeenAt: null,
      verifiedByRelay: false,
    });

    const targetStack = await createRealWebCryptoStack('db-v1-forged-target', harness);
    await targetStack.deviceRepo.saveIdentity({
      publicId: 'target-real-id',
      cryptoKeyId: 'target-real-key',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      createdAt: 1700000000000,
    });
    await targetStack.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'basic',
    });

    // Craft a legacy v1 archive claiming the TARGET device's identity & admin role,
    // containing PENDING/IN_PROGRESS events, a PAIRED peer matching migrating host ID,
    // and spoofed audit origin='LOCAL'
    const v1Body: Omit<LegacyBackupArchiveV1, 'checksumSha256'> = {
      schemaVersion: 3,
      exportedAt: 1700000050000,
      settings: {
        ...DEFAULT_APP_SETTINGS,
        role: 'admin',
      },
      identity: {
        publicId: 'target-real-id',
        cryptoKeyId: 'target-real-key',
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x: '1', y: '2' },
        ecdhPublicKeyJwk: { kty: 'EC', crv: 'P-256', x: '3', y: '4' },
        createdAt: 1700000000000,
      },
      linkedDevices: [
        {
          publicId: 'host-migrator-id',
          cryptoKeyId: 'host-migrator-key',
          publicKeyJwk: null,
          ecdhPublicKeyJwk: null,
          label: 'Peer Matching Host ID',
          role: 'basic',
          pairingState: 'PAIRED',
          pairedAt: 1700000010000,
          lastSeenAt: 1700000020000,
          verifiedByRelay: true,
        },
        {
          publicId: 'v1-revoked-peer',
          cryptoKeyId: 'ecdsa-v1-revoked',
          publicKeyJwk: null,
          ecdhPublicKeyJwk: null,
          label: 'V1 Revoked Peer',
          role: 'basic',
          pairingState: 'REVOKED',
          pairedAt: null,
          lastSeenAt: 1700000020000,
          verifiedByRelay: false,
        },
      ],
      syncEvents: [
        {
          id: 1,
          type: 'notification',
          payload: 'legacy-pending-must-freeze',
          createdAt: 1700000030000,
          status: 'PENDING',
          retryCount: 0,
          nextRetryAt: null,
          idempotencyKey: 'idem-v1-pending',
          encrypted: true,
        },
        {
          id: 2,
          type: 'notification',
          payload: 'legacy-inprogress-must-freeze',
          createdAt: 1700000040000,
          status: 'IN_PROGRESS',
          retryCount: 1,
          nextRetryAt: null,
          idempotencyKey: 'idem-v1-inprogress',
          encrypted: true,
        },
      ],
      auditEntries: [
        {
          id: 1,
          timestamp: 1700000045000,
          action: 'ROLE_CHANGED',
          actorRole: 'admin',
          deviceId: 'target-real-id',
          outcome: 'ALLOWED',
          details: 'سجل v1 قديم',
          origin: 'LOCAL',
        },
      ],
    };

    const canonical = JSON.stringify({
      schemaVersion: v1Body.schemaVersion,
      exportedAt: v1Body.exportedAt,
      settings: v1Body.settings,
      identity: v1Body.identity,
      linkedDevices: v1Body.linkedDevices,
      syncEvents: v1Body.syncEvents,
      auditEntries: v1Body.auditEntries,
    });
    const checksumSha256 = await migratingStack.crypto.sha256Hex(canonical);
    const v1Raw = JSON.stringify({ ...v1Body, checksumSha256 });

    // Rejects private JWK inside legacy.identity
    const taintedPrivateV1 = structuredClone({ ...v1Body, checksumSha256 });
    (taintedPrivateV1.identity!.publicKeyJwk as Record<string, unknown>).d = 'SECRET_D';
    await assert.rejects(
      () =>
        migratingStack.backup.migrateLegacyBackup(
          JSON.stringify(taintedPrivateV1),
          STRONG_PASSPHRASE,
          { userConfirmedLegacyImport: true }
        ),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'BACKUP_PRIVATE_KEY_REJECTED'
    );

    const migrated = await migratingStack.backup.migrateLegacyBackup(
      v1Raw,
      STRONG_PASSPHRASE,
      { userConfirmedLegacyImport: true }
    );
    const inner = JSON.parse(
      await migratingStack.crypto.decryptBackupPayload({
        archive: migrated.archive,
        passphrase: STRONG_PASSPHRASE,
      })
    );

    // Pure isolation & anti-forgery invariants inside migrated v2 archive
    assert.equal(inner.sourceDevice, null);
    assert.equal(inner.settings.role, null);
    assert.equal(inner.linkedDevices.length, 2);
    assert.ok(
      !inner.linkedDevices.some(
        (d: { publicId: string }) => d.publicId === 'host-local-revoked-secret-peer'
      )
    );
    assert.equal(
      inner.linkedDevices.find(
        (d: { publicId: string }) => d.publicId === 'host-migrator-id'
      ).pairingState,
      'UNPAIRED'
    );
    assert.equal(
      inner.linkedDevices.find(
        (d: { publicId: string }) => d.publicId === 'v1-revoked-peer'
      ).pairingState,
      'REVOKED'
    );
    assert.ok(inner.syncEvents.every((e: { status: string }) => e.status === 'FAILED'));
    assert.equal(inner.auditEntries[0].origin, undefined);

    // Restoring migrated v2 onto forged-target device MUST still treat as cross-device & preserve target role
    const restoreRes = await targetStack.backup.restoreBackup(
      migrated.archive,
      STRONG_PASSPHRASE
    );
    assert.equal(restoreRes.crossDeviceRestore, true);
    assert.equal(restoreRes.restoredRole, 'basic');
    assert.equal((await targetStack.settingsRepo.get()).role, 'basic');
    const restoredEvents = await targetStack.syncRepo.getAll();
    assert.ok(restoredEvents.every((e) => e.status === 'FAILED'));
    const restoredAudits = await targetStack.auditRepo.getAll();
    assert.equal(restoredAudits[0].origin, 'BACKUP_IMPORT');
  });

  it('enforces symmetric export and restore limits without silently dropping audit logs', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const stack = await createRealWebCryptoStack('db-symmetric-limits', harness);
    await stack.deviceRepo.saveIdentity({
      publicId: 'limit-dev-1',
      cryptoKeyId: 'limit-key-1',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      createdAt: 1700000000000,
    });

    // 1. Export rejects selectedNotificationApps > BACKUP_MAX_SELECTED_APPS
    await stack.settingsRepo.save({
      ...DEFAULT_APP_SETTINGS,
      role: 'admin',
      selectedNotificationApps: Array.from(
        { length: BACKUP_MAX_SELECTED_APPS + 1 },
        (_, i) => `com.app.${i}`
      ),
    });
    await assert.rejects(
      () => stack.backup.exportBackup(STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_LIMIT_EXCEEDED'
    );
    await stack.settingsRepo.save({ ...DEFAULT_APP_SETTINGS, role: 'admin' });

    // 2. Export rejects linkedDevices > BACKUP_MAX_LINKED_DEVICES
    for (let i = 0; i <= BACKUP_MAX_LINKED_DEVICES; i += 1) {
      await stack.deviceRepo.upsertLinkedDevice({
        publicId: `peer-${i}`,
        cryptoKeyId: `key-${i}`,
        publicKeyJwk: null,
        ecdhPublicKeyJwk: null,
        label: `Peer ${i}`,
        role: 'basic',
        pairingState: 'UNPAIRED',
        pairedAt: null,
        lastSeenAt: null,
        verifiedByRelay: false,
      });
    }
    await assert.rejects(
      () => stack.backup.exportBackup(STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_LIMIT_EXCEEDED'
    );
    for (let i = 0; i <= BACKUP_MAX_LINKED_DEVICES; i += 1) {
      await stack.deviceRepo.removeLinkedDevice(`peer-${i}`);
    }

    // 3. Export MUST NOT silently slice auditEntries beyond BACKUP_MAX_AUDIT_ENTRIES; it must fail explicitly
    for (let i = 0; i < BACKUP_MAX_AUDIT_ENTRIES; i += 1) {
      await stack.auditRepo.append({
        timestamp: 1700000000000 + i,
        action: 'VAULT_VERIFIED',
        actorRole: 'admin',
        deviceId: 'limit-dev-1',
        outcome: 'ALLOWED',
        details: `audit-${i}`,
      });
    }
    // At exact limit -> succeeds and exports all 1000 without dropping any
    const exactLimitExport = await stack.backup.exportBackup(STRONG_PASSPHRASE);
    assert.equal(exactLimitExport.auditCount, BACKUP_MAX_AUDIT_ENTRIES);

    // One over limit -> MUST throw BACKUP_LIMIT_EXCEEDED (never slice)
    await stack.auditRepo.append({
      timestamp: 1700000099999,
      action: 'DEVICE_REVOKED',
      actorRole: 'admin',
      deviceId: 'limit-dev-1',
      outcome: 'ALLOWED',
      details: 'must-not-be-silently-dropped',
    });
    await assert.rejects(
      () => stack.backup.exportBackup(STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_LIMIT_EXCEEDED'
    );

    // 4. Restore rejects atomically when existing local audits + archive audits > BACKUP_MAX_AUDIT_ENTRIES
    const targetStack = await createRealWebCryptoStack(
      'db-audit-limit-restore',
      harness
    );
    await targetStack.auditRepo.append({
      timestamp: 1700000000001,
      action: 'DEVICE_REVOKED',
      actorRole: 'admin',
      deviceId: 'target-dev',
      outcome: 'ALLOWED',
      details: 'existing-local-revocation-must-stay',
    });
    await assert.rejects(
      () =>
        targetStack.backup.restoreBackup(exactLimitExport.archive, STRONG_PASSPHRASE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'BACKUP_LIMIT_EXCEEDED'
    );
    const auditsAfterRejectedRestore = await targetStack.auditRepo.getAll();
    assert.equal(auditsAfterRejectedRestore.length, 1);
    assert.equal(
      auditsAfterRejectedRestore[0].details,
      'existing-local-revocation-must-stay'
    );
  });

  function createRecoveryHarness() {
    const baseIdentity = {
      publicId: 'rec-dev-1',
      cryptoKeyId: 'rec-key-1',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      createdAt: 1700000000000,
    };
    const stepsExecuted: string[] = [];
    const capturedErrors: Array<{ err: unknown; scope: ErrorSource; message: string }> =
      [];

    const deps: RestoreRecoveryDeps = {
      restoreBackup: async () => {
        stepsExecuted.push('restoreBackup');
        return {
          restoredEvents: 3,
          restoredLinkedDevices: 1,
          restoredAuditEntries: 2,
          crossDeviceRestore: true,
          restoredRole: 'admin',
        };
      },
      stopSyncEngine: async () => {
        stepsExecuted.push('stopSync');
      },
      startSyncEngine: async () => {
        stepsExecuted.push('startSync');
      },
      reloadSettings: async () => {
        stepsExecuted.push('reloadSettings');
        return {
          ...DEFAULT_APP_SETTINGS,
          role: 'admin',
          relayEndpoint: 'https://relay.example.test',
        };
      },
      getSettingsSnapshot: () => ({ ...DEFAULT_APP_SETTINGS, role: 'admin' }),
      setRelayBaseUrl: (url) => {
        stepsExecuted.push(`setRelayBaseUrl:${url}`);
      },
      initializeSecurity: async () => {
        stepsExecuted.push('initSecurity');
      },
      startDeviceManager: async () => {
        stepsExecuted.push('startDevices');
      },
      getIdentity: () => baseIdentity,
      fallbackIdentity: baseIdentity,
      issueSession: () => {
        stepsExecuted.push('issueSession');
      },
      clearSession: () => {
        stepsExecuted.push('clearSession');
      },
      recordAudit: async () => {
        stepsExecuted.push('recordAudit');
        return {
          id: 1,
          timestamp: Date.now(),
          action: 'BACKUP_RESTORED',
          actorRole: 'admin',
          deviceId: baseIdentity.publicId,
          outcome: 'ALLOWED',
          details: 'restored',
        };
      },
      captureError: (err, scope, message) => {
        capturedErrors.push({ err, scope, message });
      },
    };

    return { deps, stepsExecuted, capturedErrors };
  }

  it('aborts before restoreBackup when stopSyncEngine fails, attempts operational restart, logs error, and returns no success', async () => {
    // 1A. stopSyncEngine fails, operational restart succeeds
    const h1 = createRecoveryHarness();
    let restoreCalled = 0;
    h1.deps.stopSyncEngine = async () => {
      h1.stepsExecuted.push('stopSync:fail');
      throw new Error('partial stop failure');
    };
    h1.deps.restoreBackup = async () => {
      restoreCalled += 1;
      throw new Error('restoreBackup must not be called');
    };

    await assert.rejects(
      () => executeRestoreWithPostCommitRecovery(h1.deps),
      (err: unknown) => err instanceof Error && err.message === 'partial stop failure'
    );
    assert.equal(restoreCalled, 0);
    assert.deepEqual(h1.stepsExecuted, ['stopSync:fail', 'startSync']);
    assert.equal(h1.capturedErrors.length, 1);
    assert.equal(h1.capturedErrors[0].scope, 'SYNC');
    assert.match(h1.capturedErrors[0].message, /لم تبدأ عملية الاستعادة/);

    // 1B. stopSyncEngine fails AND operational restart ALSO fails
    const h2 = createRecoveryHarness();
    h2.deps.stopSyncEngine = async () => {
      h2.stepsExecuted.push('stopSync:fail');
      throw new Error('stop timeout');
    };
    h2.deps.startSyncEngine = async () => {
      h2.stepsExecuted.push('startSync:fail');
      throw new Error('restart rejected');
    };
    h2.deps.restoreBackup = async () => {
      restoreCalled += 1;
      throw new Error('restoreBackup must not be called');
    };

    await assert.rejects(
      () => executeRestoreWithPostCommitRecovery(h2.deps),
      (err: unknown) =>
        err instanceof AppError &&
        err.code === 'BACKUP_RESTORE_SYNC_STOP_AND_RESTART_FAILED' &&
        err.source === 'SYNC' &&
        err.cause instanceof Error &&
        err.cause.message === 'stop timeout' &&
        err.userMessage.includes('لم تُنفّذ عملية الاستعادة')
    );
    assert.equal(restoreCalled, 0);
    assert.deepEqual(h2.stepsExecuted, ['stopSync:fail', 'startSync:fail']);
    assert.equal(h2.capturedErrors.length, 2);
    assert.equal(h2.capturedErrors[0].scope, 'SYNC');
    assert.equal(h2.capturedErrors[1].scope, 'SYNC');
  });

  it('rethrows exact original error and skips post-commit steps when restoreBackup fails and startSyncEngine recovers', async () => {
    const h = createRecoveryHarness();
    const originalErr = new ValidationError(
      'BACKUP_AUTH_FAILED',
      'فشل التحقق من عبارة المرور.',
      'wrong passphrase'
    );
    h.deps.restoreBackup = async () => {
      h.stepsExecuted.push('restoreBackup:fail');
      throw originalErr;
    };

    await assert.rejects(
      () => executeRestoreWithPostCommitRecovery(h.deps),
      (err: unknown) => err === originalErr
    );
    assert.deepEqual(h.stepsExecuted, ['stopSync', 'restoreBackup:fail', 'startSync']);
    assert.equal(h.capturedErrors.length, 0);
  });

  it('records restart failure under SYNC without swallowing either error and preserves original restore error when both restoreBackup and startSyncEngine fail', async () => {
    const h = createRecoveryHarness();
    const originalErr = new ValidationError(
      'BACKUP_AUTH_FAILED',
      'فشل التحقق من عبارة المرور أو سلامة النسخة.',
      'gcm tag mismatch'
    );
    const restartErr = new Error('indexeddb closed during restart');
    h.deps.restoreBackup = async () => {
      h.stepsExecuted.push('restoreBackup:fail');
      throw originalErr;
    };
    h.deps.startSyncEngine = async () => {
      h.stepsExecuted.push('startSync:fail');
      throw restartErr;
    };

    await assert.rejects(
      () => executeRestoreWithPostCommitRecovery(h.deps),
      (err: unknown) => {
        if (!(err instanceof AppError)) return false;
        return (
          err.code === 'BACKUP_AUTH_FAILED' &&
          err.source === 'VALIDATION' &&
          err.cause === originalErr &&
          err.context?.originalError === originalErr &&
          err.context?.syncRestartError === restartErr &&
          err.context?.syncEngineRestartFailed === true &&
          err.userMessage.includes('فشل التحقق من عبارة المرور') &&
          err.userMessage.includes('تعذّر إعادة تشغيل محرك المزامنة') &&
          err.message.includes('gcm tag mismatch') &&
          err.message.includes('indexeddb closed during restart')
        );
      }
    );

    assert.deepEqual(h.stepsExecuted, [
      'stopSync',
      'restoreBackup:fail',
      'startSync:fail',
    ]);
    assert.equal(h.capturedErrors.length, 1);
    assert.equal(h.capturedErrors[0].scope, 'SYNC');
    assert.equal(h.capturedErrors[0].err, restartErr);
    assert.match(h.capturedErrors[0].message, /فشلت استعادة النسخة الاحتياطية/);
    assert.match(h.capturedErrors[0].message, /تعذّر إعادة تشغيل محرك المزامنة/);
  });

  it('completes normal stop -> restore -> service refreshes -> startSyncEngine flow in exact order', async () => {
    const h = createRecoveryHarness();

    const result = await executeRestoreWithPostCommitRecovery(h.deps);

    assert.equal(result.restoredEvents, 3);
    assert.equal(result.restoredRole, 'admin');
    assert.equal(result.syncEngineRunning, true);
    assert.equal(result.postRestoreWarnings, undefined);
    assert.equal(h.capturedErrors.length, 0);
    assert.deepEqual(h.stepsExecuted, [
      'stopSync',
      'restoreBackup',
      'reloadSettings',
      'setRelayBaseUrl:https://relay.example.test',
      'initSecurity',
      'startDevices',
      'startSync',
      'issueSession',
      'recordAudit',
    ]);
  });

  it('keeps committed restore result on post-commit failures, emits real warnings, and never claims SyncEngine is healthy/running when restart fails', async () => {
    const h = createRecoveryHarness();
    h.deps.startSyncEngine = async () => {
      h.stepsExecuted.push('startSync:fail');
      throw new Error('sync start transient failure');
    };
    h.deps.reloadSettings = async () => {
      h.stepsExecuted.push('reloadSettings:fail');
      throw new Error('settings cache reload failure');
    };
    h.deps.initializeSecurity = async () => {
      h.stepsExecuted.push('initSecurity:fail');
      throw new Error('security init failure');
    };
    h.deps.recordAudit = async () => {
      h.stepsExecuted.push('recordAudit:fail');
      throw new Error('audit write failure');
    };

    const result = await executeRestoreWithPostCommitRecovery(h.deps);

    assert.equal(result.restoredEvents, 3);
    assert.equal(result.restoredRole, 'admin');
    assert.equal(result.syncEngineRunning, false);
    assert.deepEqual(h.stepsExecuted, [
      'stopSync',
      'restoreBackup',
      'reloadSettings:fail',
      'initSecurity:fail',
      'startDevices',
      'startSync:fail',
      'issueSession',
      'recordAudit:fail',
    ]);
    assert.equal(result.postRestoreWarnings?.length, 4);
    assert.ok(
      result.postRestoreWarnings?.some(
        (w) => w.includes('محرك المزامنة') && w.includes('متوقف')
      )
    );
    assert.equal(h.capturedErrors.length, 4);
    assert.ok(h.capturedErrors.some((c) => c.scope === 'SYNC'));

    // Also verify real SyncEngine + HealthMonitor never report HEALTHY when start() fails
    // even if SYNCED events already exist in local repository
    const logger = new RotatingLogger();
    const errorManager = new ErrorManager(logger);
    const crypto = new NodeTestCryptoProvider();
    const settings = new SettingsService(new InMemorySettingsRepository(), logger);
    await settings.initialize();
    const security = new SecurityManager(crypto, new InMemoryAuditRepository(), logger);
    const transport: ITransportClient = {
      getState: (): ConnectionState => 'CONNECTED',
      getServerSession: () => null,
      getLastSuccessfulConnectionAt: () => Date.now(),
      connect: async () => {},
      disconnect: async () => {},
      revokeServerSession: async () => {},
      createPairingRequest: async (): Promise<PairingRequest> => {
        throw new Error('unused');
      },
      acceptPairingRequest: async (): Promise<PairingRequest> => {
        throw new Error('unused');
      },
      confirmPairingRequest: async () => null,
      fetchPendingPairingApprovals: async () => [],
      fetchLinkedDevices: async () => [],
      revokeDeviceLink: async () => {},
      sendSyncBatch: async () => ({
        acknowledged: true,
        acceptedIds: [],
        duplicateIds: [],
        serverTimestamp: Date.now(),
      }),
      fetchInboundEvents: async () => [],
      acknowledgeInboundDelivery: async () => {},
      fetchSyncDeliveryStatus: async () => [],
      subscribe: () => () => {},
      subscribeEvents: () => () => {},
      subscribeDeliveryAcks: () => () => {},
      subscribePairingUpdates: () => () => {},
    };
    const devices = new DeviceManager({
      deviceRepo: new InMemoryDeviceRepository(),
      crypto,
      transport,
      security,
      settings,
      logger,
    });
    let failStart = false;
    class FailingStartSyncRepo extends InMemorySyncEventRepository {
      override async initialize(): Promise<void> {
        if (failStart) {
          throw new Error('sync repo initialize failed');
        }
        await super.initialize();
      }
    }
    const flakyRepo = new FailingStartSyncRepo();
    const created = await flakyRepo.insert({
      type: 'NOTIFICATION',
      payload: 'cipher',
      idempotencyKey: 'evt-synced-1',
      notificationKey: 'notif-1',
      payloadHash: 'hash-1',
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'nonce-1',
    });
    await flakyRepo.updateEvent(created.id, { status: 'SYNCED', syncedAt: Date.now() });

    const syncEngine = new SyncEngine({
      repo: flakyRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    const healthMonitor = new HealthMonitor({
      syncEngine,
      transport,
      errorManager,
    });

    await syncEngine.start();
    assert.equal(syncEngine.getLifecycleState(), 'RUNNING');
    assert.equal(healthMonitor.getSnapshot().syncStatus, 'HEALTHY');

    await syncEngine.stop();
    assert.equal(syncEngine.getLifecycleState(), 'STOPPED');
    assert.notEqual(healthMonitor.getSnapshot().syncStatus, 'HEALTHY');

    failStart = true;
    await assert.rejects(() => syncEngine.start(), /sync repo initialize failed/);
    assert.equal(syncEngine.getLifecycleState(), 'ERROR');
    assert.equal(healthMonitor.getSnapshot().syncStatus, 'UNAVAILABLE');
  });
});
