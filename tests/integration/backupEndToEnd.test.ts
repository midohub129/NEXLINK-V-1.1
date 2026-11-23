import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import { SecurityError, ValidationError } from '../../src/domain/errors/appError';
import type { LegacyBackupArchiveV1 } from '../../src/domain/models/backup';
import type { LinkedDevice } from '../../src/domain/models/device';
import { DEFAULT_APP_SETTINGS } from '../../src/domain/models/settings';
import { WebCryptoProvider } from '../../src/infrastructure/security/webCryptoProvider';
import { APP_DB_VERSION, IndexedDbDatabase } from '../../src/infrastructure/storage/indexedDbDatabase';
import {
  IndexedDbAuditRepository,
  IndexedDbBackupProvider,
  IndexedDbDeviceRepository,
  IndexedDbSettingsRepository,
  IndexedDbSyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { InMemoryIndexedDbHarness } from '../helpers/inMemoryIndexedDb';

const PASS_A = 'Device-A-Backup-Passphrase-2026!';
const PASS_MIGRATE = 'Migrated-Legacy-V2-Passphrase-2026!';

async function createDeviceEnvironment(
  dbName: string,
  harness: InMemoryIndexedDbHarness,
  publicId: string
) {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB = harness.createFactory();
  const crypto = new WebCryptoProvider();
  const db = new IndexedDbDatabase(dbName);
  await db.initialize();

  const logger = new RotatingLogger(100);
  const settingsRepo = new IndexedDbSettingsRepository(db);
  const deviceRepo = new IndexedDbDeviceRepository(db);
  const auditRepo = new IndexedDbAuditRepository(db);
  const syncRepo = new IndexedDbSyncEventRepository(db, crypto);
  const settingsService = new SettingsService(settingsRepo, logger);
  const securityManager = new SecurityManager(crypto, auditRepo, logger);
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
    publicId,
    cryptoKeyId: keys.cryptoKeyId,
    publicKeyJwk: keys.publicKeyJwk,
    ecdhPublicKeyJwk: keys.ecdhPublicKeyJwk,
    createdAt: Date.now(),
  });
  await settingsRepo.save({
    ...DEFAULT_APP_SETTINGS,
    role: 'admin',
  });
  await settingsService.initialize();
  await securityManager.initialize();

  return {
    crypto,
    db,
    logger,
    settingsRepo,
    deviceRepo,
    auditRepo,
    syncRepo,
    settingsService,
    securityManager,
    backup,
  };
}

describe('Encrypted Backup v2 Integration: Identity/Trust Policy, Cross-Device Restore, Legacy v1 & Log Redaction', () => {
  it('preserves target device identity/keys across cross-device restore, downgrades peer trust, blocks revoked peer revival, and freezes cross-device pending events', async () => {
    const harnessA = new InMemoryIndexedDbHarness();
    const deviceA = await createDeviceEnvironment(
      'device-a-db',
      harnessA,
      'device-a-public-uuid'
    );

    const peerTrustedOnA: LinkedDevice = {
      publicId: 'peer-trusted-1',
      cryptoKeyId: 'ecdsa-peer-trusted-1',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' },
      ecdhPublicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'ghi', y: 'jkl' },
      label: 'Trusted Phone',
      role: 'basic',
      pairingState: 'PAIRED',
      pairedAt: 1700000001000,
      lastSeenAt: 1700000002000,
      verifiedByRelay: true,
    };
    const peerRevokedOnA: LinkedDevice = {
      publicId: 'peer-revoked-in-backup',
      cryptoKeyId: 'ecdsa-peer-revoked',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      label: 'Revoked Device',
      role: 'basic',
      pairingState: 'REVOKED',
      pairedAt: null,
      lastSeenAt: 1700000002000,
      verifiedByRelay: false,
    };
    await deviceA.deviceRepo.upsertLinkedDevice(peerTrustedOnA);
    await deviceA.deviceRepo.upsertLinkedDevice(peerRevokedOnA);

    await deviceA.syncRepo.insert({
      type: 'notification',
      payload: JSON.stringify({
        packageName: 'com.chat.app',
        title: 'Cross Device Secret',
        text: 'Encrypted with Device A AES key locally',
        postedAt: 1700000005000,
      }),
      idempotencyKey: 'idem-cross-pending',
      sourceDeviceId: 'device-a-public-uuid',
    });

    const syncedEvt = await deviceA.syncRepo.insert({
      type: 'notification',
      payload: JSON.stringify({
        packageName: 'com.mail.app',
        title: 'Historical Mail',
        text: 'Already synced on Device A',
        postedAt: 1700000006000,
      }),
      idempotencyKey: 'idem-cross-synced',
      sourceDeviceId: 'device-a-public-uuid',
    });
    await deviceA.syncRepo.updateEvent(syncedEvt.id, {
      status: 'SYNCED',
      syncedAt: 1700000007000,
    });

    const exportedFromA = await deviceA.backup.exportBackup(PASS_A);
    const exportedJson = JSON.stringify(exportedFromA.archive);

    // Separate Device B with completely independent WebCrypto keys & local revocation
    const harnessB = new InMemoryIndexedDbHarness();
    const deviceB = await createDeviceEnvironment(
      'device-b-db',
      harnessB,
      'device-b-public-uuid'
    );
    const identityBBefore = (await deviceB.deviceRepo.getIdentity())!;

    // On Device B, `peer-trusted-1` was ALREADY locally revoked prior to restore!
    await deviceB.deviceRepo.upsertLinkedDevice({
      ...peerTrustedOnA,
      pairingState: 'REVOKED',
      verifiedByRelay: false,
      pairedAt: null,
    });

    // Also test a clean peer inside backup that was PAIRED on A (must downgrade to UNPAIRED)
    const innerWithExtraPeer = JSON.parse(
      await deviceB.crypto.decryptBackupPayload({
        archive: exportedFromA.archive,
        passphrase: PASS_A,
      })
    );
    innerWithExtraPeer.linkedDevices.push({
      publicId: 'peer-paired-only-in-backup',
      cryptoKeyId: 'ecdsa-peer-extra',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      label: 'Another Paired Peer',
      role: 'basic',
      pairingState: 'PAIRED',
      pairedAt: 1700000001000,
      lastSeenAt: 1700000002000,
      verifiedByRelay: true,
    });
    const rewrappedForB = await deviceA.crypto.encryptBackupPayload({
      plaintext: JSON.stringify(innerWithExtraPeer),
      passphrase: PASS_A,
      schemaVersion: APP_DB_VERSION,
      exportedAt: innerWithExtraPeer.exportedAt,
    });

    const result = await deviceB.backup.restoreBackup(
      JSON.stringify(rewrappedForB),
      PASS_A
    );
    assert.equal(result.crossDeviceRestore, true);
    assert.equal(result.restoredEvents, 2);

    // 17. Device B keeps its own identity and keys (NEVER replaced by Device A!)
    const identityBAfter = (await deviceB.deviceRepo.getIdentity())!;
    assert.equal(identityBAfter.publicId, 'device-b-public-uuid');
    assert.equal(identityBAfter.cryptoKeyId, identityBBefore.cryptoKeyId);
    assert.notEqual(identityBAfter.cryptoKeyId, (await deviceA.deviceRepo.getIdentity())!.cryptoKeyId);

    // 18 & 19. Linked devices NEVER auto-trusted; locally REVOKED peer stays REVOKED!
    const restoredPeersB = await deviceB.deviceRepo.getLinkedDevices();
    const peer1After = restoredPeersB.find((d) => d.publicId === 'peer-trusted-1')!;
    const peer2After = restoredPeersB.find(
      (d) => d.publicId === 'peer-revoked-in-backup'
    )!;
    const peer3After = restoredPeersB.find(
      (d) => d.publicId === 'peer-paired-only-in-backup'
    )!;

    assert.equal(peer1After.pairingState, 'REVOKED');
    assert.equal(peer1After.verifiedByRelay, false);
    assert.equal(peer2After.pairingState, 'REVOKED');
    assert.equal(peer2After.verifiedByRelay, false);
    assert.equal(peer3After.pairingState, 'UNPAIRED');
    assert.equal(peer3After.verifiedByRelay, false);
    assert.equal(peer3After.pairedAt, null);

    // 20. Device B can decrypt restored events using Device B's own local AES key;
    // Cross-device PENDING event is frozen to FAILED so B doesn't re-send with A's identity!
    const eventsB = await deviceB.syncRepo.getAll();
    assert.equal(eventsB.length, 2);
    const crossPending = eventsB.find(
      (e) => e.idempotencyKey === 'idem-cross-pending'
    )!;
    const crossSynced = eventsB.find(
      (e) => e.idempotencyKey === 'idem-cross-synced'
    )!;
    assert.equal(crossPending.status, 'FAILED');
    assert.ok(crossPending.payload.includes('Cross Device Secret'));
    assert.equal(crossSynced.status, 'SYNCED');
    assert.ok(crossSynced.payload.includes('Historical Mail'));

    // Also verify rejecting backup containing private JWK 'd' parameter inside linkedDevices
    const poisonedInner = structuredClone(innerWithExtraPeer);
    poisonedInner.linkedDevices[0].publicKeyJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: 'abc',
      y: 'def',
      d: 'LEAKED_PRIVATE_KEY',
    };
    const poisonedArchive = await deviceA.crypto.encryptBackupPayload({
      plaintext: JSON.stringify(poisonedInner),
      passphrase: PASS_A,
      schemaVersion: APP_DB_VERSION,
      exportedAt: poisonedInner.exportedAt,
    });
    await assert.rejects(
      () => deviceB.backup.restoreBackup(poisonedArchive, PASS_A),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'BACKUP_PRIVATE_KEY_REJECTED'
    );

    void exportedJson;
  });

  it('rejects legacy v1 unencrypted backups by default and safely migrates v1 to encrypted v2 on explicit confirmation without leaking secrets to logs', async () => {
    const harness = new InMemoryIndexedDbHarness();
    const env = await createDeviceEnvironment(
      'legacy-migration-db',
      harness,
      'device-current-uuid'
    );

    await env.syncRepo.insert({
      type: 'notification',
      payload: 'current-live-event-stays',
      idempotencyKey: 'idem-current-live',
    });

    const legacyBodyWithoutChecksum: Omit<LegacyBackupArchiveV1, 'checksumSha256'> = {
      schemaVersion: 3,
      exportedAt: 1700000010000,
      settings: {
        ...DEFAULT_APP_SETTINGS,
        role: 'admin',
      },
      identity: {
        publicId: 'legacy-device-uuid',
        cryptoKeyId: 'ecdsa-legacy-1234',
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x: '1', y: '2' },
        ecdhPublicKeyJwk: { kty: 'EC', crv: 'P-256', x: '3', y: '4' },
        createdAt: 1700000000000,
      },
      linkedDevices: [
        {
          publicId: 'legacy-peer-paired',
          cryptoKeyId: 'ecdsa-legacy-peer',
          publicKeyJwk: null,
          ecdhPublicKeyJwk: null,
          label: 'Legacy Paired Peer',
          role: 'basic',
          pairingState: 'PAIRED',
          pairedAt: 1700000005000,
          lastSeenAt: 1700000006000,
          verifiedByRelay: true,
        },
        {
          publicId: 'legacy-peer-revoked',
          cryptoKeyId: 'ecdsa-legacy-revoked',
          publicKeyJwk: null,
          ecdhPublicKeyJwk: null,
          label: 'Legacy Revoked Peer',
          role: 'basic',
          pairingState: 'REVOKED',
          pairedAt: null,
          lastSeenAt: 1700000006000,
          verifiedByRelay: false,
        },
      ],
      syncEvents: [
        {
          id: 1,
          type: 'notification',
          payload: JSON.stringify({
            packageName: 'com.legacy.app',
            title: 'Legacy Secret Title',
            text: 'Legacy sensitive body',
            postedAt: 1700000009000,
          }),
          createdAt: 1700000009000,
          status: 'SYNCED',
          retryCount: 0,
          nextRetryAt: null,
          idempotencyKey: 'idem-legacy-1',
          encrypted: true,
          syncedAt: 1700000009500,
        },
      ],
      auditEntries: [],
    };

    const canonical = JSON.stringify({
      schemaVersion: legacyBodyWithoutChecksum.schemaVersion,
      exportedAt: legacyBodyWithoutChecksum.exportedAt,
      settings: legacyBodyWithoutChecksum.settings,
      identity: legacyBodyWithoutChecksum.identity,
      linkedDevices: legacyBodyWithoutChecksum.linkedDevices,
      syncEvents: legacyBodyWithoutChecksum.syncEvents,
      auditEntries: legacyBodyWithoutChecksum.auditEntries,
    });
    const checksumSha256 = await env.crypto.sha256Hex(canonical);
    const legacyArchive: LegacyBackupArchiveV1 = {
      ...legacyBodyWithoutChecksum,
      checksumSha256,
    };
    const legacyRaw = JSON.stringify(legacyArchive);

    // Format detection identifies legacy v1 cleanly
    assert.equal(env.backup.inspectBackupJson(legacyRaw).kind, 'LEGACY_UNENCRYPTED_V1');

    // 21. Default restore rejects legacy unencrypted v1 backup
    await assert.rejects(
      () => env.backup.restoreBackup(legacyRaw, PASS_MIGRATE),
      (err: unknown) =>
        err instanceof ValidationError && err.code === 'LEGACY_UNENCRYPTED_BACKUP'
    );
    assert.equal((await env.syncRepo.getAll()).length, 1);

    // 22. Migration requires explicit user confirmation
    await assert.rejects(
      () =>
        env.backup.migrateLegacyBackup(legacyRaw, PASS_MIGRATE, {
          userConfirmedLegacyImport: false,
        }),
      (err: unknown) =>
        err instanceof ValidationError &&
        err.code === 'LEGACY_MIGRATION_CONFIRMATION_REQUIRED'
    );

    // Confirmed migration creates encrypted v2 WITHOUT altering current live DB
    const migrated = await env.backup.migrateLegacyBackup(legacyRaw, PASS_MIGRATE, {
      userConfirmedLegacyImport: true,
    });
    const migratedJson = JSON.stringify(migrated.archive);
    assert.equal(migrated.archive.formatVersion, 2);
    assert.ok(!migratedJson.includes('Legacy Secret Title'));
    assert.ok(!migratedJson.includes(PASS_MIGRATE));
    assert.equal(
      (await env.syncRepo.getAll())[0].idempotencyKey,
      'idem-current-live'
    );

    // 23. Restoring the migrated v2 enforces trust/identity policies
    await env.backup.restoreBackup(migratedJson, PASS_MIGRATE);
    const currentId = (await env.deviceRepo.getIdentity())!;
    assert.equal(currentId.publicId, 'device-current-uuid');

    const migratedPeers = await env.deviceRepo.getLinkedDevices();
    assert.equal(
      migratedPeers.find((p) => p.publicId === 'legacy-peer-paired')!.pairingState,
      'UNPAIRED'
    );
    assert.equal(
      migratedPeers.find((p) => p.publicId === 'legacy-peer-paired')!.verifiedByRelay,
      false
    );
    assert.equal(
      migratedPeers.find((p) => p.publicId === 'legacy-peer-revoked')!.pairingState,
      'REVOKED'
    );

    // 27. Ensure passphrases & decrypted contents never leak into logger or audit logs
    env.logger.info('BACKUP', 'Backup lifecycle completed', {
      passphrase: PASS_MIGRATE,
      plaintext: 'Legacy Secret Title',
      eventCount: migrated.eventCount,
    });
    const logsStr = JSON.stringify(env.logger.getLogs());
    const auditsStr = JSON.stringify(await env.auditRepo.getAll());
    assert.ok(!logsStr.includes(PASS_MIGRATE));
    assert.ok(!logsStr.includes('Legacy Secret Title'));
    assert.ok(!auditsStr.includes(PASS_MIGRATE));
    assert.ok(!auditsStr.includes('Legacy Secret Title'));
  });
});
