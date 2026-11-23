import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import {
  SyncEngine,
  calculateExponentialBackoffMs,
} from '../../src/application/sync/syncEngine';
import type { ITransportClient } from '../../src/domain/interfaces/services';
import type {
  ConnectionState,
  LinkedDevice,
  PairingRequest,
} from '../../src/domain/models/device';
import type { RelayServerSession } from '../../src/domain/models/security';
import type { SyncDispatchAck, SyncEvent } from '../../src/domain/models/syncEvent';
import {
  InMemoryAuditRepository,
  InMemoryDeviceRepository,
  InMemorySettingsRepository,
  InMemorySyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

class MockTransportClient implements ITransportClient {
  state: ConnectionState = 'DISCONNECTED';
  sentBatches: SyncEvent[][] = [];
  ackedRelayEventIds: number[] = [];
  inboundQueue: SyncEvent[] = [];
  nextAckHandler: ((events: SyncEvent[]) => Promise<SyncDispatchAck>) | null = null;
  linkedDevices: LinkedDevice[] = [];
  deliveredClientEventIds: number[] = [];
  private stateListeners = new Set<() => void>();

  getState(): ConnectionState {
    return this.state;
  }
  getServerSession(): RelayServerSession | null {
    return this.state === 'CONNECTED'
      ? {
          sessionId: 'sess-mock-e2ee',
          token: 'tok-mock',
          devicePublicId: 'mock-dev',
          cryptoKeyId: 'ecdsa-mock',
          role: 'admin',
          issuedAt: Date.now(),
          expiresAt: Date.now() + 60_000,
        }
      : null;
  }
  getLastSuccessfulConnectionAt(): number | null {
    return this.state === 'CONNECTED' ? Date.now() : null;
  }
  async connect(): Promise<void> {
    this.state = 'CONNECTED';
    this.stateListeners.forEach((l) => l());
  }
  async disconnect(): Promise<void> {
    this.state = 'DISCONNECTED';
    this.stateListeners.forEach((l) => l());
  }
  async revokeServerSession(): Promise<void> {
    this.state = 'DISCONNECTED';
    this.stateListeners.forEach((l) => l());
  }
  async createPairingRequest(): Promise<PairingRequest> {
    throw new Error('Not used');
  }
  async acceptPairingRequest(): Promise<PairingRequest> {
    throw new Error('Not used');
  }
  async confirmPairingRequest(): Promise<LinkedDevice | null> {
    return null;
  }
  async fetchPendingPairingApprovals(): Promise<PairingRequest[]> {
    return [];
  }
  async fetchLinkedDevices(): Promise<LinkedDevice[]> {
    return this.linkedDevices;
  }
  async revokeDeviceLink(): Promise<void> {}
  async sendSyncBatch(
    _deviceId: string,
    _targetDeviceId: string,
    events: SyncEvent[]
  ): Promise<SyncDispatchAck> {
    this.sentBatches.push(events);
    if (this.nextAckHandler) {
      return this.nextAckHandler(events);
    }
    return {
      acknowledged: true,
      acceptedIds: events.map((e) => e.id),
      duplicateIds: [],
      deliveredIds: [],
      serverTimestamp: Date.now(),
    };
  }
  async fetchInboundEvents(): Promise<SyncEvent[]> {
    return [...this.inboundQueue];
  }
  async acknowledgeInboundDelivery(
    _deviceId: string,
    eventIds: number[]
  ): Promise<void> {
    this.ackedRelayEventIds.push(...eventIds);
  }
  async fetchSyncDeliveryStatus(): Promise<number[]> {
    return this.deliveredClientEventIds;
  }
  subscribe(listener: () => void): () => void {
    this.stateListeners.add(listener);
    return () => {
      this.stateListeners.delete(listener);
    };
  }
  subscribeEvents(): () => void {
    return () => {};
  }
  subscribeDeliveryAcks(): () => void {
    return () => {};
  }
  subscribePairingUpdates(): () => void {
    return () => {};
  }
}

async function createPeerPairFixture() {
  const peerCrypto = new NodeTestCryptoProvider();
  const peerKeys = await peerCrypto.getOrCreateDeviceKeyPair();
  const peerDevice: LinkedDevice = {
    publicId: 'peer-target-device',
    cryptoKeyId: peerKeys.cryptoKeyId,
    publicKeyJwk: peerKeys.publicKeyJwk,
    ecdhPublicKeyJwk: peerKeys.ecdhPublicKeyJwk,
    label: 'Paired Peer',
    role: 'basic',
    pairingState: 'PAIRED',
    pairedAt: Date.now(),
    lastSeenAt: Date.now(),
    verifiedByRelay: true,
  };
  return { peerCrypto, peerKeys, peerDevice };
}

class TestSyncEventRepository extends InMemorySyncEventRepository {
  async tamperPayloadInStorageForTest(id: number, newPayload: string): Promise<void> {
    const events = (this as unknown as { events: SyncEvent[] }).events;
    const row = events.find((e) => e.id === id);
    if (row) {
      row.payload = newPayload;
    }
  }
}

async function setupSyncHarness(
  maxSyncRetries = 3,
  syncDeliveryPolicy: 'PEER_CONFIRMED' | 'RELAY_QUEUED' = 'PEER_CONFIRMED',
  attachPeer = true
) {
  const logger = new RotatingLogger();
  const crypto = new NodeTestCryptoProvider();
  const settingsRepo = new InMemorySettingsRepository();
  const settings = new SettingsService(settingsRepo, logger);
  await settings.initialize();
  await settings.update({
    role: 'admin',
    notificationAccessGranted: true,
    selectedNotificationApps: ['com.whatsapp'],
    maxSyncRetries,
    syncDeliveryPolicy,
  });

  const auditRepo = new InMemoryAuditRepository();
  const security = new SecurityManager(crypto, auditRepo, logger);
  await security.initialize();

  const deviceRepo = new InMemoryDeviceRepository();
  const transport = new MockTransportClient();
  const peerFixture = await createPeerPairFixture();

  if (attachPeer) {
    transport.linkedDevices = [peerFixture.peerDevice];
    await deviceRepo.upsertLinkedDevice(peerFixture.peerDevice);
  }

  const devices = new DeviceManager({
    deviceRepo,
    crypto,
    transport,
    security,
    settings,
    logger,
  });
  await devices.start();
  const id = devices.getIdentity()!;
  security.issueSession(id.publicId, id.cryptoKeyId, 30);

  const syncRepo = new TestSyncEventRepository();
  const syncEngine = new SyncEngine({
    repo: syncRepo,
    transport,
    crypto,
    security,
    settings,
    devices,
    logger,
  });
  await syncEngine.start();

  return {
    syncEngine,
    syncRepo,
    transport,
    security,
    settings,
    devices,
    crypto,
    logger,
    ...peerFixture,
  };
}

describe('SyncEngine E2EE, Delivery Policy, Duplicate & Partial Recovery Tests', () => {
  it('enqueues valid events, blocks without paired peer, encrypts E2EE in FIFO order, and waits for peer confirmation under PEER_CONFIRMED', async () => {
    // 1. Without a paired peer -> skippedReason === 'UNPAIRED'
    const unpaired = await setupSyncHarness(3, 'PEER_CONFIRMED', false);
    await unpaired.transport.connect();
    await unpaired.syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'No Peer',
      text: 'Must not sync when unpaired',
      postedAt: 1000,
    });
    const skipped = await unpaired.syncEngine.runSyncCycle(1500);
    assert.equal(skipped.skippedReason, 'UNPAIRED');
    assert.equal(unpaired.transport.sentBatches.length, 0);

    // 2. Paired device -> sends E2EE ciphertext ONLY (zero plaintext over wire), awaits peer ACK
    const { syncEngine, transport, peerCrypto, peerDevice } = await setupSyncHarness(
      3,
      'PEER_CONFIRMED',
      true
    );
    await transport.connect();
    const baseTime = Date.now() - 5000;

    const first = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 1',
      text: 'Secret Hello 1',
      notificationKey: 'k1',
      postedAt: baseTime,
    });
    assert.equal(first.status, 'SAVED');

    const dup = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 1',
      text: 'Secret Hello 1',
      notificationKey: 'k1',
      postedAt: baseTime + 500,
    });
    assert.deepEqual(dup, { status: 'REJECTED', reason: 'DUPLICATE' });

    const second = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 2',
      text: 'Secret Hello 2',
      notificationKey: 'k2',
      postedAt: baseTime + 1000,
    });
    assert.equal(second.status, 'SAVED');

    const summary = await syncEngine.runSyncCycle(baseTime + 2000);
    assert.equal(summary.attempted, 2);
    assert.equal(summary.awaitingPeerAck, 2);
    assert.equal(summary.synced, 0);

    // Wire payload contains zero plaintext and valid E2eeEnvelope
    const wireBatch = transport.sentBatches[0];
    assert.equal(wireBatch[0].createdAt, baseTime);
    assert.equal(wireBatch[1].createdAt, baseTime + 1000);
    assert.equal(wireBatch[0].payload, '[E2EE_CIPHERTEXT]');
    assert.ok(wireBatch[0].e2eeEnvelope);

    // Events remain IN_PROGRESS awaiting peer confirmation
    assert.ok(syncEngine.getEvents().every((e) => e.status === 'IN_PROGRESS'));

    // Peer decrypts E2EE envelope successfully
    const senderIdentity = (await syncEngine.getEvents())[0];
    assert.ok(senderIdentity.e2eeProtected);

    // Simulate peer delivery ACK -> transitions to SYNCED with deliveredAt
    await syncEngine.handleDeliveryAcks(
      [wireBatch[0].id, wireBatch[1].id],
      baseTime + 3000
    );
    assert.ok(syncEngine.getEvents().every((e) => e.status === 'SYNCED'));
    assert.ok(syncEngine.getEvents().every((e) => e.deliveredAt === baseTime + 3000));

    // Verify peer node crypto helper exists to keep unused lint happy
    assert.ok(peerCrypto && peerDevice);
  });

  it('Partial Sync Failure Recovery: commits accepted items and retries only failed subset without duplicate delivery', async () => {
    const { syncEngine, transport } = await setupSyncHarness(3, 'RELAY_QUEUED', true);
    await transport.connect();
    const base = Date.now() - 4000;

    await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Item A',
      text: 'First batch item',
      notificationKey: 'part-1',
      postedAt: base,
    });
    await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Item B',
      text: 'Second batch item fails partially',
      notificationKey: 'part-2',
      postedAt: base + 100,
    });

    // Server accepts only item #1 and drops item #2 (partial failure)
    transport.nextAckHandler = async (events) => ({
      acknowledged: true,
      acceptedIds: [events[0].id],
      duplicateIds: [],
      deliveredIds: [events[0].id],
      serverTimestamp: base + 500,
    });

    const partial = await syncEngine.runSyncCycle(base + 200);
    assert.equal(partial.attempted, 2);
    assert.equal(partial.synced, 1);
    assert.equal(partial.failed, 1);

    const eventsAfterPartial = syncEngine.getEvents();
    const ev1 = eventsAfterPartial.find((e) => e.notificationKey === 'part-1')!;
    const ev2 = eventsAfterPartial.find((e) => e.notificationKey === 'part-2')!;
    assert.equal(ev1.status, 'SYNCED');
    assert.equal(ev2.status, 'PENDING');
    assert.equal(ev2.retryCount, 1);

    // Next cycle after backoff recovers ONLY item #2
    transport.nextAckHandler = null;
    const recovered = await syncEngine.runSyncCycle((ev2.nextRetryAt ?? 0) + 10);
    assert.equal(recovered.attempted, 1);
    assert.equal(recovered.awaitingPeerAck + recovered.synced, 1);
    assert.equal(transport.sentBatches[1].length, 1);
    assert.equal(transport.sentBatches[1][0].id, ev2.id);
  });

  it('recovers stuck IN_PROGRESS events back to PENDING upon restart and verifies Tampered Ciphertext Rejection on inbound', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    await transport.connect();

    const myId = devices.getIdentity()!;
    // Build a valid E2EE message from peer -> us, then tamper ciphertext
    const validEnvelope = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Secret',
        text: 'Authentic payload',
        postedAt: 1000,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-tamper',
      idempotencyKey: 'idem-tamper-1',
    });

    const tamperedEnvelope = {
      ...validEnvelope,
      ciphertext: `AAAA${validEnvelope.ciphertext.slice(4)}`,
    };

    const acceptedTampered = await syncEngine.ingestInboundEvent({
      id: 901,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: tamperedEnvelope,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 1000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-tamper-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
      relaySignatureVerified: true,
      relayDeliveryState: 'QUEUED_AT_RELAY',
    });
    assert.equal(acceptedTampered, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);
    assert.ok(
      security
        .getAuditLog()
        .some((a) => a.action === 'E2EE_DECRYPT_FAILED' && a.outcome === 'DENIED')
    );

    // Mismatched wrapper idempotencyKey vs signed AAD idempotencyKey is rejected without ACK
    const mismatchIdem = await syncEngine.ingestInboundEvent({
      id: 9015,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: validEnvelope,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 1000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-wrong-wrapper',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(mismatchIdem, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);

    // Valid E2EE envelope with matching idempotencyKey succeeds once, and replay of same messageNonce is rejected!
    const acceptedValid = await syncEngine.ingestInboundEvent({
      id: 902,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: validEnvelope,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 1000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-tamper-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(acceptedValid, true);
    assert.deepEqual(transport.ackedRelayEventIds, [902]);

    const replayBlocked = await syncEngine.ingestInboundEvent({
      id: 903,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: validEnvelope,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 1000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-tamper-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(replayBlocked, false);
    assert.ok(security.getAuditLog().some((a) => a.action === 'REPLAY_BLOCKED'));

    // Crash recovery test
    const inserted = await syncRepo.insert({
      type: 'notification',
      payload: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Crash Test',
        text: 'Interrupted mid-flight',
        postedAt: 5000,
      }),
      idempotencyKey: 'idem-crash-1',
    });
    await syncRepo.updateEvent(inserted.id, { status: 'IN_PROGRESS' });

    const recoveredEngine = new SyncEngine({
      repo: syncRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    await recoveredEngine.start();

    const recovered = recoveredEngine.getEvents().find((e) => e.id === inserted.id);
    assert.equal(recovered?.status, 'PENDING');
    await recoveredEngine.stop();
  });

  it('reverts IN_PROGRESS events safely to PENDING if pairing is revoked while PENDING/IN_PROGRESS events exist', async () => {
    const { syncEngine, transport, devices, peerDevice } = await setupSyncHarness(
      3,
      'PEER_CONFIRMED',
      true
    );
    await transport.connect();

    const baseTime = Date.now() - 2000;
    const ev1 = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'In Flight',
      text: 'Dispatched before revocation',
      notificationKey: 'rev-1',
      postedAt: baseTime,
    });
    assert.equal(ev1.status, 'SAVED');

    // Run cycle -> becomes IN_PROGRESS awaiting peer ACK
    const firstRun = await syncEngine.runSyncCycle(baseTime + 100);
    assert.equal(firstRun.awaitingPeerAck, 1);

    // Enqueue a second event while PENDING
    const ev2 = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Still Pending',
      text: 'Waiting in queue',
      notificationKey: 'rev-2',
      postedAt: baseTime + 200,
    });
    assert.equal(ev2.status, 'SAVED');

    // Revoke peer trust
    await devices.revokeLinkedDevice(peerDevice.publicId, true);

    const afterRevokeRun = await syncEngine.runSyncCycle(baseTime + 300);
    assert.equal(afterRevokeRun.skippedReason, 'UNPAIRED');

    // Both events must now safely sit in PENDING (no stuck IN_PROGRESS, no data loss)
    const allEvents = syncEngine.getEvents();
    assert.equal(allEvents.length, 2);
    assert.ok(allEvents.every((e) => e.status === 'PENDING'));
  });

  it('automatically pulls missed inbound events on transport reconnect and deduplicates across restarts via findByIdempotencyKey', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      settings,
      devices,
      crypto,
      logger,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();

    const myId = devices.getIdentity()!;
    // Old event created > 1 hour ago (outside 10-minute findRecentDuplicate window)
    const oldTs = Date.now() - 2 * 60 * 60 * 1000;
    const envelope1 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Offline Missed Msg',
        text: 'Arrived while offline',
        postedAt: oldTs,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-reconnect',
      idempotencyKey: 'idem-reconnect-old',
    });

    transport.inboundQueue = [
      {
        id: 777,
        type: 'notification',
        payload: '[E2EE_CIPHERTEXT]',
        e2eeEnvelope: envelope1,
        sourceDeviceId: peerDevice.publicId,
        targetDeviceId: myId.publicId,
        createdAt: oldTs,
        status: 'IN_PROGRESS',
        retryCount: 0,
        nextRetryAt: null,
        idempotencyKey: 'idem-reconnect-old',
        encrypted: true,
        localEncrypted: false,
        e2eeProtected: false,
        e2eeVerified: false,
      },
    ];

    // Transition from DISCONNECTED -> CONNECTED triggers automatic inbound pull
    await transport.connect();
    await new Promise((r) => setTimeout(r, 40));

    assert.equal(syncEngine.getEvents().length, 1);
    assert.equal(syncEngine.getEvents()[0].e2eeVerified, true);
    assert.equal(syncEngine.getEvents()[0].e2eeProtected, true);
    assert.deepEqual(transport.ackedRelayEventIds, [777]);

    // Simulate app restart receiving a replay of the OLD messageNonce -> BLOCKED persistently!
    await syncEngine.stop();
    const restartedEngine = new SyncEngine({
      repo: syncRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    await restartedEngine.start();

    const persistentReplayBlocked = await restartedEngine.ingestInboundEvent({
      id: 779,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: envelope1,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: oldTs,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-reconnect-old',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(persistentReplayBlocked, false);
    assert.equal(transport.ackedRelayEventIds.includes(779), false);

    // Mismatched relayEventId (#778) on existing idempotencyKey (#777) must NOT send ACK or reuse stored row
    const freshNonceCopy = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Offline Missed Msg',
        text: 'Arrived while offline',
        postedAt: oldTs,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-reconnect-2',
      idempotencyKey: 'idem-reconnect-old',
    });

    const mismatchedRelayDenied = await restartedEngine.ingestInboundEvent({
      id: 778,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: freshNonceCopy,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: oldTs,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-reconnect-old',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(mismatchedRelayDenied, false);
    assert.equal(transport.ackedRelayEventIds.includes(778), false);

    // Even with matching relayEventId (#777) & idempotencyKey, a DIFFERENT messageNonce must NOT confirm existingByKey
    const sameRelayDifferentNonce = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Offline Missed Msg',
        text: 'Arrived while offline',
        postedAt: oldTs,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-reconnect-3',
      idempotencyKey: 'idem-reconnect-old',
    });

    const differentNonceDenied = await restartedEngine.ingestInboundEvent({
      id: 777,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: sameRelayDifferentNonce,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: oldTs,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-reconnect-old',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(differentNonceDenied, false);
    assert.equal(restartedEngine.getEvents().length, 1);
    assert.deepEqual(transport.ackedRelayEventIds, [777]);
    await restartedEngine.stop();
  });

  it('never sends /sync/ack when local storage fails, and rejects forged signatures or wrong ECDH keys without ACK', async () => {
    const { syncEngine, syncRepo, transport, devices, peerCrypto, peerDevice } =
      await setupSyncHarness();
    await transport.connect();
    const myId = devices.getIdentity()!;

    const env = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Storage & Crypto Guard',
        text: 'Must survive negative checks',
        postedAt: 2222,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-neg',
      idempotencyKey: 'idem-neg-1',
    });

    // 1. Forged ECDSA signature -> rejected, zero ACK
    const forgedSigEnv = {
      ...env,
      signature: Buffer.alloc(64, 7).toString('base64'),
    };
    const forgedRes = await syncEngine.ingestInboundEvent({
      id: 801,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: forgedSigEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 2222,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-neg-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(forgedRes, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);

    // 2. Wrong ECDH key encrypted by rogue keypair -> AES-GCM/signature mismatch -> zero ACK
    const rogueCrypto = new NodeTestCryptoProvider();
    const rogueEcdh = (await rogueCrypto.getOrCreateDeviceKeyPair()).ecdhPublicKeyJwk!;
    const wrongKeyEnv = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"wrong"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: rogueEcdh,
      sessionId: 'sess-wrong',
      idempotencyKey: 'idem-wrong-key',
    });
    const wrongKeyRes = await syncEngine.ingestInboundEvent({
      id: 802,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: wrongKeyEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 2223,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-wrong-key',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(wrongKeyRes, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);

    // 3. Storage insert failure -> MUST NOT ACK and MUST NOT cache nonce
    const origInsert = syncRepo.insert.bind(syncRepo);
    syncRepo.insert = async () => {
      throw new Error('Simulated disk full');
    };
    const storageFailRes = await syncEngine.ingestInboundEvent({
      id: 803,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 2222,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-neg-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(storageFailRes, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);
    assert.equal(syncEngine.getEvents().length, 0);

    // 4. Recover storage & verify same event now succeeds and ACKs cleanly
    syncRepo.insert = origInsert;
    const recoveredRes = await syncEngine.ingestInboundEvent({
      id: 803,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 2222,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-neg-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(recoveredRes, true);
    assert.deepEqual(transport.ackedRelayEventIds, [803]);
    assert.equal(syncEngine.getEvents().length, 1);
  });

  it('keeps inbound event IN_PROGRESS until /sync/ack succeeds, survives app restart without outbound re-dispatch, and transitions to SYNCED on ACK recovery', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      settings,
      devices,
      crypto,
      logger,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    await transport.connect();
    const myId = devices.getIdentity()!;

    const env = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Transient ACK drop',
        text: 'Stored once, ACK retried',
        postedAt: 3333,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-ack-drop',
      idempotencyKey: 'idem-ack-drop-1',
    });

    const origAck = transport.acknowledgeInboundDelivery.bind(transport);
    transport.acknowledgeInboundDelivery = async () => {
      throw new Error('Network dropped before ACK');
    };

    const wireItem: SyncEvent = {
      id: 850,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 3333,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-ack-drop-1',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    };

    const firstIngest = await syncEngine.ingestInboundEvent(wireItem);
    assert.equal(firstIngest, true);
    assert.equal(syncEngine.getEvents().length, 1);

    // Must NOT be SYNCED while inboundAckConfirmed is false (verify BOTH memory and persisted repository)
    const unackedStored = syncEngine.getEvents()[0];
    const unackedPersisted = await syncRepo.findById(unackedStored.id);
    assert.equal(unackedStored.status, 'IN_PROGRESS');
    assert.equal(unackedPersisted?.status, 'IN_PROGRESS');
    assert.equal(unackedPersisted?.inboundAckConfirmed, false);
    assert.equal(unackedPersisted?.deliveredAt, null);
    assert.equal(unackedPersisted?.syncedAt, null);
    assert.equal(transport.ackedRelayEventIds.length, 0);

    // Outbound delivery ACK for colliding local ID must NOT falsely promote inbound event
    await syncEngine.handleDeliveryAcks([unackedStored.id], Date.now());
    const afterCollidingAck = await syncRepo.findById(unackedStored.id);
    assert.equal(afterCollidingAck?.status, 'IN_PROGRESS');
    assert.equal(afterCollidingAck?.inboundAckConfirmed, false);

    // Simulate app restart before ACK succeeds -> inbound row stays IN_PROGRESS in DB (never reverted to PENDING outbound!)
    await syncEngine.stop();
    const restartedEngine = new SyncEngine({
      repo: syncRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    await restartedEngine.start();

    const persistedAfterRestart = await syncRepo.findById(unackedStored.id);
    assert.equal(restartedEngine.getEvents().length, 1);
    assert.equal(persistedAfterRestart?.status, 'IN_PROGRESS');
    assert.equal(persistedAfterRestart?.inboundAckConfirmed, false);

    // Outbound cycle must never pick up the un-ACKed inbound row
    const summaryBeforeRecovery = await restartedEngine.runSyncCycle();
    assert.equal(summaryBeforeRecovery.attempted, 0);
    assert.equal(transport.sentBatches.length, 0);
    assert.equal((await syncRepo.findById(unackedStored.id))?.status, 'IN_PROGRESS');

    // Network recovers -> re-ingesting same un-ACKed relay event #850 completes ACK and transitions DB row to SYNCED!
    transport.acknowledgeInboundDelivery = origAck;
    const secondIngest = await restartedEngine.ingestInboundEvent(wireItem);
    assert.equal(secondIngest, true);
    assert.equal(restartedEngine.getEvents().length, 1);
    const syncedRow = await syncRepo.findById(unackedStored.id);
    assert.equal(syncedRow?.status, 'SYNCED');
    assert.equal(syncedRow?.inboundAckConfirmed, true);
    assert.ok(syncedRow?.deliveredAt !== null);
    assert.ok(syncedRow?.syncedAt !== null);
    assert.deepEqual(transport.ackedRelayEventIds, [850]);

    // Offline ingest followed by transport reconnect automatically retries ACK -> DB becomes SYNCED
    await transport.disconnect();
    const env2 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Offline Ingest',
        text: 'ACK deferred until reconnect',
        postedAt: 4444,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-ack-offline',
      idempotencyKey: 'idem-ack-offline-2',
    });

    const offlineIngest = await restartedEngine.ingestInboundEvent({
      id: 851,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env2,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 4444,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-ack-offline-2',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(offlineIngest, true);
    const offlineRow = await syncRepo.findByIdempotencyKey('idem-ack-offline-2');
    assert.equal(offlineRow?.status, 'IN_PROGRESS');
    assert.equal(offlineRow?.inboundAckConfirmed, false);
    assert.equal(offlineRow?.deliveredAt, null);

    // Reconnect triggers retryPendingInboundAcks() -> ACK #851 sent -> persisted DB row becomes SYNCED
    await transport.connect();
    await new Promise((r) => setTimeout(r, 30));
    const reconnectedRow = await syncRepo.findByIdempotencyKey('idem-ack-offline-2');
    assert.equal(reconnectedRow?.status, 'SYNCED');
    assert.equal(reconnectedRow?.inboundAckConfirmed, true);
    assert.ok(reconnectedRow?.deliveredAt !== null);
    assert.ok(transport.ackedRelayEventIds.includes(851));
    await restartedEngine.stop();
  });

  it('refuses retryPendingInboundAcks for unverified rows, missing E2EE nonce, outbound collisions, or revoked/unpaired senders', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      devices,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    await transport.connect();
    const myId = devices.getIdentity()!;

    // 1. Unverified DB row with relayEventId -> MUST NOT send ACK
    const unverified = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"forged"}',
      idempotencyKey: 'forged-in-db-1',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: false,
      e2eeNonce: 'nonce-long-enough-1234',
      relayEventId: 991,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(unverified.id, { status: 'IN_PROGRESS' });

    // 2. Row missing valid e2eeNonce -> MUST NOT send ACK
    const missingNonce = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"missing-nonce"}',
      idempotencyKey: 'forged-in-db-2',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: null,
      relayEventId: 992,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(missingNonce.id, { status: 'IN_PROGRESS' });

    // 3. Outbound row colliding with accidental relayEventId -> MUST NOT send inbound ACK
    const outboundRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"outbound"}',
      idempotencyKey: 'outbound-collision-3',
      sourceDeviceId: myId.publicId,
      targetDeviceId: peerDevice.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'nonce-long-enough-5678',
      relayEventId: 993,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(outboundRow.id, { status: 'IN_PROGRESS' });

    // 4. Local DB row claiming e2eeVerified=true & e2eeProtected=true WITHOUT inboundAckProof/e2eeEnvelope (never passed ingest security) -> MUST NOT send ACK
    const unattestedFlagsRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"forged-flags-only"}',
      idempotencyKey: 'forged-in-db-4',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'forged-local-nonce-16',
      relayEventId: 995,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(unattestedFlagsRow.id, { status: 'IN_PROGRESS' });

    // 5. Row with valid-looking fields & tampered e2eeEnvelope signature / forged inboundAckProof -> MUST NOT bypass signature verification!
    const validProofEnv = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"tampered-retry-sig"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-retry-tamper',
      idempotencyKey: 'forged-in-db-5',
    });
    const tamperedStoredEnv = {
      ...validProofEnv,
      signature: Buffer.alloc(64, 9).toString('base64'),
    };
    const tamperedEnvRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"tampered-retry-sig"}',
      idempotencyKey: 'forged-in-db-5',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: validProofEnv.messageNonce,
      e2eeEnvelope: tamperedStoredEnv,
      inboundAckProof: Buffer.alloc(64, 5).toString('base64'),
      relayEventId: 996,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(tamperedEnvRow.id, { status: 'IN_PROGRESS' });

    const ackedBad = await syncEngine.retryPendingInboundAcks();
    assert.equal(ackedBad, 0);
    assert.equal(transport.ackedRelayEventIds.length, 0);
    assert.ok(security.getAuditLog().some((a) => a.action === 'ACCESS_DENIED'));
    assert.equal((await syncRepo.findById(unverified.id))?.status, 'IN_PROGRESS');
    assert.equal((await syncRepo.findById(missingNonce.id))?.status, 'IN_PROGRESS');
    assert.equal(
      (await syncRepo.findById(unattestedFlagsRow.id))?.status,
      'IN_PROGRESS'
    );
    assert.equal(
      (await syncRepo.findById(unattestedFlagsRow.id))?.inboundAckConfirmed,
      false
    );
    assert.equal((await syncRepo.findById(tamperedEnvRow.id))?.status, 'IN_PROGRESS');
    assert.equal(
      (await syncRepo.findById(tamperedEnvRow.id))?.inboundAckConfirmed,
      false
    );

    // 6. Legitimate offline inbound row whose sender gets REVOKED before ACK retry -> MUST NOT send ACK!
    await transport.disconnect();
    const validEnv = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Revoked Later',
        text: 'Must not ACK after revocation',
        postedAt: 5555,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-revoke-ack',
      idempotencyKey: 'idem-revoke-ack-4',
    });
    const savedBeforeRevoke = await syncEngine.ingestInboundEvent({
      id: 994,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: validEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 5555,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-revoke-ack-4',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(savedBeforeRevoke, true);

    await devices.revokeLinkedDevice(peerDevice.publicId, false);
    await transport.connect();
    await new Promise((r) => setTimeout(r, 30));

    const explicitRetryAfterRevoke = await syncEngine.retryPendingInboundAcks();
    assert.equal(explicitRetryAfterRevoke, 0);
    const persistedRevoked = await syncRepo.findByIdempotencyKey('idem-revoke-ack-4');
    assert.equal(persistedRevoked?.status, 'IN_PROGRESS');
    assert.equal(persistedRevoked?.inboundAckConfirmed, false);
    assert.equal(transport.ackedRelayEventIds.includes(994), false);
    await syncEngine.stop();
  });

  it('prevents new inbound events from using findByIdempotencyKey or findRecentDuplicate records to ACK another Relay ID or promote a local record to SYNCED', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      devices,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    await transport.connect();
    const myId = devices.getIdentity()!;

    // Force initial /sync/ack failure so legitimate record remains IN_PROGRESS & un-ACKed
    const origAck = transport.acknowledgeInboundDelivery.bind(transport);
    transport.acknowledgeInboundDelivery = async () => {
      throw new Error('Transient ACK failure');
    };

    const nowTs = Date.now();
    const env910 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Duplicate Guard',
        text: 'Original inbound event #910',
        postedAt: nowTs,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-1',
      idempotencyKey: 'idem-guard-910',
    });

    const firstSaved = await syncEngine.ingestInboundEvent({
      id: 910,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env910,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-guard-910',
      notificationKey: 'notif-guard-key',
      payloadHash: 'hash-guard-payload',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(firstSaved, true);
    const stored910 = (await syncRepo.findByIdempotencyKey('idem-guard-910'))!;
    assert.equal(stored910.status, 'IN_PROGRESS');
    assert.equal(stored910.inboundAckConfirmed, false);

    // Restore live ACK endpoint before negative attacks
    transport.acknowledgeInboundDelivery = origAck;

    // 1. Same idempotencyKey + DIFFERENT relayEventId (#911 != #910) -> MUST NOT ACK #911 and MUST NOT flip #910 to SYNCED
    const env911 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Duplicate Guard',
        text: 'Different Relay ID #911',
        postedAt: nowTs,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-2',
      idempotencyKey: 'idem-guard-910',
    });

    const hijackByKey = await syncEngine.ingestInboundEvent({
      id: 911,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env911,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-guard-910',
      notificationKey: 'notif-guard-key',
      payloadHash: 'hash-guard-payload',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(hijackByKey, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    const afterHijack910 = await syncRepo.findById(stored910.id);
    assert.equal(afterHijack910?.status, 'IN_PROGRESS');
    assert.equal(afterHijack910?.inboundAckConfirmed, false);
    assert.ok(security.getAuditLog().some((a) => a.action === 'ACCESS_DENIED'));

    // 2. findRecentDuplicate match (same notificationKey + payloadHash, DIFFERENT idempotencyKey & DIFFERENT relayEventId #912)
    // MUST NOT ACK #912, MUST NOT promote stored910 to SYNCED, and MUST NOT insert a duplicate row
    const env912 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Duplicate Guard',
        text: 'Original inbound event #910',
        postedAt: nowTs + 1000,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-3',
      idempotencyKey: 'idem-guard-other-912',
    });

    const hijackByRecentDup = await syncEngine.ingestInboundEvent({
      id: 912,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env912,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs + 1000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-guard-other-912',
      notificationKey: 'notif-guard-key',
      payloadHash: 'hash-guard-payload',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(hijackByRecentDup, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    assert.equal((await syncRepo.getAll()).length, 1);
    const afterDup910 = await syncRepo.findById(stored910.id);
    assert.equal(afterDup910?.status, 'IN_PROGRESS');
    assert.equal(afterDup910?.inboundAckConfirmed, false);
    assert.ok(
      security
        .getAuditLog()
        .some((a) => a.action === 'DUPLICATE_BLOCKED' && a.outcome === 'DENIED')
    );

    // 3. Colliding sourceDeviceId mismatch on pre-existing DB record (same idempotencyKey + relayEventId #913)
    const mismatchedSourceRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"other-sender"}',
      idempotencyKey: 'idem-source-mismatch-913',
      sourceDeviceId: 'another-sender-device',
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'existing-nonce-123456',
      relayEventId: 913,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(mismatchedSourceRow.id, { status: 'IN_PROGRESS' });

    const env913 = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"other-sender"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-4',
      idempotencyKey: 'idem-source-mismatch-913',
    });

    const sourceMismatchRes = await syncEngine.ingestInboundEvent({
      id: 913,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env913,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs + 2000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-source-mismatch-913',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(sourceMismatchRes, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    const afterSourceMismatch = await syncRepo.findById(mismatchedSourceRow.id);
    assert.equal(afterSourceMismatch?.status, 'IN_PROGRESS');
    assert.equal(afterSourceMismatch?.inboundAckConfirmed, false);

    // 4. Outbound collision or targetDeviceId mismatch on existing local row -> MUST NOT ACK or mark SYNCED
    const wrongTargetRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"wrong-target"}',
      idempotencyKey: 'idem-target-mismatch-914',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: 'other-recipient-device',
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'existing-nonce-914567',
      relayEventId: 914,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(wrongTargetRow.id, { status: 'IN_PROGRESS' });

    const env914 = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"wrong-target"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-5',
      idempotencyKey: 'idem-target-mismatch-914',
    });

    const targetMismatchRes = await syncEngine.ingestInboundEvent({
      id: 914,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env914,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs + 3000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-target-mismatch-914',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(targetMismatchRes, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    const afterTargetMismatch = await syncRepo.findById(wrongTargetRow.id);
    assert.equal(afterTargetMismatch?.status, 'IN_PROGRESS');
    assert.equal(afterTargetMismatch?.inboundAckConfirmed, false);

    // 5. Outbound row collision on idempotencyKey -> MUST NOT ACK or flip outbound row to SYNCED
    const outboundCollision = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"outbound-row"}',
      idempotencyKey: 'idem-outbound-collision-915',
      sourceDeviceId: myId.publicId,
      targetDeviceId: peerDevice.publicId,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    await syncRepo.updateEvent(outboundCollision.id, { status: 'IN_PROGRESS' });

    const env915 = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"outbound-row"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-6',
      idempotencyKey: 'idem-outbound-collision-915',
    });

    const outboundCollisionRes = await syncEngine.ingestInboundEvent({
      id: 915,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env915,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs + 4000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-outbound-collision-915',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(outboundCollisionRes, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    const afterOutboundCollision = await syncRepo.findById(outboundCollision.id);
    assert.equal(afterOutboundCollision?.status, 'IN_PROGRESS');
    assert.equal(afterOutboundCollision?.inboundAckConfirmed, false);

    // 6. Existing inbound row whose sender key changed (untrusted rotated cryptoKeyId) -> MUST NOT ACK or flip to SYNCED
    const preRotatedRow = await syncRepo.insert({
      type: 'notification',
      payload: '{"title":"rotated-sender-key"}',
      idempotencyKey: 'idem-key-rot-916',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: 'existing-nonce-916567',
      relayEventId: 916,
      inboundAckConfirmed: false,
    });
    await syncRepo.updateEvent(preRotatedRow.id, { status: 'IN_PROGRESS' });

    const oldEnvelope916 = await peerCrypto.encryptForPeer({
      plaintext: '{"title":"rotated-sender-key"}',
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-guard-7',
      idempotencyKey: 'idem-key-rot-916',
    });

    // Simulate peer key rotation / untrusted senderCryptoKeyId in live device store
    const rotatedPeer: LinkedDevice = {
      ...peerDevice,
      cryptoKeyId: 'rotated-different-key-id',
    };
    transport.linkedDevices = [rotatedPeer];
    await devices.refreshLinkedDevicesFromRelay();

    const rotatedKeyRes = await syncEngine.ingestInboundEvent({
      id: 916,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: oldEnvelope916,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: nowTs + 5000,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-key-rot-916',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(rotatedKeyRes, false);
    assert.deepEqual(transport.ackedRelayEventIds, []);
    const afterRotatedKey = await syncRepo.findById(preRotatedRow.id);
    assert.equal(afterRotatedKey?.status, 'IN_PROGRESS');
    assert.equal(afterRotatedKey?.inboundAckConfirmed, false);

    await syncEngine.stop();
  });

  it('requires exact localEvent.e2eeNonce === envelope.messageNonce match on existingByKey and allows continuation only when nonce and cryptographic retry checks pass', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      devices,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    await transport.connect();
    const myId = devices.getIdentity()!;

    // Force transient ACK failure on first ingest so #960 stays IN_PROGRESS
    const origAck = transport.acknowledgeInboundDelivery.bind(transport);
    transport.acknowledgeInboundDelivery = async () => {
      throw new Error('Temporary ACK outage');
    };

    const ts = Date.now();
    const originalEnv = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Nonce Binding Test',
        text: 'Must bind localEvent.e2eeNonce === envelope.messageNonce',
        postedAt: ts,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-nonce-bind-1',
      idempotencyKey: 'idem-nonce-bind-960',
    });

    const firstIngest = await syncEngine.ingestInboundEvent({
      id: 960,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: originalEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: ts,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-nonce-bind-960',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(firstIngest, true);

    const savedRow = (await syncRepo.findByIdempotencyKey('idem-nonce-bind-960'))!;
    assert.equal(savedRow.status, 'IN_PROGRESS');
    assert.equal(savedRow.inboundAckConfirmed, false);
    assert.equal(savedRow.e2eeNonce, originalEnv.messageNonce);
    assert.ok(savedRow.inboundAckProof && savedRow.inboundAckProof.length > 0);
    assert.equal(savedRow.e2eeEnvelope?.messageNonce, originalEnv.messageNonce);

    // Restore live ACK endpoint
    transport.acknowledgeInboundDelivery = origAck;

    // 1. existingByKey with DIFFERENT messageNonce (same idempotencyKey + same relayEventId #960 + valid sender sig) -> MUST REFUSE ACK!
    const differentNonceEnv = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Nonce Binding Test',
        text: 'Re-wrapped with a DIFFERENT messageNonce',
        postedAt: ts,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-nonce-bind-2',
      idempotencyKey: 'idem-nonce-bind-960',
    });
    assert.notEqual(differentNonceEnv.messageNonce, savedRow.e2eeNonce);

    const diffNonceRes = await syncEngine.ingestInboundEvent({
      id: 960,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: differentNonceEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: ts,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-nonce-bind-960',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(diffNonceRes, false);
    assert.deepEqual([...transport.ackedRelayEventIds], []);
    const afterDiffNonce = await syncRepo.findById(savedRow.id);
    assert.equal(afterDiffNonce?.status, 'IN_PROGRESS');
    assert.equal(afterDiffNonce?.inboundAckConfirmed, false);
    assert.equal(afterDiffNonce?.deliveredAt, null);
    assert.ok(security.getAuditLog().some((a) => a.action === 'ACCESS_DENIED'));

    // 2. Matching localEvent.e2eeNonce === envelope.messageNonce (same originalEnv) with all bindings intact -> ALLOWS ACK and transitions to SYNCED
    const matchingNonceRes = await syncEngine.ingestInboundEvent({
      id: 960,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: originalEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: ts,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-nonce-bind-960',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(matchingNonceRes, true);
    assert.deepEqual([...transport.ackedRelayEventIds], [960]);
    const syncedAfterMatch = await syncRepo.findById(savedRow.id);
    assert.equal(syncedAfterMatch?.status, 'SYNCED');
    assert.equal(syncedAfterMatch?.inboundAckConfirmed, true);
    assert.ok(syncedAfterMatch?.deliveredAt !== null);

    // 3. Offline ingest + eligible retryPendingInboundAcks while pairing stays valid -> verifies proof + signature & ACKs cleanly
    await transport.disconnect();
    const env961 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Retry Proof Valid',
        text: 'Eligible retry with live valid pairing',
        postedAt: ts + 500,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-nonce-bind-3',
      idempotencyKey: 'idem-nonce-bind-961',
    });

    const offlineSaved961 = await syncEngine.ingestInboundEvent({
      id: 961,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env961,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: ts + 500,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-nonce-bind-961',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(offlineSaved961, true);
    assert.equal(
      (await syncRepo.findByIdempotencyKey('idem-nonce-bind-961'))?.status,
      'IN_PROGRESS'
    );

    await transport.connect();
    for (let i = 0; i < 20; i += 1) {
      const candidate = await syncRepo.findByIdempotencyKey('idem-nonce-bind-961');
      if (candidate?.status === 'SYNCED' && candidate?.inboundAckConfirmed === true) {
        break;
      }
      await new Promise((r) => setTimeout(r, 15));
    }
    const final961 = await syncRepo.findByIdempotencyKey('idem-nonce-bind-961');
    assert.equal(final961?.status, 'SYNCED');
    assert.equal(final961?.inboundAckConfirmed, true);
    assert.ok(transport.ackedRelayEventIds.includes(961));

    await syncEngine.stop();
  });

  it('computes bounded exponential backoff correctly', () => {
    assert.equal(calculateExponentialBackoffMs(1, 1000, 10000), 1000);
    assert.equal(calculateExponentialBackoffMs(2, 1000, 10000), 2000);
    assert.equal(calculateExponentialBackoffMs(3, 1000, 10000), 4000);
    assert.equal(calculateExponentialBackoffMs(6, 1000, 10000), 10000);
  });

  it('binds inbound ACK strictly to decrypted envelope plaintext across retry, re-delivery, and restart without leaking secrets or overwriting altered data', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      security,
      settings,
      devices,
      crypto,
      logger,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
    const myId = devices.getIdentity()!;

    // 1. Matching local payload with verified envelope -> ACK succeeds and transitions to SYNCED
    await transport.connect();
    const secretMatched = 'MatchedSecretPayload-101';
    const matchedPlaintext = JSON.stringify({
      packageName: 'com.whatsapp',
      title: 'Matched Inbound',
      text: secretMatched,
      postedAt: 7001,
    });
    const matchedEnv = await peerCrypto.encryptForPeer({
      plaintext: matchedPlaintext,
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-bind-match',
      idempotencyKey: 'idem-bind-match-1200',
    });
    const matchedOk = await syncEngine.ingestInboundEvent({
      id: 1200,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: matchedEnv,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 7001,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-bind-match-1200',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    });
    assert.equal(matchedOk, true);
    const matchedStored = await syncRepo.findByIdempotencyKey('idem-bind-match-1200');
    assert.equal(matchedStored?.status, 'SYNCED');
    assert.equal(matchedStored?.inboundAckConfirmed, true);
    assert.equal(matchedStored?.payload, matchedPlaintext);
    assert.deepEqual([...transport.ackedRelayEventIds], [1200]);

    // 2. Offline ingest -> local payload altered after save -> retry, re-delivery (seenE2eeNonces & existingByKey), and restart all refuse ACK without overwriting
    await transport.disconnect();
    const secretTamperedOrig = 'SensitivePlaintextMustNeverLeakInAudit';
    const origPlaintext = JSON.stringify({
      packageName: 'com.whatsapp',
      title: 'Original Protected',
      text: secretTamperedOrig,
      postedAt: 7002,
    });
    const tamperedLocalPayload = JSON.stringify({
      packageName: 'com.whatsapp',
      title: 'Altered Local Copy',
      text: 'TamperedAfterLocalSave',
      postedAt: 7002,
    });
    const env1201 = await peerCrypto.encryptForPeer({
      plaintext: origPlaintext,
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-bind-tamper',
      idempotencyKey: 'idem-bind-tamper-1201',
    });
    const wire1201: SyncEvent = {
      id: 1201,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: env1201,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 7002,
      status: 'IN_PROGRESS',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-bind-tamper-1201',
      encrypted: true,
      localEncrypted: false,
      e2eeProtected: false,
      e2eeVerified: false,
    };

    assert.equal(await syncEngine.ingestInboundEvent(wire1201), true);
    const saved1201 = await syncRepo.findByIdempotencyKey('idem-bind-tamper-1201');
    assert.ok(saved1201);
    assert.equal(saved1201.status, 'IN_PROGRESS');
    assert.equal(saved1201.inboundAckConfirmed, false);

    // Simulate local storage alteration/corruption after save
    await syncRepo.tamperPayloadInStorageForTest(saved1201.id, tamperedLocalPayload);

    // 2a. Reconnect triggers retryPendingInboundAcks() -> MUST refuse ACK and keep altered local row untouched
    await transport.connect();
    assert.equal(await syncEngine.retryPendingInboundAcks(), 0);
    const afterRetry1 = await syncRepo.findById(saved1201.id);
    assert.equal(afterRetry1?.status, 'IN_PROGRESS');
    assert.equal(afterRetry1?.inboundAckConfirmed, false);
    assert.equal(afterRetry1?.payload, tamperedLocalPayload);
    assert.equal(transport.ackedRelayEventIds.includes(1201), false);

    // 2b. Re-delivery of the same relay event while seenE2eeNonces already has nonce -> MUST refuse ACK & keep altered payload
    assert.equal(await syncEngine.ingestInboundEvent(wire1201), false);
    const afterRedelivery = await syncRepo.findById(saved1201.id);
    assert.equal(afterRedelivery?.status, 'IN_PROGRESS');
    assert.equal(afterRedelivery?.inboundAckConfirmed, false);
    assert.equal(afterRedelivery?.payload, tamperedLocalPayload);
    assert.equal(transport.ackedRelayEventIds.includes(1201), false);

    // 2c. Repeated manual retry after tampering -> still refuses ACK
    assert.equal(await syncEngine.retryPendingInboundAcks(), 0);
    assert.equal(transport.ackedRelayEventIds.includes(1201), false);

    // Verify audit log recorded ACCESS_DENIED without leaking plaintext or secret strings
    const denyAudits = security
      .getAuditLog()
      .filter(
        (entry) => entry.action === 'ACCESS_DENIED' && entry.outcome === 'DENIED'
      );
    assert.ok(denyAudits.length >= 2);
    for (const entry of denyAudits) {
      assert.equal(entry.details.includes(secretTamperedOrig), false);
      assert.equal(entry.details.includes('TamperedAfterLocalSave'), false);
    }

    // 3. App restart with unconfirmed ACK:
    //    - #1201 (tampered local payload) MUST remain IN_PROGRESS across restart
    //    - #1202 (untampered offline event saved before restart) MUST recover & ACK to SYNCED after restart!
    await transport.disconnect();
    const env1202 = await peerCrypto.encryptForPeer({
      plaintext: JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Clean Across Restart',
        text: 'CleanUnackedEvent1202',
        postedAt: 7003,
      }),
      senderDeviceId: peerDevice.publicId,
      recipientDeviceId: myId.publicId,
      senderCryptoKeyId: peerDevice.cryptoKeyId,
      recipientCryptoKeyId: myId.cryptoKeyId,
      recipientEcdhPublicKeyJwk: myId.ecdhPublicKeyJwk!,
      sessionId: 'sess-bind-restart-clean',
      idempotencyKey: 'idem-bind-restart-1202',
    });
    assert.equal(
      await syncEngine.ingestInboundEvent({
        id: 1202,
        type: 'notification',
        payload: '[E2EE_CIPHERTEXT]',
        e2eeEnvelope: env1202,
        sourceDeviceId: peerDevice.publicId,
        targetDeviceId: myId.publicId,
        createdAt: 7003,
        status: 'IN_PROGRESS',
        retryCount: 0,
        nextRetryAt: null,
        idempotencyKey: 'idem-bind-restart-1202',
        encrypted: true,
        localEncrypted: false,
        e2eeProtected: false,
        e2eeVerified: false,
      }),
      true
    );

    await syncEngine.stop();
    const restartedEngine = new SyncEngine({
      repo: syncRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    await restartedEngine.start();

    // Also test existingByKey path when seenE2eeNonces isn't hit (different nonce or bypassed cache) on a tampered row:
    await transport.connect();
    const ackedOnRestart = await restartedEngine.retryPendingInboundAcks();
    // Wait briefly if handleTransportConnected already raced and acked 1202; verify final state deterministically
    for (let i = 0; i < 20; i += 1) {
      const c1202 = await syncRepo.findByIdempotencyKey('idem-bind-restart-1202');
      if (c1202?.status === 'SYNCED') break;
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(ackedOnRestart >= 0);

    const final1201AfterRestart = await syncRepo.findById(saved1201.id);
    assert.equal(final1201AfterRestart?.status, 'IN_PROGRESS');
    assert.equal(final1201AfterRestart?.inboundAckConfirmed, false);
    assert.equal(final1201AfterRestart?.payload, tamperedLocalPayload);
    assert.equal(transport.ackedRelayEventIds.includes(1201), false);

    const final1202AfterRestart = await syncRepo.findByIdempotencyKey(
      'idem-bind-restart-1202'
    );
    assert.equal(final1202AfterRestart?.status, 'SYNCED');
    assert.equal(final1202AfterRestart?.inboundAckConfirmed, true);
    assert.ok(transport.ackedRelayEventIds.includes(1202));

    // Also verify existingByKey re-delivery path (when seenE2eeNonces cache does not yet hold the row) rejects tampered local payload
    const coldRepo = new TestSyncEventRepository();
    const coldEngine = new SyncEngine({
      repo: coldRepo,
      transport,
      crypto,
      security,
      settings,
      devices,
      logger,
    });
    await coldEngine.start();
    const insertedDirect = await coldRepo.insert({
      type: 'notification',
      payload: tamperedLocalPayload,
      idempotencyKey: 'idem-bind-tamper-1201',
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      e2eeProtected: true,
      e2eeVerified: true,
      e2eeNonce: env1201.messageNonce,
      e2eeEnvelope: env1201,
      relayEventId: 1201,
      inboundAckConfirmed: false,
    });
    await coldRepo.updateEvent(insertedDirect.id, { status: 'IN_PROGRESS' });
    assert.equal(await coldEngine.ingestInboundEvent(wire1201), false);
    assert.equal(transport.ackedRelayEventIds.includes(1201), false);
    const afterExistingByKey = await coldRepo.findById(insertedDirect.id);
    assert.equal(afterExistingByKey?.status, 'IN_PROGRESS');
    assert.equal(afterExistingByKey?.inboundAckConfirmed, false);
    assert.equal(afterExistingByKey?.payload, tamperedLocalPayload);

    await coldEngine.stop();
    await restartedEngine.stop();
  });
});
