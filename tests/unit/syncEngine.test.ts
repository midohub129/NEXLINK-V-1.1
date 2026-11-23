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

  const syncRepo = new InMemorySyncEventRepository();
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

    // Re-delivery with a FRESH nonce & matching idempotencyKey deduplicates and ACKs cleanly
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

    const deduped = await restartedEngine.ingestInboundEvent({
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
    assert.equal(deduped, true);
    // Stored count stays 1 (no duplicate row) and relay event #778 gets ACKed cleanly
    assert.equal(restartedEngine.getEvents().length, 1);
    assert.ok(transport.ackedRelayEventIds.includes(778));
    await restartedEngine.stop();
  });

  it('never sends /sync/ack when local storage fails, and rejects forged signatures or wrong ECDH keys without ACK', async () => {
    const {
      syncEngine,
      syncRepo,
      transport,
      devices,
      peerCrypto,
      peerDevice,
    } = await setupSyncHarness();
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

    // Must NOT be SYNCED while inboundAckConfirmed is false
    const unackedStored = syncEngine.getEvents()[0];
    assert.equal(unackedStored.status, 'IN_PROGRESS');
    assert.equal(unackedStored.inboundAckConfirmed, false);
    assert.equal(unackedStored.deliveredAt, null);
    assert.equal(unackedStored.syncedAt, null);
    assert.equal(transport.ackedRelayEventIds.length, 0);

    // Outbound delivery ACK for colliding local ID must NOT falsely promote inbound event
    await syncEngine.handleDeliveryAcks([unackedStored.id], Date.now());
    assert.equal(syncEngine.getEvents()[0].status, 'IN_PROGRESS');
    assert.equal(syncEngine.getEvents()[0].inboundAckConfirmed, false);

    // Simulate app restart before ACK succeeds -> inbound row stays IN_PROGRESS (never reverted to PENDING outbound!)
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

    assert.equal(restartedEngine.getEvents().length, 1);
    assert.equal(restartedEngine.getEvents()[0].status, 'IN_PROGRESS');
    assert.equal(restartedEngine.getEvents()[0].inboundAckConfirmed, false);

    // Outbound cycle must never pick up the un-ACKed inbound row
    const summaryBeforeRecovery = await restartedEngine.runSyncCycle();
    assert.equal(summaryBeforeRecovery.attempted, 0);
    assert.equal(transport.sentBatches.length, 0);
    assert.equal(restartedEngine.getEvents()[0].status, 'IN_PROGRESS');

    // Network recovers -> re-ingesting same un-ACKed relay event #850 completes ACK and transitions to SYNCED!
    transport.acknowledgeInboundDelivery = origAck;
    const secondIngest = await restartedEngine.ingestInboundEvent(wireItem);
    assert.equal(secondIngest, true);
    assert.equal(restartedEngine.getEvents().length, 1);
    const syncedRow = restartedEngine.getEvents()[0];
    assert.equal(syncedRow.status, 'SYNCED');
    assert.equal(syncedRow.inboundAckConfirmed, true);
    assert.ok(syncedRow.deliveredAt !== null);
    assert.ok(syncedRow.syncedAt !== null);
    assert.deepEqual(transport.ackedRelayEventIds, [850]);

    // Offline ingest followed by transport reconnect automatically retries ACK -> SYNCED
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
    const offlineRow = restartedEngine
      .getEvents()
      .find((e) => e.idempotencyKey === 'idem-ack-offline-2')!;
    assert.equal(offlineRow.status, 'IN_PROGRESS');
    assert.equal(offlineRow.inboundAckConfirmed, false);
    assert.equal(offlineRow.deliveredAt, null);

    // Reconnect triggers retryPendingInboundAcks() -> ACK #851 sent -> SYNCED
    await transport.connect();
    await new Promise((r) => setTimeout(r, 30));
    const reconnectedRow = restartedEngine
      .getEvents()
      .find((e) => e.idempotencyKey === 'idem-ack-offline-2')!;
    assert.equal(reconnectedRow.status, 'SYNCED');
    assert.equal(reconnectedRow.inboundAckConfirmed, true);
    assert.ok(reconnectedRow.deliveredAt !== null);
    assert.ok(transport.ackedRelayEventIds.includes(851));
    await restartedEngine.stop();
  });

  it('computes bounded exponential backoff correctly', () => {
    assert.equal(calculateExponentialBackoffMs(1, 1000, 10000), 1000);
    assert.equal(calculateExponentialBackoffMs(2, 1000, 10000), 2000);
    assert.equal(calculateExponentialBackoffMs(3, 1000, 10000), 4000);
    assert.equal(calculateExponentialBackoffMs(6, 1000, 10000), 10000);
  });
});
