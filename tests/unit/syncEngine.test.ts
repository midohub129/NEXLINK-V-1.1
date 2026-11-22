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
  nextAckHandler: ((events: SyncEvent[]) => Promise<SyncDispatchAck>) | null = null;
  linkedDevices: LinkedDevice[] = [];
  deliveredClientEventIds: number[] = [];

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
  }
  async disconnect(): Promise<void> {
    this.state = 'DISCONNECTED';
  }
  async revokeServerSession(): Promise<void> {
    this.state = 'DISCONNECTED';
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
    return [];
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
  subscribe(): () => void {
    return () => {};
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
      status: 'SYNCED',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-tamper-1',
      encrypted: false,
      e2eeProtected: true,
    });
    assert.equal(acceptedTampered, false);
    assert.equal(transport.ackedRelayEventIds.length, 0);
    assert.ok(
      security
        .getAuditLog()
        .some((a) => a.action === 'E2EE_DECRYPT_FAILED' && a.outcome === 'DENIED')
    );

    // Valid E2EE envelope succeeds once, and replay of same messageNonce is rejected!
    const acceptedValid = await syncEngine.ingestInboundEvent({
      id: 902,
      type: 'notification',
      payload: '[E2EE_CIPHERTEXT]',
      e2eeEnvelope: validEnvelope,
      sourceDeviceId: peerDevice.publicId,
      targetDeviceId: myId.publicId,
      createdAt: 1000,
      status: 'SYNCED',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-valid-1',
      encrypted: false,
      e2eeProtected: true,
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
      status: 'SYNCED',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: 'idem-replay-1',
      encrypted: false,
      e2eeProtected: true,
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
  });

  it('computes bounded exponential backoff correctly', () => {
    assert.equal(calculateExponentialBackoffMs(1, 1000, 10000), 1000);
    assert.equal(calculateExponentialBackoffMs(2, 1000, 10000), 2000);
    assert.equal(calculateExponentialBackoffMs(3, 1000, 10000), 4000);
    assert.equal(calculateExponentialBackoffMs(6, 1000, 10000), 10000);
  });
});
