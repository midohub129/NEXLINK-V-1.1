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
import type { ConnectionState, LinkedDevice, PairingRequest } from '../../src/domain/models/device';
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
  nextAckHandler: ((events: SyncEvent[]) => Promise<SyncDispatchAck>) | null = null;
  linkedDevices: LinkedDevice[] = [];

  getState(): ConnectionState {
    return this.state;
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
  async createPairingRequest(): Promise<PairingRequest> {
    throw new Error('Not used');
  }
  async acceptPairingRequest(): Promise<LinkedDevice> {
    throw new Error('Not used');
  }
  async fetchLinkedDevices(): Promise<LinkedDevice[]> {
    return this.linkedDevices;
  }
  async revokeDeviceLink(): Promise<void> {}
  async sendSyncBatch(
    _deviceId: string,
    _targetDeviceId: string | null,
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
      serverTimestamp: Date.now(),
    };
  }
  async fetchInboundEvents(): Promise<SyncEvent[]> {
    return [];
  }
  subscribe(): () => void {
    return () => {};
  }
  subscribeEvents(): () => void {
    return () => {};
  }
}

async function setupSyncHarness(maxSyncRetries = 3) {
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
  });

  const auditRepo = new InMemoryAuditRepository();
  const security = new SecurityManager(crypto, auditRepo, logger);
  await security.initialize();

  const deviceRepo = new InMemoryDeviceRepository();
  const transport = new MockTransportClient();
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

  return { syncEngine, syncRepo, transport, security, settings, crypto, logger };
}

describe('SyncEngine Unit & Recovery Tests', () => {
  it('enqueues valid events, prevents duplicates within 60s, and preserves FIFO sync order', async () => {
    const { syncEngine, transport } = await setupSyncHarness();
    await transport.connect();
    const baseTime = Date.now() - 5000;

    const first = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 1',
      text: 'Hello 1',
      notificationKey: 'k1',
      postedAt: baseTime,
    });
    assert.equal(first.status, 'SAVED');

    const dup = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 1',
      text: 'Hello 1',
      notificationKey: 'k1',
      postedAt: baseTime + 500,
    });
    assert.deepEqual(dup, { status: 'REJECTED', reason: 'DUPLICATE' });

    const second = await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Msg 2',
      text: 'Hello 2',
      notificationKey: 'k2',
      postedAt: baseTime + 1000,
    });
    assert.equal(second.status, 'SAVED');

    const summary = await syncEngine.runSyncCycle(baseTime + 2000);
    assert.equal(summary.attempted, 2);
    assert.equal(summary.synced, 2);
    assert.equal(summary.failed, 0);

    // FIFO order verification
    assert.equal(transport.sentBatches[0][0].createdAt, baseTime);
    assert.equal(transport.sentBatches[0][1].createdAt, baseTime + 1000);

    const stored = syncEngine.getEvents();
    assert.ok(stored.every((e) => e.status === 'SYNCED'));
  });

  it('never marks events SYNCED when transport is offline or server rejects ACK', async () => {
    const { syncEngine, transport } = await setupSyncHarness(2);

    await syncEngine.enqueueNotification({
      packageName: 'com.whatsapp',
      title: 'Offline test',
      text: 'Should stay pending',
      postedAt: Date.now(),
    });

    const offlineSummary = await syncEngine.runSyncCycle();
    assert.equal(offlineSummary.skippedReason, 'OFFLINE');
    assert.equal(syncEngine.getEvents()[0].status, 'PENDING');

    await transport.connect();
    transport.nextAckHandler = async () => ({
      acknowledged: false,
      acceptedIds: [],
      duplicateIds: [],
      serverTimestamp: Date.now(),
      error: 'Relay rejected batch',
    });

    const fail1 = await syncEngine.runSyncCycle(Date.now() + 100);
    assert.equal(fail1.failed, 1);
    const afterAttempt1 = syncEngine.getEvents()[0];
    assert.equal(afterAttempt1.status, 'PENDING');
    assert.equal(afterAttempt1.retryCount, 1);
    assert.ok(afterAttempt1.nextRetryAt !== null);

    // Run cycle after backoff expires -> hits maxSyncRetries (2) -> FAILED
    const fail2 = await syncEngine.runSyncCycle((afterAttempt1.nextRetryAt ?? 0) + 10);
    assert.equal(fail2.failed, 1);
    const afterAttempt2 = syncEngine.getEvents()[0];
    assert.equal(afterAttempt2.status, 'FAILED');
    assert.equal(afterAttempt2.retryCount, 2);
  });

  it('recovers stuck IN_PROGRESS events back to PENDING upon restart', async () => {
    const { syncRepo, transport, crypto, security, settings, logger } =
      await setupSyncHarness();
    const devices = new DeviceManager({
      deviceRepo: new InMemoryDeviceRepository(),
      crypto,
      transport,
      security,
      settings,
      logger,
    });
    await devices.start();

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
