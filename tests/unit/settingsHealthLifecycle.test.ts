import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ErrorManager } from '../../src/application/errors/errorManager';
import { HealthMonitor } from '../../src/application/health/healthMonitor';
import { LifecycleManager } from '../../src/application/lifecycle/lifecycleManager';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SettingsService, validateAppSettings } from '../../src/application/settings/settingsService';
import { SyncEngine } from '../../src/application/sync/syncEngine';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { SecurityManager } from '../../src/application/security/securityManager';
import { TransportError, ValidationError } from '../../src/domain/errors/appError';
import type { ILifecycleParticipant, ITransportClient } from '../../src/domain/interfaces/services';
import type { ConnectionState, LinkedDevice, PairingRequest } from '../../src/domain/models/device';
import { DEFAULT_APP_SETTINGS } from '../../src/domain/models/settings';
import type { SyncDispatchAck, SyncEvent } from '../../src/domain/models/syncEvent';
import {
  InMemoryAuditRepository,
  InMemoryDeviceRepository,
  InMemorySettingsRepository,
  InMemorySyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

class NoopTransport implements ITransportClient {
  state: ConnectionState = 'DISCONNECTED';
  getState(): ConnectionState {
    return this.state;
  }
  getLastSuccessfulConnectionAt(): number | null {
    return null;
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
    return [];
  }
  async revokeDeviceLink(): Promise<void> {}
  async sendSyncBatch(): Promise<SyncDispatchAck> {
    return {
      acknowledged: true,
      acceptedIds: [],
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

describe('Settings, ErrorManager, HealthMonitor & LifecycleManager Tests', () => {
  it('validates settings constraints and rejects invalid values', async () => {
    const logger = new RotatingLogger();
    const settings = new SettingsService(new InMemorySettingsRepository(), logger);
    await settings.initialize();

    assert.throws(
      () =>
        validateAppSettings({
          ...DEFAULT_APP_SETTINGS,
          sessionTimeoutMinutes: 0,
        }),
      (err: unknown) => err instanceof ValidationError && err.code === 'INVALID_SESSION_TIMEOUT'
    );

    assert.throws(
      () =>
        validateAppSettings({
          ...DEFAULT_APP_SETTINGS,
          relayEndpoint: 'ftp://invalid-endpoint',
        }),
      (err: unknown) => err instanceof ValidationError && err.code === 'INVALID_RELAY_ENDPOINT'
    );

    const saved = await settings.update({
      selectedNotificationApps: ['com.whatsapp', 'com.nexlink.app', 'com.whatsapp'],
      sessionTimeoutMinutes: 45,
    });
    assert.deepEqual(saved.selectedNotificationApps, ['com.whatsapp']);
    assert.equal(saved.sessionTimeoutMinutes, 45);
  });

  it('captures typed errors, updates HealthMonitor, and runs ordered LifecycleManager', async () => {
    const logger = new RotatingLogger();
    const errorManager = new ErrorManager(logger);
    const crypto = new NodeTestCryptoProvider();
    const settings = new SettingsService(new InMemorySettingsRepository(), logger);
    await settings.initialize();

    const security = new SecurityManager(crypto, new InMemoryAuditRepository(), logger);
    const transport = new NoopTransport();
    const devices = new DeviceManager({
      deviceRepo: new InMemoryDeviceRepository(),
      crypto,
      transport,
      security,
      settings,
      logger,
    });
    const syncEngine = new SyncEngine({
      repo: new InMemorySyncEventRepository(),
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

    assert.equal(healthMonitor.getSnapshot().databaseStatus, 'UNAVAILABLE');
    healthMonitor.setDatabaseReady(true);

    errorManager.capture(
      new TransportError('RELAY_DOWN', 'المرحل متوقف', 'ECONNREFUSED', true)
    );
    const snap = healthMonitor.getSnapshot();
    assert.equal(snap.databaseStatus, 'HEALTHY');
    assert.equal(snap.lastError?.code, 'RELAY_DOWN');

    const order: string[] = [];
    const p1: ILifecycleParticipant = {
      name: 'First',
      start: async () => {
        await new Promise((r) => setTimeout(r, 15));
        order.push('start:1');
      },
      stop: async () => {
        order.push('stop:1');
      },
    };
    const p2: ILifecycleParticipant = {
      name: 'Second',
      start: async () => {
        order.push('start:2');
      },
      stop: async () => {
        order.push('stop:2');
      },
    };

    const lifecycle = new LifecycleManager([p1, p2], logger, errorManager);
    // Simultaneous calls to startup() must not duplicate execution
    await Promise.all([lifecycle.startup(), lifecycle.startup()]);
    assert.equal(lifecycle.getPhase(), 'RUNNING');
    assert.deepEqual(order, ['start:1', 'start:2']);

    await lifecycle.shutdown();
    assert.equal(lifecycle.getPhase(), 'STOPPED');
    assert.deepEqual(order, ['start:1', 'start:2', 'stop:2', 'stop:1']);
  });
});
