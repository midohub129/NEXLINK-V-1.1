import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import type { ITransportClient, RelayRegistrationPayload } from '../../src/domain/interfaces/services';
import type { ConnectionState, LinkedDevice, PairingRequest } from '../../src/domain/models/device';
import type { SyncDispatchAck, SyncEvent } from '../../src/domain/models/syncEvent';
import {
  InMemoryAuditRepository,
  InMemoryDeviceRepository,
  InMemorySettingsRepository,
} from '../../src/infrastructure/storage/repositories';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

class StubRelayTransport implements ITransportClient {
  state: ConnectionState = 'DISCONNECTED';
  remoteLinks: LinkedDevice[] = [];
  revokedTargets: string[] = [];

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
  async createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest> {
    return {
      pairingCode: '482910',
      targetDeviceId: '',
      requesterDeviceId,
      requesterCryptoKeyId,
      expiresAt: Date.now() + 60_000,
    };
  }
  async acceptPairingRequest(
    _pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<LinkedDevice> {
    const peer: LinkedDevice = {
      publicId: 'peer-device-99',
      cryptoKeyId: 'ecdsa-peer-99',
      label: responder.label,
      role: 'admin',
      pairingState: 'PAIRED',
      pairedAt: Date.now(),
      lastSeenAt: Date.now(),
      verifiedByRelay: true,
    };
    this.remoteLinks = [peer];
    return peer;
  }
  async fetchLinkedDevices(): Promise<LinkedDevice[]> {
    return this.remoteLinks;
  }
  async revokeDeviceLink(_deviceId: string, targetDeviceId: string): Promise<void> {
    this.revokedTargets.push(targetDeviceId);
    this.remoteLinks = this.remoteLinks.map((d) =>
      d.publicId === targetDeviceId
        ? { ...d, pairingState: 'REVOKED', verifiedByRelay: false }
        : d
    );
  }
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

describe('DeviceManager Identity, Pairing & Revocation Tests', () => {
  it('separates publicId from cryptoKeyId and requires relay confirmation for paired state', async () => {
    const logger = new RotatingLogger();
    const crypto = new NodeTestCryptoProvider();
    const settings = new SettingsService(new InMemorySettingsRepository(), logger);
    await settings.initialize();
    await settings.update({ role: 'admin' });

    const security = new SecurityManager(
      crypto,
      new InMemoryAuditRepository(),
      logger
    );
    await security.initialize();

    const transport = new StubRelayTransport();
    const manager = new DeviceManager({
      deviceRepo: new InMemoryDeviceRepository(),
      crypto,
      transport,
      security,
      settings,
      logger,
    });

    await manager.start();
    const identity = manager.getIdentity()!;
    assert.ok(identity.publicId.length > 8);
    assert.ok(identity.cryptoKeyId.startsWith('ecdsa-'));
    assert.notEqual(identity.publicId, identity.cryptoKeyId);
    assert.ok(identity.publicKeyJwk !== null);

    // Local setup leaves zero paired devices
    assert.equal(manager.getLinkedDevices().length, 0);

    security.issueSession(identity.publicId, identity.cryptoKeyId, 30);
    await manager.connectRelay('admin');

    const req = await manager.createPairingRequest();
    assert.equal(req.pairingCode, '482910');

    const peer = await manager.acceptPairingCode('482910', 'basic', 'هاتف اختبار');
    assert.equal(peer.pairingState, 'PAIRED');
    assert.equal(peer.verifiedByRelay, true);
    assert.equal(manager.getLinkedDevices().length, 1);

    await manager.revokeLinkedDevice(peer.publicId);
    assert.deepEqual(transport.revokedTargets, [peer.publicId]);
    const revoked = manager.getLinkedDevices()[0];
    assert.equal(revoked.pairingState, 'REVOKED');
    assert.equal(revoked.verifiedByRelay, false);
  });
});
