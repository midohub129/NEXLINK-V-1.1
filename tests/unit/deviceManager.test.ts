import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import type {
  ITransportClient,
  RelayRegistrationPayload,
} from '../../src/domain/interfaces/services';
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
} from '../../src/infrastructure/storage/repositories';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

class StubRelayTransport implements ITransportClient {
  state: ConnectionState = 'DISCONNECTED';
  remoteLinks: LinkedDevice[] = [];
  pendingApprovals: PairingRequest[] = [];
  revokedTargets: string[] = [];

  getState(): ConnectionState {
    return this.state;
  }
  getServerSession(): RelayServerSession | null {
    return this.state === 'CONNECTED'
      ? {
          sessionId: 'stub-sess',
          token: 'stub-token',
          devicePublicId: 'stub',
          cryptoKeyId: 'ecdsa-stub',
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
  async createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest> {
    return {
      pairingId: 'pair-stub-1',
      pairingCode: '482910',
      targetDeviceId: '',
      requesterDeviceId,
      requesterCryptoKeyId,
      status: 'PENDING',
      expiresAt: Date.now() + 60_000,
    };
  }
  async acceptPairingRequest(
    pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<PairingRequest> {
    const req: PairingRequest = {
      pairingId: 'pair-stub-1',
      pairingCode,
      targetDeviceId: 'requester-1',
      requesterDeviceId: 'requester-1',
      requesterCryptoKeyId: 'ecdsa-requester-1',
      responderDeviceId: responder.publicId,
      responderCryptoKeyId: responder.cryptoKeyId,
      responderLabel: responder.label,
      status: 'AWAITING_REQUESTER_CONFIRMATION',
      expiresAt: Date.now() + 60_000,
    };
    this.pendingApprovals = [req];
    return req;
  }
  async confirmPairingRequest(
    _pairingId: string,
    approve: boolean
  ): Promise<LinkedDevice | null> {
    if (!approve) {
      this.pendingApprovals = [];
      return null;
    }
    const peer: LinkedDevice = {
      publicId: 'peer-device-99',
      cryptoKeyId: 'ecdsa-peer-99',
      publicKeyJwk: null,
      ecdhPublicKeyJwk: null,
      label: 'هاتف اختبار',
      role: 'basic',
      pairingState: 'PAIRED',
      pairedAt: Date.now(),
      lastSeenAt: Date.now(),
      verifiedByRelay: true,
    };
    this.pendingApprovals = [];
    this.remoteLinks = [peer];
    return peer;
  }
  async fetchPendingPairingApprovals(): Promise<PairingRequest[]> {
    return this.pendingApprovals;
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
  async acknowledgeInboundDelivery(): Promise<void> {}
  async fetchSyncDeliveryStatus(): Promise<number[]> {
    return [];
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

describe('DeviceManager Identity, Mutual Pairing & Revocation Tests', () => {
  it('separates publicId from cryptoKeyId, requires mutual confirmation before PAIRED, and revokes cleanly', async () => {
    const logger = new RotatingLogger();
    const crypto = new NodeTestCryptoProvider();
    const settings = new SettingsService(new InMemorySettingsRepository(), logger);
    await settings.initialize();
    await settings.update({ role: 'admin' });

    const security = new SecurityManager(crypto, new InMemoryAuditRepository(), logger);
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
    assert.ok(identity.ecdhPublicKeyJwk !== null);

    // Local setup leaves zero paired devices
    assert.equal(manager.getLinkedDevices().length, 0);

    security.issueSession(identity.publicId, identity.cryptoKeyId, 30);
    await manager.connectRelay('admin');

    const req = await manager.createPairingRequest();
    assert.equal(req.pairingCode, '482910');

    // Accepting pairing code enters AWAITING_REQUESTER_CONFIRMATION (not PAIRED yet!)
    const pendingReq = await manager.acceptPairingCode(
      '482910',
      'basic',
      'هاتف اختبار'
    );
    assert.equal(pendingReq.status, 'AWAITING_REQUESTER_CONFIRMATION');
    assert.equal(manager.getLinkedDevices().length, 0);

    // Explicit requester confirmation promotes to PAIRED
    const peer = await manager.confirmPairingApproval(pendingReq.pairingId, true);
    assert.ok(peer);
    assert.equal(peer.pairingState, 'PAIRED');
    assert.equal(peer.verifiedByRelay, true);
    assert.equal(manager.getLinkedDevices().length, 1);

    await manager.revokeLinkedDevice(peer.publicId, true);
    assert.deepEqual(transport.revokedTargets, [peer.publicId]);
    const revoked = manager.getLinkedDevices()[0];
    assert.equal(revoked.pairingState, 'REVOKED');
    assert.equal(revoked.verifiedByRelay, false);
  });
});
