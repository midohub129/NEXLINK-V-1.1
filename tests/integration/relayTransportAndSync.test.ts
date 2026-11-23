import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import express from 'express';
import { WebSocket } from 'ws';
import { DeviceManager } from '../../src/application/devices/deviceManager';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SettingsService } from '../../src/application/settings/settingsService';
import { SyncEngine } from '../../src/application/sync/syncEngine';
import { TransportError } from '../../src/domain/errors/appError';
import {
  InMemoryAuditRepository,
  InMemoryDeviceRepository,
  InMemorySettingsRepository,
  InMemorySyncEventRepository,
} from '../../src/infrastructure/storage/repositories';
import { RelayTransportClient } from '../../src/infrastructure/transport/relayTransportClient';
import { SqliteRelayDatabase } from '../../server/db/sqliteRelayDb';
import { attachRelayUpgrade, createRelayServer } from '../../server/relay/relayRouter';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

async function buildDeviceStack(baseUrl: string, role: 'admin' | 'basic') {
  const logger = new RotatingLogger();
  const crypto = new NodeTestCryptoProvider();
  const settings = new SettingsService(new InMemorySettingsRepository(), logger);
  await settings.initialize();
  await settings.update({
    role,
    notificationAccessGranted: true,
    selectedNotificationApps: ['com.whatsapp'],
    relayEndpoint: baseUrl,
    syncDeliveryPolicy: 'PEER_CONFIRMED',
  });

  const security = new SecurityManager(crypto, new InMemoryAuditRepository(), logger);
  await security.initialize();

  const transport = new RelayTransportClient({
    baseUrl,
    requestTimeoutMs: 4000,
    logger,
    crypto,
    webSocketFactory: (url) => new WebSocket(url) as unknown as globalThis.WebSocket,
  });

  const devices = new DeviceManager({
    deviceRepo: new InMemoryDeviceRepository(),
    crypto,
    transport,
    security,
    settings,
    logger,
  });
  await devices.start();
  const identity = devices.getIdentity()!;
  security.issueSession(identity.publicId, identity.cryptoKeyId, 30);

  const syncEngine = new SyncEngine({
    repo: new InMemorySyncEventRepository(),
    transport,
    crypto,
    security,
    settings,
    devices,
    logger,
  });
  await syncEngine.start();

  return { devices, syncEngine, transport, security, identity };
}

describe('End-to-End Authenticated Relay Transport, Mutual Pairing, E2EE & Peer ACK Tests', () => {
  it('completes challenge-response auth, two-phase mutual pairing, zero-plaintext E2EE WS sync, peer ACK, and trust revocation', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'nexlink-e2e-'));
    const db = new SqliteRelayDatabase(path.join(dir, 'relay.sqlite'));
    const relay = createRelayServer(db);
    const app = express();
    app.use('/api/relay', relay.router);

    const server = http.createServer(app);
    attachRelayUpgrade(server, relay);

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });

    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const baseUrl = `http://127.0.0.1:${address.port}/api/relay`;

    const deviceA = await buildDeviceStack(baseUrl, 'admin');
    const deviceB = await buildDeviceStack(baseUrl, 'basic');

    try {
      await deviceA.devices.connectRelay('admin', 'Admin Phone');
      await deviceB.devices.connectRelay('basic', 'Basic Tablet');

      assert.equal(deviceA.transport.getState(), 'CONNECTED');
      assert.equal(deviceB.transport.getState(), 'CONNECTED');
      assert.ok(deviceA.transport.getServerSession()?.token);
      assert.ok(deviceB.transport.getServerSession()?.token);

      // 1. Two-phase mutual pairing: A creates code -> B enters code -> A verifies B fingerprint & approves
      const pairingReq = await deviceA.devices.createPairingRequest();
      assert.equal(pairingReq.pairingCode.length, 6);

      const pendingFromB = await deviceB.devices.acceptPairingCode(
        pairingReq.pairingCode,
        'basic',
        'Basic Tablet'
      );
      assert.equal(pendingFromB.status, 'AWAITING_REQUESTER_CONFIRMATION');

      // Before A confirms, zero devices are paired
      assert.equal((await deviceA.devices.refreshLinkedDevicesFromRelay()).length, 0);

      // Device A explicitly confirms peer cryptoKeyId fingerprint
      const confirmedPeer = await deviceA.devices.confirmPairingApproval(
        pendingFromB.pairingId,
        true,
        deviceB.identity.cryptoKeyId
      );
      assert.ok(confirmedPeer);
      assert.equal(confirmedPeer.pairingState, 'PAIRED');

      // Wait briefly for WS device:paired notification & refresh on B
      await new Promise((r) => setTimeout(r, 80));
      const linksOnB = await deviceB.devices.refreshLinkedDevicesFromRelay();
      assert.equal(linksOnB.length, 1);
      assert.equal(linksOnB[0].publicId, deviceA.identity.publicId);

      // 2. Device A enqueues notification and runs E2EE SyncEngine cycle
      const secretText = 'Top Secret E2EE Payload Only Peer Reads';
      const enqueued = await deviceA.syncEngine.enqueueNotification({
        packageName: 'com.whatsapp',
        title: 'Live E2EE Relay Message',
        text: secretText,
        notificationKey: 'live-k1',
      });
      assert.equal(enqueued.status, 'SAVED');

      const syncSummary = await deviceA.syncEngine.runSyncCycle();
      assert.equal(syncSummary.attempted, 1);

      // Verify zero plaintext exists in SQLite relay_events!
      const rawDbRow = db.db
        .prepare('SELECT payload FROM relay_events LIMIT 1')
        .get() as { payload: string };
      assert.equal(rawDbRow.payload.includes(secretText), false);
      assert.equal(rawDbRow.payload.includes('Live E2EE Relay Message'), false);

      // Wait briefly for WebSocket delivery onto B -> E2EE decrypt -> ACK back to A
      await new Promise((r) => setTimeout(r, 150));

      const inboundOnB = deviceB.syncEngine.getEvents();
      assert.equal(inboundOnB.length, 1);
      assert.equal(inboundOnB[0].status, 'SYNCED');
      assert.equal(inboundOnB[0].e2eeProtected, true);
      assert.ok(inboundOnB[0].payload.includes(secretText));

      // Device A received peer confirmation ACK and transitioned from IN_PROGRESS -> SYNCED
      const onA = deviceA.syncEngine.getEvents()[0];
      assert.equal(onA.status, 'SYNCED');
      assert.ok(onA.deliveredAt !== null);

      // 3. Trust revocation by Device A terminates B's access
      await deviceA.devices.revokeLinkedDevice(deviceB.identity.publicId, true);
      const afterRevoke = deviceA.devices.getLinkedDevices()[0];
      assert.equal(afterRevoke.pairingState, 'REVOKED');
      assert.equal(afterRevoke.verifiedByRelay, false);
    } finally {
      await deviceA.syncEngine.stop();
      await deviceA.devices.stop();
      await deviceB.syncEngine.stop();
      await deviceB.devices.stop();
      await relay.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces request timeouts and throws retryable TransportError', async () => {
    const logger = new RotatingLogger();
    const crypto = new NodeTestCryptoProvider();
    const keys = await crypto.getOrCreateDeviceKeyPair();
    const slowFetch: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const err = new Error('Aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });

    const client = new RelayTransportClient({
      baseUrl: 'http://127.0.0.1:9999/api/relay',
      requestTimeoutMs: 40,
      logger,
      crypto,
      fetchImpl: slowFetch,
    });

    await assert.rejects(
      () =>
        client.connect({
          publicId: 'dev-timeout',
          cryptoKeyId: keys.cryptoKeyId,
          publicKeyJwk: keys.publicKeyJwk,
          ecdhPublicKeyJwk: keys.ecdhPublicKeyJwk,
          role: 'admin',
          label: 'Timeout Probe',
        }),
      (err: unknown) =>
        err instanceof TransportError &&
        err.code === 'RELAY_TIMEOUT' &&
        err.retryable === true
    );
    assert.equal(client.getState(), 'ERROR');
  });

  it('handles full 2-device offline->online cycle: target offline keeps IN_PROGRESS, reconnect pulls & ACKs without duplicates, and revocation halts sync', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'nexlink-offline-cycle-'));
    const db = new SqliteRelayDatabase(path.join(dir, 'relay.sqlite'));
    const relay = createRelayServer(db);
    const app = express();
    app.use('/api/relay', relay.router);

    const server = http.createServer(app);
    attachRelayUpgrade(server, relay);

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    assert.ok(addr && typeof addr !== 'string');
    const baseUrl = `http://127.0.0.1:${addr.port}/api/relay`;

    const deviceA = await buildDeviceStack(baseUrl, 'admin');
    const deviceB = await buildDeviceStack(baseUrl, 'basic');

    try {
      await deviceA.devices.connectRelay('admin', 'Sender Phone');
      await deviceB.devices.connectRelay('basic', 'Receiver Tablet');

      // Pair A <-> B
      const req = await deviceA.devices.createPairingRequest();
      const pending = await deviceB.devices.acceptPairingCode(
        req.pairingCode,
        'basic',
        'Receiver Tablet'
      );
      await deviceA.devices.confirmPairingApproval(
        pending.pairingId,
        true,
        deviceB.identity.cryptoKeyId
      );
      await new Promise((r) => setTimeout(r, 60));
      await deviceB.devices.refreshLinkedDevicesFromRelay();

      // Target device B goes offline
      await deviceB.devices.disconnectRelay();
      assert.equal(deviceB.transport.getState(), 'DISCONNECTED');

      // Device A sends event while B is offline
      const enqueued = await deviceA.syncEngine.enqueueNotification({
        packageName: 'com.whatsapp',
        title: 'Offline Queued',
        text: 'Delivered once B reconnects',
        notificationKey: 'off-1',
      });
      assert.equal(enqueued.status, 'SAVED');

      const sendWhileOffline = await deviceA.syncEngine.runSyncCycle();
      assert.equal(sendWhileOffline.attempted, 1);
      assert.equal(sendWhileOffline.awaitingPeerAck, 1);
      assert.equal(sendWhileOffline.synced, 0);

      // Verify A's event is IN_PROGRESS (relayAcceptedAt set, deliveredAt still null!)
      const midFlightOnA = deviceA.syncEngine.getEvents()[0];
      assert.equal(midFlightOnA.status, 'IN_PROGRESS');
      assert.ok(midFlightOnA.relayAcceptedAt !== null);
      assert.equal(midFlightOnA.deliveredAt, null);

      // Inspect raw Relay /inbox wire format BEFORE B ingests/ACKs:
      // Must NOT claim status === 'SYNCED' or encrypted === false or e2eeProtected === true!
      const rawInboxBeforeAck = await deviceB.transport.fetchInboundEvents(
        deviceB.identity.publicId
      );
      assert.equal(rawInboxBeforeAck.length, 1);
      assert.equal(rawInboxBeforeAck[0].status, 'IN_PROGRESS');
      assert.equal(rawInboxBeforeAck[0].relayDeliveryState, 'QUEUED_AT_RELAY');
      assert.equal(rawInboxBeforeAck[0].encrypted, true);
      assert.equal(rawInboxBeforeAck[0].localEncrypted, false);
      assert.equal(rawInboxBeforeAck[0].e2eeProtected, false);
      assert.equal(rawInboxBeforeAck[0].e2eeVerified, false);
      assert.equal(rawInboxBeforeAck[0].relaySignatureVerified, true);
      assert.equal(rawInboxBeforeAck[0].deliveredAt, null);
      assert.equal(rawInboxBeforeAck[0].payload, '[E2EE_CIPHERTEXT]');

      // Device B comes back online -> auto-pulls /inbox, decrypts E2EE, stores locally, and sends /sync/ack
      await deviceB.devices.connectRelay('basic', 'Receiver Tablet');
      await new Promise((r) => setTimeout(r, 150));

      assert.equal(deviceB.syncEngine.getEvents().length, 1);
      assert.equal(deviceB.syncEngine.getEvents()[0].e2eeProtected, true);
      assert.equal(deviceB.syncEngine.getEvents()[0].e2eeVerified, true);
      assert.ok(
        deviceB.syncEngine
          .getEvents()[0]
          .payload.includes('Delivered once B reconnects')
      );

      // After B ACKs, /inbox no longer serves the delivered event
      const rawInboxAfterAck = await deviceB.transport.fetchInboundEvents(
        deviceB.identity.publicId
      );
      assert.equal(rawInboxAfterAck.length, 0);

      // Polling / status or WS sync:delivered moves A to SYNCED with deliveredAt
      await deviceA.syncEngine.runSyncCycle();
      const finalOnA = deviceA.syncEngine.getEvents()[0];
      assert.equal(finalOnA.status, 'SYNCED');
      assert.ok(finalOnA.deliveredAt !== null);

      // Device B disconnects & reconnects again -> pulls /inbox again -> ZERO duplicates stored
      await deviceB.devices.disconnectRelay();
      await deviceB.devices.connectRelay('basic', 'Receiver Tablet');
      await new Promise((r) => setTimeout(r, 120));
      assert.equal(deviceB.syncEngine.getEvents().length, 1);

      // Device A enqueues another event -> dispatches -> IN_PROGRESS -> then revokes pairing
      const ev2 = await deviceA.syncEngine.enqueueNotification({
        packageName: 'com.whatsapp',
        title: 'Before Revoke',
        text: 'Must revert on revocation',
        notificationKey: 'off-2',
      });
      assert.equal(ev2.status, 'SAVED');
      await deviceA.devices.revokeLinkedDevice(deviceB.identity.publicId, false);

      const postRevoke = await deviceA.syncEngine.runSyncCycle();
      assert.equal(postRevoke.skippedReason, 'UNPAIRED');

      // Revoked B's /inbox returns empty because link is no longer PAIRED
      const inboxAfterRevoke = await deviceB.transport.fetchInboundEvents(
        deviceB.identity.publicId
      );
      assert.equal(inboxAfterRevoke.length, 0);
    } finally {
      await deviceA.syncEngine.stop();
      await deviceA.devices.stop();
      await deviceB.syncEngine.stop();
      await deviceB.devices.stop();
      await relay.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps recipient IN_PROGRESS when /sync/ack fails transiently across restart and promotes both peers to SYNCED only after ACK succeeds on reconnect', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'nexlink-ack-recovery-'));
    const db = new SqliteRelayDatabase(path.join(dir, 'relay.sqlite'));
    const relay = createRelayServer(db);
    const app = express();
    app.use('/api/relay', relay.router);

    const server = http.createServer(app);
    attachRelayUpgrade(server, relay);

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    assert.ok(addr && typeof addr !== 'string');
    const baseUrl = `http://127.0.0.1:${addr.port}/api/relay`;

    const deviceA = await buildDeviceStack(baseUrl, 'admin');
    const loggerB = new RotatingLogger();
    const cryptoB = new NodeTestCryptoProvider();
    const settingsB = new SettingsService(new InMemorySettingsRepository(), loggerB);
    await settingsB.initialize();
    await settingsB.update({
      role: 'basic',
      notificationAccessGranted: true,
      selectedNotificationApps: ['com.whatsapp'],
      relayEndpoint: baseUrl,
      syncDeliveryPolicy: 'PEER_CONFIRMED',
    });
    const securityB = new SecurityManager(
      cryptoB,
      new InMemoryAuditRepository(),
      loggerB
    );
    await securityB.initialize();
    const transportB = new RelayTransportClient({
      baseUrl,
      requestTimeoutMs: 4000,
      logger: loggerB,
      crypto: cryptoB,
      webSocketFactory: (url) => new WebSocket(url) as unknown as globalThis.WebSocket,
    });
    const devicesB = new DeviceManager({
      deviceRepo: new InMemoryDeviceRepository(),
      crypto: cryptoB,
      transport: transportB,
      security: securityB,
      settings: settingsB,
      logger: loggerB,
    });
    await devicesB.start();
    const idB = devicesB.getIdentity()!;
    securityB.issueSession(idB.publicId, idB.cryptoKeyId, 30);

    const repoB = new InMemorySyncEventRepository();
    let syncEngineB = new SyncEngine({
      repo: repoB,
      transport: transportB,
      crypto: cryptoB,
      security: securityB,
      settings: settingsB,
      devices: devicesB,
      logger: loggerB,
    });
    await syncEngineB.start();

    try {
      await deviceA.devices.connectRelay('admin', 'Sender');
      await devicesB.connectRelay('basic', 'Receiver');

      const req = await deviceA.devices.createPairingRequest();
      const pending = await devicesB.acceptPairingCode(
        req.pairingCode,
        'basic',
        'Receiver'
      );
      await deviceA.devices.confirmPairingApproval(
        pending.pairingId,
        true,
        idB.cryptoKeyId
      );
      await new Promise((r) => setTimeout(r, 60));
      await devicesB.refreshLinkedDevicesFromRelay();

      // Simulate transient ACK transport failure on Receiver B
      const origAckB = transportB.acknowledgeInboundDelivery.bind(transportB);
      transportB.acknowledgeInboundDelivery = async () => {
        throw new Error('Simulated /sync/ack timeout');
      };

      await deviceA.syncEngine.enqueueNotification({
        packageName: 'com.whatsapp',
        title: 'ACK Failure Drill',
        text: 'Must remain IN_PROGRESS until ACK succeeds',
        notificationKey: 'ack-drill-1',
      });
      await deviceA.syncEngine.runSyncCycle();
      await new Promise((r) => setTimeout(r, 150));

      // Both Receiver B repo, SQLite relay_events, and Sender A must remain IN_PROGRESS (NOT SYNCED!)
      const bStoredBeforeAck = await repoB.getAll();
      assert.equal(bStoredBeforeAck.length, 1);
      assert.equal(bStoredBeforeAck[0].status, 'IN_PROGRESS');
      assert.equal(bStoredBeforeAck[0].inboundAckConfirmed, false);
      assert.equal(bStoredBeforeAck[0].deliveredAt, null);
      assert.equal(deviceA.syncEngine.getEvents()[0].status, 'IN_PROGRESS');
      assert.equal(deviceA.syncEngine.getEvents()[0].deliveredAt, null);

      const relayRowBeforeAck = db.db
        .prepare('SELECT id, delivered_at FROM relay_events WHERE idempotency_key = ?')
        .get(bStoredBeforeAck[0].idempotencyKey) as {
        id: number;
        delivered_at: number | null;
      };
      assert.equal(relayRowBeforeAck.delivered_at, null);

      // Receiver B restarts while offline with ACK still unconfirmed
      await syncEngineB.stop();
      await devicesB.disconnectRelay();
      transportB.acknowledgeInboundDelivery = origAckB;

      syncEngineB = new SyncEngine({
        repo: repoB,
        transport: transportB,
        crypto: cryptoB,
        security: securityB,
        settings: settingsB,
        devices: devicesB,
        logger: loggerB,
      });
      await syncEngineB.start();
      const bStoredAfterRestart = await repoB.findById(bStoredBeforeAck[0].id);
      assert.equal(bStoredAfterRestart?.status, 'IN_PROGRESS');
      assert.equal(bStoredAfterRestart?.inboundAckConfirmed, false);

      // Reconnect triggers retryPendingInboundAcks() + /inbox reconciliation -> ACK succeeds with 0 duplicates!
      await devicesB.connectRelay('basic', 'Receiver');
      await new Promise((r) => setTimeout(r, 180));

      const bStoredAfterRecovery = await repoB.getAll();
      assert.equal(bStoredAfterRecovery.length, 1);
      assert.equal(bStoredAfterRecovery[0].status, 'SYNCED');
      assert.equal(bStoredAfterRecovery[0].inboundAckConfirmed, true);
      assert.ok(bStoredAfterRecovery[0].deliveredAt !== null);
      assert.equal((await transportB.fetchInboundEvents(idB.publicId)).length, 0);

      const relayRowAfterAck = db.db
        .prepare('SELECT id, delivered_at FROM relay_events WHERE idempotency_key = ?')
        .get(bStoredBeforeAck[0].idempotencyKey) as {
        id: number;
        delivered_at: number | null;
      };
      assert.ok(relayRowAfterAck.delivered_at !== null);

      // Sender A received sync:delivered / status poll and transitioned to SYNCED
      await deviceA.syncEngine.runSyncCycle();
      assert.equal(deviceA.syncEngine.getEvents()[0].status, 'SYNCED');
      assert.ok(deviceA.syncEngine.getEvents()[0].deliveredAt !== null);
    } finally {
      await deviceA.syncEngine.stop();
      await deviceA.devices.stop();
      await syncEngineB.stop();
      await devicesB.stop();
      await relay.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
