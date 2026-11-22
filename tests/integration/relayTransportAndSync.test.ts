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
  });

  const security = new SecurityManager(
    crypto,
    new InMemoryAuditRepository(),
    logger
  );
  await security.initialize();

  const transport = new RelayTransportClient({
    baseUrl,
    requestTimeoutMs: 4000,
    logger,
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

describe('End-to-End Relay Transport, Pairing & Sync Integration Tests', () => {
  it('pairs two real DeviceManagers over HTTP+WS relay, syncs idempotent batches, and pushes inbound events', async () => {
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

      // 1. Device A creates pairing code, Device B accepts it
      const pairingReq = await deviceA.devices.createPairingRequest();
      assert.equal(pairingReq.pairingCode.length, 6);

      const pairedFromB = await deviceB.devices.acceptPairingCode(
        pairingReq.pairingCode,
        'basic',
        'Basic Tablet'
      );
      assert.equal(pairedFromB.publicId, deviceA.identity.publicId);
      assert.equal(pairedFromB.verifiedByRelay, true);

      // Refresh Device A's authoritative links from relay
      const linksOnA = await deviceA.devices.refreshLinkedDevicesFromRelay();
      assert.equal(linksOnA.length, 1);
      assert.equal(linksOnA[0].publicId, deviceB.identity.publicId);
      assert.equal(linksOnA[0].pairingState, 'PAIRED');

      // 2. Device A enqueues notification and runs SyncEngine cycle
      const enqueued = await deviceA.syncEngine.enqueueNotification({
        packageName: 'com.whatsapp',
        title: 'Live Relay Message',
        text: 'Delivered through Express + SQLite + WebSocket',
        notificationKey: 'live-k1',
      });
      assert.equal(enqueued.status, 'SAVED');

      const syncSummary = await deviceA.syncEngine.runSyncCycle();
      assert.equal(syncSummary.synced, 1);
      assert.equal(syncSummary.failed, 0);
      assert.equal(deviceA.syncEngine.getEvents()[0].status, 'SYNCED');

      // Wait briefly for WebSocket delivery onto Device B's SyncEngine
      await new Promise((r) => setTimeout(r, 150));
      const inboundOnB = deviceB.syncEngine.getEvents();
      assert.equal(inboundOnB.length, 1);
      assert.equal(inboundOnB[0].status, 'SYNCED');
      assert.ok(inboundOnB[0].payload.includes('Live Relay Message'));

      // 3. Revocation on Device A marks link REVOKED
      await deviceA.devices.revokeLinkedDevice(deviceB.identity.publicId);
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
      fetchImpl: slowFetch,
    });

    await assert.rejects(
      () =>
        client.connect({
          publicId: 'dev-timeout',
          cryptoKeyId: 'ecdsa-timeout',
          publicKeyJwk: null,
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
});
