import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import express from 'express';
import { WebSocket } from 'ws';
import { SqliteRelayDatabase } from '../../server/db/sqliteRelayDb';
import { attachRelayUpgrade, createRelayServer } from '../../server/relay/relayRouter';
import { SecurityError } from '../../src/domain/errors/appError';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

function sha256(val: string): string {
  return createHash('sha256').update(val, 'utf8').digest('hex');
}

async function createTestRelayServer() {
  const dir = mkdtempSync(path.join(tmpdir(), 'nexlink-sec-'));
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
  const port = addr.port;
  const baseUrl = `http://127.0.0.1:${port}/api/relay`;
  const wsBaseUrl = `ws://127.0.0.1:${port}/ws/relay`;

  return {
    baseUrl,
    wsBaseUrl,
    db,
    relay,
    close: async () => {
      await relay.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}


const WEBSOCKET_TEST_TIMEOUT_MS = 10_000;

function waitForWebSocketClose(
  ws: WebSocket,
  label: string,
  timeoutMs = WEBSOCKET_TEST_TIMEOUT_MS
): Promise<number> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      ws.off('close', onClose);
      ws.off('error', onError);
    };
    const onClose = (code: number) => {
      cleanup();
      resolve(code);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(new Error(`${label}: WebSocket error: ${error.message}`));
    };
    const timer = setTimeout(() => {
      cleanup();
      ws.terminate();
      reject(new Error(`${label}: timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    ws.once('close', onClose);
    ws.once('error', onError);
  });
}

function waitForFirstWebSocketMessage(
  ws: WebSocket,
  label: string,
  timeoutMs = WEBSOCKET_TEST_TIMEOUT_MS
): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      ws.off('message', onMessage);
      ws.off('close', onClose);
      ws.off('error', onError);
    };
    const onMessage = () => {
      cleanup();
      resolve();
    };
    const onClose = (code: number) => {
      cleanup();
      reject(new Error(`${label}: WebSocket closed before its first message (code ${code})`));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(new Error(`${label}: WebSocket error: ${error.message}`));
    };
    const timer = setTimeout(() => {
      cleanup();
      ws.terminate();
      reject(new Error(`${label}: timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    ws.once('message', onMessage);
    ws.once('close', onClose);
    ws.once('error', onError);
  });
}

function waitForWebSocketSyncEvent(
  ws: WebSocket,
  label: string,
  timeoutMs = WEBSOCKET_TEST_TIMEOUT_MS
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      ws.off('message', onMessage);
      ws.off('close', onClose);
      ws.off('error', onError);
    };
    const onMessage = (raw: WebSocket.RawData) => {
      try {
        const msg = JSON.parse(raw.toString('utf8')) as {
          type?: string;
          event?: Record<string, unknown>;
        };
        if (msg.type === 'sync:event' && msg.event) {
          cleanup();
          resolve(msg.event);
        }
      } catch (error) {
        cleanup();
        reject(error);
      }
    };
    const onClose = (code: number) => {
      cleanup();
      reject(new Error(`${label}: WebSocket closed before sync:event (code ${code})`));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(new Error(`${label}: WebSocket error: ${error.message}`));
    };
    const timer = setTimeout(() => {
      cleanup();
      ws.terminate();
      reject(new Error(`${label}: timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    ws.on('message', onMessage);
    ws.once('close', onClose);
    ws.once('error', onError);
  });
}

async function registerAndAuthenticate(
  baseUrl: string,
  publicId: string,
  role: 'admin' | 'basic',
  label: string
) {
  const crypto = new NodeTestCryptoProvider();
  const keys = await crypto.getOrCreateDeviceKeyPair();
  const ts = Date.now();
  const nonce = crypto.randomHex(16);
  const ecdhHash = sha256(JSON.stringify(keys.ecdhPublicKeyJwk));
  const regMsg = `REGISTER|${publicId}|${keys.cryptoKeyId}|${ecdhHash}|${role}|${ts}|${nonce}`;
  const regSig = await crypto.signPayload(regMsg);

  const regRes = await fetch(`${baseUrl}/devices/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      publicId,
      cryptoKeyId: keys.cryptoKeyId,
      publicKeyJwk: keys.publicKeyJwk,
      ecdhPublicKeyJwk: keys.ecdhPublicKeyJwk,
      role,
      label,
      timestamp: ts,
      nonce,
      signature: regSig,
    }),
  });
  assert.equal(regRes.status, 200);

  const chalRes = await fetch(`${baseUrl}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicId }),
  });
  assert.equal(chalRes.status, 200);
  const { challenge } = (await chalRes.json()) as { challenge: string };

  const authTs = Date.now();
  const authNonce = crypto.randomHex(16);
  const authSig = await crypto.signPayload(
    `AUTH|${publicId}|${challenge}|${authTs}|${authNonce}`
  );
  const sessRes = await fetch(`${baseUrl}/auth/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      publicId,
      challenge,
      timestamp: authTs,
      nonce: authNonce,
      signature: authSig,
    }),
  });
  assert.equal(sessRes.status, 200);
  const session = (await sessRes.json()) as {
    sessionId: string;
    token: string;
  };

  async function signedFetch(
    method: string,
    subPath: string,
    bodyObj?: unknown
  ): Promise<Response> {
    const bodyString = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
    const fullUrl = `${baseUrl}${subPath}`;
    const canonicalPath = new URL(fullUrl).pathname + new URL(fullUrl).search;
    const reqTs = Date.now();
    const reqNonce = crypto.randomHex(16);
    const msg = `${method.toUpperCase()}|${canonicalPath}|${sha256(bodyString)}|${reqTs}|${reqNonce}`;
    const sig = await crypto.signPayload(msg);

    return fetch(fullUrl, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.token}`,
        'X-Nexlink-Timestamp': String(reqTs),
        'X-Nexlink-Nonce': reqNonce,
        'X-Nexlink-Signature': sig,
      },
      body: method === 'GET' ? undefined : bodyString || '{}',
    });
  }

  return { publicId, crypto, keys, session, signedFetch };
}

describe('P0/P1 Negative Security, E2EE & Reliability Audit Suite', () => {
  it('1. Unauthorized Device Registration & 2. Forged Device Identity', async () => {
    const srv = await createTestRelayServer();
    try {
      const attackerCrypto = new NodeTestCryptoProvider();
      const attackerKeys = await attackerCrypto.getOrCreateDeviceKeyPair();

      // Unsigned / mismatched registration signature rejected 401
      const badReg = await fetch(`${srv.baseUrl}/devices/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          publicId: 'victim-device',
          cryptoKeyId: attackerKeys.cryptoKeyId,
          publicKeyJwk: attackerKeys.publicKeyJwk,
          ecdhPublicKeyJwk: attackerKeys.ecdhPublicKeyJwk,
          role: 'admin',
          label: 'Unsigned',
          timestamp: Date.now(),
          nonce: attackerCrypto.randomHex(16),
          signature: Buffer.alloc(64).toString('base64'),
        }),
      });
      assert.equal(badReg.status, 401);

      // Register real victim device
      const victim = await registerAndAuthenticate(
        srv.baseUrl,
        'victim-device',
        'admin',
        'Victim'
      );

      // Forged identity re-registration of existing publicId with different keypair rejected 403 IDENTITY_CONFLICT
      const ts = Date.now();
      const nonce = attackerCrypto.randomHex(16);
      const ecdhHash = sha256(JSON.stringify(attackerKeys.ecdhPublicKeyJwk));
      const hijackSig = await attackerCrypto.signPayload(
        `REGISTER|victim-device|${attackerKeys.cryptoKeyId}|${ecdhHash}|admin|${ts}|${nonce}`
      );
      const hijackRes = await fetch(`${srv.baseUrl}/devices/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          publicId: 'victim-device',
          cryptoKeyId: attackerKeys.cryptoKeyId,
          publicKeyJwk: attackerKeys.publicKeyJwk,
          ecdhPublicKeyJwk: attackerKeys.ecdhPublicKeyJwk,
          role: 'admin',
          label: 'Hijacker',
          timestamp: ts,
          nonce,
          signature: hijackSig,
        }),
      });
      assert.equal(hijackRes.status, 403);

      // Authenticated attacker cannot read victim links or inbox (ownership check)
      const attacker = await registerAndAuthenticate(
        srv.baseUrl,
        'attacker-device',
        'basic',
        'Attacker'
      );
      const readVictimLinks = await attacker.signedFetch(
        'GET',
        `/devices/${victim.publicId}/links`
      );
      assert.equal(readVictimLinks.status, 403);

      const readVictimInbox = await attacker.signedFetch(
        'GET',
        `/sync/${victim.publicId}/inbox`
      );
      assert.equal(readVictimInbox.status, 403);
    } finally {
      await srv.close();
    }
  });

  it('3. Unauthorized Device Revocation & 4. Pairing Replay Attack & 5. Invalid Signature Rejection', async () => {
    const srv = await createTestRelayServer();
    try {
      const admin = await registerAndAuthenticate(
        srv.baseUrl,
        'admin-dev',
        'admin',
        'Admin'
      );
      const basic = await registerAndAuthenticate(
        srv.baseUrl,
        'basic-dev',
        'basic',
        'Basic'
      );
      const intruder = await registerAndAuthenticate(
        srv.baseUrl,
        'intruder-dev',
        'admin',
        'Intruder'
      );

      // Basic device cannot create pairing request (403 FORBIDDEN_ROLE)
      const basicPairReq = await basic.signedFetch('POST', '/pairing/request', {});
      assert.equal(basicPairReq.status, 403);

      // Admin creates pairing code
      const pairRes = await admin.signedFetch('POST', '/pairing/request', {});
      assert.equal(pairRes.status, 200);
      const pairing = (await pairRes.json()) as {
        pairingId: string;
        pairingCode: string;
      };

      // Basic submits pairing code acceptance -> AWAITING_REQUESTER_CONFIRMATION
      const accept1 = await basic.signedFetch('POST', '/pairing/accept', {
        pairingCode: pairing.pairingCode,
      });
      assert.equal(accept1.status, 200);

      // Replay attack: intruder tries reusing the same pairing code -> rejected 409 ALREADY_CONSUMED
      const replayPairing = await intruder.signedFetch('POST', '/pairing/accept', {
        pairingCode: pairing.pairingCode,
      });
      assert.equal(replayPairing.status, 409);

      // Intruder tries confirming admin's pairing request -> rejected 403 FORBIDDEN_OWNERSHIP
      const hijackConfirm = await intruder.signedFetch('POST', '/pairing/confirm', {
        pairingId: pairing.pairingId,
        approve: true,
      });
      assert.equal(hijackConfirm.status, 403);

      // Admin confirms with WRONG key fingerprint -> rejected 409 KEY_FINGERPRINT_MISMATCH
      const mismatchConfirm = await admin.signedFetch('POST', '/pairing/confirm', {
        pairingId: pairing.pairingId,
        approve: true,
        expectedResponderCryptoKeyId: 'ecdsa-wrongfingerprint',
      });
      assert.equal(mismatchConfirm.status, 409);

      // Admin confirms with valid peer fingerprint -> PAIRED
      const validConfirm = await admin.signedFetch('POST', '/pairing/confirm', {
        pairingId: pairing.pairingId,
        approve: true,
        expectedResponderCryptoKeyId: basic.keys.cryptoKeyId,
      });
      assert.equal(validConfirm.status, 200);

      // 3. Unauthorized Device Revocation: intruder cannot revoke admin's device link
      const intruderRevoke = await intruder.signedFetch(
        'POST',
        `/devices/${admin.publicId}/revoke`,
        { targetDeviceId: basic.publicId, revokeDeviceTrust: true }
      );
      assert.equal(intruderRevoke.status, 403);

      // 5. Invalid Signature Rejection & HTTP Replay Rejection
      const badSigRes = await fetch(`${srv.baseUrl}/devices/${admin.publicId}/links`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${admin.session.token}`,
          'X-Nexlink-Timestamp': String(Date.now()),
          'X-Nexlink-Nonce': admin.crypto.randomHex(16),
          'X-Nexlink-Signature': Buffer.alloc(64).toString('base64'),
        },
      });
      assert.equal(badSigRes.status, 401);

      // HTTP Request Replay Attack: send identical signed request twice
      const pathStr = `/devices/${admin.publicId}/links`;
      const replayTs = Date.now();
      const replayNonce = admin.crypto.randomHex(16);
      const msg = `GET|/api/relay${pathStr}|${sha256('')}|${replayTs}|${replayNonce}`;
      const sig = await admin.crypto.signPayload(msg);
      const headers = {
        Authorization: `Bearer ${admin.session.token}`,
        'X-Nexlink-Timestamp': String(replayTs),
        'X-Nexlink-Nonce': replayNonce,
        'X-Nexlink-Signature': sig,
      };
      const firstReq = await fetch(`${srv.baseUrl}${pathStr}`, { headers });
      assert.equal(firstReq.status, 200);
      const secondReplayReq = await fetch(`${srv.baseUrl}${pathStr}`, { headers });
      assert.equal(secondReplayReq.status, 409);
    } finally {
      await srv.close();
    }
  });

  it('6. WebSocket Identity Spoofing & 12. Revoked Device Session Rejection', async () => {
    const srv = await createTestRelayServer();
    let peerWs: WebSocket | undefined;
    try {
      const admin = await registerAndAuthenticate(
        srv.baseUrl,
        'ws-admin',
        'admin',
        'WS Admin'
      );
      const peer = await registerAndAuthenticate(
        srv.baseUrl,
        'ws-peer',
        'basic',
        'WS Peer'
      );

      // 6a. Spoofing WS with legacy ?deviceId= query param without ticket -> closed 1008
      const spoofWs = new WebSocket(`${srv.wsBaseUrl}?deviceId=${admin.publicId}`);
      const spoofCode = await waitForWebSocketClose(
        spoofWs,
        'Unauthenticated WebSocket rejection'
      );
      assert.equal(spoofCode, 1008);

      // 6b. Obtain legitimate single-use ticket for peer
      const ticketRes = await peer.signedFetch('POST', '/ws/ticket', {});
      assert.equal(ticketRes.status, 200);
      const { ticket } = (await ticketRes.json()) as { ticket: string };

      // Connect peer WS cleanly
      peerWs = new WebSocket(
        `${srv.wsBaseUrl}?ticket=${encodeURIComponent(ticket)}`
      );
      await waitForFirstWebSocketMessage(peerWs, 'Authenticated peer WebSocket');

      // Replaying the same single-use WS ticket fails with 1008
      const replayWs = new WebSocket(
        `${srv.wsBaseUrl}?ticket=${encodeURIComponent(ticket)}`
      );
      const replayWsCode = await waitForWebSocketClose(
        replayWs,
        'Replayed single-use WebSocket ticket rejection'
      );
      assert.equal(replayWsCode, 1008);

      // Pair admin <-> peer so admin can revoke trust
      const pairReq = (await (
        await admin.signedFetch('POST', '/pairing/request', {})
      ).json()) as { pairingId: string; pairingCode: string };
      await peer.signedFetch('POST', '/pairing/accept', {
        pairingCode: pairReq.pairingCode,
      });
      await admin.signedFetch('POST', '/pairing/confirm', {
        pairingId: pairReq.pairingId,
        approve: true,
      });

      // 12. Revoked Device Session Rejection: Admin revokes trust on peer
      const closePromise = waitForWebSocketClose(
        peerWs,
        'Revoked peer WebSocket closure'
      );
      const revokeRes = await admin.signedFetch(
        'POST',
        `/devices/${admin.publicId}/revoke`,
        { targetDeviceId: peer.publicId, revokeDeviceTrust: true }
      );
      assert.equal(revokeRes.status, 200);
      assert.equal(await closePromise, 1008);

      // Revoked peer's existing Bearer session is immediately rejected (401)
      const afterRevokeFetch = await peer.signedFetch(
        'GET',
        `/devices/${peer.publicId}/links`
      );
      assert.equal(afterRevokeFetch.status, 401);

      // Revoked peer cannot request a new auth challenge (403 DEVICE_REVOKED)
      const newChal = await fetch(`${srv.baseUrl}/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ publicId: peer.publicId }),
      });
      assert.equal(newChal.status, 403);
    } finally {
      peerWs?.terminate();
      await srv.close();
    }
  });

  it('7. Unauthorized Sync, 8. E2EE Integrity, 9. Tampered Ciphertext Rejection & 10. Duplicate Delivery Prevention', async () => {
    const srv = await createTestRelayServer();
    let rxWs: WebSocket | undefined;
    try {
      const sender = await registerAndAuthenticate(
        srv.baseUrl,
        'e2ee-sender',
        'admin',
        'Sender'
      );
      const receiver = await registerAndAuthenticate(
        srv.baseUrl,
        'e2ee-receiver',
        'basic',
        'Receiver'
      );
      const stranger = await registerAndAuthenticate(
        srv.baseUrl,
        'e2ee-stranger',
        'basic',
        'Stranger'
      );

      // 7a. Unauthenticated sync rejected 401
      const unauthSync = await fetch(`${srv.baseUrl}/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: sender.publicId,
          targetDeviceId: receiver.publicId,
          events: [],
        }),
      });
      assert.equal(unauthSync.status, 401);

      // 7b. Sync to unpaired device rejected 403 NOT_PAIRED_OR_REVOKED
      const unpairedSync = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [],
      });
      assert.equal(unpairedSync.status, 403);

      // Pair sender and receiver
      const pr = (await (
        await sender.signedFetch('POST', '/pairing/request', {})
      ).json()) as { pairingId: string; pairingCode: string };
      await receiver.signedFetch('POST', '/pairing/accept', {
        pairingCode: pr.pairingCode,
      });
      await sender.signedFetch('POST', '/pairing/confirm', {
        pairingId: pr.pairingId,
        approve: true,
      });

      // 7c. Plaintext event without valid E2eeEnvelope rejected 422 E2EE_ENVELOPE_REQUIRED
      const plaintextReject = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            id: 1,
            type: 'notification',
            payload: '{"plaintext":"forbidden"}',
            idempotencyKey: 'plain-1',
            createdAt: Date.now(),
          },
        ],
      });
      assert.equal(plaintextReject.status, 422);

      // 8. End-to-End Encryption Integrity: sender -> receiver
      const plaintextMsg = JSON.stringify({
        packageName: 'com.whatsapp',
        title: 'Confidential',
        text: 'Only receiver should decrypt this',
        postedAt: 123456,
      });

      const envelope = await sender.crypto.encryptForPeer({
        plaintext: plaintextMsg,
        senderDeviceId: sender.publicId,
        recipientDeviceId: receiver.publicId,
        senderCryptoKeyId: sender.keys.cryptoKeyId,
        recipientCryptoKeyId: receiver.keys.cryptoKeyId,
        recipientEcdhPublicKeyJwk: receiver.keys.ecdhPublicKeyJwk!,
        sessionId: sender.session.sessionId,
        idempotencyKey: 'e2ee-idem-1',
      });

      const decryptedByReceiver = await receiver.crypto.decryptFromPeer({
        envelope,
        senderEcdsaPublicKeyJwk: sender.keys.publicKeyJwk!,
        senderEcdhPublicKeyJwk: sender.keys.ecdhPublicKeyJwk!,
        expectedRecipientDeviceId: receiver.publicId,
        expectedRecipientCryptoKeyId: receiver.keys.cryptoKeyId,
      });
      assert.equal(decryptedByReceiver, plaintextMsg);

      // Stranger cannot decrypt using their keys
      await assert.rejects(
        () =>
          stranger.crypto.decryptFromPeer({
            envelope,
            senderEcdsaPublicKeyJwk: sender.keys.publicKeyJwk!,
            senderEcdhPublicKeyJwk: sender.keys.ecdhPublicKeyJwk!,
            expectedRecipientDeviceId: receiver.publicId,
            expectedRecipientCryptoKeyId: receiver.keys.cryptoKeyId,
          }),
        (err: unknown) =>
          err instanceof SecurityError && err.code === 'E2EE_DECRYPT_FAILED'
      );

      // 9. Tampered Ciphertext & Signature Rejection
      const tamperedCipher = {
        ...envelope,
        ciphertext: `XXXX${envelope.ciphertext.slice(4)}`,
      };
      await assert.rejects(
        () =>
          receiver.crypto.decryptFromPeer({
            envelope: tamperedCipher,
            senderEcdsaPublicKeyJwk: sender.keys.publicKeyJwk!,
            senderEcdhPublicKeyJwk: sender.keys.ecdhPublicKeyJwk!,
            expectedRecipientDeviceId: receiver.publicId,
            expectedRecipientCryptoKeyId: receiver.keys.cryptoKeyId,
          }),
        (err: unknown) =>
          err instanceof SecurityError && err.code === 'E2EE_INVALID_SIGNATURE'
      );

      // 10. Duplicate Delivery Prevention at Relay SQLite boundary
      const wireEvent = {
        id: 101,
        type: 'notification',
        payload: '[E2EE_CIPHERTEXT]',
        idempotencyKey: 'e2ee-idem-1',
        createdAt: Date.now(),
        e2eeEnvelope: envelope,
      };
      const sync1 = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [wireEvent],
      });
      assert.equal(sync1.status, 200);
      const ack1 = (await sync1.json()) as {
        acceptedIds: number[];
        duplicateIds: number[];
      };
      assert.deepEqual(ack1.acceptedIds, [101]);
      assert.deepEqual(ack1.duplicateIds, []);

      const syncDup = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [wireEvent],
      });
      assert.equal(syncDup.status, 200);
      const ackDup = (await syncDup.json()) as {
        acceptedIds: number[];
        duplicateIds: number[];
      };
      assert.deepEqual(ackDup.acceptedIds, []);
      assert.deepEqual(ackDup.duplicateIds, [101]);

      // 11. Tampered AAD metadata rejection & direction mismatch binding
      const tamperedAad = {
        ...envelope,
        aad: envelope.aad.replace('e2ee-idem-1', 'e2ee-idem-evil'),
      };
      await assert.rejects(
        () =>
          receiver.crypto.decryptFromPeer({
            envelope: tamperedAad,
            senderEcdsaPublicKeyJwk: sender.keys.publicKeyJwk!,
            senderEcdhPublicKeyJwk: sender.keys.ecdhPublicKeyJwk!,
            expectedRecipientDeviceId: receiver.publicId,
            expectedRecipientCryptoKeyId: receiver.keys.cryptoKeyId,
          }),
        (err: unknown) =>
          err instanceof SecurityError && err.code === 'E2EE_INVALID_SIGNATURE'
      );

      // Sender/wrong-direction binding rejected
      await assert.rejects(
        () =>
          sender.crypto.decryptFromPeer({
            envelope,
            senderEcdsaPublicKeyJwk: sender.keys.publicKeyJwk!,
            senderEcdhPublicKeyJwk: sender.keys.ecdhPublicKeyJwk!,
            expectedRecipientDeviceId: sender.publicId,
            expectedRecipientCryptoKeyId: sender.keys.cryptoKeyId,
          }),
        (err: unknown) =>
          err instanceof SecurityError && err.code === 'E2EE_BINDING_MISMATCH'
      );

      // 12. Relay rejects mismatched senderCryptoKeyId / recipientCryptoKeyId in envelope (422)
      const spoofedKeyIdEnvelope = {
        ...envelope,
        senderCryptoKeyId: 'ecdsa-spoofed000000000000000',
      };
      const badKeyIdSync = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            ...wireEvent,
            id: 102,
            idempotencyKey: 'e2ee-idem-spoofed',
            e2eeEnvelope: spoofedKeyIdEnvelope,
          },
        ],
      });
      assert.equal(badKeyIdSync.status, 422);
      const badKeyJson = (await badKeyIdSync.json()) as { code: string };
      assert.equal(badKeyJson.code, 'E2EE_KEY_ID_MISMATCH');

      // 13. Relay rejects forged ECDSA signature inside E2EE envelope (422 E2EE_ENVELOPE_SIGNATURE_INVALID)
      const forgedTargetEnv = await sender.crypto.encryptForPeer({
        plaintext: plaintextMsg,
        senderDeviceId: sender.publicId,
        recipientDeviceId: receiver.publicId,
        senderCryptoKeyId: sender.keys.cryptoKeyId,
        recipientCryptoKeyId: receiver.keys.cryptoKeyId,
        recipientEcdhPublicKeyJwk: receiver.keys.ecdhPublicKeyJwk!,
        sessionId: sender.session.sessionId,
        idempotencyKey: 'e2ee-idem-forged-sig',
      });
      const forgedRelayEnv = {
        ...forgedTargetEnv,
        signature: Buffer.alloc(64, 5).toString('base64'),
      };
      const forgedRelaySync = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            ...wireEvent,
            id: 103,
            idempotencyKey: 'e2ee-idem-forged-sig',
            e2eeEnvelope: forgedRelayEnv,
          },
        ],
      });
      assert.equal(forgedRelaySync.status, 422);
      const forgedRelayJson = (await forgedRelaySync.json()) as { code: string };
      assert.equal(forgedRelayJson.code, 'E2EE_ENVELOPE_SIGNATURE_INVALID');

      // 14. Relay rejects AAD metadata tampering inside E2EE envelope (422 E2EE_AAD_INVALID)
      const tamperedRelaySync = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            ...wireEvent,
            id: 104,
            idempotencyKey: 'e2ee-idem-aad-mismatch',
            e2eeEnvelope: envelope,
          },
        ],
      });
      assert.equal(tamperedRelaySync.status, 422);
      const tamperedRelayJson = (await tamperedRelaySync.json()) as { code: string };
      assert.equal(tamperedRelayJson.code, 'E2EE_AAD_INVALID');

      // 15. Relay rejects reused messageNonce on a different idempotencyKey (409 E2EE_NONCE_REUSED)
      const forgedNonceReusedAad = JSON.stringify({
        v: 1,
        senderDeviceId: sender.publicId,
        recipientDeviceId: receiver.publicId,
        senderCryptoKeyId: sender.keys.cryptoKeyId,
        recipientCryptoKeyId: receiver.keys.cryptoKeyId,
        sessionId: sender.session.sessionId,
        messageNonce: envelope.messageNonce,
        idempotencyKey: 'e2ee-idem-nonce-reused',
      });
      const nonceReuseSig = await sender.crypto.signPayload(
        `E2EE|${sha256(forgedNonceReusedAad)}|${sha256(`${envelope.iv}:${envelope.ciphertext}`)}`
      );
      const nonceReuseRes = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            ...wireEvent,
            id: 105,
            idempotencyKey: 'e2ee-idem-nonce-reused',
            e2eeEnvelope: {
              ...envelope,
              aad: forgedNonceReusedAad,
              signature: nonceReuseSig,
            },
          },
        ],
      });
      assert.equal(nonceReuseRes.status, 409);
      const nonceReuseJson = (await nonceReuseRes.json()) as { code: string };
      assert.equal(nonceReuseJson.code, 'E2EE_NONCE_REUSED');

      // 16. Verify receiver's /inbox returns truthful encryption flags and non-SYNCED pre-ACK status
      const receiverInboxRes = await receiver.signedFetch(
        'GET',
        `/sync/${receiver.publicId}/inbox`
      );
      assert.equal(receiverInboxRes.status, 200);
      const inboxBody = (await receiverInboxRes.json()) as {
        events: Array<Record<string, unknown>>;
      };
      assert.equal(inboxBody.events.length, 1);
      assert.equal(inboxBody.events[0].encrypted, true);
      assert.equal(inboxBody.events[0].localEncrypted, false);
      assert.equal(inboxBody.events[0].e2eeProtected, false);
      assert.equal(inboxBody.events[0].e2eeVerified, false);
      assert.equal(inboxBody.events[0].relaySignatureVerified, true);
      assert.equal(inboxBody.events[0].status, 'IN_PROGRESS');
      assert.equal(inboxBody.events[0].relayDeliveryState, 'QUEUED_AT_RELAY');

      // 17. Verify WebSocket sync:event push emits identical honest encryption & IN_PROGRESS status flags
      const wsTicketRes = await receiver.signedFetch('POST', '/ws/ticket', {});
      assert.equal(wsTicketRes.status, 200);
      const { ticket: rxTicket } = (await wsTicketRes.json()) as { ticket: string };
      rxWs = new WebSocket(
        `${srv.wsBaseUrl}?ticket=${encodeURIComponent(rxTicket)}`
      );
      const wsSyncFramePromise = waitForWebSocketSyncEvent(
        rxWs,
        'Relay sync:event delivery'
      );

      const wsEnv = await sender.crypto.encryptForPeer({
        plaintext: plaintextMsg,
        senderDeviceId: sender.publicId,
        recipientDeviceId: receiver.publicId,
        senderCryptoKeyId: sender.keys.cryptoKeyId,
        recipientCryptoKeyId: receiver.keys.cryptoKeyId,
        recipientEcdhPublicKeyJwk: receiver.keys.ecdhPublicKeyJwk!,
        sessionId: sender.session.sessionId,
        idempotencyKey: 'e2ee-idem-ws-check',
      });
      const wsSendRes = await sender.signedFetch('POST', '/sync', {
        deviceId: sender.publicId,
        targetDeviceId: receiver.publicId,
        events: [
          {
            id: 106,
            type: 'notification',
            payload: '[E2EE_CIPHERTEXT]',
            idempotencyKey: 'e2ee-idem-ws-check',
            createdAt: Date.now(),
            e2eeEnvelope: wsEnv,
          },
        ],
      });
      assert.equal(wsSendRes.status, 200);

      const wsEvent = await wsSyncFramePromise;
      assert.equal(wsEvent.encrypted, true);
      assert.equal(wsEvent.localEncrypted, false);
      assert.equal(wsEvent.e2eeProtected, false);
      assert.equal(wsEvent.e2eeVerified, false);
      assert.equal(wsEvent.relaySignatureVerified, true);
      assert.equal(wsEvent.status, 'IN_PROGRESS');
      assert.equal(wsEvent.relayDeliveryState, 'QUEUED_AT_RELAY');
      rxWs.close();
    } finally {
      rxWs?.terminate();
      await srv.close();
    }
  });

  it('13. Pairing code wrong/expired rejection, 5-attempt brute-force lockout (423), and mutual pairing rejection (approve=false)', async () => {
    const srv = await createTestRelayServer();
    try {
      const admin = await registerAndAuthenticate(
        srv.baseUrl,
        'lock-admin',
        'admin',
        'Lock Admin'
      );
      const peer = await registerAndAuthenticate(
        srv.baseUrl,
        'lock-peer',
        'basic',
        'Lock Peer'
      );

      // Issue pairing request #1 and test mutual rejection (approve: false)
      const p1 = (await (
        await admin.signedFetch('POST', '/pairing/request', {})
      ).json()) as { pairingId: string; pairingCode: string };

      // Wrong code -> 404 NOT_FOUND
      const wrongCodeRes = await peer.signedFetch('POST', '/pairing/accept', {
        pairingCode: p1.pairingCode === '000000' ? '111111' : '000000',
      });
      assert.equal(wrongCodeRes.status, 404);

      // Valid accept then Admin explicitly rejects (approve: false)
      const acc1 = await peer.signedFetch('POST', '/pairing/accept', {
        pairingCode: p1.pairingCode,
      });
      assert.equal(acc1.status, 200);

      const rejectRes = await admin.signedFetch('POST', '/pairing/confirm', {
        pairingId: p1.pairingId,
        approve: false,
      });
      assert.equal(rejectRes.status, 200);
      const rejectBody = (await rejectRes.json()) as {
        approved: boolean;
        peer: unknown;
      };
      assert.equal(rejectBody.approved, false);
      assert.equal(rejectBody.peer, null);

      const linksAfterReject = (await (
        await admin.signedFetch('GET', `/devices/${admin.publicId}/links`)
      ).json()) as { devices: unknown[] };
      assert.equal(linksAfterReject.devices.length, 0);

      // Issue pairing request #2 and exhaust 5 failed guesses -> LOCKED (423)
      const p2 = (await (
        await admin.signedFetch('POST', '/pairing/request', {})
      ).json()) as { pairingId: string; pairingCode: string };
      const wrongGuess = p2.pairingCode === '999999' ? '888888' : '999999';

      for (let i = 0; i < 5; i += 1) {
        const miss = await peer.signedFetch('POST', '/pairing/accept', {
          pairingCode: wrongGuess,
        });
        assert.equal(miss.status, 404);
      }

      // Now even the real pairing code p2.pairingCode is locked -> 423 LOCKED
      const lockedRes = await peer.signedFetch('POST', '/pairing/accept', {
        pairingCode: p2.pairingCode,
      });
      assert.equal(lockedRes.status, 423);
      const lockedBody = (await lockedRes.json()) as { code: string };
      assert.equal(lockedBody.code, 'LOCKED');

      // Issue pairing request #3 and expire it in SQLite -> 404 EXPIRED
      const p3 = (await (
        await admin.signedFetch('POST', '/pairing/request', {})
      ).json()) as { pairingId: string; pairingCode: string };
      srv.db.db
        .prepare('UPDATE pairing_requests SET expires_at = ? WHERE pairing_id = ?')
        .run(Date.now() - 5000, p3.pairingId);

      const expiredRes = await peer.signedFetch('POST', '/pairing/accept', {
        pairingCode: p3.pairingCode,
      });
      assert.equal(expiredRes.status, 404);
      const expiredBody = (await expiredRes.json()) as { code: string };
      assert.equal(expiredBody.code, 'EXPIRED');
    } finally {
      await srv.close();
    }
  });
});
