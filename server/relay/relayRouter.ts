import { randomInt } from 'node:crypto';
import type { Server as HttpServer } from 'node:http';
import express, { type Router } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import type { SqliteRelayDatabase } from '../db/sqliteRelayDb';

export interface RelayServerHandle {
  router: Router;
  wss: WebSocketServer;
  getConnectedClientCount: () => number;
  close: () => Promise<void>;
}

export function createRelayServer(db: SqliteRelayDatabase): RelayServerHandle {
  const router = express.Router();
  router.use(express.json({ limit: '1mb' }));

  const clientsByDevice = new Map<string, Set<WebSocket>>();
  const wss = new WebSocketServer({ noServer: true });

  function pushToDevice(deviceId: string, message: Record<string, unknown>): void {
    const sockets = clientsByDevice.get(deviceId);
    if (!sockets) return;
    const serialized = JSON.stringify(message);
    for (const sock of sockets) {
      if (sock.readyState === WebSocket.OPEN) {
        sock.send(serialized);
      }
    }
  }

  wss.on('connection', (socket, req) => {
    const url = new URL(req.url ?? '/ws/relay', 'http://localhost');
    const deviceId = url.searchParams.get('deviceId')?.trim();

    if (!deviceId) {
      socket.close(1008, 'Missing deviceId');
      return;
    }

    let group = clientsByDevice.get(deviceId);
    if (!group) {
      group = new Set();
      clientsByDevice.set(deviceId, group);
    }
    group.add(socket);

    socket.send(
      JSON.stringify({
        type: 'relay:connected',
        deviceId,
        serverTimestamp: Date.now(),
      })
    );

    socket.on('close', () => {
      const set = clientsByDevice.get(deviceId);
      if (set) {
        set.delete(socket);
        if (set.size === 0) {
          clientsByDevice.delete(deviceId);
        }
      }
    });
  });

  router.get('/health', (_req, res) => {
    try {
      const schemaVersion = db.getSchemaVersion();
      res.json({
        ok: true,
        schemaVersion,
        connectedSockets: wss.clients.size,
        serverTimestamp: Date.now(),
      });
    } catch (err) {
      res.status(500).json({
        ok: false,
        error: err instanceof Error ? err.message : 'Database unavailable',
      });
    }
  });

  router.post('/devices/register', (req, res) => {
    const { publicId, cryptoKeyId, publicKeyJwk, role, label } = req.body ?? {};
    if (
      typeof publicId !== 'string' ||
      publicId.trim().length < 4 ||
      typeof cryptoKeyId !== 'string' ||
      cryptoKeyId.trim().length < 4 ||
      (role !== 'admin' && role !== 'basic')
    ) {
      res.status(400).json({ error: 'بيانات تسجيل الجهاز غير صالحة.' });
      return;
    }

    db.upsertDevice({
      publicId: publicId.trim(),
      cryptoKeyId: cryptoKeyId.trim(),
      publicKeyJwk: publicKeyJwk ? JSON.stringify(publicKeyJwk) : null,
      role,
      label:
        typeof label === 'string' && label.trim() ? label.trim() : 'NEXLINK Device',
    });

    res.json({
      registered: true,
      publicId: publicId.trim(),
      serverTimestamp: Date.now(),
    });
  });

  router.post('/pairing/request', (req, res) => {
    const { requesterDeviceId, requesterCryptoKeyId } = req.body ?? {};
    if (
      typeof requesterDeviceId !== 'string' ||
      typeof requesterCryptoKeyId !== 'string'
    ) {
      res.status(400).json({ error: 'بيانات طلب الاقتران غير صالحة.' });
      return;
    }

    const pairingCode = String(randomInt(100000, 999999));
    const expiresAt = Date.now() + 5 * 60 * 1000;

    try {
      db.createPairingRequest({
        pairingCode,
        requesterDeviceId: requesterDeviceId.trim(),
        requesterCryptoKeyId: requesterCryptoKeyId.trim(),
        expiresAt,
      });

      res.json({
        pairingCode,
        targetDeviceId: '',
        requesterDeviceId: requesterDeviceId.trim(),
        requesterCryptoKeyId: requesterCryptoKeyId.trim(),
        expiresAt,
      });
    } catch {
      res.status(409).json({
        error: 'يجب تسجيل الجهاز على خادم المرحل قبل إنشاء رمز اقتران.',
      });
    }
  });

  router.post('/pairing/accept', (req, res) => {
    const { pairingCode, responder } = req.body ?? {};
    if (
      typeof pairingCode !== 'string' ||
      !responder ||
      typeof responder.publicId !== 'string' ||
      typeof responder.cryptoKeyId !== 'string' ||
      (responder.role !== 'admin' && responder.role !== 'basic')
    ) {
      res.status(400).json({ error: 'رمز الاقتران أو بيانات الجهاز غير صالحة.' });
      return;
    }

    db.upsertDevice({
      publicId: responder.publicId.trim(),
      cryptoKeyId: responder.cryptoKeyId.trim(),
      publicKeyJwk: responder.publicKeyJwk
        ? JSON.stringify(responder.publicKeyJwk)
        : null,
      role: responder.role,
      label:
        typeof responder.label === 'string' && responder.label.trim()
          ? responder.label.trim()
          : 'NEXLINK Device',
    });

    const paired = db.acceptPairingRequest(
      pairingCode.trim(),
      responder.publicId.trim()
    );
    if (!paired) {
      res.status(404).json({
        error: 'رمز الاقتران غير صالح أو منتهي الصلاحية.',
      });
      return;
    }

    pushToDevice(paired.requesterDeviceId, {
      type: 'device:paired',
      peer: {
        publicId: responder.publicId.trim(),
        cryptoKeyId: responder.cryptoKeyId.trim(),
        label: responder.label ?? 'NEXLINK Device',
        role: responder.role,
        pairingState: 'PAIRED',
        pairedAt: paired.pairedAt,
        lastSeenAt: paired.pairedAt,
        verifiedByRelay: true,
      },
    });

    res.json({
      publicId: paired.requesterDeviceId,
      cryptoKeyId: paired.requesterCryptoKeyId,
      label: paired.requesterLabel,
      role: paired.requesterRole,
      pairingState: 'PAIRED',
      pairedAt: paired.pairedAt,
      lastSeenAt: paired.pairedAt,
      verifiedByRelay: true,
    });
  });

  router.get('/devices/:deviceId/links', (req, res) => {
    const links = db.getLinkedDevices(req.params.deviceId).map((d) => ({
      ...d,
      verifiedByRelay: d.pairingState === 'PAIRED',
    }));
    res.json({ devices: links });
  });

  router.post('/devices/:deviceId/revoke', (req, res) => {
    const { targetDeviceId } = req.body ?? {};
    if (typeof targetDeviceId !== 'string' || !targetDeviceId.trim()) {
      res.status(400).json({ error: 'معرّف الجهاز المستهدف مطلوب.' });
      return;
    }
    db.revokeDeviceLink(req.params.deviceId, targetDeviceId.trim());
    pushToDevice(targetDeviceId.trim(), {
      type: 'device:revoked',
      byDeviceId: req.params.deviceId,
    });
    res.json({ revoked: true });
  });

  router.post('/sync', (req, res) => {
    const { deviceId, targetDeviceId, events } = req.body ?? {};
    if (typeof deviceId !== 'string' || !Array.isArray(events)) {
      res.status(400).json({ error: 'حزمة المزامنة غير صالحة.' });
      return;
    }

    try {
      const result = db.ingestSyncBatch(
        deviceId,
        typeof targetDeviceId === 'string' ? targetDeviceId : null,
        events
      );
      const serverTimestamp = Date.now();

      for (const row of result.insertedRows) {
        if (row.targetDeviceId) {
          pushToDevice(row.targetDeviceId, {
            type: 'sync:event',
            event: {
              id: row.clientEventId,
              type: row.type,
              payload: row.payload,
              createdAt: row.createdAt,
              status: 'SYNCED',
              retryCount: 0,
              nextRetryAt: null,
              idempotencyKey: row.idempotencyKey,
              notificationKey: row.notificationKey ?? undefined,
              payloadHash: row.payloadHash ?? undefined,
              encrypted: false,
            },
          });
        }
      }

      res.json({
        acknowledged: true,
        acceptedIds: result.acceptedIds,
        duplicateIds: result.duplicateIds,
        serverTimestamp,
      });
    } catch (err) {
      res.status(500).json({
        acknowledged: false,
        acceptedIds: [],
        duplicateIds: [],
        serverTimestamp: Date.now(),
        error: err instanceof Error ? err.message : 'Sync ingestion failed',
      });
    }
  });

  router.get('/sync/:deviceId/inbox', (req, res) => {
    const rows = db.getInboundEvents(req.params.deviceId).map((r) => ({
      id: r.id,
      type: r.type,
      payload: r.payload,
      createdAt: r.createdAt,
      status: 'SYNCED',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: r.idempotencyKey,
      notificationKey: r.notificationKey ?? undefined,
      payloadHash: r.payloadHash ?? undefined,
      encrypted: false,
    }));
    res.json({ events: rows });
  });

  return {
    router,
    wss,
    getConnectedClientCount: () => wss.clients.size,
    close: async () => {
      for (const client of wss.clients) {
        client.close();
      }
      await new Promise<void>((resolve) => {
        wss.close(() => resolve());
      });
    },
  };
}

export function attachRelayUpgrade(
  httpServer: HttpServer,
  relay: RelayServerHandle
): void {
  httpServer.on('upgrade', (req, socket, head) => {
    const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (pathname === '/ws/relay') {
      relay.wss.handleUpgrade(req, socket, head, (ws) => {
        relay.wss.emit('connection', ws, req);
      });
    }
  });
}
