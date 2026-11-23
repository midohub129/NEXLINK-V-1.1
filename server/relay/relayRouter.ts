import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  randomInt,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import type { Server as HttpServer } from 'node:http';
import express, {
  type NextFunction,
  type Request,
  type Response,
  type Router,
} from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import type { SqliteRelayDatabase } from '../db/sqliteRelayDb';

const MAX_CLOCK_SKEW_MS = 60_000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const WS_TICKET_TTL_MS = 30_000;
const PAIRING_TTL_MS = 5 * 60 * 1000;

interface AuthenticatedDevice {
  sessionId: string;
  publicId: string;
  cryptoKeyId: string;
  role: 'admin' | 'basic';
}

interface AuthenticatedRequest extends Request {
  authDevice?: AuthenticatedDevice;
  rawBodyString?: string;
}

export interface RelayServerHandle {
  router: Router;
  wss: WebSocketServer;
  getConnectedClientCount: () => number;
  close: () => Promise<void>;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function computeExpectedCryptoKeyId(jwk: JsonWebKey): string | null {
  if (
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string'
  ) {
    return null;
  }
  const digest = sha256Hex(`${jwk.x}:${jwk.y}`);
  return `ecdsa-${digest.slice(0, 24)}`;
}

function verifyEcdsaSignature(
  publicKeyJwk: JsonWebKey,
  expectedCryptoKeyId: string,
  signedMessage: string,
  signatureBase64: string
): boolean {
  try {
    const derivedKeyId = computeExpectedCryptoKeyId(publicKeyJwk);
    if (!derivedKeyId || derivedKeyId !== expectedCryptoKeyId) {
      return false;
    }

    const publicKey = createPublicKey({
      key: publicKeyJwk as Record<string, unknown>,
      format: 'jwk',
    });

    return verify(
      'sha256',
      Buffer.from(signedMessage, 'utf8'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureBase64, 'base64')
    );
  } catch {
    return false;
  }
}

function isValidEcdhJwk(jwk: unknown): jwk is JsonWebKey {
  if (!jwk || typeof jwk !== 'object') return false;
  const candidate = jwk as JsonWebKey;
  return (
    candidate.kty === 'EC' &&
    candidate.crv === 'P-256' &&
    typeof candidate.x === 'string' &&
    typeof candidate.y === 'string'
  );
}

function isValidE2eeEnvelope(
  envelope: unknown,
  expectedSenderId: string,
  expectedTargetId: string
): boolean {
  if (!envelope || typeof envelope !== 'object') return false;
  const e = envelope as Record<string, unknown>;
  return (
    e.version === 1 &&
    e.algorithm === 'ECDH-P256+HKDF-SHA256+AES-256-GCM' &&
    e.senderDeviceId === expectedSenderId &&
    e.recipientDeviceId === expectedTargetId &&
    typeof e.senderCryptoKeyId === 'string' &&
    e.senderCryptoKeyId.startsWith('ecdsa-') &&
    typeof e.recipientCryptoKeyId === 'string' &&
    e.recipientCryptoKeyId.startsWith('ecdsa-') &&
    typeof e.sessionId === 'string' &&
    e.sessionId.length >= 8 &&
    typeof e.messageNonce === 'string' &&
    e.messageNonce.length >= 16 &&
    typeof e.iv === 'string' &&
    e.iv.length >= 12 &&
    typeof e.aad === 'string' &&
    e.aad.length >= 10 &&
    typeof e.ciphertext === 'string' &&
    e.ciphertext.length >= 16 &&
    typeof e.signature === 'string' &&
    e.signature.length >= 16
  );
}

function createSlidingWindowRateLimiter(maxRequests: number, windowMs: number) {
  const buckets = new Map<string, number[]>();

  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${req.ip ?? 'unknown'}:${req.path}`;
    const now = Date.now();
    const windowStart = now - windowMs;
    const timestamps = (buckets.get(key) ?? []).filter((t) => t > windowStart);

    if (timestamps.length >= maxRequests) {
      res.status(429).json({
        error: 'تم تجاوز الحد المسموح به للطلبات. حاول لاحقاً.',
        code: 'RATE_LIMIT_EXCEEDED',
      });
      return;
    }

    timestamps.push(now);
    buckets.set(key, timestamps);
    next();
  };
}

export function createRelayServer(db: SqliteRelayDatabase): RelayServerHandle {
  const sessionSecret =
    process.env.NEXLINK_SESSION_SECRET &&
    process.env.NEXLINK_SESSION_SECRET.length >= 16
      ? process.env.NEXLINK_SESSION_SECRET
      : randomBytes(32).toString('hex');

  const router = express.Router();
  router.use(
    express.json({
      limit: '1mb',
      verify: (req, _res, buf) => {
        (req as AuthenticatedRequest).rawBodyString = buf.toString('utf8');
      },
    })
  );

  const generalLimiter = createSlidingWindowRateLimiter(180, 60_000);
  const strictAuthLimiter = createSlidingWindowRateLimiter(20, 60_000);
  router.use(generalLimiter);

  const clientsByDevice = new Map<string, Set<WebSocket>>();
  const wss = new WebSocketServer({ noServer: true });

  function signSessionToken(sessionId: string): string {
    const mac = createHmac('sha256', sessionSecret).update(sessionId).digest('hex');
    return `${sessionId}.${mac}`;
  }

  function verifySignedSessionToken(
    bearerToken: string
  ): { sessionId: string; tokenHash: string } | null {
    const parts = bearerToken.split('.');
    if (parts.length !== 2) return null;
    const [sessionId, providedMac] = parts;
    if (!sessionId || !providedMac) return null;

    const expectedMac = createHmac('sha256', sessionSecret)
      .update(sessionId)
      .digest('hex');
    const a = Buffer.from(providedMac, 'utf8');
    const b = Buffer.from(expectedMac, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return null;
    }

    return { sessionId, tokenHash: sha256Hex(bearerToken) };
  }

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

  function closeDeviceSockets(deviceId: string, reason: string): void {
    const sockets = clientsByDevice.get(deviceId);
    if (!sockets) return;
    for (const sock of sockets) {
      try {
        sock.close(1008, reason);
      } catch {
        // ignore socket close errors
      }
    }
    clientsByDevice.delete(deviceId);
  }

  function verifyRequestProof(
    req: AuthenticatedRequest,
    publicKeyJwk: JsonWebKey,
    cryptoKeyId: string,
    deviceId: string
  ): { ok: true } | { ok: false; status: number; code: string; error: string } {
    const tsHeader = req.header('x-nexlink-timestamp');
    const nonce = req.header('x-nexlink-nonce');
    const signature = req.header('x-nexlink-signature');

    if (!tsHeader || !nonce || !signature || nonce.trim().length < 16) {
      return {
        ok: false,
        status: 401,
        code: 'MISSING_REQUEST_SIGNATURE',
        error: 'توقيع الطلب التشفيري مفقود.',
      };
    }

    const timestamp = Number(tsHeader);
    const now = Date.now();
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) {
      return {
        ok: false,
        status: 401,
        code: 'TIMESTAMP_OUT_OF_WINDOW',
        error: 'انتهت نافذة التوقيت المسموحة للطلب.',
      };
    }

    const rawBody = req.rawBodyString ?? '';
    const bodyHash = sha256Hex(rawBody);
    const canonicalPath = req.originalUrl;
    const messageToVerify = `${req.method.toUpperCase()}|${canonicalPath}|${bodyHash}|${timestamp}|${nonce}`;

    if (!verifyEcdsaSignature(publicKeyJwk, cryptoKeyId, messageToVerify, signature)) {
      return {
        ok: false,
        status: 401,
        code: 'INVALID_REQUEST_SIGNATURE',
        error: 'فشل التحقق من التوقيع الرقمي للطلب.',
      };
    }

    const nonceAccepted = db.consumeNonce(
      `${deviceId}:${nonce}`,
      deviceId,
      now + MAX_CLOCK_SKEW_MS * 2,
      now
    );
    if (!nonceAccepted) {
      return {
        ok: false,
        status: 409,
        code: 'REPLAY_DETECTED',
        error: 'تم رفض الطلب بسبب إعادة استخدام Nonce (Replay Attack).',
      };
    }

    return { ok: true };
  }

  function requireAuthenticatedDevice(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void {
    const authHeader = req.header('authorization') ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'مصادقة الجلسة مطلوبة.',
        code: 'MISSING_BEARER_TOKEN',
      });
      return;
    }

    const rawToken = authHeader.slice('Bearer '.length).trim();
    const parsedToken = verifySignedSessionToken(rawToken);
    if (!parsedToken) {
      res.status(401).json({
        error: 'رمز الجلسة غير صالح.',
        code: 'INVALID_BEARER_TOKEN',
      });
      return;
    }

    const session = db.getValidSession(parsedToken.sessionId, parsedToken.tokenHash);
    if (!session || !session.publicKeyJwk) {
      res.status(401).json({
        error: 'الجلسة منتهية أو تم سحب تفويض الجهاز.',
        code: 'SESSION_REVOKED_OR_EXPIRED',
      });
      return;
    }

    const publicKeyJwk = JSON.parse(session.publicKeyJwk) as JsonWebKey;
    const proof = verifyRequestProof(
      req,
      publicKeyJwk,
      session.cryptoKeyId,
      session.deviceId
    );
    if (!proof.ok) {
      res.status(proof.status).json({ error: proof.error, code: proof.code });
      return;
    }

    req.authDevice = {
      sessionId: session.sessionId,
      publicId: session.deviceId,
      cryptoKeyId: session.cryptoKeyId,
      role: session.role,
    };
    next();
  }

  wss.on('connection', (socket, req) => {
    const url = new URL(req.url ?? '/ws/relay', 'http://localhost');
    const ticket = url.searchParams.get('ticket')?.trim();

    if (!ticket) {
      socket.close(1008, 'Authentication ticket required');
      return;
    }

    const deviceId = db.consumeWsTicket(ticket);
    if (!deviceId) {
      socket.close(1008, 'Invalid, expired, or replayed ticket');
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

  router.post(
    '/devices/register',
    strictAuthLimiter,
    (req: AuthenticatedRequest, res) => {
      const {
        publicId,
        cryptoKeyId,
        publicKeyJwk,
        ecdhPublicKeyJwk,
        role,
        label,
        timestamp,
        nonce,
        signature,
      } = req.body ?? {};

      if (
        typeof publicId !== 'string' ||
        publicId.trim().length < 4 ||
        typeof cryptoKeyId !== 'string' ||
        !publicKeyJwk ||
        typeof publicKeyJwk !== 'object' ||
        !isValidEcdhJwk(ecdhPublicKeyJwk) ||
        (role !== 'admin' && role !== 'basic') ||
        typeof timestamp !== 'number' ||
        typeof nonce !== 'string' ||
        nonce.length < 16 ||
        typeof signature !== 'string'
      ) {
        res.status(400).json({
          error: 'بيانات تسجيل الجهاز والتوقيع غير مكتملة.',
          code: 'INVALID_REGISTRATION_PAYLOAD',
        });
        return;
      }

      const now = Date.now();
      if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) {
        res.status(401).json({
          error: 'انتهت نافذة التوقيت المسموحة لطلب التسجيل.',
          code: 'TIMESTAMP_OUT_OF_WINDOW',
        });
        return;
      }

      const cleanId = publicId.trim();
      const cleanKeyId = cryptoKeyId.trim();
      const ecdhHash = sha256Hex(JSON.stringify(ecdhPublicKeyJwk));
      const registrationMessage = `REGISTER|${cleanId}|${cleanKeyId}|${ecdhHash}|${role}|${timestamp}|${nonce}`;

      if (
        !verifyEcdsaSignature(
          publicKeyJwk as JsonWebKey,
          cleanKeyId,
          registrationMessage,
          signature
        )
      ) {
        res.status(401).json({
          error: 'فشل التحقق من التوقيع أو بصمة المفتاح العام للجهاز.',
          code: 'INVALID_DEVICE_SIGNATURE',
        });
        return;
      }

      if (
        !db.consumeNonce(
          `reg:${cleanId}:${nonce}`,
          cleanId,
          now + MAX_CLOCK_SKEW_MS * 2,
          now
        )
      ) {
        res.status(409).json({
          error: 'تم رفض التسجيل لتكرار Nonce.',
          code: 'REPLAY_DETECTED',
        });
        return;
      }

      const regResult = db.registerDevice({
        publicId: cleanId,
        cryptoKeyId: cleanKeyId,
        publicKeyJwk: JSON.stringify(publicKeyJwk),
        ecdhPublicKeyJwk: JSON.stringify(ecdhPublicKeyJwk),
        role,
        label:
          typeof label === 'string' && label.trim() ? label.trim() : 'NEXLINK Device',
      });

      if (!regResult.ok) {
        res.status(403).json({
          error:
            regResult.reason === 'DEVICE_REVOKED'
              ? 'تم سحب الثقة من هذا الجهاز ولا يمكن إعادة تسجيله.'
              : 'معرّف الجهاز مسجل بالفعل بمفتاح تشفيري مختلف.',
          code: regResult.reason,
        });
        return;
      }

      res.json({
        registered: true,
        authenticated: false,
        publicId: cleanId,
        serverTimestamp: Date.now(),
      });
    }
  );

  router.post('/auth/challenge', strictAuthLimiter, (req, res) => {
    const { publicId } = req.body ?? {};
    if (typeof publicId !== 'string' || publicId.trim().length < 4) {
      res.status(400).json({ error: 'معرّف الجهاز مطلوب.', code: 'INVALID_DEVICE_ID' });
      return;
    }

    const device = db.getDevice(publicId.trim());
    if (!device || !device.publicKeyJwk) {
      res.status(404).json({ error: 'الجهاز غير مسجل.', code: 'DEVICE_NOT_FOUND' });
      return;
    }
    if (device.status === 'REVOKED') {
      res.status(403).json({ error: 'تم سحب ثقة هذا الجهاز.', code: 'DEVICE_REVOKED' });
      return;
    }

    const challenge = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60_000;
    db.createAuthChallenge(challenge, device.publicId, expiresAt);

    res.json({ challenge, expiresAt });
  });

  router.post('/auth/session', strictAuthLimiter, (req, res) => {
    const { publicId, challenge, timestamp, nonce, signature } = req.body ?? {};
    if (
      typeof publicId !== 'string' ||
      typeof challenge !== 'string' ||
      typeof timestamp !== 'number' ||
      typeof nonce !== 'string' ||
      nonce.length < 16 ||
      typeof signature !== 'string'
    ) {
      res
        .status(400)
        .json({ error: 'بيانات المصادقة غير صالحة.', code: 'INVALID_AUTH_PAYLOAD' });
      return;
    }

    const now = Date.now();
    if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) {
      res.status(401).json({
        error: 'انتهت المهلة الزمنية للتحدي.',
        code: 'TIMESTAMP_OUT_OF_WINDOW',
      });
      return;
    }

    const cleanId = publicId.trim();
    const device = db.getDevice(cleanId);
    if (!device || !device.publicKeyJwk) {
      res.status(404).json({ error: 'الجهاز غير مسجل.', code: 'DEVICE_NOT_FOUND' });
      return;
    }
    if (device.status === 'REVOKED') {
      res.status(403).json({ error: 'الجهاز مسحوب التفويض.', code: 'DEVICE_REVOKED' });
      return;
    }

    const publicKeyJwk = JSON.parse(device.publicKeyJwk) as JsonWebKey;
    const signedChallenge = `AUTH|${cleanId}|${challenge}|${timestamp}|${nonce}`;
    if (
      !verifyEcdsaSignature(
        publicKeyJwk,
        device.cryptoKeyId,
        signedChallenge,
        signature
      )
    ) {
      res
        .status(401)
        .json({ error: 'توقيع المصادقة غير صحيح.', code: 'INVALID_AUTH_SIGNATURE' });
      return;
    }

    if (!db.consumeAuthChallenge(challenge, cleanId, now)) {
      res.status(401).json({
        error: 'التحدي منتهي الصلاحية أو مستخدم مسبقاً.',
        code: 'INVALID_CHALLENGE',
      });
      return;
    }

    if (
      !db.consumeNonce(
        `auth:${cleanId}:${nonce}`,
        cleanId,
        now + MAX_CLOCK_SKEW_MS * 2,
        now
      )
    ) {
      res
        .status(409)
        .json({ error: 'تم رصد محاولة إعادة إرسال.', code: 'REPLAY_DETECTED' });
      return;
    }

    const sessionId = `sess_${randomBytes(24).toString('hex')}`;
    const token = signSessionToken(sessionId);
    const expiresAt = now + SESSION_TTL_MS;

    db.createDeviceSession({
      sessionId,
      deviceId: cleanId,
      cryptoKeyId: device.cryptoKeyId,
      tokenHash: sha256Hex(token),
      expiresAt,
    });

    res.json({
      sessionId,
      token,
      devicePublicId: cleanId,
      cryptoKeyId: device.cryptoKeyId,
      role: device.role,
      issuedAt: now,
      expiresAt,
    });
  });

  router.post(
    '/auth/revoke',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      db.revokeDeviceSessions(auth.publicId, false);
      closeDeviceSockets(auth.publicId, 'Session revoked by device');
      res.json({ revoked: true });
    }
  );

  router.post(
    '/ws/ticket',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      const ticket = randomBytes(24).toString('hex');
      const expiresAt = Date.now() + WS_TICKET_TTL_MS;
      db.createWsTicket(ticket, auth.publicId, expiresAt);
      res.json({ ticket, expiresAt });
    }
  );

  router.post(
    '/pairing/request',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.role !== 'admin') {
        res.status(403).json({
          error: 'إنشاء رمز الاقتران مقتصر على الجهاز الرئيسي (Super Admin).',
          code: 'FORBIDDEN_ROLE',
        });
        return;
      }

      const device = db.getDevice(auth.publicId);
      if (!device) {
        res.status(404).json({ error: 'الجهاز غير موجود.' });
        return;
      }

      const pairingId = `pair_${randomBytes(16).toString('hex')}`;
      const pairingCode = String(randomInt(100000, 999999));
      const expiresAt = Date.now() + PAIRING_TTL_MS;

      db.createPairingRequest({
        pairingId,
        pairingCode,
        requesterDeviceId: auth.publicId,
        requesterCryptoKeyId: auth.cryptoKeyId,
        requesterEcdhJwk: device.ecdhPublicKeyJwk,
        expiresAt,
      });

      res.json({
        pairingId,
        pairingCode,
        targetDeviceId: '',
        requesterDeviceId: auth.publicId,
        requesterCryptoKeyId: auth.cryptoKeyId,
        status: 'PENDING',
        expiresAt,
      });
    }
  );

  router.post(
    '/pairing/accept',
    strictAuthLimiter,
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      const { pairingCode } = req.body ?? {};
      if (typeof pairingCode !== 'string' || !/^\d{6}$/.test(pairingCode.trim())) {
        res.status(400).json({
          error: 'رمز الاقتران يجب أن يتكون من 6 أرقام.',
          code: 'INVALID_PAIRING_CODE',
        });
        return;
      }

      const responder = db.getDevice(auth.publicId);
      if (!responder) {
        res.status(404).json({ error: 'بيانات الجهاز غير موجودة.' });
        return;
      }

      const result = db.submitPairingAcceptance({
        pairingCode: pairingCode.trim(),
        responderDeviceId: responder.publicId,
        responderCryptoKeyId: responder.cryptoKeyId,
        responderEcdsaJwk: responder.publicKeyJwk,
        responderEcdhJwk: responder.ecdhPublicKeyJwk,
        responderLabel: responder.label,
      });

      if (!result.ok) {
        if (result.reason === 'NOT_FOUND') {
          db.recordFailedPairingAttemptOnActive();
        }
        const status =
          result.reason === 'LOCKED'
            ? 423
            : result.reason === 'ALREADY_CONSUMED' || result.reason === 'SELF_PAIRING'
              ? 409
              : 404;
        res.status(status).json({
          error:
            result.reason === 'LOCKED'
              ? 'تم قفل طلب الاقتران مؤقتاً بعد عدة محاولات خاطئة.'
              : result.reason === 'SELF_PAIRING'
                ? 'لا يمكن إقران الجهاز بنفسه.'
                : result.reason === 'ALREADY_CONSUMED'
                  ? 'تم استخدام رمز الاقتران مسبقاً.'
                  : 'رمز الاقتران غير صالح أو منتهي الصلاحية.',
          code: result.reason,
        });
        return;
      }

      pushToDevice(result.pairing.requesterDeviceId, {
        type: 'pairing:pending_approval',
        pairing: result.pairing,
      });

      res.json({
        ...result.pairing,
        targetDeviceId: result.pairing.requesterDeviceId,
      });
    }
  );

  router.get(
    '/pairing/pending/:deviceId',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.publicId !== req.params.deviceId) {
        res.status(403).json({
          error: 'غير مصرح بالوصول إلى طلبات اقتران جهاز آخر.',
          code: 'FORBIDDEN_OWNERSHIP',
        });
        return;
      }
      res.json({ requests: db.getPendingPairingApprovals(auth.publicId) });
    }
  );

  router.post(
    '/pairing/confirm',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      const { pairingId, approve, expectedResponderCryptoKeyId } = req.body ?? {};
      if (typeof pairingId !== 'string' || typeof approve !== 'boolean') {
        res.status(400).json({ error: 'بيانات تأكيد الاقتران غير صالحة.' });
        return;
      }

      const result = db.confirmPairingRequest({
        pairingId: pairingId.trim(),
        requesterDeviceId: auth.publicId,
        approve,
        expectedResponderCryptoKeyId:
          typeof expectedResponderCryptoKeyId === 'string'
            ? expectedResponderCryptoKeyId
            : undefined,
      });

      if (!result.ok) {
        const status =
          result.reason === 'FORBIDDEN_OWNERSHIP'
            ? 403
            : result.reason === 'KEY_FINGERPRINT_MISMATCH' ||
                result.reason === 'INVALID_STATE'
              ? 409
              : 404;
        res.status(status).json({
          error: 'تعذّر إتمام تأكيد الاقتران أو تم رفض البصمة الأمنية.',
          code: result.reason,
        });
        return;
      }

      if (!result.approved) {
        pushToDevice(result.responder.publicId, {
          type: 'pairing:rejected',
          pairingId: pairingId.trim(),
        });
        res.json({ approved: false, peer: null });
        return;
      }

      const responderPeer = {
        publicId: result.responder.publicId,
        cryptoKeyId: result.responder.cryptoKeyId,
        publicKeyJwk: result.responder.publicKeyJwk
          ? (JSON.parse(result.responder.publicKeyJwk) as JsonWebKey)
          : null,
        ecdhPublicKeyJwk: result.responder.ecdhPublicKeyJwk
          ? (JSON.parse(result.responder.ecdhPublicKeyJwk) as JsonWebKey)
          : null,
        label: result.responder.label,
        role: result.responder.role,
        pairingState: 'PAIRED',
        pairedAt: result.pairedAt,
        lastSeenAt: result.responder.lastSeenAt,
        verifiedByRelay: true,
      };

      const requesterPeer = {
        publicId: result.requester.publicId,
        cryptoKeyId: result.requester.cryptoKeyId,
        publicKeyJwk: result.requester.publicKeyJwk
          ? (JSON.parse(result.requester.publicKeyJwk) as JsonWebKey)
          : null,
        ecdhPublicKeyJwk: result.requester.ecdhPublicKeyJwk
          ? (JSON.parse(result.requester.ecdhPublicKeyJwk) as JsonWebKey)
          : null,
        label: result.requester.label,
        role: result.requester.role,
        pairingState: 'PAIRED',
        pairedAt: result.pairedAt,
        lastSeenAt: result.requester.lastSeenAt,
        verifiedByRelay: true,
      };

      pushToDevice(result.responder.publicId, {
        type: 'device:paired',
        peer: requesterPeer,
      });
      pushToDevice(result.requester.publicId, {
        type: 'device:paired',
        peer: responderPeer,
      });

      res.json({ approved: true, peer: responderPeer });
    }
  );

  router.get(
    '/devices/:deviceId/links',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.publicId !== req.params.deviceId) {
        res.status(403).json({
          error: 'غير مصرح بعرض الأجهزة المرتبطة لجهاز آخر.',
          code: 'FORBIDDEN_OWNERSHIP',
        });
        return;
      }

      const links = db.getLinkedDevices(auth.publicId).map((d) => ({
        ...d,
        verifiedByRelay: d.pairingState === 'PAIRED',
      }));
      res.json({ devices: links });
    }
  );

  router.post(
    '/devices/:deviceId/revoke',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.publicId !== req.params.deviceId) {
        res.status(403).json({
          error: 'غير مصرح بسحب ارتباط لا تملكه.',
          code: 'FORBIDDEN_OWNERSHIP',
        });
        return;
      }

      const { targetDeviceId, revokeDeviceTrust } = req.body ?? {};
      if (typeof targetDeviceId !== 'string' || !targetDeviceId.trim()) {
        res.status(400).json({ error: 'معرّف الجهاز المستهدف مطلوب.' });
        return;
      }

      const cleanTarget = targetDeviceId.trim();
      const shouldRevokeTrust = revokeDeviceTrust === true && auth.role === 'admin';
      const revoked = db.revokeDeviceLink(
        auth.publicId,
        cleanTarget,
        shouldRevokeTrust
      );

      if (!revoked) {
        res.status(404).json({
          error: 'لا يوجد ارتباط قائم بين الجهازين.',
          code: 'LINK_NOT_FOUND',
        });
        return;
      }

      pushToDevice(cleanTarget, {
        type: 'device:revoked',
        byDeviceId: auth.publicId,
        trustRevoked: shouldRevokeTrust,
      });

      if (shouldRevokeTrust) {
        closeDeviceSockets(cleanTarget, 'Device trust revoked by Super Admin');
      }

      res.json({ revoked: true, trustRevoked: shouldRevokeTrust });
    }
  );

  router.post('/sync', requireAuthenticatedDevice, (req: AuthenticatedRequest, res) => {
    const auth = req.authDevice!;
    const { deviceId, targetDeviceId, events } = req.body ?? {};

    if (
      typeof deviceId !== 'string' ||
      deviceId !== auth.publicId ||
      typeof targetDeviceId !== 'string' ||
      !targetDeviceId.trim() ||
      !Array.isArray(events)
    ) {
      res.status(400).json({
        error: 'حزمة المزامنة غير صالحة أو تفتقد الجهاز المستهدف.',
        code: 'INVALID_SYNC_BATCH',
      });
      return;
    }

    const cleanTarget = targetDeviceId.trim();
    const senderDevice = db.getDevice(auth.publicId);
    const targetDevice = db.getDevice(cleanTarget);
    if (
      !senderDevice ||
      !senderDevice.publicKeyJwk ||
      senderDevice.status !== 'ACTIVE' ||
      !targetDevice ||
      targetDevice.status !== 'ACTIVE' ||
      !db.isLinkPaired(auth.publicId, cleanTarget)
    ) {
      res.status(403).json({
        error: 'الجهاز المستهدف غير مقترن أو تم سحب الثقة منه.',
        code: 'NOT_PAIRED_OR_REVOKED',
      });
      return;
    }

    const senderPublicKeyJwk = JSON.parse(senderDevice.publicKeyJwk) as JsonWebKey;
    const seenBatchNonces = new Map<string, string>();

    const normalizedEvents: Array<{
      id: number;
      idempotencyKey: string;
      type: string;
      payload: string;
      senderCryptoKeyId: string;
      recipientCryptoKeyId: string;
      messageNonce: string;
      notificationKey?: string;
      payloadHash?: string;
      createdAt: number;
    }> = [];

    for (const evt of events) {
      if (
        !evt ||
        typeof evt !== 'object' ||
        typeof evt.id !== 'number' ||
        typeof evt.idempotencyKey !== 'string' ||
        typeof evt.type !== 'string' ||
        typeof evt.createdAt !== 'number' ||
        !isValidE2eeEnvelope(evt.e2eeEnvelope, auth.publicId, cleanTarget)
      ) {
        res.status(422).json({
          error: 'يرفض خادم المرحل أي حدث غير مشفّر ببروتوكول E2EE المعتمد بين الطرفين.',
          code: 'E2EE_ENVELOPE_REQUIRED',
        });
        return;
      }

      const env = evt.e2eeEnvelope as Record<string, unknown>;
      if (
        env.senderCryptoKeyId !== auth.cryptoKeyId ||
        env.recipientCryptoKeyId !== targetDevice.cryptoKeyId
      ) {
        res.status(422).json({
          error: 'بصمة مفاتيح E2EE في المغلف لا تطابق بصمة المرسل أو المستلم المسجلة.',
          code: 'E2EE_KEY_ID_MISMATCH',
        });
        return;
      }

      let parsedAad: Record<string, unknown>;
      try {
        parsedAad = JSON.parse(String(env.aad)) as Record<string, unknown>;
      } catch {
        res.status(422).json({
          error: 'بيانات السياق AAD في مغلف E2EE غير صالحة.',
          code: 'E2EE_AAD_INVALID',
        });
        return;
      }

      if (
        parsedAad.v !== 1 ||
        parsedAad.senderDeviceId !== auth.publicId ||
        parsedAad.recipientDeviceId !== cleanTarget ||
        parsedAad.senderCryptoKeyId !== auth.cryptoKeyId ||
        parsedAad.recipientCryptoKeyId !== targetDevice.cryptoKeyId ||
        parsedAad.sessionId !== env.sessionId ||
        parsedAad.messageNonce !== env.messageNonce ||
        parsedAad.idempotencyKey !== evt.idempotencyKey
      ) {
        res.status(422).json({
          error:
            'عدم تطابق بيانات السياق AAD مع هوية المرسل أو المستلم أو مفتاح الحدث.',
          code: 'E2EE_AAD_INVALID',
        });
        return;
      }

      const sigTarget = `E2EE|${sha256Hex(String(env.aad))}|${sha256Hex(`${String(env.iv)}:${String(env.ciphertext)}`)}`;
      if (
        !verifyEcdsaSignature(
          senderPublicKeyJwk,
          auth.cryptoKeyId,
          sigTarget,
          String(env.signature)
        )
      ) {
        res.status(422).json({
          error: 'فشل التحقق من التوقيع الرقمي لمغلف E2EE.',
          code: 'E2EE_ENVELOPE_SIGNATURE_INVALID',
        });
        return;
      }

      const messageNonce = String(env.messageNonce);
      const batchPrevKey = seenBatchNonces.get(messageNonce);
      if (
        (batchPrevKey !== undefined && batchPrevKey !== evt.idempotencyKey) ||
        db.hasUsedMessageNonce(auth.publicId, messageNonce, evt.idempotencyKey)
      ) {
        res.status(409).json({
          error: 'تم رفض الحدث بسبب إعادة استخدام messageNonce لحدث مختلف.',
          code: 'E2EE_NONCE_REUSED',
        });
        return;
      }
      seenBatchNonces.set(messageNonce, evt.idempotencyKey);

      normalizedEvents.push({
        id: evt.id,
        idempotencyKey: evt.idempotencyKey,
        type: evt.type,
        // Store ONLY encrypted E2eeEnvelope JSON on relay — zero plaintext
        payload: JSON.stringify(env),
        senderCryptoKeyId: String(env.senderCryptoKeyId),
        recipientCryptoKeyId: String(env.recipientCryptoKeyId),
        messageNonce,
        notificationKey:
          typeof evt.notificationKey === 'string' ? evt.notificationKey : undefined,
        payloadHash: typeof evt.payloadHash === 'string' ? evt.payloadHash : undefined,
        createdAt: evt.createdAt,
      });
    }

    const result = db.ingestSyncBatch(auth.publicId, cleanTarget, normalizedEvents);
    const serverTimestamp = Date.now();

    for (const row of result.insertedRows) {
      pushToDevice(row.targetDeviceId, {
        type: 'sync:event',
        relayEventId: row.relayEventId,
        event: {
          id: row.relayEventId,
          type: row.type,
          payload: '[E2EE_CIPHERTEXT]',
          e2eeEnvelope: JSON.parse(row.payload),
          sourceDeviceId: row.sourceDeviceId,
          targetDeviceId: row.targetDeviceId,
          createdAt: row.createdAt,
          status: 'IN_PROGRESS',
          retryCount: 0,
          nextRetryAt: null,
          idempotencyKey: row.idempotencyKey,
          notificationKey: row.notificationKey ?? undefined,
          payloadHash: row.payloadHash ?? undefined,
          encrypted: true,
          localEncrypted: false,
          e2eeProtected: false,
          e2eeVerified: false,
          relaySignatureVerified: true,
          relayDeliveryState: 'QUEUED_AT_RELAY',
          relayAcceptedAt: row.receivedAt,
          deliveredAt: null,
        },
      });
    }

    res.json({
      acknowledged: true,
      acceptedIds: result.acceptedIds,
      duplicateIds: result.duplicateIds,
      deliveredIds: result.deliveredIds,
      serverTimestamp,
    });
  });

  router.get(
    '/sync/:deviceId/inbox',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.publicId !== req.params.deviceId) {
        res.status(403).json({
          error: 'غير مصرح بقراءة صندوق وارد جهاز آخر.',
          code: 'FORBIDDEN_OWNERSHIP',
        });
        return;
      }

      const rows = db.getInboundEvents(auth.publicId).map((r) => ({
        id: r.id,
        type: r.type,
        payload: '[E2EE_CIPHERTEXT]',
        e2eeEnvelope: JSON.parse(r.payload),
        sourceDeviceId: r.sourceDeviceId,
        targetDeviceId: auth.publicId,
        createdAt: r.createdAt,
        status: r.deliveredAt != null ? 'SYNCED' : 'IN_PROGRESS',
        retryCount: 0,
        nextRetryAt: null,
        idempotencyKey: r.idempotencyKey,
        notificationKey: r.notificationKey ?? undefined,
        payloadHash: r.payloadHash ?? undefined,
        encrypted: true,
        localEncrypted: false,
        e2eeProtected: false,
        e2eeVerified: false,
        relaySignatureVerified: true,
        relayDeliveryState: r.deliveredAt != null ? 'DELIVERED' : 'QUEUED_AT_RELAY',
        relayAcceptedAt: r.receivedAt,
        deliveredAt: r.deliveredAt ?? null,
      }));
      res.json({ events: rows });
    }
  );

  router.post(
    '/sync/ack',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      const { eventIds } = req.body ?? {};
      if (!Array.isArray(eventIds)) {
        res.status(400).json({ error: 'قائمة معرفات الاستلام مطلوبة.' });
        return;
      }

      const cleanIds = eventIds.filter(
        (id) => typeof id === 'number' && Number.isInteger(id)
      );
      const acked = db.acknowledgeDelivery(auth.publicId, cleanIds);
      const serverTimestamp = Date.now();

      const bySender = new Map<string, number[]>();
      for (const item of acked) {
        const list = bySender.get(item.senderDeviceId) ?? [];
        list.push(item.clientEventId);
        bySender.set(item.senderDeviceId, list);
      }

      for (const [senderId, clientEventIds] of bySender.entries()) {
        pushToDevice(senderId, {
          type: 'sync:delivered',
          clientEventIds,
          byDeviceId: auth.publicId,
          serverTimestamp,
        });
      }

      res.json({
        acknowledged: acked.length,
        acknowledgedEventIds: acked.map((item) => item.relayEventId),
        serverTimestamp,
      });
    }
  );

  router.get(
    '/sync/:deviceId/status',
    requireAuthenticatedDevice,
    (req: AuthenticatedRequest, res) => {
      const auth = req.authDevice!;
      if (auth.publicId !== req.params.deviceId) {
        res.status(403).json({
          error: 'غير مصرح بالاستعلام عن حالة مزامنة جهاز آخر.',
          code: 'FORBIDDEN_OWNERSHIP',
        });
        return;
      }

      const rawIds = String(req.query.ids ?? '');
      const ids = rawIds
        .split(',')
        .map((v) => Number(v.trim()))
        .filter((n) => Number.isInteger(n) && n > 0);
      const deliveredClientEventIds = db.getDeliveredClientEventIds(auth.publicId, ids);
      res.json({ deliveredClientEventIds, serverTimestamp: Date.now() });
    }
  );

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
