import { TransportError } from '../../domain/errors/appError';
import type {
  ICryptoProvider,
  ILogger,
  ITransportClient,
  RelayRegistrationPayload,
} from '../../domain/interfaces/services';
import type {
  ConnectionState,
  LinkedDevice,
  PairingRequest,
} from '../../domain/models/device';
import type { RelayServerSession } from '../../domain/models/security';
import type { SyncDispatchAck, SyncEvent } from '../../domain/models/syncEvent';
import { calculateExponentialBackoffMs } from '../../application/sync/syncEngine';

export interface RelayTransportOptions {
  baseUrl?: string;
  requestTimeoutMs?: number;
  maxReconnectAttempts?: number;
  logger: ILogger;
  crypto: ICryptoProvider;
  fetchImpl?: typeof fetch;
  webSocketFactory?: (url: string) => WebSocket;
}

export class RelayTransportClient implements ITransportClient {
  private baseUrl: string;
  private readonly requestTimeoutMs: number;
  private readonly maxReconnectAttempts: number;
  private readonly logger: ILogger;
  private readonly crypto: ICryptoProvider;
  private readonly fetchImpl: typeof fetch;
  private readonly webSocketFactory?: (url: string) => WebSocket;

  private state: ConnectionState = 'DISCONNECTED';
  private lastSuccessfulConnectionAt: number | null = null;
  private socket: WebSocket | null = null;
  private activeDevice: RelayRegistrationPayload | null = null;
  private serverSession: RelayServerSession | null = null;
  private manualDisconnect = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  private stateListeners = new Set<() => void>();
  private eventListeners = new Set<(event: SyncEvent) => void>();
  private deliveryAckListeners = new Set<
    (deliveredClientEventIds: number[], serverTimestamp: number) => void
  >();
  private pairingListeners = new Set<() => void>();

  constructor(options: RelayTransportOptions) {
    this.baseUrl = (options.baseUrl ?? '/api/relay').replace(/\/+$/, '');
    this.requestTimeoutMs = options.requestTimeoutMs ?? 8000;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 5;
    this.logger = options.logger;
    this.crypto = options.crypto;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.webSocketFactory = options.webSocketFactory;
  }

  setBaseUrl(nextBaseUrl: string): void {
    this.baseUrl = nextBaseUrl.replace(/\/+$/, '');
  }

  getState(): ConnectionState {
    return this.state;
  }

  getServerSession(): RelayServerSession | null {
    if (!this.serverSession) return null;
    if (Date.now() >= this.serverSession.expiresAt) return null;
    return { ...this.serverSession };
  }

  getLastSuccessfulConnectionAt(): number | null {
    return this.lastSuccessfulConnectionAt;
  }

  private setState(next: ConnectionState): void {
    if (this.state === next) return;
    this.state = next;
    this.stateListeners.forEach((listener) => listener());
  }

  private buildWsUrl(ticket: string): string {
    if (this.baseUrl.startsWith('http://') || this.baseUrl.startsWith('https://')) {
      const parsed = new URL(this.baseUrl);
      const wsProtocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${wsProtocol}//${parsed.host}/ws/relay?ticket=${encodeURIComponent(ticket)}`;
    }
    if (typeof window !== 'undefined') {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${wsProtocol}//${window.location.host}/ws/relay?ticket=${encodeURIComponent(ticket)}`;
    }
    return `ws://127.0.0.1:3000/ws/relay?ticket=${encodeURIComponent(ticket)}`;
  }

  private computeCanonicalPath(path: string): string {
    const full = `${this.baseUrl}${path}`;
    const parsed = new URL(full, 'http://localhost');
    return `${parsed.pathname}${parsed.search}`;
  }

  private async requestJson<T>(
    path: string,
    init?: RequestInit,
    authenticated = true
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...((init?.headers as Record<string, string> | undefined) ?? {}),
      };

      if (authenticated) {
        const session = this.getServerSession();
        if (!session) {
          throw new TransportError(
            'RELAY_UNAUTHENTICATED',
            'لا توجد جلسة مصادقة نشطة مع خادم المرحل.',
            'Missing or expired RelayServerSession',
            false
          );
        }

        const method = (init?.method ?? 'GET').toUpperCase();
        const canonicalPath = this.computeCanonicalPath(path);
        const bodyString = typeof init?.body === 'string' ? init.body : '';
        const bodyHash = await this.crypto.sha256Hex(bodyString);
        const timestamp = Date.now();
        const nonce = this.crypto.randomHex(16);
        const signedPayload = `${method}|${canonicalPath}|${bodyHash}|${timestamp}|${nonce}`;
        const signature = await this.crypto.signPayload(signedPayload);
        if (!signature) {
          throw new TransportError(
            'REQUEST_SIGNING_FAILED',
            'تعذّر توقيع الطلب التشفيري.',
            'signPayload returned null',
            false
          );
        }

        headers.Authorization = `Bearer ${session.token}`;
        headers['X-Nexlink-Timestamp'] = String(timestamp);
        headers['X-Nexlink-Nonce'] = nonce;
        headers['X-Nexlink-Signature'] = signature;
      }

      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers,
      });

      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          const code = typeof body.code === 'string' ? body.code : '';
          if (code === 'SESSION_REVOKED_OR_EXPIRED' || code === 'DEVICE_REVOKED') {
            this.serverSession = null;
          }
        }
        const message =
          typeof body.error === 'string'
            ? body.error
            : `فشل طلب المرحل برمز الحالة ${response.status}`;
        throw new TransportError(
          typeof body.code === 'string' ? body.code : `RELAY_HTTP_${response.status}`,
          message,
          `Relay ${path} returned HTTP ${response.status}`,
          response.status >= 500 || response.status === 408
        );
      }

      return body as T;
    } catch (err) {
      if (err instanceof TransportError) throw err;
      if (err instanceof Error && err.name === 'AbortError') {
        throw new TransportError(
          'RELAY_TIMEOUT',
          'انتهت المهلة الزمنية للاتصال بخادم المرحل.',
          `Request timeout after ${this.requestTimeoutMs}ms on ${path}`,
          true,
          err
        );
      }
      throw new TransportError(
        'RELAY_NETWORK_ERROR',
        'تعذّر الوصول إلى خادم المرحل. تحقق من الاتصال.',
        err instanceof Error ? err.message : 'Network error',
        true,
        err
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async connect(device: RelayRegistrationPayload): Promise<void> {
    this.manualDisconnect = false;
    this.activeDevice = device;
    this.clearReconnectTimer();
    this.setState('CONNECTING');

    try {
      if (!device.publicKeyJwk || !device.ecdhPublicKeyJwk) {
        throw new TransportError(
          'MISSING_DEVICE_KEYS',
          'مفاتيح الهوية التشفيرية للجهاز غير مكتملة.',
          'ECDSA and ECDH public JWKs are required to register with relay',
          false
        );
      }

      const regTimestamp = Date.now();
      const regNonce = this.crypto.randomHex(16);
      const ecdhHash = await this.crypto.sha256Hex(
        JSON.stringify(device.ecdhPublicKeyJwk)
      );
      const regMsg = `REGISTER|${device.publicId}|${device.cryptoKeyId}|${ecdhHash}|${device.role}|${regTimestamp}|${regNonce}`;
      const regSignature = await this.crypto.signPayload(regMsg);
      if (!regSignature) {
        throw new TransportError(
          'REGISTRATION_SIGN_FAILED',
          'تعذّر توقيع طلب تسجيل الجهاز.',
          'Failed to sign device registration',
          false
        );
      }

      await this.requestJson(
        '/devices/register',
        {
          method: 'POST',
          body: JSON.stringify({
            ...device,
            timestamp: regTimestamp,
            nonce: regNonce,
            signature: regSignature,
          }),
        },
        false
      );

      const challengeResp = await this.requestJson<{
        challenge: string;
        expiresAt: number;
      }>(
        '/auth/challenge',
        {
          method: 'POST',
          body: JSON.stringify({ publicId: device.publicId }),
        },
        false
      );

      const authTs = Date.now();
      const authNonce = this.crypto.randomHex(16);
      const authMsg = `AUTH|${device.publicId}|${challengeResp.challenge}|${authTs}|${authNonce}`;
      const authSig = await this.crypto.signPayload(authMsg);
      if (!authSig) {
        throw new TransportError(
          'AUTH_SIGN_FAILED',
          'تعذّر توقيع تحدي مصادقة الخادم.',
          'Failed to sign auth challenge',
          false
        );
      }

      const session = await this.requestJson<RelayServerSession>(
        '/auth/session',
        {
          method: 'POST',
          body: JSON.stringify({
            publicId: device.publicId,
            challenge: challengeResp.challenge,
            timestamp: authTs,
            nonce: authNonce,
            signature: authSig,
          }),
        },
        false
      );

      this.serverSession = session;

      const ticketResp = await this.requestJson<{ ticket: string }>(
        '/ws/ticket',
        { method: 'POST', body: '{}' },
        true
      );

      await this.openWebSocket(ticketResp.ticket);
      this.reconnectAttempts = 0;
      this.lastSuccessfulConnectionAt = Date.now();
      this.setState('CONNECTED');
      this.logger.info(
        'TRANSPORT',
        'تمت المصادقة التشفيرية والاتصال بخادم المرحل عبر Bearer Session و WebSocket',
        { deviceId: device.publicId }
      );
    } catch (err) {
      this.setState('ERROR');
      throw err;
    }
  }

  private openWebSocket(ticket: string): Promise<void> {
    const wsUrl = this.buildWsUrl(ticket);
    const WSImpl =
      this.webSocketFactory ??
      (typeof WebSocket !== 'undefined' ? (u: string) => new WebSocket(u) : undefined);

    if (!WSImpl) {
      return Promise.resolve();
    }

    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        // ignore close errors
      }
      this.socket = null;
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = WSImpl(wsUrl);
      this.socket = ws;

      const connectTimer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(
            new TransportError(
              'WS_CONNECT_TIMEOUT',
              'انتهت مهلة فتح قناة WebSocket الفورية.',
              'WebSocket handshake timeout',
              true
            )
          );
        }
      }, this.requestTimeoutMs);

      ws.onopen = () => {
        clearTimeout(connectTimer);
        settled = true;
        resolve();
      };

      ws.onerror = () => {
        clearTimeout(connectTimer);
        if (!settled) {
          settled = true;
          reject(
            new TransportError(
              'WS_CONNECT_ERROR',
              'تعذّر فتح قناة WebSocket مع خادم المرحل.',
              'WebSocket error during connection',
              true
            )
          );
        }
      };

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(String(msg.data)) as {
            type?: string;
            event?: SyncEvent;
            clientEventIds?: number[];
            serverTimestamp?: number;
            trustRevoked?: boolean;
          };
          if (data.type === 'sync:event' && data.event) {
            const incoming = data.event;
            this.eventListeners.forEach((listener) => listener(incoming));
          } else if (
            data.type === 'sync:delivered' &&
            Array.isArray(data.clientEventIds)
          ) {
            const ids = data.clientEventIds;
            const ts = data.serverTimestamp ?? Date.now();
            this.deliveryAckListeners.forEach((listener) => listener(ids, ts));
          } else if (data.type === 'device:revoked' && data.trustRevoked) {
            this.serverSession = null;
            this.manualDisconnect = true;
            this.setState('ERROR');
            this.pairingListeners.forEach((listener) => listener());
          } else if (
            data.type === 'pairing:pending_approval' ||
            data.type === 'pairing:rejected' ||
            data.type === 'device:paired' ||
            data.type === 'device:revoked'
          ) {
            this.pairingListeners.forEach((listener) => listener());
            this.stateListeners.forEach((listener) => listener());
          }
        } catch {
          // ignore malformed frames
        }
      };

      ws.onclose = (ev) => {
        clearTimeout(connectTimer);
        if (ev.code === 1008) {
          this.serverSession = null;
          this.setState('ERROR');
          return;
        }
        if (!this.manualDisconnect && this.activeDevice) {
          this.scheduleReconnect();
        }
      };
    });
  }

  private scheduleReconnect(): void {
    if (this.manualDisconnect || !this.activeDevice) return;
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.setState('ERROR');
      this.logger.warn(
        'TRANSPORT',
        'توقفت محاولات إعادة الاتصال التلقائي بعد بلوغ الحد الأقصى'
      );
      return;
    }

    this.reconnectAttempts += 1;
    const delayMs = calculateExponentialBackoffMs(this.reconnectAttempts, 1000, 30_000);
    this.setState('RECONNECTING');
    this.logger.info('TRANSPORT', 'جدولة إعادة الاتصال بخادم المرحل', {
      attempt: this.reconnectAttempts,
      delayMs,
    });

    this.clearReconnectTimer();
    this.reconnectTimer = setTimeout(() => {
      if (this.activeDevice && !this.manualDisconnect) {
        void this.connect(this.activeDevice).catch(() => {
          this.scheduleReconnect();
        });
      }
    }, delayMs);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  async disconnect(): Promise<void> {
    this.manualDisconnect = true;
    this.activeDevice = null;
    this.clearReconnectTimer();
    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        // ignore close failure
      }
      this.socket = null;
    }
    this.setState('DISCONNECTED');
  }

  async revokeServerSession(deviceId: string): Promise<void> {
    if (this.getServerSession()?.devicePublicId === deviceId) {
      try {
        await this.requestJson('/auth/revoke', { method: 'POST', body: '{}' }, true);
      } catch {
        // best-effort server revocation
      }
    }
    this.serverSession = null;
    await this.disconnect();
  }

  async createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest> {
    const session = this.getServerSession();
    if (
      session &&
      (session.devicePublicId !== requesterDeviceId ||
        session.cryptoKeyId !== requesterCryptoKeyId)
    ) {
      throw new TransportError(
        'IDENTITY_MISMATCH',
        'تضارب في هوية الجهاز مع جلسة المرحل الحالية.',
        'Session identity mismatch on createPairingRequest',
        false
      );
    }
    return this.requestJson<PairingRequest>(
      '/pairing/request',
      { method: 'POST', body: '{}' },
      true
    );
  }

  async acceptPairingRequest(
    pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<PairingRequest> {
    return this.requestJson<PairingRequest>(
      '/pairing/accept',
      {
        method: 'POST',
        body: JSON.stringify({
          pairingCode: pairingCode.trim(),
          responderDeviceId: responder.publicId,
        }),
      },
      true
    );
  }

  async confirmPairingRequest(
    pairingId: string,
    approve: boolean,
    expectedResponderCryptoKeyId?: string
  ): Promise<LinkedDevice | null> {
    const res = await this.requestJson<{
      approved: boolean;
      peer: LinkedDevice | null;
    }>(
      '/pairing/confirm',
      {
        method: 'POST',
        body: JSON.stringify({
          pairingId,
          approve,
          expectedResponderCryptoKeyId,
        }),
      },
      true
    );
    return res.peer ?? null;
  }

  async fetchPendingPairingApprovals(deviceId: string): Promise<PairingRequest[]> {
    const res = await this.requestJson<{ requests: PairingRequest[] }>(
      `/pairing/pending/${encodeURIComponent(deviceId)}`,
      undefined,
      true
    );
    return res.requests ?? [];
  }

  async fetchLinkedDevices(deviceId: string): Promise<LinkedDevice[]> {
    const res = await this.requestJson<{ devices: LinkedDevice[] }>(
      `/devices/${encodeURIComponent(deviceId)}/links`,
      undefined,
      true
    );
    return res.devices ?? [];
  }

  async revokeDeviceLink(
    deviceId: string,
    targetDeviceId: string,
    revokeDeviceTrust = false
  ): Promise<void> {
    await this.requestJson(
      `/devices/${encodeURIComponent(deviceId)}/revoke`,
      {
        method: 'POST',
        body: JSON.stringify({ targetDeviceId, revokeDeviceTrust }),
      },
      true
    );
  }

  async sendSyncBatch(
    deviceId: string,
    targetDeviceId: string,
    events: SyncEvent[]
  ): Promise<SyncDispatchAck> {
    return this.requestJson<SyncDispatchAck>(
      '/sync',
      {
        method: 'POST',
        headers: {
          'X-Idempotency-Batch': events.map((e) => e.idempotencyKey).join(','),
        },
        body: JSON.stringify({ deviceId, targetDeviceId, events }),
      },
      true
    );
  }

  async fetchInboundEvents(deviceId: string): Promise<SyncEvent[]> {
    const res = await this.requestJson<{ events: SyncEvent[] }>(
      `/sync/${encodeURIComponent(deviceId)}/inbox`,
      undefined,
      true
    );
    return res.events ?? [];
  }

  async acknowledgeInboundDelivery(
    deviceId: string,
    eventIds: number[]
  ): Promise<void> {
    if (eventIds.length === 0) return;
    if (
      !eventIds.every((id) => typeof id === 'number' && Number.isInteger(id) && id > 0)
    ) {
      throw new TransportError(
        'RELAY_ACK_INVALID_REQUEST',
        'معرّفات الأحداث المطلوب تأكيدها غير صالحة.',
        'Invalid non-positive or non-integer event ID passed to acknowledgeInboundDelivery',
        false
      );
    }

    const requestedIds = Array.from(new Set(eventIds));
    const response = await this.requestJson<{
      acknowledged?: unknown;
      acknowledgedEventIds?: unknown;
      serverTimestamp?: unknown;
    }>(
      '/sync/ack',
      {
        method: 'POST',
        body: JSON.stringify({ deviceId, eventIds: requestedIds }),
      },
      true
    );

    const confirmedIds =
      response && typeof response === 'object'
        ? response.acknowledgedEventIds
        : undefined;
    const confirmedSet = new Set(Array.isArray(confirmedIds) ? confirmedIds : []);
    const exactMatch =
      response !== null &&
      typeof response === 'object' &&
      Array.isArray(confirmedIds) &&
      confirmedIds.length === requestedIds.length &&
      confirmedIds.every(
        (id): id is number =>
          typeof id === 'number' &&
          Number.isInteger(id) &&
          id > 0 &&
          requestedIds.includes(id)
      ) &&
      confirmedSet.size === requestedIds.length &&
      requestedIds.every((id) => confirmedSet.has(id)) &&
      response.acknowledged === requestedIds.length;

    if (!exactMatch) {
      throw new TransportError(
        'RELAY_ACK_INCOMPLETE',
        'لم يؤكد خادم المرحل استلام جميع الأحداث المطلوبة؛ ستبقى الأحداث قيد التأكيد.',
        `Relay ACK mismatch: requested=${requestedIds.length}, acknowledged=${Array.isArray(confirmedIds) ? confirmedIds.length : 'invalid'}`,
        true
      );
    }
  }

  async fetchSyncDeliveryStatus(
    deviceId: string,
    clientEventIds: number[]
  ): Promise<number[]> {
    if (clientEventIds.length === 0) return [];
    const qs = clientEventIds.join(',');
    const res = await this.requestJson<{ deliveredClientEventIds: number[] }>(
      `/sync/${encodeURIComponent(deviceId)}/status?ids=${encodeURIComponent(qs)}`,
      undefined,
      true
    );
    return res.deliveredClientEventIds ?? [];
  }

  subscribe(listener: () => void): () => void {
    this.stateListeners.add(listener);
    return () => {
      this.stateListeners.delete(listener);
    };
  }

  subscribeEvents(listener: (event: SyncEvent) => void): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  subscribeDeliveryAcks(
    listener: (deliveredClientEventIds: number[], serverTimestamp: number) => void
  ): () => void {
    this.deliveryAckListeners.add(listener);
    return () => {
      this.deliveryAckListeners.delete(listener);
    };
  }

  subscribePairingUpdates(listener: () => void): () => void {
    this.pairingListeners.add(listener);
    return () => {
      this.pairingListeners.delete(listener);
    };
  }
}
