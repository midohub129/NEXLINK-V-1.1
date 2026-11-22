import { TransportError } from '../../domain/errors/appError';
import type {
  ILogger,
  ITransportClient,
  RelayRegistrationPayload,
} from '../../domain/interfaces/services';
import type {
  ConnectionState,
  LinkedDevice,
  PairingRequest,
} from '../../domain/models/device';
import type { SyncDispatchAck, SyncEvent } from '../../domain/models/syncEvent';
import { calculateExponentialBackoffMs } from '../../application/sync/syncEngine';

export interface RelayTransportOptions {
  baseUrl?: string;
  requestTimeoutMs?: number;
  maxReconnectAttempts?: number;
  logger: ILogger;
  fetchImpl?: typeof fetch;
  webSocketFactory?: (url: string) => WebSocket;
}

export class RelayTransportClient implements ITransportClient {
  private baseUrl: string;
  private readonly requestTimeoutMs: number;
  private readonly maxReconnectAttempts: number;
  private readonly logger: ILogger;
  private readonly fetchImpl: typeof fetch;
  private readonly webSocketFactory?: (url: string) => WebSocket;

  private state: ConnectionState = 'DISCONNECTED';
  private lastSuccessfulConnectionAt: number | null = null;
  private socket: WebSocket | null = null;
  private activeDevice: RelayRegistrationPayload | null = null;
  private manualDisconnect = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private stateListeners = new Set<() => void>();
  private eventListeners = new Set<(event: SyncEvent) => void>();

  constructor(options: RelayTransportOptions) {
    this.baseUrl = (options.baseUrl ?? '/api/relay').replace(/\/+$/, '');
    this.requestTimeoutMs = options.requestTimeoutMs ?? 8000;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 5;
    this.logger = options.logger;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.webSocketFactory = options.webSocketFactory;
  }

  setBaseUrl(nextBaseUrl: string): void {
    this.baseUrl = nextBaseUrl.replace(/\/+$/, '');
  }

  getState(): ConnectionState {
    return this.state;
  }

  getLastSuccessfulConnectionAt(): number | null {
    return this.lastSuccessfulConnectionAt;
  }

  private setState(next: ConnectionState): void {
    if (this.state === next) return;
    this.state = next;
    this.stateListeners.forEach((listener) => listener());
  }

  private buildWsUrl(deviceId: string): string {
    if (this.baseUrl.startsWith('http://') || this.baseUrl.startsWith('https://')) {
      const parsed = new URL(this.baseUrl);
      const wsProtocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${wsProtocol}//${parsed.host}/ws/relay?deviceId=${encodeURIComponent(deviceId)}`;
    }
    if (typeof window !== 'undefined') {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${wsProtocol}//${window.location.host}/ws/relay?deviceId=${encodeURIComponent(deviceId)}`;
    }
    return `ws://127.0.0.1:3000/ws/relay?deviceId=${encodeURIComponent(deviceId)}`;
  }

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(init?.headers ?? {}),
        },
      });

      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;

      if (!response.ok) {
        const message =
          typeof body.error === 'string'
            ? body.error
            : `فشل طلب المرحل برمز الحالة ${response.status}`;
        throw new TransportError(
          `RELAY_HTTP_${response.status}`,
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
      await this.requestJson('/devices/register', {
        method: 'POST',
        body: JSON.stringify(device),
      });

      await this.openWebSocket(device.publicId);
      this.reconnectAttempts = 0;
      this.lastSuccessfulConnectionAt = Date.now();
      this.setState('CONNECTED');
      this.logger.info('TRANSPORT', 'تم الاتصال بخادم المرحل عبر HTTP و WebSocket', {
        deviceId: device.publicId,
      });
    } catch (err) {
      this.setState('ERROR');
      throw err;
    }
  }

  private openWebSocket(deviceId: string): Promise<void> {
    const wsUrl = this.buildWsUrl(deviceId);
    const WSImpl =
      this.webSocketFactory ??
      (typeof WebSocket !== 'undefined' ? (u: string) => new WebSocket(u) : undefined);

    if (!WSImpl) {
      // If WebSocket constructor isn't available in test environment, HTTP registration still succeeded.
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
          };
          if (data.type === 'sync:event' && data.event) {
            const incoming = data.event;
            this.eventListeners.forEach((listener) => listener(incoming));
          } else if (data.type === 'device:paired' || data.type === 'device:revoked') {
            this.stateListeners.forEach((listener) => listener());
          }
        } catch {
          // ignore malformed frames
        }
      };

      ws.onclose = () => {
        clearTimeout(connectTimer);
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

  async createPairingRequest(
    requesterDeviceId: string,
    requesterCryptoKeyId: string
  ): Promise<PairingRequest> {
    return this.requestJson<PairingRequest>('/pairing/request', {
      method: 'POST',
      body: JSON.stringify({ requesterDeviceId, requesterCryptoKeyId }),
    });
  }

  async acceptPairingRequest(
    pairingCode: string,
    responder: RelayRegistrationPayload
  ): Promise<LinkedDevice> {
    return this.requestJson<LinkedDevice>('/pairing/accept', {
      method: 'POST',
      body: JSON.stringify({ pairingCode, responder }),
    });
  }

  async fetchLinkedDevices(deviceId: string): Promise<LinkedDevice[]> {
    const res = await this.requestJson<{ devices: LinkedDevice[] }>(
      `/devices/${encodeURIComponent(deviceId)}/links`
    );
    return res.devices ?? [];
  }

  async revokeDeviceLink(deviceId: string, targetDeviceId: string): Promise<void> {
    await this.requestJson(`/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ targetDeviceId }),
    });
  }

  async sendSyncBatch(
    deviceId: string,
    targetDeviceId: string | null,
    events: SyncEvent[]
  ): Promise<SyncDispatchAck> {
    return this.requestJson<SyncDispatchAck>('/sync', {
      method: 'POST',
      headers: {
        'X-Idempotency-Batch': events.map((e) => e.idempotencyKey).join(','),
      },
      body: JSON.stringify({ deviceId, targetDeviceId, events }),
    });
  }

  async fetchInboundEvents(deviceId: string): Promise<SyncEvent[]> {
    const res = await this.requestJson<{ events: SyncEvent[] }>(
      `/sync/${encodeURIComponent(deviceId)}/inbox`
    );
    return res.events ?? [];
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
}
