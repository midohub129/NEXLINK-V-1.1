import { SyncError } from '../../domain/errors/appError';
import type { ISyncEventRepository } from '../../domain/interfaces/repositories';
import type {
  ICryptoProvider,
  ILifecycleParticipant,
  ILogger,
  ITransportClient,
} from '../../domain/interfaces/services';
import type {
  NotificationPayload,
  SyncEvent,
  SyncEventStatus,
  SyncRunSummary,
} from '../../domain/models/syncEvent';
import type { DeviceManager } from '../devices/deviceManager';
import type { SecurityManager } from '../security/securityManager';
import type { SettingsService } from '../settings/settingsService';

const DEDUP_WINDOW_MS = 60_000;
const BASE_BACKOFF_MS = 1_500;
const MAX_BACKOFF_MS = 60_000;

export function calculateExponentialBackoffMs(
  retryCount: number,
  baseMs = BASE_BACKOFF_MS,
  maxMs = MAX_BACKOFF_MS
): number {
  const exponent = Math.max(0, retryCount - 1);
  return Math.min(maxMs, baseMs * Math.pow(2, exponent));
}

export interface EnqueueNotificationInput {
  packageName: string;
  title: string;
  text: string;
  notificationKey?: string;
  postedAt?: number;
}

export type EnqueueOutcome =
  | { status: 'SAVED'; event: SyncEvent }
  | {
      status: 'REJECTED';
      reason:
        | 'SESSION_EXPIRED'
        | 'PERMISSION_DENIED'
        | 'SELF_PACKAGE'
        | 'APP_NOT_SELECTED'
        | 'DUPLICATE';
    };

export class SyncEngine implements ILifecycleParticipant {
  readonly name = 'SyncEngine';

  private readonly repo: ISyncEventRepository;
  private readonly transport: ITransportClient;
  private readonly crypto: ICryptoProvider;
  private readonly security: SecurityManager;
  private readonly settings: SettingsService;
  private readonly devices: DeviceManager;
  private readonly logger: ILogger;

  private eventsCache: SyncEvent[] = [];
  private isProcessing = false;
  private lastSuccessfulSyncAt: number | null = null;
  private lastRunSummary: SyncRunSummary | null = null;
  private listeners = new Set<() => void>();
  private unsubInbound: (() => void) | null = null;

  constructor(deps: {
    repo: ISyncEventRepository;
    transport: ITransportClient;
    crypto: ICryptoProvider;
    security: SecurityManager;
    settings: SettingsService;
    devices: DeviceManager;
    logger: ILogger;
  }) {
    this.repo = deps.repo;
    this.transport = deps.transport;
    this.crypto = deps.crypto;
    this.security = deps.security;
    this.settings = deps.settings;
    this.devices = deps.devices;
    this.logger = deps.logger;
  }

  async start(): Promise<void> {
    await this.repo.initialize();
    const recoveredCount = await this.repo.resetInProgressToPending();
    if (recoveredCount > 0) {
      this.logger.warn(
        'SYNC',
        'تمت استعادة أحداث متوقفة إلى PENDING بعد إعادة التشغيل',
        {
          recoveredCount,
        }
      );
    }

    this.eventsCache = await this.repo.getAll();

    if (!this.unsubInbound) {
      this.unsubInbound = this.transport.subscribeEvents((remoteEvent) => {
        void this.ingestInboundEvent(remoteEvent);
      });
    }

    this.notify();
  }

  async stop(): Promise<void> {
    if (this.unsubInbound) {
      this.unsubInbound();
      this.unsubInbound = null;
    }
    this.isProcessing = false;
    this.notify();
  }

  getEvents(): SyncEvent[] {
    return [...this.eventsCache];
  }

  getLastSuccessfulSyncAt(): number | null {
    return this.lastSuccessfulSyncAt;
  }

  getLastRunSummary(): SyncRunSummary | null {
    return this.lastRunSummary ? { ...this.lastRunSummary } : null;
  }

  isSyncRunning(): boolean {
    return this.isProcessing;
  }

  async enqueueNotification(input: EnqueueNotificationInput): Promise<EnqueueOutcome> {
    const currentSettings = this.settings.getSnapshot();
    const deviceId = this.devices.getIdentity()?.publicId ?? 'unknown';

    if (!this.security.isSessionAuthenticated()) {
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: currentSettings.role ?? 'none',
        deviceId,
        outcome: 'DENIED',
        details: 'تعذّر حفظ إشعار بسبب انتهاء صلاحية الجلسة',
      });
      return { status: 'REJECTED', reason: 'SESSION_EXPIRED' };
    }

    if (!currentSettings.notificationAccessGranted) {
      return { status: 'REJECTED', reason: 'PERMISSION_DENIED' };
    }

    if (input.packageName === 'com.nexlink.app') {
      return { status: 'REJECTED', reason: 'SELF_PACKAGE' };
    }

    if (!currentSettings.selectedNotificationApps.includes(input.packageName)) {
      return { status: 'REJECTED', reason: 'APP_NOT_SELECTED' };
    }

    const postedAt = input.postedAt ?? Date.now();
    const payloadObj: NotificationPayload = {
      packageName: input.packageName,
      title: input.title,
      text: input.text,
      postedAt,
    };

    const notificationKey =
      input.notificationKey?.trim() ||
      `0|${input.packageName}|0|null|${input.title.trim()}`;
    const payloadHash = await this.crypto.sha256Hex(
      `${input.packageName}|${input.title}|${input.text}`
    );

    const existingDuplicate = await this.repo.findRecentDuplicate(
      'notification',
      notificationKey,
      payloadHash,
      DEDUP_WINDOW_MS,
      Date.now()
    );

    if (existingDuplicate) {
      await this.security.recordAudit({
        action: 'DUPLICATE_BLOCKED',
        actorRole: currentSettings.role ?? 'none',
        deviceId,
        outcome: 'INFO',
        details: `منع إشعار مكرر للمفتاح ${notificationKey}`,
      });
      return { status: 'REJECTED', reason: 'DUPLICATE' };
    }

    const idempotencyKey = await this.crypto.sha256Hex(
      `${deviceId}:${notificationKey}:${payloadHash}:${postedAt}`
    );

    const event = await this.repo.insert({
      type: 'notification',
      payload: JSON.stringify(payloadObj),
      idempotencyKey,
      notificationKey,
      payloadHash,
      createdAt: postedAt,
    });

    this.eventsCache = await this.repo.getAll();
    this.logger.info('SYNC', 'تم إدراج حدث جديد في طابور المزامنة', {
      eventId: event.id,
      idempotencyKey,
    });
    this.notify();
    return { status: 'SAVED', event };
  }

  private async ingestInboundEvent(remoteEvent: SyncEvent): Promise<void> {
    const existing = await this.repo.findRecentDuplicate(
      remoteEvent.type,
      remoteEvent.notificationKey ?? remoteEvent.idempotencyKey,
      remoteEvent.payloadHash ?? remoteEvent.idempotencyKey,
      DEDUP_WINDOW_MS * 10,
      Date.now()
    );
    if (existing) return;

    const inserted = await this.repo.insert({
      type: remoteEvent.type,
      payload: remoteEvent.payload,
      idempotencyKey: remoteEvent.idempotencyKey,
      notificationKey: remoteEvent.notificationKey,
      payloadHash: remoteEvent.payloadHash,
      createdAt: remoteEvent.createdAt,
    });
    await this.repo.updateEvent(inserted.id, {
      status: 'SYNCED',
      syncedAt: Date.now(),
    });
    this.eventsCache = await this.repo.getAll();
    this.notify();
  }

  /**
   * Executes one full synchronization cycle in chronological FIFO order.
   * Never marks any event SYNCED without explicit server/relay confirmation.
   */
  async runSyncCycle(nowMs = Date.now()): Promise<SyncRunSummary> {
    if (this.isProcessing) {
      const summary: SyncRunSummary = {
        attempted: 0,
        synced: 0,
        duplicates: 0,
        failed: 0,
        skippedReason: 'LOCKED',
        completedAt: nowMs,
      };
      this.lastRunSummary = summary;
      return summary;
    }

    const currentSettings = this.settings.getSnapshot();
    const identity = this.devices.getIdentity();
    if (!this.security.isSessionAuthenticated(nowMs)) {
      const summary: SyncRunSummary = {
        attempted: 0,
        synced: 0,
        duplicates: 0,
        failed: 0,
        skippedReason: 'SESSION_EXPIRED',
        completedAt: nowMs,
      };
      this.lastRunSummary = summary;
      this.notify();
      return summary;
    }

    if (this.transport.getState() !== 'CONNECTED' || !identity) {
      const summary: SyncRunSummary = {
        attempted: 0,
        synced: 0,
        duplicates: 0,
        failed: 0,
        skippedReason: 'OFFLINE',
        completedAt: nowMs,
      };
      this.lastRunSummary = summary;
      this.notify();
      return summary;
    }

    const activePeer = this.devices
      .getLinkedDevices()
      .find((d) => d.pairingState === 'PAIRED' && d.verifiedByRelay);

    this.isProcessing = true;
    this.notify();

    try {
      const dueEvents = await this.repo.getDuePendingEvents(nowMs);
      if (dueEvents.length === 0) {
        const emptySummary: SyncRunSummary = {
          attempted: 0,
          synced: 0,
          duplicates: 0,
          failed: 0,
          completedAt: Date.now(),
        };
        this.lastRunSummary = emptySummary;
        return emptySummary;
      }

      // Preserve chronological FIFO order
      const orderedBatch = [...dueEvents].sort(
        (a, b) => a.createdAt - b.createdAt || a.id - b.id
      );

      for (const evt of orderedBatch) {
        await this.repo.updateEvent(evt.id, { status: 'IN_PROGRESS' });
      }
      this.eventsCache = await this.repo.getAll();
      this.notify();

      try {
        const ack = await this.transport.sendSyncBatch(
          identity.publicId,
          activePeer?.publicId ?? null,
          orderedBatch
        );

        if (!ack.acknowledged) {
          throw new SyncError(
            'SYNC_ACK_REJECTED',
            'لم يؤكد الخادم استلام أحداث المزامنة.',
            ack.error ?? 'Relay rejected batch without acknowledgment',
            true
          );
        }

        const acceptedSet = new Set(ack.acceptedIds);
        const duplicateSet = new Set(ack.duplicateIds);
        let synced = 0;
        let duplicates = 0;
        let failed = 0;

        for (const evt of orderedBatch) {
          if (acceptedSet.has(evt.id) || duplicateSet.has(evt.id)) {
            await this.repo.updateEvent(evt.id, {
              status: 'SYNCED',
              syncedAt: ack.serverTimestamp,
              nextRetryAt: null,
              lastError: null,
            });
            if (duplicateSet.has(evt.id)) {
              duplicates += 1;
            } else {
              synced += 1;
            }
          } else {
            failed += 1;
            await this.scheduleRetryOrFail(
              evt,
              currentSettings.maxSyncRetries,
              'لم يدرج الخادم الحدث ضمن قائمة التأكيد.'
            );
          }
        }

        if (synced > 0 || duplicates > 0) {
          this.lastSuccessfulSyncAt = ack.serverTimestamp;
        }

        const summary: SyncRunSummary = {
          attempted: orderedBatch.length,
          synced,
          duplicates,
          failed,
          completedAt: Date.now(),
        };
        this.lastRunSummary = summary;
        this.logger.info('SYNC', 'اكتملت دورة المزامنة بتأكيد الخادم', {
          attempted: summary.attempted,
          synced: summary.synced,
          duplicates: summary.duplicates,
          failed: summary.failed,
        });
        return summary;
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'Network dispatch failure';
        for (const evt of orderedBatch) {
          await this.scheduleRetryOrFail(evt, currentSettings.maxSyncRetries, reason);
        }
        const failSummary: SyncRunSummary = {
          attempted: orderedBatch.length,
          synced: 0,
          duplicates: 0,
          failed: orderedBatch.length,
          completedAt: Date.now(),
        };
        this.lastRunSummary = failSummary;
        this.logger.warn('SYNC', 'فشل إرسال دفعة المزامنة وجدولة إعادة المحاولة', {
          reason,
          count: orderedBatch.length,
        });
        return failSummary;
      }
    } finally {
      this.eventsCache = await this.repo.getAll();
      this.isProcessing = false;
      this.notify();
    }
  }

  private async scheduleRetryOrFail(
    evt: SyncEvent,
    maxRetries: number,
    errorMessage: string
  ): Promise<void> {
    const nextRetryCount = evt.retryCount + 1;
    if (nextRetryCount >= maxRetries) {
      await this.repo.updateEvent(evt.id, {
        status: 'FAILED',
        retryCount: nextRetryCount,
        nextRetryAt: null,
        lastError: errorMessage,
      });
      return;
    }

    const delayMs = calculateExponentialBackoffMs(nextRetryCount);
    await this.repo.updateEvent(evt.id, {
      status: 'PENDING',
      retryCount: nextRetryCount,
      nextRetryAt: Date.now() + delayMs,
      lastError: errorMessage,
    });
  }

  async updateEventStatus(
    eventId: number,
    status: SyncEventStatus
  ): Promise<SyncEvent | null> {
    const role = this.settings.getSnapshot().role;
    const deviceId = this.devices.getIdentity()?.publicId ?? 'unknown';
    await this.security.assertAuthorized(
      role,
      deviceId,
      'updateEventStatus',
      `تغيير حالة الحدث #${eventId}`
    );

    const updated = await this.repo.updateEvent(eventId, {
      status,
      nextRetryAt: status === 'PENDING' ? Date.now() : null,
      syncedAt: status === 'SYNCED' ? Date.now() : null,
    });
    this.eventsCache = await this.repo.getAll();
    this.notify();
    return updated;
  }

  async manualRetryEvent(eventId: number): Promise<SyncEvent | null> {
    const role = this.settings.getSnapshot().role;
    const deviceId = this.devices.getIdentity()?.publicId ?? 'unknown';
    await this.security.assertAuthorized(
      role,
      deviceId,
      'updateEventStatus',
      `إعادة محاولة الحدث #${eventId}`
    );

    const existing = await this.repo.findById(eventId);
    if (!existing) return null;

    const updated = await this.repo.updateEvent(eventId, {
      status: 'PENDING',
      retryCount: existing.retryCount + 1,
      nextRetryAt: Date.now(),
    });
    this.eventsCache = await this.repo.getAll();
    this.notify();
    return updated;
  }

  async deleteEvent(eventId: number): Promise<boolean> {
    const role = this.settings.getSnapshot().role;
    const deviceId = this.devices.getIdentity()?.publicId ?? 'unknown';
    await this.security.assertAuthorized(
      role,
      deviceId,
      'deleteEvents',
      `حذف الحدث #${eventId}`
    );

    const deleted = await this.repo.delete(eventId);
    this.eventsCache = await this.repo.getAll();
    this.notify();
    return deleted;
  }

  async clearAllEvents(): Promise<void> {
    const role = this.settings.getSnapshot().role;
    const deviceId = this.devices.getIdentity()?.publicId ?? 'unknown';
    await this.security.assertAuthorized(
      role,
      deviceId,
      'deleteEvents',
      'مسح جميع أحداث المزامنة'
    );

    await this.repo.clearAll();
    this.eventsCache = [];
    await this.security.recordAudit({
      action: 'SECURE_WIPE',
      actorRole: role ?? 'none',
      deviceId,
      outcome: 'ALLOWED',
      details: 'تم مسح جميع أحداث المزامنة المشفّرة محلياً',
    });
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}
