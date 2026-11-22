import { SecurityError, SyncError } from '../../domain/errors/appError';
import type { ISyncEventRepository } from '../../domain/interfaces/repositories';
import type {
  ICryptoProvider,
  ILifecycleParticipant,
  ILogger,
  ITransportClient,
} from '../../domain/interfaces/services';
import type { LinkedDevice } from '../../domain/models/device';
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
  private seenE2eeNonces = new Set<string>();
  private listeners = new Set<() => void>();
  private unsubInbound: (() => void) | null = null;
  private unsubDeliveryAcks: (() => void) | null = null;

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
        'تمت استعادة أحداث غير مؤكدة إلى PENDING بعد إعادة التشغيل لضمان عدم الفقدان',
        { recoveredCount }
      );
    }

    this.eventsCache = await this.repo.getAll();

    if (!this.unsubInbound) {
      this.unsubInbound = this.transport.subscribeEvents((remoteEvent) => {
        void this.ingestInboundEvent(remoteEvent);
      });
    }

    if (!this.unsubDeliveryAcks) {
      this.unsubDeliveryAcks = this.transport.subscribeDeliveryAcks(
        (clientEventIds, serverTimestamp) => {
          void this.handleDeliveryAcks(clientEventIds, serverTimestamp);
        }
      );
    }

    this.notify();
  }

  async stop(): Promise<void> {
    if (this.unsubInbound) {
      this.unsubInbound();
      this.unsubInbound = null;
    }
    if (this.unsubDeliveryAcks) {
      this.unsubDeliveryAcks();
      this.unsubDeliveryAcks = null;
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

  private resolveTargetPeer(): LinkedDevice | null {
    const currentSettings = this.settings.getSnapshot();
    const peers = this.devices
      .getLinkedDevices()
      .filter(
        (d) =>
          d.pairingState === 'PAIRED' &&
          d.verifiedByRelay &&
          Boolean(d.publicKeyJwk) &&
          Boolean(d.ecdhPublicKeyJwk)
      );

    if (peers.length === 0) return null;
    if (currentSettings.targetDeviceId) {
      return peers.find((p) => p.publicId === currentSettings.targetDeviceId) ?? null;
    }
    return peers[0];
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
      sourceDeviceId: deviceId,
      e2eeProtected: false,
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

  async handleDeliveryAcks(
    clientEventIds: number[],
    serverTimestamp = Date.now()
  ): Promise<void> {
    if (clientEventIds.length === 0) return;
    let changed = false;
    for (const id of clientEventIds) {
      const existing = await this.repo.findById(id);
      if (existing && existing.status === 'IN_PROGRESS') {
        await this.repo.updateEvent(id, {
          status: 'SYNCED',
          deliveredAt: serverTimestamp,
          syncedAt: serverTimestamp,
          nextRetryAt: null,
          lastError: null,
        });
        changed = true;
      }
    }
    if (changed) {
      this.lastSuccessfulSyncAt = serverTimestamp;
      this.eventsCache = await this.repo.getAll();
      this.notify();
    }
  }

  async pullInboundEvents(): Promise<number> {
    const identity = this.devices.getIdentity();
    if (!identity || this.transport.getState() !== 'CONNECTED') return 0;

    const inbound = await this.transport.fetchInboundEvents(identity.publicId);
    let ingested = 0;
    for (const evt of inbound) {
      const ok = await this.ingestInboundEvent(evt);
      if (ok) ingested += 1;
    }
    return ingested;
  }

  async ingestInboundEvent(remoteEvent: SyncEvent): Promise<boolean> {
    const identity = this.devices.getIdentity();
    const role = this.settings.getSnapshot().role ?? 'none';
    if (!identity) return false;

    const envelope = remoteEvent.e2eeEnvelope;
    if (!envelope) {
      await this.security.recordAudit({
        action: 'E2EE_DECRYPT_FAILED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `رفض حدث وارد #${remoteEvent.id} لعدم وجود مغلف E2EE`,
      });
      return false;
    }

    if (this.seenE2eeNonces.has(envelope.messageNonce)) {
      await this.security.recordAudit({
        action: 'REPLAY_BLOCKED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `تم رفض إعادة إرسال رسالة E2EE بالرمز المتكرر ${envelope.messageNonce.slice(0, 12)}`,
      });
      return false;
    }

    const senderPeer = this.devices
      .getLinkedDevices()
      .find(
        (d) =>
          d.publicId === envelope.senderDeviceId &&
          d.pairingState === 'PAIRED' &&
          d.verifiedByRelay &&
          d.publicKeyJwk &&
          d.ecdhPublicKeyJwk
      );

    if (
      !senderPeer ||
      !senderPeer.publicKeyJwk ||
      !senderPeer.ecdhPublicKeyJwk ||
      senderPeer.cryptoKeyId !== envelope.senderCryptoKeyId
    ) {
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `رفض رسالة من مرسل غير موثوق أو مسحوب الصلاحية (${envelope.senderDeviceId})`,
      });
      return false;
    }

    let decryptedPlaintext: string;
    try {
      decryptedPlaintext = await this.crypto.decryptFromPeer({
        envelope,
        senderEcdsaPublicKeyJwk: senderPeer.publicKeyJwk,
        senderEcdhPublicKeyJwk: senderPeer.ecdhPublicKeyJwk,
        expectedRecipientDeviceId: identity.publicId,
        expectedRecipientCryptoKeyId: identity.cryptoKeyId,
      });
    } catch (err) {
      const msg =
        err instanceof SecurityError ? err.message : 'فشل التحقق وفك التشفير E2EE';
      await this.security.recordAudit({
        action: 'E2EE_DECRYPT_FAILED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `${msg} (مرسل: ${senderPeer.publicId})`,
      });
      return false;
    }

    this.seenE2eeNonces.add(envelope.messageNonce);

    const existing = await this.repo.findRecentDuplicate(
      remoteEvent.type,
      remoteEvent.notificationKey ?? remoteEvent.idempotencyKey,
      remoteEvent.payloadHash ?? remoteEvent.idempotencyKey,
      DEDUP_WINDOW_MS * 10,
      Date.now()
    );

    if (existing) {
      if (this.transport.getState() === 'CONNECTED') {
        await this.transport
          .acknowledgeInboundDelivery(identity.publicId, [remoteEvent.id])
          .catch(() => {});
      }
      return true;
    }

    const inserted = await this.repo.insert({
      type: remoteEvent.type,
      payload: decryptedPlaintext,
      idempotencyKey: remoteEvent.idempotencyKey,
      notificationKey: remoteEvent.notificationKey,
      payloadHash: remoteEvent.payloadHash,
      sourceDeviceId: senderPeer.publicId,
      targetDeviceId: identity.publicId,
      e2eeProtected: true,
      createdAt: remoteEvent.createdAt,
    });

    const now = Date.now();
    await this.repo.updateEvent(inserted.id, {
      status: 'SYNCED',
      syncedAt: now,
      deliveredAt: now,
      e2eeProtected: true,
    });

    if (this.transport.getState() === 'CONNECTED') {
      await this.transport
        .acknowledgeInboundDelivery(identity.publicId, [remoteEvent.id])
        .catch(() => {});
    }

    await this.security.recordAudit({
      action: 'E2EE_VERIFIED',
      actorRole: role,
      deviceId: identity.publicId,
      outcome: 'ALLOWED',
      details: `تم فك تشفير حدث وارد وتوثيق مصدره E2EE من ${senderPeer.publicId}`,
    });

    this.eventsCache = await this.repo.getAll();
    this.notify();
    return true;
  }

  /**
   * Executes one full synchronization cycle in chronological FIFO order.
   * Requires an active verified paired peer, encrypts every event E2EE before dispatch,
   * and respects the configured SyncDeliveryPolicy (`PEER_CONFIRMED` vs `RELAY_QUEUED`).
   */
  async runSyncCycle(nowMs = Date.now()): Promise<SyncRunSummary> {
    if (this.isProcessing) {
      const summary: SyncRunSummary = {
        attempted: 0,
        synced: 0,
        awaitingPeerAck: 0,
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
        awaitingPeerAck: 0,
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
        awaitingPeerAck: 0,
        duplicates: 0,
        failed: 0,
        skippedReason: 'OFFLINE',
        completedAt: nowMs,
      };
      this.lastRunSummary = summary;
      this.notify();
      return summary;
    }

    const activePeer = this.resolveTargetPeer();
    if (!activePeer || !activePeer.publicKeyJwk || !activePeer.ecdhPublicKeyJwk) {
      const summary: SyncRunSummary = {
        attempted: 0,
        synced: 0,
        awaitingPeerAck: 0,
        duplicates: 0,
        failed: 0,
        skippedReason: 'UNPAIRED',
        completedAt: nowMs,
      };
      this.lastRunSummary = summary;
      this.notify();
      return summary;
    }

    this.isProcessing = true;
    this.notify();

    try {
      // Refresh delivery receipts for relay-accepted IN_PROGRESS events
      if (currentSettings.syncDeliveryPolicy === 'PEER_CONFIRMED') {
        const waitingDelivery = (await this.repo.getByStatus('IN_PROGRESS'))
          .filter((e) => e.relayAcceptedAt != null)
          .map((e) => e.id);
        if (waitingDelivery.length > 0) {
          const delivered = await this.transport
            .fetchSyncDeliveryStatus(identity.publicId, waitingDelivery)
            .catch(() => []);
          await this.handleDeliveryAcks(delivered, Date.now());
        }
      }

      const dueEvents = await this.repo.getDuePendingEvents(nowMs);
      if (dueEvents.length === 0) {
        const emptySummary: SyncRunSummary = {
          attempted: 0,
          synced: 0,
          awaitingPeerAck: 0,
          duplicates: 0,
          failed: 0,
          completedAt: Date.now(),
        };
        this.lastRunSummary = emptySummary;
        return emptySummary;
      }

      const orderedBatch = [...dueEvents].sort(
        (a, b) => a.createdAt - b.createdAt || a.id - b.id
      );

      for (const evt of orderedBatch) {
        await this.repo.updateEvent(evt.id, {
          status: 'IN_PROGRESS',
          targetDeviceId: activePeer.publicId,
        });
      }
      this.eventsCache = await this.repo.getAll();
      this.notify();

      const sessionId =
        this.transport.getServerSession()?.sessionId ??
        this.security.getSession()?.sessionId ??
        'e2ee-session';

      try {
        const outboundBatch: SyncEvent[] = [];
        for (const evt of orderedBatch) {
          const e2eeEnvelope = await this.crypto.encryptForPeer({
            plaintext: evt.payload,
            senderDeviceId: identity.publicId,
            recipientDeviceId: activePeer.publicId,
            senderCryptoKeyId: identity.cryptoKeyId,
            recipientCryptoKeyId: activePeer.cryptoKeyId,
            recipientEcdhPublicKeyJwk: activePeer.ecdhPublicKeyJwk,
            sessionId,
            idempotencyKey: evt.idempotencyKey,
          });
          outboundBatch.push({
            ...evt,
            payload: '[E2EE_CIPHERTEXT]',
            sourceDeviceId: identity.publicId,
            targetDeviceId: activePeer.publicId,
            e2eeProtected: true,
            e2eeEnvelope,
          });
        }

        const ack = await this.transport.sendSyncBatch(
          identity.publicId,
          activePeer.publicId,
          outboundBatch
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
        const deliveredSet = new Set(ack.deliveredIds ?? []);
        let synced = 0;
        let awaitingPeerAck = 0;
        let duplicates = 0;
        let failed = 0;

        for (const evt of orderedBatch) {
          const acceptedOrDuplicate =
            acceptedSet.has(evt.id) || duplicateSet.has(evt.id);
          if (!acceptedOrDuplicate) {
            failed += 1;
            await this.scheduleRetryOrFail(
              evt,
              currentSettings.maxSyncRetries,
              'لم يدرج الخادم الحدث ضمن قائمة التأكيد.'
            );
            continue;
          }

          if (
            deliveredSet.has(evt.id) ||
            currentSettings.syncDeliveryPolicy === 'RELAY_QUEUED'
          ) {
            await this.repo.updateEvent(evt.id, {
              status: 'SYNCED',
              syncedAt: ack.serverTimestamp,
              relayAcceptedAt: ack.serverTimestamp,
              deliveredAt: deliveredSet.has(evt.id) ? ack.serverTimestamp : null,
              targetDeviceId: activePeer.publicId,
              e2eeProtected: true,
              nextRetryAt: null,
              lastError: null,
            });
            if (duplicateSet.has(evt.id)) {
              duplicates += 1;
            } else {
              synced += 1;
            }
          } else {
            await this.repo.updateEvent(evt.id, {
              status: 'IN_PROGRESS',
              relayAcceptedAt: ack.serverTimestamp,
              targetDeviceId: activePeer.publicId,
              e2eeProtected: true,
              nextRetryAt: null,
              lastError: null,
            });
            if (duplicateSet.has(evt.id)) {
              duplicates += 1;
            } else {
              awaitingPeerAck += 1;
            }
          }
        }

        if (synced > 0) {
          this.lastSuccessfulSyncAt = ack.serverTimestamp;
        }

        const summary: SyncRunSummary = {
          attempted: orderedBatch.length,
          synced,
          awaitingPeerAck,
          duplicates,
          failed,
          completedAt: Date.now(),
        };
        this.lastRunSummary = summary;
        this.logger.info('SYNC', 'اكتملت دورة إرسال E2EE عبر المرحل', {
          attempted: summary.attempted,
          synced: summary.synced,
          awaitingPeerAck: summary.awaitingPeerAck,
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
          awaitingPeerAck: 0,
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
