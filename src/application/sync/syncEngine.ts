import { SecurityError, SyncError } from '../../domain/errors/appError';
import type { ISyncEventRepository } from '../../domain/interfaces/repositories';
import type {
  ICryptoProvider,
  ILifecycleParticipant,
  ILogger,
  ITransportClient,
} from '../../domain/interfaces/services';
import type { DeviceIdentityProfile, LinkedDevice } from '../../domain/models/device';
import type { E2eeEnvelope } from '../../domain/models/security';
import type {
  NotificationPayload,
  SyncEvent,
  SyncEventStatus,
  SyncRunSummary,
} from '../../domain/models/syncEvent';
import type { DeviceManager } from '../devices/deviceManager';
import type { SecurityManager } from '../security/securityManager';
import type { SettingsService } from '../settings/settingsService';

interface InboundDeliveryContext {
  localEvent: SyncEvent;
  remoteEvent: SyncEvent;
  envelope: E2eeEnvelope;
  senderPeer: LinkedDevice;
  devicePublicId: string;
  deviceCryptoKeyId: string;
  decryptedPlaintext: string;
}

interface InboundConfirmResult {
  bindingValid: boolean;
  ackConfirmed: boolean;
}

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
  private unsubTransportState: (() => void) | null = null;
  private lastTransportState = 'DISCONNECTED';
  private pullInFlight: Promise<number> | null = null;

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
    this.seenE2eeNonces.clear();
    for (const evt of this.eventsCache) {
      if (evt.e2eeNonce) {
        this.seenE2eeNonces.add(evt.e2eeNonce);
      }
    }
    this.lastTransportState = this.transport.getState();

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

    if (!this.unsubTransportState) {
      this.unsubTransportState = this.transport.subscribe(() => {
        const nextState = this.transport.getState();
        const prevState = this.lastTransportState;
        this.lastTransportState = nextState;
        if (nextState === 'CONNECTED' && prevState !== 'CONNECTED') {
          const isReconnect = prevState === 'RECONNECTING' || prevState === 'ERROR';
          void this.handleTransportConnected(isReconnect);
        }
      });
    }

    this.notify();
  }

  private async handleTransportConnected(isReconnect: boolean): Promise<void> {
    await this.retryPendingInboundAcks().catch(() => 0);
    await this.pullInboundEvents().catch(() => 0);
    if (isReconnect) {
      await this.runSyncCycle().catch(() => null);
    }
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
    if (this.unsubTransportState) {
      this.unsubTransportState();
      this.unsubTransportState = null;
    }
    this.isProcessing = false;
    this.pullInFlight = null;
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
  ): Promise<number> {
    if (clientEventIds.length === 0) return 0;
    let confirmedCount = 0;
    for (const id of clientEventIds) {
      const existing = await this.repo.findById(id);
      if (
        existing &&
        existing.status === 'IN_PROGRESS' &&
        existing.relayEventId == null &&
        !existing.e2eeVerified
      ) {
        await this.repo.updateEvent(id, {
          status: 'SYNCED',
          deliveredAt: serverTimestamp,
          syncedAt: serverTimestamp,
          nextRetryAt: null,
          lastError: null,
        });
        confirmedCount += 1;
      }
    }
    if (confirmedCount > 0) {
      this.lastSuccessfulSyncAt = serverTimestamp;
      this.eventsCache = await this.repo.getAll();
      this.notify();
    }
    return confirmedCount;
  }

  private getTrustedPairedPeersMap(): Map<string, LinkedDevice> {
    return new Map(
      this.devices
        .getLinkedDevices()
        .filter(
          (d) =>
            d.pairingState === 'PAIRED' &&
            d.verifiedByRelay &&
            Boolean(d.publicKeyJwk) &&
            Boolean(d.ecdhPublicKeyJwk)
        )
        .map((d) => [d.publicId, d])
    );
  }

  private buildInboundAckProofPayload(params: {
    devicePublicId: string;
    deviceCryptoKeyId: string;
    relayEventId: number;
    sourceDeviceId: string;
    targetDeviceId: string;
    idempotencyKey: string;
    senderCryptoKeyId: string;
    e2eeNonce: string;
  }): string {
    return [
      'INBOUND_ACK_ELIGIBLE_V1',
      params.devicePublicId,
      params.deviceCryptoKeyId,
      String(params.relayEventId),
      params.sourceDeviceId,
      params.targetDeviceId,
      params.idempotencyKey,
      params.senderCryptoKeyId,
      params.e2eeNonce,
    ].join('|');
  }

  private async verifyRetryInboundAckEligibility(
    evt: SyncEvent,
    identity: DeviceIdentityProfile,
    pairedSenders: ReadonlyMap<string, LinkedDevice>
  ): Promise<
    | {
        eligible: true;
        event: SyncEvent & { relayEventId: number; sourceDeviceId: string };
      }
    | { eligible: false; shouldAuditDeny: boolean; reason: string }
  > {
    if (evt.status !== 'IN_PROGRESS' || evt.inboundAckConfirmed === true) {
      return { eligible: false, shouldAuditDeny: false, reason: 'not pending ack' };
    }

    const looksLikeInboundCandidate =
      typeof evt.relayEventId === 'number' ||
      evt.targetDeviceId === identity.publicId ||
      evt.e2eeVerified === true;

    if (
      typeof evt.relayEventId !== 'number' ||
      !Number.isInteger(evt.relayEventId) ||
      evt.relayEventId <= 0
    ) {
      return {
        eligible: false,
        shouldAuditDeny:
          looksLikeInboundCandidate && evt.sourceDeviceId !== identity.publicId,
        reason: 'missing valid relayEventId',
      };
    }

    if (
      evt.targetDeviceId !== identity.publicId ||
      typeof evt.sourceDeviceId !== 'string' ||
      evt.sourceDeviceId.length === 0 ||
      evt.sourceDeviceId === identity.publicId
    ) {
      return {
        eligible: false,
        shouldAuditDeny: evt.sourceDeviceId !== identity.publicId,
        reason: 'source/target identity mismatch',
      };
    }

    if (
      evt.e2eeProtected !== true ||
      evt.e2eeVerified !== true ||
      typeof evt.e2eeNonce !== 'string' ||
      evt.e2eeNonce.length < 16
    ) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason: 'missing local E2EE verification flags or nonce',
      };
    }

    const senderPeer = pairedSenders.get(evt.sourceDeviceId);
    if (
      !senderPeer ||
      !senderPeer.publicKeyJwk ||
      !senderPeer.ecdhPublicKeyJwk ||
      !identity.publicKeyJwk
    ) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason: `peer unpaired or revoked (${evt.sourceDeviceId})`,
      };
    }

    const storedEnvelope = evt.e2eeEnvelope;
    if (
      !storedEnvelope ||
      storedEnvelope.senderDeviceId !== senderPeer.publicId ||
      storedEnvelope.recipientDeviceId !== identity.publicId ||
      storedEnvelope.senderCryptoKeyId !== senderPeer.cryptoKeyId ||
      storedEnvelope.recipientCryptoKeyId !== identity.cryptoKeyId ||
      storedEnvelope.messageNonce !== evt.e2eeNonce
    ) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason: 'missing or mismatched E2EE envelope/nonce binding',
      };
    }

    if (typeof evt.inboundAckProof !== 'string' || evt.inboundAckProof.length === 0) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason: 'missing trusted inbound ACK attestation proof',
      };
    }

    const expectedProofPayload = this.buildInboundAckProofPayload({
      devicePublicId: identity.publicId,
      deviceCryptoKeyId: identity.cryptoKeyId,
      relayEventId: evt.relayEventId,
      sourceDeviceId: senderPeer.publicId,
      targetDeviceId: identity.publicId,
      idempotencyKey: evt.idempotencyKey,
      senderCryptoKeyId: senderPeer.cryptoKeyId,
      e2eeNonce: evt.e2eeNonce,
    });

    const proofValid = await this.crypto.verifySignatureWithJwk(
      identity.publicKeyJwk,
      identity.cryptoKeyId,
      expectedProofPayload,
      evt.inboundAckProof
    );
    if (!proofValid) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason: 'invalid inbound ACK attestation signature',
      };
    }

    try {
      const decryptedPlaintext = await this.crypto.decryptFromPeer({
        envelope: storedEnvelope,
        senderEcdsaPublicKeyJwk: senderPeer.publicKeyJwk,
        senderEcdhPublicKeyJwk: senderPeer.ecdhPublicKeyJwk,
        expectedRecipientDeviceId: identity.publicId,
        expectedRecipientCryptoKeyId: identity.cryptoKeyId,
        expectedIdempotencyKey: evt.idempotencyKey,
      });
      if (decryptedPlaintext !== evt.payload) {
        return {
          eligible: false,
          shouldAuditDeny: true,
          reason: 'persisted local payload does not match verified E2EE plaintext',
        };
      }
    } catch (err) {
      return {
        eligible: false,
        shouldAuditDeny: true,
        reason:
          err instanceof Error
            ? `envelope verification failed on retry: ${err.message}`
            : 'envelope verification failed on retry',
      };
    }

    return {
      eligible: true,
      event: evt as SyncEvent & { relayEventId: number; sourceDeviceId: string },
    };
  }

  async retryPendingInboundAcks(): Promise<number> {
    const identity = this.devices.getIdentity();
    if (!identity || this.transport.getState() !== 'CONNECTED') return 0;

    const pairedSenders = this.getTrustedPairedPeersMap();
    const inProgress = await this.repo.getByStatus('IN_PROGRESS');
    const pendingInbound: (SyncEvent & {
      relayEventId: number;
      sourceDeviceId: string;
    })[] = [];

    for (const evt of inProgress) {
      const eligibility = await this.verifyRetryInboundAckEligibility(
        evt,
        identity,
        pairedSenders
      );
      if (eligibility.eligible) {
        pendingInbound.push(eligibility.event);
        continue;
      }

      if (eligibility.shouldAuditDeny) {
        const role = this.settings.getSnapshot().role ?? 'none';
        await this.security.recordAudit({
          action: 'ACCESS_DENIED',
          actorRole: role,
          deviceId: identity.publicId,
          outcome: 'DENIED',
          details: `رفض إرسال ACK عند إعادة المحاولة للحدث #${evt.id}: ${eligibility.reason}`,
        });
      }
    }

    if (pendingInbound.length === 0) return 0;

    // Re-verify live transport state and active pairing immediately prior to dispatch
    if (this.transport.getState() !== 'CONNECTED') return 0;
    const activeSendersBeforeAck = this.getTrustedPairedPeersMap();
    const stillPaired = pendingInbound.filter((evt) => {
      const peer = activeSendersBeforeAck.get(evt.sourceDeviceId);
      return Boolean(
        peer &&
        evt.e2eeEnvelope &&
        peer.cryptoKeyId === evt.e2eeEnvelope.senderCryptoKeyId
      );
    });
    if (stillPaired.length === 0) return 0;

    const relayIds = Array.from(new Set(stillPaired.map((e) => e.relayEventId)));
    try {
      await this.transport.acknowledgeInboundDelivery(identity.publicId, relayIds);
    } catch (ackErr) {
      const reason = ackErr instanceof Error ? ackErr.message : 'ack error';
      for (const evt of stillPaired) {
        if (evt.inboundAckConfirmed !== true) {
          await this.repo.updateEvent(evt.id, {
            status: 'IN_PROGRESS',
            inboundAckConfirmed: false,
            deliveredAt: null,
            syncedAt: null,
            lastError: `تعذّر إتمام تأكيد ACK على المرحل وسيُعاد المحاولة (${reason})`,
          });
        }
      }
      this.eventsCache = await this.repo.getAll();
      this.notify();
      this.logger.warn(
        'SYNC',
        'فشل تأكيد استلام الأحداث الواردة أثناء إعادة محاولة ACK وستبقى قيد المزامنة',
        { relayIds, reason }
      );
      return 0;
    }

    const ackedAt = Date.now();
    let confirmed = 0;
    for (const evt of stillPaired) {
      const updated = await this.repo.updateEvent(evt.id, {
        status: 'SYNCED',
        inboundAckConfirmed: true,
        deliveredAt: evt.deliveredAt ?? ackedAt,
        syncedAt: evt.syncedAt ?? ackedAt,
        lastError: null,
      });
      if (updated) confirmed += 1;
    }

    if (confirmed > 0) {
      this.eventsCache = await this.repo.getAll();
      this.notify();
    }
    return confirmed;
  }

  async pullInboundEvents(): Promise<number> {
    const identity = this.devices.getIdentity();
    if (!identity || this.transport.getState() !== 'CONNECTED') return 0;

    if (this.pullInFlight) {
      return this.pullInFlight;
    }

    this.pullInFlight = (async () => {
      try {
        const inbound = await this.transport.fetchInboundEvents(identity.publicId);
        let ingested = 0;
        for (const evt of inbound) {
          const ok = await this.ingestInboundEvent(evt);
          if (ok) ingested += 1;
        }
        return ingested;
      } finally {
        this.pullInFlight = null;
      }
    })();

    return this.pullInFlight;
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

    if (
      typeof remoteEvent.id !== 'number' ||
      !Number.isInteger(remoteEvent.id) ||
      remoteEvent.id <= 0
    ) {
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: 'رفض حدث وارد لعدم وجود معرف Relay صالح',
      });
      return false;
    }

    if (
      remoteEvent.sourceDeviceId &&
      remoteEvent.sourceDeviceId !== envelope.senderDeviceId
    ) {
      await this.security.recordAudit({
        action: 'E2EE_DECRYPT_FAILED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `رفض حدث وارد #${remoteEvent.id} لعدم تطابق هوية المرسل مع المغلف`,
      });
      return false;
    }

    if (
      envelope.recipientDeviceId !== identity.publicId ||
      (remoteEvent.targetDeviceId &&
        remoteEvent.targetDeviceId !== identity.publicId) ||
      envelope.senderDeviceId === identity.publicId
    ) {
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `رفض حدث وارد #${remoteEvent.id} لعدم تطابق الجهاز المستلم أو انتحال المرسل`,
      });
      return false;
    }

    if (this.seenE2eeNonces.has(envelope.messageNonce)) {
      const existingUnacked = await this.repo.findByIdempotencyKey(
        remoteEvent.idempotencyKey
      );
      const trustedSender = this.getTrustedPairedPeersMap().get(
        envelope.senderDeviceId
      );

      if (
        existingUnacked &&
        trustedSender &&
        trustedSender.publicKeyJwk &&
        trustedSender.ecdhPublicKeyJwk &&
        trustedSender.cryptoKeyId === envelope.senderCryptoKeyId &&
        existingUnacked.e2eeNonce === envelope.messageNonce &&
        existingUnacked.relayEventId === remoteEvent.id &&
        existingUnacked.sourceDeviceId === trustedSender.publicId &&
        existingUnacked.targetDeviceId === identity.publicId &&
        existingUnacked.e2eeProtected === true &&
        existingUnacked.e2eeVerified === true &&
        (existingUnacked.inboundAckConfirmed === false ||
          existingUnacked.status !== 'SYNCED')
      ) {
        let retryPlaintext: string;
        try {
          retryPlaintext = await this.crypto.decryptFromPeer({
            envelope,
            senderEcdsaPublicKeyJwk: trustedSender.publicKeyJwk,
            senderEcdhPublicKeyJwk: trustedSender.ecdhPublicKeyJwk,
            expectedRecipientDeviceId: identity.publicId,
            expectedRecipientCryptoKeyId: identity.cryptoKeyId,
            expectedIdempotencyKey: remoteEvent.idempotencyKey,
          });
          if (retryPlaintext !== existingUnacked.payload) {
            await this.security.recordAudit({
              action: 'ACCESS_DENIED',
              actorRole: role,
              deviceId: identity.publicId,
              outcome: 'DENIED',
              details: `رفض ACK لإعادة التسليم #${remoteEvent.id}: المحتوى المحلي لا يطابق النص المفكوك من المغلف`,
            });
            return false;
          }
        } catch (err) {
          const msg =
            err instanceof SecurityError ? err.message : 'فشل التحقق وفك التشفير E2EE';
          await this.security.recordAudit({
            action: 'E2EE_DECRYPT_FAILED',
            actorRole: role,
            deviceId: identity.publicId,
            outcome: 'DENIED',
            details: `${msg} (إعادة تسليم #${remoteEvent.id})`,
          });
          return false;
        }

        const confirmOutcome = await this.confirmInboundDeliveryOrKeepInProgress({
          localEvent: existingUnacked,
          remoteEvent,
          envelope,
          senderPeer: trustedSender,
          devicePublicId: identity.publicId,
          deviceCryptoKeyId: identity.cryptoKeyId,
          decryptedPlaintext: retryPlaintext,
        });
        return confirmOutcome.bindingValid;
      }

      await this.security.recordAudit({
        action: 'REPLAY_BLOCKED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `تم رفض إعادة إرسال رسالة E2EE بالرمز المتكرر ${envelope.messageNonce.slice(0, 12)}`,
      });
      return false;
    }

    const senderPeer = this.getTrustedPairedPeersMap().get(envelope.senderDeviceId);

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
        expectedIdempotencyKey: remoteEvent.idempotencyKey,
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

    const existingByKey = await this.repo.findByIdempotencyKey(
      remoteEvent.idempotencyKey
    );
    if (existingByKey) {
      const confirmOutcome = await this.confirmInboundDeliveryOrKeepInProgress({
        localEvent: existingByKey,
        remoteEvent,
        envelope,
        senderPeer,
        devicePublicId: identity.publicId,
        deviceCryptoKeyId: identity.cryptoKeyId,
        decryptedPlaintext,
      });
      if (!confirmOutcome.bindingValid) {
        return false;
      }
      this.seenE2eeNonces.add(envelope.messageNonce);
      return true;
    }

    const recentDuplicate = await this.repo.findRecentDuplicate(
      remoteEvent.type,
      remoteEvent.notificationKey ?? remoteEvent.idempotencyKey,
      remoteEvent.payloadHash ?? remoteEvent.idempotencyKey,
      DEDUP_WINDOW_MS * 10,
      Date.now()
    );
    if (recentDuplicate) {
      await this.security.recordAudit({
        action: 'DUPLICATE_BLOCKED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `منع استخدام سجل تكرار مختلف (#${recentDuplicate.id}) لتأكيد الحدث الوارد #${remoteEvent.id}`,
      });
      return false;
    }

    const inboundAckProof = await this.crypto.signPayload(
      this.buildInboundAckProofPayload({
        devicePublicId: identity.publicId,
        deviceCryptoKeyId: identity.cryptoKeyId,
        relayEventId: remoteEvent.id,
        sourceDeviceId: senderPeer.publicId,
        targetDeviceId: identity.publicId,
        idempotencyKey: remoteEvent.idempotencyKey,
        senderCryptoKeyId: senderPeer.cryptoKeyId,
        e2eeNonce: envelope.messageNonce,
      })
    );
    if (!inboundAckProof) {
      await this.security.recordAudit({
        action: 'E2EE_DECRYPT_FAILED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `تعذّر توقيع إثبات الأهلية المحلي للحدث الوارد #${remoteEvent.id} — لن يتم إرسال ACK`,
      });
      return false;
    }

    let insertedId: number | null = null;
    let persistedEvent: SyncEvent | null = null;
    try {
      const inserted = await this.repo.insert({
        type: remoteEvent.type,
        payload: decryptedPlaintext,
        idempotencyKey: remoteEvent.idempotencyKey,
        notificationKey: remoteEvent.notificationKey,
        payloadHash: remoteEvent.payloadHash,
        sourceDeviceId: senderPeer.publicId,
        targetDeviceId: identity.publicId,
        e2eeProtected: true,
        e2eeVerified: true,
        e2eeNonce: envelope.messageNonce,
        e2eeEnvelope: envelope,
        inboundAckProof,
        relayEventId: remoteEvent.id,
        inboundAckConfirmed: false,
        createdAt: remoteEvent.createdAt,
      });
      insertedId = inserted.id;

      const updated = await this.repo.updateEvent(inserted.id, {
        status: 'IN_PROGRESS',
        syncedAt: null,
        deliveredAt: null,
        e2eeProtected: true,
        e2eeVerified: true,
        inboundAckConfirmed: false,
        lastError: null,
      });
      if (!updated) {
        throw new Error('Failed to persist inbound event prior to ACK');
      }
      persistedEvent = updated;
    } catch (storageErr) {
      if (insertedId !== null) {
        await this.repo.delete(insertedId).catch(() => false);
      }
      await this.security.recordAudit({
        action: 'E2EE_DECRYPT_FAILED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'DENIED',
        details: `تعذّر حفظ الحدث المفكوك محلياً — لن يتم إرسال ACK للخادم (${storageErr instanceof Error ? storageErr.message : 'storage error'})`,
      });
      return false;
    }

    this.seenE2eeNonces.add(envelope.messageNonce);
    this.eventsCache = await this.repo.getAll();
    this.notify();

    const confirmResult = await this.confirmInboundDeliveryOrKeepInProgress({
      localEvent: persistedEvent,
      remoteEvent,
      envelope,
      senderPeer,
      devicePublicId: identity.publicId,
      deviceCryptoKeyId: identity.cryptoKeyId,
      decryptedPlaintext,
    });
    if (!confirmResult.bindingValid) {
      return false;
    }

    await this.security.recordAudit({
      action: 'E2EE_VERIFIED',
      actorRole: role,
      deviceId: identity.publicId,
      outcome: 'ALLOWED',
      details: `تم فك تشفير حدث وارد وتوثيق مصدره E2EE من ${senderPeer.publicId}`,
    });

    return true;
  }

  private async confirmInboundDeliveryOrKeepInProgress(
    ctx: InboundDeliveryContext
  ): Promise<InboundConfirmResult> {
    const {
      localEvent,
      remoteEvent,
      envelope,
      senderPeer,
      devicePublicId,
      deviceCryptoKeyId,
      decryptedPlaintext,
    } = ctx;
    if (localEvent.payload !== decryptedPlaintext) {
      const role = this.settings.getSnapshot().role ?? 'none';
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role,
        deviceId: devicePublicId,
        outcome: 'DENIED',
        details: `رفض ACK للحدث #${localEvent.id}: المحتوى المحلي لا يطابق النص المفكوك من المغلف`,
      });
      return { bindingValid: false, ackConfirmed: false };
    }
    const pairedSenders = this.getTrustedPairedPeersMap();
    const liveTrustedSender = pairedSenders.get(senderPeer.publicId);

    let parsedAad: Record<string, unknown> | null = null;
    try {
      const candidate = JSON.parse(envelope.aad) as unknown;
      if (candidate && typeof candidate === 'object') {
        parsedAad = candidate as Record<string, unknown>;
      }
    } catch {
      parsedAad = null;
    }

    const relayEventIdValid =
      typeof remoteEvent.id === 'number' &&
      Number.isInteger(remoteEvent.id) &&
      remoteEvent.id > 0 &&
      typeof localEvent.relayEventId === 'number' &&
      Number.isInteger(localEvent.relayEventId) &&
      localEvent.relayEventId > 0 &&
      localEvent.relayEventId === remoteEvent.id;

    const sourceDeviceIdValid =
      typeof localEvent.sourceDeviceId === 'string' &&
      localEvent.sourceDeviceId.length > 0 &&
      localEvent.sourceDeviceId !== devicePublicId &&
      localEvent.sourceDeviceId === senderPeer.publicId &&
      envelope.senderDeviceId === senderPeer.publicId &&
      (!remoteEvent.sourceDeviceId ||
        remoteEvent.sourceDeviceId === senderPeer.publicId) &&
      parsedAad?.senderDeviceId === senderPeer.publicId;

    const targetDeviceIdValid =
      typeof devicePublicId === 'string' &&
      devicePublicId.length > 0 &&
      localEvent.targetDeviceId === devicePublicId &&
      envelope.recipientDeviceId === devicePublicId &&
      (!remoteEvent.targetDeviceId || remoteEvent.targetDeviceId === devicePublicId) &&
      parsedAad?.recipientDeviceId === devicePublicId;

    const idempotencyKeyValid =
      typeof remoteEvent.idempotencyKey === 'string' &&
      remoteEvent.idempotencyKey.length > 0 &&
      localEvent.idempotencyKey === remoteEvent.idempotencyKey &&
      parsedAad?.idempotencyKey === remoteEvent.idempotencyKey;

    const nonceBindingValid =
      typeof envelope.messageNonce === 'string' &&
      envelope.messageNonce.length >= 16 &&
      typeof localEvent.e2eeNonce === 'string' &&
      localEvent.e2eeNonce.length >= 16 &&
      localEvent.e2eeNonce === envelope.messageNonce &&
      parsedAad?.messageNonce === envelope.messageNonce;

    const trustedSenderAndKeyValid =
      Boolean(liveTrustedSender) &&
      liveTrustedSender?.publicId === senderPeer.publicId &&
      liveTrustedSender?.pairingState === 'PAIRED' &&
      liveTrustedSender?.verifiedByRelay === true &&
      Boolean(liveTrustedSender?.publicKeyJwk) &&
      Boolean(liveTrustedSender?.ecdhPublicKeyJwk) &&
      liveTrustedSender?.cryptoKeyId === senderPeer.cryptoKeyId &&
      liveTrustedSender?.cryptoKeyId === envelope.senderCryptoKeyId &&
      envelope.recipientCryptoKeyId === deviceCryptoKeyId &&
      parsedAad?.senderCryptoKeyId === liveTrustedSender?.cryptoKeyId &&
      parsedAad?.recipientCryptoKeyId === deviceCryptoKeyId &&
      localEvent.e2eeProtected === true &&
      localEvent.e2eeVerified === true;

    if (
      !relayEventIdValid ||
      !sourceDeviceIdValid ||
      !targetDeviceIdValid ||
      !idempotencyKeyValid ||
      !nonceBindingValid ||
      !trustedSenderAndKeyValid
    ) {
      const role = this.settings.getSnapshot().role ?? 'none';
      await this.security.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role,
        deviceId: devicePublicId,
        outcome: 'DENIED',
        details: `رفض إرسال ACK لحدث #${localEvent.id} لعدم تطابق Relay ID أو Nonce أو هوية الطرفين أو idempotencyKey أو مفتاح المرسل الموثوق`,
      });
      return { bindingValid: false, ackConfirmed: false };
    }

    const relayEventId = remoteEvent.id;

    if (this.transport.getState() !== 'CONNECTED') {
      if (
        localEvent.status !== 'IN_PROGRESS' &&
        localEvent.inboundAckConfirmed !== true
      ) {
        await this.repo.updateEvent(localEvent.id, {
          status: 'IN_PROGRESS',
          inboundAckConfirmed: false,
          deliveredAt: null,
          syncedAt: null,
          lastError: 'تم حفظ الحدث محلياً بانتظار الاتصال لإرسال تأكيد ACK إلى المرحل',
        });
        this.eventsCache = await this.repo.getAll();
        this.notify();
      }
      return { bindingValid: true, ackConfirmed: false };
    }

    try {
      await this.transport.acknowledgeInboundDelivery(devicePublicId, [relayEventId]);
      const ackTime = Date.now();
      await this.repo.updateEvent(localEvent.id, {
        status: 'SYNCED',
        inboundAckConfirmed: true,
        deliveredAt: localEvent.deliveredAt ?? ackTime,
        syncedAt: localEvent.syncedAt ?? ackTime,
        lastError: null,
      });
      this.eventsCache = await this.repo.getAll();
      this.notify();
      return { bindingValid: true, ackConfirmed: true };
    } catch (ackErr) {
      const reason = ackErr instanceof Error ? ackErr.message : 'ack error';
      if (localEvent.inboundAckConfirmed !== true) {
        await this.repo.updateEvent(localEvent.id, {
          status: 'IN_PROGRESS',
          inboundAckConfirmed: false,
          deliveredAt: null,
          syncedAt: null,
          lastError: `تم حفظ الحدث محلياً بانتظار إعادة إرسال تأكيد ACK (${reason})`,
        });
        this.eventsCache = await this.repo.getAll();
        this.notify();
      }
      this.logger.warn(
        'SYNC',
        'تم حفظ الحدث محلياً لكن تعذّر إرسال تأكيد ACK للخادم وسيبقى قيد المزامنة حتى نجاح التأكيد',
        {
          relayEventId,
          reason,
        }
      );
      return { bindingValid: true, ackConfirmed: false };
    }
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
      await this.retryPendingInboundAcks().catch(() => 0);
      const stuckInProgress = (await this.repo.getByStatus('IN_PROGRESS')).filter(
        (evt) => evt.relayEventId == null && !evt.e2eeVerified
      );
      if (stuckInProgress.length > 0) {
        for (const evt of stuckInProgress) {
          await this.repo.updateEvent(evt.id, {
            status: 'PENDING',
            targetDeviceId: null,
            relayAcceptedAt: null,
            nextRetryAt: nowMs,
            lastError:
              'تم إلغاء أو فقدان اقتران الجهاز المستهدف — بانتظار إعادة الاقتران.',
          });
        }
        this.eventsCache = await this.repo.getAll();
      }
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
      await this.retryPendingInboundAcks().catch(() => 0);

      // Revert any outbound IN_PROGRESS events targeting a peer whose link was revoked
      const pairedIds = new Set(
        this.devices
          .getLinkedDevices()
          .filter((d) => d.pairingState === 'PAIRED' && d.verifiedByRelay)
          .map((d) => d.publicId)
      );
      const currentInProgress = (await this.repo.getByStatus('IN_PROGRESS')).filter(
        (evt) => evt.relayEventId == null && !evt.e2eeVerified
      );
      for (const evt of currentInProgress) {
        if (!evt.targetDeviceId || !pairedIds.has(evt.targetDeviceId)) {
          await this.repo.updateEvent(evt.id, {
            status: 'PENDING',
            targetDeviceId: null,
            relayAcceptedAt: null,
            nextRetryAt: nowMs,
            lastError:
              'تم تغيير حالة الاقتران للطرف المستهدف — أُعيد الحدث لطابور الانتظار.',
          });
        }
      }

      // Refresh delivery receipts for relay-accepted outbound IN_PROGRESS events
      let resolvedAckCount = 0;
      if (currentSettings.syncDeliveryPolicy === 'PEER_CONFIRMED') {
        const waitingDelivery = (await this.repo.getByStatus('IN_PROGRESS'))
          .filter(
            (e) =>
              e.relayAcceptedAt != null && e.relayEventId == null && !e.e2eeVerified
          )
          .map((e) => e.id);
        if (waitingDelivery.length > 0) {
          const delivered = await this.transport
            .fetchSyncDeliveryStatus(identity.publicId, waitingDelivery)
            .catch(() => []);
          resolvedAckCount = await this.handleDeliveryAcks(delivered, Date.now());
        }
      }

      const dueEvents = (await this.repo.getDuePendingEvents(nowMs)).filter(
        (e) => e.relayEventId == null && !e.e2eeVerified
      );
      if (dueEvents.length === 0) {
        const remainingWaiting = (await this.repo.getByStatus('IN_PROGRESS')).filter(
          (e) => e.relayEventId == null && !e.e2eeVerified
        ).length;
        const emptySummary: SyncRunSummary = {
          attempted: 0,
          synced: resolvedAckCount,
          awaitingPeerAck: remainingWaiting,
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
            encrypted: true,
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
