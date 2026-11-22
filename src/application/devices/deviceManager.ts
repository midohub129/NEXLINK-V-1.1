import { TransportError } from '../../domain/errors/appError';
import type { IDeviceRepository } from '../../domain/interfaces/repositories';
import type {
  ICryptoProvider,
  ILifecycleParticipant,
  ILogger,
  ITransportClient,
} from '../../domain/interfaces/services';
import type {
  ConnectionState,
  DeviceIdentityProfile,
  DeviceRole,
  LinkedDevice,
  PairingRequest,
} from '../../domain/models/device';
import type { RelayServerSession } from '../../domain/models/security';
import type { SecurityManager } from '../security/securityManager';
import type { SettingsService } from '../settings/settingsService';

export class DeviceManager implements ILifecycleParticipant {
  readonly name = 'DeviceManager';

  private readonly deviceRepo: IDeviceRepository;
  private readonly crypto: ICryptoProvider;
  private readonly transport: ITransportClient;
  private readonly security: SecurityManager;
  private readonly settings: SettingsService;
  private readonly logger: ILogger;

  private identity: DeviceIdentityProfile | null = null;
  private linkedDevices: LinkedDevice[] = [];
  private activePairingRequest: PairingRequest | null = null;
  private pendingApprovals: PairingRequest[] = [];
  private listeners = new Set<() => void>();
  private unsubTransport: (() => void) | null = null;
  private unsubPairing: (() => void) | null = null;

  constructor(deps: {
    deviceRepo: IDeviceRepository;
    crypto: ICryptoProvider;
    transport: ITransportClient;
    security: SecurityManager;
    settings: SettingsService;
    logger: ILogger;
  }) {
    this.deviceRepo = deps.deviceRepo;
    this.crypto = deps.crypto;
    this.transport = deps.transport;
    this.security = deps.security;
    this.settings = deps.settings;
    this.logger = deps.logger;
  }

  private generatePublicDeviceId(): string {
    if (
      typeof globalThis.crypto !== 'undefined' &&
      typeof globalThis.crypto.randomUUID === 'function'
    ) {
      return globalThis.crypto.randomUUID();
    }
    return `dev-${this.crypto.randomHex(16)}`;
  }

  async start(): Promise<void> {
    await this.deviceRepo.initialize();

    let saved = await this.deviceRepo.getIdentity();
    const keyPair = await this.crypto.getOrCreateDeviceKeyPair();

    if (!saved) {
      saved = {
        publicId: this.generatePublicDeviceId(),
        cryptoKeyId: keyPair.cryptoKeyId,
        publicKeyJwk: keyPair.publicKeyJwk,
        ecdhPublicKeyJwk: keyPair.ecdhPublicKeyJwk,
        createdAt: Date.now(),
      };
      await this.deviceRepo.saveIdentity(saved);
    } else if (
      saved.cryptoKeyId !== keyPair.cryptoKeyId ||
      (!saved.publicKeyJwk && keyPair.publicKeyJwk) ||
      (!saved.ecdhPublicKeyJwk && keyPair.ecdhPublicKeyJwk)
    ) {
      saved = {
        ...saved,
        cryptoKeyId: keyPair.cryptoKeyId,
        publicKeyJwk: keyPair.publicKeyJwk,
        ecdhPublicKeyJwk: keyPair.ecdhPublicKeyJwk,
      };
      await this.deviceRepo.saveIdentity(saved);
    }

    this.identity = saved;
    this.linkedDevices = await this.deviceRepo.getLinkedDevices();

    if (!this.unsubTransport) {
      this.unsubTransport = this.transport.subscribe(() => {
        this.notify();
      });
    }

    if (!this.unsubPairing) {
      this.unsubPairing = this.transport.subscribePairingUpdates(() => {
        if (this.transport.getState() === 'CONNECTED') {
          void this.refreshLinkedDevicesFromRelay().catch(() => {});
          void this.refreshPendingPairingApprovals().catch(() => {});
        }
      });
    }

    this.logger.info('DEVICES', 'تمت تهيئة هوية الجهاز المنفصلة ومفاتيح ECDH/ECDSA', {
      publicId: saved.publicId,
      cryptoKeyId: saved.cryptoKeyId,
    });
    this.notify();
  }

  async stop(): Promise<void> {
    await this.disconnectRelay();
    if (this.unsubTransport) {
      this.unsubTransport();
      this.unsubTransport = null;
    }
    if (this.unsubPairing) {
      this.unsubPairing();
      this.unsubPairing = null;
    }
  }

  getIdentity(): DeviceIdentityProfile | null {
    return this.identity ? { ...this.identity } : null;
  }

  getLinkedDevices(): LinkedDevice[] {
    return [...this.linkedDevices];
  }

  getActivePairingRequest(): PairingRequest | null {
    return this.activePairingRequest ? { ...this.activePairingRequest } : null;
  }

  getPendingPairingApprovals(): PairingRequest[] {
    return [...this.pendingApprovals];
  }

  getConnectionState(): ConnectionState {
    return this.transport.getState();
  }

  getServerSession(): RelayServerSession | null {
    return this.transport.getServerSession();
  }

  async connectRelay(role: DeviceRole, label = 'متصفح NEXLINK'): Promise<void> {
    if (!this.identity) {
      throw new TransportError(
        'IDENTITY_NOT_READY',
        'هوية الجهاز غير مهيأة بعد.',
        'DeviceIdentityProfile is null during connectRelay',
        false
      );
    }

    await this.transport.connect({
      publicId: this.identity.publicId,
      cryptoKeyId: this.identity.cryptoKeyId,
      publicKeyJwk: this.identity.publicKeyJwk,
      ecdhPublicKeyJwk: this.identity.ecdhPublicKeyJwk,
      role,
      label,
    });

    await Promise.all([
      this.refreshLinkedDevicesFromRelay(),
      this.refreshPendingPairingApprovals(),
    ]);
    this.notify();
  }

  async disconnectRelay(): Promise<void> {
    await this.transport.disconnect();
    this.notify();
  }

  async revokeRelaySession(): Promise<void> {
    if (!this.identity) return;
    await this.transport.revokeServerSession(this.identity.publicId);
    this.notify();
  }

  async createPairingRequest(): Promise<PairingRequest> {
    const currentSettings = this.settings.getSnapshot();
    if (!this.identity) {
      throw new TransportError(
        'IDENTITY_NOT_READY',
        'هوية الجهاز غير مهيأة بعد.',
        'Missing device identity',
        false
      );
    }

    await this.security.assertAuthorized(
      currentSettings.role,
      this.identity.publicId,
      'manageDevices',
      'إنشاء رمز ربط جهاز جديد'
    );

    const request = await this.transport.createPairingRequest(
      this.identity.publicId,
      this.identity.cryptoKeyId
    );
    this.activePairingRequest = request;
    this.logger.info('DEVICES', 'تم إنشاء طلب اقتران مزدوج التحقق عبر خادم المرحل', {
      expiresAt: request.expiresAt,
      pairingId: request.pairingId,
    });
    this.notify();
    return request;
  }

  async acceptPairingCode(
    pairingCode: string,
    role: DeviceRole,
    label = 'جهاز NEXLINK مرتبط'
  ): Promise<PairingRequest> {
    if (!this.identity) {
      throw new TransportError(
        'IDENTITY_NOT_READY',
        'هوية الجهاز غير مهيأة بعد.',
        'Missing device identity',
        false
      );
    }

    const req = await this.transport.acceptPairingRequest(pairingCode.trim(), {
      publicId: this.identity.publicId,
      cryptoKeyId: this.identity.cryptoKeyId,
      publicKeyJwk: this.identity.publicKeyJwk,
      ecdhPublicKeyJwk: this.identity.ecdhPublicKeyJwk,
      role,
      label,
    });

    this.logger.info(
      'DEVICES',
      'تم إرسال طلب قبول الاقتران وبانتظار موافقة الجهاز الرئيسي',
      {
        pairingId: req.pairingId,
        targetDeviceId: req.requesterDeviceId,
      }
    );
    this.notify();
    return req;
  }

  async refreshPendingPairingApprovals(): Promise<PairingRequest[]> {
    if (!this.identity || this.transport.getState() !== 'CONNECTED') {
      this.pendingApprovals = [];
      return [];
    }
    if (this.settings.getSnapshot().role !== 'admin') {
      this.pendingApprovals = [];
      return [];
    }
    try {
      this.pendingApprovals = await this.transport.fetchPendingPairingApprovals(
        this.identity.publicId
      );
      this.notify();
      return this.pendingApprovals;
    } catch {
      return this.pendingApprovals;
    }
  }

  async confirmPairingApproval(
    pairingId: string,
    approve: boolean,
    expectedResponderCryptoKeyId?: string
  ): Promise<LinkedDevice | null> {
    if (!this.identity) return null;
    const role = this.settings.getSnapshot().role;

    await this.security.assertAuthorized(
      role,
      this.identity.publicId,
      'manageDevices',
      approve ? 'تأكيد وقبول اقتران جهاز' : 'رفض طلب اقتران جهاز'
    );

    const peer = await this.transport.confirmPairingRequest(
      pairingId,
      approve,
      expectedResponderCryptoKeyId
    );

    if (approve && peer) {
      await this.deviceRepo.upsertLinkedDevice(peer);
      await this.security.recordAudit({
        action: 'PAIRING_CONFIRMED',
        actorRole: role ?? 'none',
        deviceId: this.identity.publicId,
        outcome: 'ALLOWED',
        details: `تمت الموافقة المتبادلة والتحقق من بصمة ${peer.cryptoKeyId} للجهاز ${peer.publicId}`,
      });
    } else {
      await this.security.recordAudit({
        action: 'PAIRING_REJECTED',
        actorRole: role ?? 'none',
        deviceId: this.identity.publicId,
        outcome: 'DENIED',
        details: `تم رفض طلب الاقتران ${pairingId}`,
      });
    }

    await this.refreshPendingPairingApprovals();
    await this.refreshLinkedDevicesFromRelay();
    this.notify();
    return peer;
  }

  async refreshLinkedDevicesFromRelay(): Promise<LinkedDevice[]> {
    if (!this.identity) return [];
    if (this.transport.getState() !== 'CONNECTED') {
      return this.linkedDevices;
    }

    const remoteDevices = await this.transport.fetchLinkedDevices(
      this.identity.publicId
    );

    for (const remote of remoteDevices) {
      await this.deviceRepo.upsertLinkedDevice(remote);
    }
    const remoteIds = new Set(remoteDevices.map((d) => d.publicId));
    for (const local of this.linkedDevices) {
      if (!remoteIds.has(local.publicId)) {
        await this.deviceRepo.removeLinkedDevice(local.publicId);
      }
    }

    this.linkedDevices = await this.deviceRepo.getLinkedDevices();
    this.notify();
    return this.linkedDevices;
  }

  async revokeLinkedDevice(
    targetDeviceId: string,
    revokeDeviceTrust = false
  ): Promise<void> {
    if (!this.identity) return;
    const role = this.settings.getSnapshot().role;

    await this.security.assertAuthorized(
      role,
      this.identity.publicId,
      'revokeAuthorization',
      'إلغاء اقتران وسحب تفويض جهاز'
    );

    if (this.transport.getState() === 'CONNECTED') {
      await this.transport.revokeDeviceLink(
        this.identity.publicId,
        targetDeviceId,
        revokeDeviceTrust
      );
    }

    const existing = this.linkedDevices.find((d) => d.publicId === targetDeviceId);
    if (existing) {
      await this.deviceRepo.upsertLinkedDevice({
        ...existing,
        pairingState: 'REVOKED',
        verifiedByRelay: false,
      });
    }
    this.linkedDevices = await this.deviceRepo.getLinkedDevices();

    await this.security.recordAudit({
      action: 'DEVICE_REVOKED',
      actorRole: role ?? 'none',
      deviceId: this.identity.publicId,
      outcome: 'ALLOWED',
      details: revokeDeviceTrust
        ? `تم سحب تفويض الجهاز ${targetDeviceId} وإنهاء جلساته على الخادم`
        : `تم إلغاء ارتباط الجهاز ${targetDeviceId}`,
    });

    this.notify();
  }

  async removeLinkedDevice(targetDeviceId: string): Promise<void> {
    if (!this.identity) return;
    const role = this.settings.getSnapshot().role;

    await this.security.assertAuthorized(
      role,
      this.identity.publicId,
      'manageDevices',
      'إزالة جهاز من القائمة'
    );

    if (this.transport.getState() === 'CONNECTED') {
      await this.transport.revokeDeviceLink(
        this.identity.publicId,
        targetDeviceId,
        false
      );
    }

    await this.deviceRepo.removeLinkedDevice(targetDeviceId);
    this.linkedDevices = await this.deviceRepo.getLinkedDevices();
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
