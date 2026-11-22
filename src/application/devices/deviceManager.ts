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
import type { SecurityManager } from '../security/securityManager';
import type { SettingsService } from '../settings/settingsService';

function generatePublicDeviceId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `dev-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

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
  private listeners = new Set<() => void>();
  private unsubTransport: (() => void) | null = null;

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

  async start(): Promise<void> {
    await this.deviceRepo.initialize();

    let saved = await this.deviceRepo.getIdentity();
    const keyPair = await this.crypto.getOrCreateDeviceKeyPair();

    if (!saved) {
      saved = {
        publicId: generatePublicDeviceId(),
        cryptoKeyId: keyPair.cryptoKeyId,
        publicKeyJwk: keyPair.publicKeyJwk,
        createdAt: Date.now(),
      };
      await this.deviceRepo.saveIdentity(saved);
    } else if (
      saved.cryptoKeyId !== keyPair.cryptoKeyId ||
      (!saved.publicKeyJwk && keyPair.publicKeyJwk)
    ) {
      saved = {
        ...saved,
        cryptoKeyId: keyPair.cryptoKeyId,
        publicKeyJwk: keyPair.publicKeyJwk,
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

    this.logger.info('DEVICES', 'تمت تهيئة هوية الجهاز المنفصلة', {
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

  getConnectionState(): ConnectionState {
    return this.transport.getState();
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

    const challengePayload = `${this.identity.publicId}:${this.identity.cryptoKeyId}:${role}`;
    const signature = await this.crypto.signPayload(challengePayload);

    await this.transport.connect({
      publicId: this.identity.publicId,
      cryptoKeyId: this.identity.cryptoKeyId,
      publicKeyJwk: this.identity.publicKeyJwk,
      role,
      label,
      signature,
    });

    await this.refreshLinkedDevicesFromRelay();
    this.notify();
  }

  async disconnectRelay(): Promise<void> {
    await this.transport.disconnect();
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
    this.logger.info('DEVICES', 'تم إنشاء طلب اقتران عبر خادم المرحل', {
      expiresAt: request.expiresAt,
    });
    this.notify();
    return request;
  }

  async acceptPairingCode(
    pairingCode: string,
    role: DeviceRole,
    label = 'جهاز NEXLINK مرتبط'
  ): Promise<LinkedDevice> {
    if (!this.identity) {
      throw new TransportError(
        'IDENTITY_NOT_READY',
        'هوية الجهاز غير مهيأة بعد.',
        'Missing device identity',
        false
      );
    }

    const challengePayload = `${this.identity.publicId}:${this.identity.cryptoKeyId}:${pairingCode}`;
    const signature = await this.crypto.signPayload(challengePayload);

    const peer = await this.transport.acceptPairingRequest(pairingCode.trim(), {
      publicId: this.identity.publicId,
      cryptoKeyId: this.identity.cryptoKeyId,
      publicKeyJwk: this.identity.publicKeyJwk,
      role,
      label,
      signature,
    });

    await this.deviceRepo.upsertLinkedDevice(peer);
    this.linkedDevices = await this.deviceRepo.getLinkedDevices();

    await this.security.recordAudit({
      action: 'DEVICE_PAIRED',
      actorRole: role,
      deviceId: this.identity.publicId,
      outcome: 'ALLOWED',
      details: `تم الاقتران الفعلي مع الجهاز ${peer.publicId} عبر المرحل`,
    });

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

    // Sync authoritative relay state to local device repository
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

  async revokeLinkedDevice(targetDeviceId: string): Promise<void> {
    if (!this.identity) return;
    const role = this.settings.getSnapshot().role;

    await this.security.assertAuthorized(
      role,
      this.identity.publicId,
      'revokeAuthorization',
      'إلغاء اقتران وسحب تفويض جهاز'
    );

    if (this.transport.getState() === 'CONNECTED') {
      await this.transport.revokeDeviceLink(this.identity.publicId, targetDeviceId);
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
      details: `تم سحب تفويض الجهاز ${targetDeviceId}`,
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
      await this.transport.revokeDeviceLink(this.identity.publicId, targetDeviceId);
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
