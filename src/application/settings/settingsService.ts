import { ValidationError } from '../../domain/errors/appError';
import type { ISettingsRepository } from '../../domain/interfaces/repositories';
import type { ILogger } from '../../domain/interfaces/services';
import { type AppSettings, DEFAULT_APP_SETTINGS } from '../../domain/models/settings';

export function validateAppSettings(candidate: AppSettings): AppSettings {
  if (
    candidate.role !== null &&
    candidate.role !== 'admin' &&
    candidate.role !== 'basic'
  ) {
    throw new ValidationError(
      'INVALID_ROLE',
      'دور الجهاز المحدد غير صالح.',
      `Invalid role value: ${String(candidate.role)}`
    );
  }

  if (
    !Number.isFinite(candidate.sessionTimeoutMinutes) ||
    candidate.sessionTimeoutMinutes < 1 ||
    candidate.sessionTimeoutMinutes > 1440
  ) {
    throw new ValidationError(
      'INVALID_SESSION_TIMEOUT',
      'يجب أن تتراوح مهلة الجلسة بين 1 و1440 دقيقة.',
      `Invalid sessionTimeoutMinutes: ${candidate.sessionTimeoutMinutes}`
    );
  }

  if (
    !Number.isFinite(candidate.syncIntervalMs) ||
    candidate.syncIntervalMs < 1000 ||
    candidate.syncIntervalMs > 300000
  ) {
    throw new ValidationError(
      'INVALID_SYNC_INTERVAL',
      'يجب أن يتراوح فاصل المزامنة بين 1 و300 ثانية.',
      `Invalid syncIntervalMs: ${candidate.syncIntervalMs}`
    );
  }

  if (
    !Number.isFinite(candidate.maxSyncRetries) ||
    candidate.maxSyncRetries < 1 ||
    candidate.maxSyncRetries > 20
  ) {
    throw new ValidationError(
      'INVALID_MAX_RETRIES',
      'يجب أن يتراوح الحد الأقصى لإعادة المحاولة بين 1 و20.',
      `Invalid maxSyncRetries: ${candidate.maxSyncRetries}`
    );
  }

  const trimmedEndpoint = candidate.relayEndpoint.trim();
  if (!trimmedEndpoint.startsWith('/') && !trimmedEndpoint.startsWith('http')) {
    throw new ValidationError(
      'INVALID_RELAY_ENDPOINT',
      'عنوان خادم المرحل غير صالح.',
      `Invalid relayEndpoint: ${candidate.relayEndpoint}`
    );
  }

  const syncDeliveryPolicy =
    candidate.syncDeliveryPolicy === 'RELAY_QUEUED' ? 'RELAY_QUEUED' : 'PEER_CONFIRMED';
  const targetDeviceId =
    typeof candidate.targetDeviceId === 'string' && candidate.targetDeviceId.trim()
      ? candidate.targetDeviceId.trim()
      : null;

  const uniqueApps = Array.from(
    new Set(
      candidate.selectedNotificationApps
        .map((pkg) => pkg.trim())
        .filter((pkg) => pkg.length > 0 && pkg !== 'com.nexlink.app')
    )
  );

  return {
    ...candidate,
    relayEndpoint: trimmedEndpoint,
    syncDeliveryPolicy,
    targetDeviceId,
    selectedNotificationApps: uniqueApps,
  };
}

export class SettingsService {
  private readonly repo: ISettingsRepository;
  private readonly logger: ILogger;
  private cached: AppSettings = { ...DEFAULT_APP_SETTINGS };
  private listeners = new Set<() => void>();

  constructor(repo: ISettingsRepository, logger: ILogger) {
    this.repo = repo;
    this.logger = logger;
  }

  async initialize(): Promise<AppSettings> {
    await this.repo.initialize();
    const loaded = await this.repo.get();
    this.cached = validateAppSettings({ ...DEFAULT_APP_SETTINGS, ...loaded });
    this.notify();
    return this.cached;
  }

  getSnapshot(): AppSettings {
    return {
      ...this.cached,
      selectedNotificationApps: [...this.cached.selectedNotificationApps],
    };
  }

  async update(patch: Partial<AppSettings>): Promise<AppSettings> {
    const merged = validateAppSettings({
      ...this.cached,
      ...patch,
    });
    await this.repo.save(merged);
    this.cached = merged;
    this.logger.info('SETTINGS', 'تم تحديث إعدادات التطبيق والتحقق من صحتها');
    this.notify();
    return this.getSnapshot();
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
