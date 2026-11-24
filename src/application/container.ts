import { AppError, type ErrorSource } from '../domain/errors/appError';
import type { IBackupProvider } from '../domain/interfaces/repositories';
import type { IDataSource, ILifecycleParticipant } from '../domain/interfaces/services';
import type {
  BackupRestoreResult,
  DetectedBackupFormat,
} from '../domain/models/backup';
import type { DeviceIdentityProfile, DeviceRole } from '../domain/models/device';
import type { SecurityAuditEntry } from '../domain/models/security';
import type { AppSettings } from '../domain/models/settings';
import type { SyncRunSummary } from '../domain/models/syncEvent';
import {
  BrowserDeviceDataSource,
  SELF_PACKAGE_NAME,
  TestFixtureDeviceDataSource,
} from '../infrastructure/datasources/deviceDataSources';
import { WebCryptoProvider } from '../infrastructure/security/webCryptoProvider';
import { IndexedDbDatabase } from '../infrastructure/storage/indexedDbDatabase';
import {
  IndexedDbAuditRepository,
  IndexedDbBackupProvider,
  IndexedDbDeviceRepository,
  IndexedDbSettingsRepository,
  IndexedDbSyncEventRepository,
} from '../infrastructure/storage/repositories';
import { RelayTransportClient } from '../infrastructure/transport/relayTransportClient';
import { DeviceManager } from './devices/deviceManager';
import { ErrorManager } from './errors/errorManager';
import { HealthMonitor } from './health/healthMonitor';
import { LifecycleManager } from './lifecycle/lifecycleManager';
import { RotatingLogger } from './logging/loggerService';
import { SecurityManager } from './security/securityManager';
import { SettingsService } from './settings/settingsService';
import { SyncEngine } from './sync/syncEngine';

export interface AppContainer {
  readonly logger: RotatingLogger;
  readonly errorManager: ErrorManager;
  readonly crypto: WebCryptoProvider;
  readonly database: IndexedDbDatabase;
  readonly settingsService: SettingsService;
  readonly securityManager: SecurityManager;
  readonly transportClient: RelayTransportClient;
  readonly deviceManager: DeviceManager;
  readonly syncEngine: SyncEngine;
  readonly healthMonitor: HealthMonitor;
  readonly backupProvider: IBackupProvider;
  readonly lifecycleManager: LifecycleManager;
  getDataSource(): IDataSource;
  selectRole(role: DeviceRole): Promise<void>;
  changeRole(role: DeviceRole): Promise<void>;
  resetInitialSetup(): Promise<void>;
  toggleConnectionService(enabled: boolean): Promise<void>;
  runSyncNow(): Promise<SyncRunSummary>;
  renewSession(): void;
  expireSession(): void;
  revokeAllAuthorizations(): Promise<void>;
  setNotificationAccess(granted: boolean): Promise<void>;
  setUsageAccess(granted: boolean): Promise<void>;
  toggleSelectedApp(packageName: string, checked: boolean): Promise<void>;
  setTestFixtureMode(enabled: boolean): Promise<void>;
  inspectBackupJson(rawJson: string): DetectedBackupFormat;
  exportBackupJson(passphrase: string): Promise<string>;
  restoreBackupJson(rawJson: string, passphrase: string): Promise<BackupRestoreResult>;
  migrateLegacyBackupJson(
    rawJson: string,
    newPassphrase: string,
    userConfirmedLegacyImport: boolean
  ): Promise<string>;
}

export interface RestoreRecoveryDeps {
  restoreBackup: () => Promise<BackupRestoreResult>;
  stopSyncEngine: () => Promise<void>;
  startSyncEngine: () => Promise<void>;
  reloadSettings: () => Promise<AppSettings>;
  getSettingsSnapshot: () => AppSettings;
  setRelayBaseUrl: (url: string) => void;
  initializeSecurity: () => Promise<void>;
  startDeviceManager: () => Promise<void>;
  getIdentity: () => DeviceIdentityProfile | null;
  fallbackIdentity: DeviceIdentityProfile;
  issueSession: (deviceId: string, cryptoKeyId: string, timeoutMinutes: number) => void;
  clearSession: () => void;
  recordAudit: (
    entry: Omit<SecurityAuditEntry, 'id' | 'timestamp'>
  ) => Promise<SecurityAuditEntry>;
  captureError: (err: unknown, scope: ErrorSource, userMessage: string) => void;
}

function describeRestoreError(err: unknown): string {
  if (err instanceof AppError) {
    return err.userMessage || err.message || err.code;
  }
  if (err instanceof Error) {
    return err.message || err.name;
  }
  return String(err ?? 'Unknown error');
}

/**
 * Executes backup restore with strict separation between:
 * 1) Pre-commit validation/decryption + atomic IndexedDB commit.
 * 2) Post-commit in-memory service refreshes & audit logging.
 *
 * Pre-commit invariants:
 * - If stopSyncEngine() fails, restoreBackup() NEVER starts; operational
 *   startSyncEngine() recovery is attempted cleanly without swallowing errors.
 * - If restoreBackup() fails, startSyncEngine() failure is NEVER swallowed;
 *   it is captured under 'SYNC' and surfaced alongside the preserved original
 *   restore failure.
 *
 * Post-commit invariants:
 * - Once restoreBackup() commits, subsequent refresh failures NEVER masquerade
 *   as a failed/rolled-back restore and never short-circuit remaining refreshes.
 * - SyncEngine is never reported as running if startSyncEngine() fails.
 */
export async function executeRestoreWithPostCommitRecovery(
  deps: RestoreRecoveryDeps
): Promise<BackupRestoreResult> {
  try {
    await deps.stopSyncEngine();
  } catch (stopErr) {
    deps.captureError(
      stopErr,
      'SYNC',
      'تعذّر إيقاف محرك المزامنة مؤقتاً قبل الاستعادة، لذلك لم تبدأ عملية الاستعادة.'
    );

    let restartErr: unknown = null;
    try {
      await deps.startSyncEngine();
    } catch (recoverErr) {
      restartErr = recoverErr;
      deps.captureError(
        recoverErr,
        'SYNC',
        `تعذّر إيقاف محرك المزامنة قبل الاستعادة، كما فشلت محاولة استعادة تشغيله (${describeRestoreError(recoverErr)}).`
      );
    }

    if (restartErr !== null) {
      throw new AppError({
        code: 'BACKUP_RESTORE_SYNC_STOP_AND_RESTART_FAILED',
        source: 'SYNC',
        userMessage: `تعذّر إيقاف محرك المزامنة قبل بدء الاستعادة (${describeRestoreError(stopErr)})، كما تعذّرت إعادة تشغيله (${describeRestoreError(restartErr)}). لم تُنفّذ عملية الاستعادة.`,
        technicalMessage: `Restore aborted before execution because stopSyncEngine failed (${describeRestoreError(stopErr)}); operational startSyncEngine recovery also failed (${describeRestoreError(restartErr)})`,
        retryable: false,
        cause: stopErr,
        context: {
          stopError: stopErr,
          syncRestartError: restartErr,
          syncEngineRestartFailed: true,
        },
      });
    }

    if (stopErr instanceof Error) {
      throw stopErr;
    }

    throw new AppError({
      code: 'BACKUP_RESTORE_SYNC_STOP_FAILED',
      source: 'SYNC',
      userMessage: `تعذّر إيقاف محرك المزامنة مؤقتاً (${describeRestoreError(stopErr)})، لذلك لم تبدأ عملية الاستعادة.`,
      technicalMessage: `Restore aborted before execution because stopSyncEngine failed: ${describeRestoreError(stopErr)}`,
      retryable: false,
      cause: stopErr,
    });
  }

  let result: BackupRestoreResult;
  try {
    result = await deps.restoreBackup();
  } catch (preCommitErr) {
    let restartErr: unknown = null;
    try {
      await deps.startSyncEngine();
    } catch (syncRestartErr) {
      restartErr = syncRestartErr;
      deps.captureError(
        syncRestartErr,
        'SYNC',
        `فشلت استعادة النسخة الاحتياطية (${describeRestoreError(preCommitErr)})، كما تعذّر إعادة تشغيل محرك المزامنة (${describeRestoreError(syncRestartErr)}).`
      );
    }

    if (restartErr !== null) {
      if (preCommitErr instanceof AppError) {
        throw new AppError({
          code: preCommitErr.code,
          source: preCommitErr.source,
          userMessage: `${preCommitErr.userMessage} بالإضافة إلى ذلك، تعذّر إعادة تشغيل محرك المزامنة (${describeRestoreError(restartErr)}).`,
          technicalMessage: `${preCommitErr.message} | SyncEngine restart failed: ${describeRestoreError(restartErr)}`,
          retryable: preCommitErr.retryable,
          cause: preCommitErr,
          context: {
            ...(preCommitErr.context ?? {}),
            originalError: preCommitErr,
            syncRestartError: restartErr,
            syncEngineRestartFailed: true,
          },
        });
      }

      throw new AppError({
        code: 'BACKUP_RESTORE_AND_SYNC_RESTART_FAILED',
        source: 'STORAGE',
        userMessage: `فشلت استعادة النسخة الاحتياطية (${describeRestoreError(preCommitErr)})، كما تعذّر إعادة تشغيل محرك المزامنة (${describeRestoreError(restartErr)}).`,
        technicalMessage: `Restore failed (${describeRestoreError(preCommitErr)}) | SyncEngine restart failed (${describeRestoreError(restartErr)})`,
        retryable: false,
        cause: preCommitErr,
        context: {
          originalError: preCommitErr,
          syncRestartError: restartErr,
          syncEngineRestartFailed: true,
        },
      });
    }

    throw preCommitErr;
  }

  const postRestoreWarnings: string[] = [];
  let syncEngineRunning = false;
  let restoredSettings = deps.getSettingsSnapshot();

  try {
    restoredSettings = await deps.reloadSettings();
    deps.setRelayBaseUrl(restoredSettings.relayEndpoint);
  } catch (err) {
    deps.captureError(
      err,
      'STORAGE',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر إعادة تحميل الإعدادات في الذاكرة.'
    );
    postRestoreWarnings.push('تعذّر إعادة تحميل الإعدادات في الذاكرة.');
  }

  try {
    await deps.initializeSecurity();
  } catch (err) {
    deps.captureError(
      err,
      'SECURITY',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر إعادة تهيئة مدير الأمان.'
    );
    postRestoreWarnings.push('تعذّر إعادة تهيئة سجل الأمان في الذاكرة.');
  }

  try {
    await deps.startDeviceManager();
  } catch (err) {
    deps.captureError(
      err,
      'LIFECYCLE',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر تحديث الأجهزة المرتبطة في الذاكرة.'
    );
    postRestoreWarnings.push('تعذّر تحديث قائمة الأجهزة المرتبطة في الذاكرة.');
  }

  try {
    await deps.startSyncEngine();
    syncEngineRunning = true;
  } catch (err) {
    deps.captureError(
      err,
      'SYNC',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر إعادة تشغيل محرك المزامنة.'
    );
    postRestoreWarnings.push('تعذّر إعادة تشغيل محرك المزامنة (المحرك متوقف حالياً).');
  }

  const currentIdentity = deps.getIdentity() ?? deps.fallbackIdentity;
  const effectiveRole = restoredSettings.role ?? result.restoredRole;
  try {
    if (effectiveRole) {
      deps.issueSession(
        currentIdentity.publicId,
        currentIdentity.cryptoKeyId,
        restoredSettings.sessionTimeoutMinutes
      );
    } else {
      deps.clearSession();
    }
  } catch (err) {
    deps.captureError(
      err,
      'SECURITY',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر تحديث جلسة الواجهة المحلية.'
    );
    postRestoreWarnings.push('تعذّر تحديث جلسة الواجهة المحلية.');
  }

  try {
    await deps.recordAudit({
      action: 'BACKUP_RESTORED',
      actorRole: effectiveRole ?? 'none',
      deviceId: currentIdentity.publicId,
      outcome: 'ALLOWED',
      details: result.crossDeviceRestore
        ? `تمت استعادة نسخة v2 من جهاز آخر مع الحفاظ على هوية الجهاز الحالي (${result.restoredEvents} حدث، ${result.restoredLinkedDevices} جهاز بحالة غير موثوقة)`
        : `تمت استعادة نسخة v2 والتحقق من سلامتها (${result.restoredEvents} حدث، ${result.restoredLinkedDevices} جهاز)`,
    });
  } catch (err) {
    deps.captureError(
      err,
      'STORAGE',
      'تمت استعادة البيانات في قاعدة البيانات، لكن تعذّر تسجيل حدث BACKUP_RESTORED في سجل التدقيق.'
    );
    postRestoreWarnings.push('تعذّر تسجيل حدث BACKUP_RESTORED في سجل التدقيق.');
  }

  return {
    ...result,
    syncEngineRunning,
    ...(postRestoreWarnings.length > 0 ? { postRestoreWarnings } : {}),
  };
}

export function createAppContainer(): AppContainer {
  const logger = new RotatingLogger(250);
  const errorManager = new ErrorManager(logger);
  const crypto = new WebCryptoProvider();
  const database = new IndexedDbDatabase();

  const settingsRepo = new IndexedDbSettingsRepository(database);
  const deviceRepo = new IndexedDbDeviceRepository(database);
  const auditRepo = new IndexedDbAuditRepository(database);
  const syncRepo = new IndexedDbSyncEventRepository(database, crypto);

  const settingsService = new SettingsService(settingsRepo, logger);
  const securityManager = new SecurityManager(crypto, auditRepo, logger);
  const transportClient = new RelayTransportClient({
    baseUrl: '/api/relay',
    requestTimeoutMs: 8000,
    logger,
    crypto,
  });

  const deviceManager = new DeviceManager({
    deviceRepo,
    crypto,
    transport: transportClient,
    security: securityManager,
    settings: settingsService,
    logger,
  });

  const syncEngine = new SyncEngine({
    repo: syncRepo,
    transport: transportClient,
    crypto,
    security: securityManager,
    settings: settingsService,
    devices: deviceManager,
    logger,
  });

  const healthMonitor = new HealthMonitor({
    syncEngine,
    transport: transportClient,
    errorManager,
  });

  const backupProvider = new IndexedDbBackupProvider({
    db: database,
    crypto,
    syncRepo,
    deviceRepo,
    auditRepo,
    settingsRepo,
  });

  const productionSource = new BrowserDeviceDataSource();
  const fixtureSource = new TestFixtureDeviceDataSource();

  let syncTimer: ReturnType<typeof setInterval> | null = null;
  let unsubSettingsEndpoint: (() => void) | null = null;

  const bootstrapParticipant: ILifecycleParticipant = {
    name: 'StorageAndSecurityBootstrap',
    start: async () => {
      await database.initialize();
      const loaded = await settingsService.initialize();
      transportClient.setBaseUrl(loaded.relayEndpoint);
      await securityManager.initialize();
      healthMonitor.setDatabaseReady(true);
    },
    stop: async () => {
      healthMonitor.setDatabaseReady(false);
    },
  };

  const schedulerParticipant: ILifecycleParticipant = {
    name: 'SyncAndSessionCoordinator',
    start: async () => {
      const current = settingsService.getSnapshot();
      const identity = deviceManager.getIdentity();

      if (current.role && identity) {
        securityManager.issueSession(
          identity.publicId,
          identity.cryptoKeyId,
          current.sessionTimeoutMinutes
        );
      }

      if (current.role && current.connectionServiceEnabled) {
        try {
          await deviceManager.connectRelay(current.role);
          await syncEngine.pullInboundEvents();
          await syncEngine.runSyncCycle();
        } catch (err) {
          errorManager.capture(
            err,
            'TRANSPORT',
            'خادم المرحل غير متاح حالياً؛ ستبقى الأحداث في طابور الانتظار المحلي.'
          );
        }
      }

      const restartTimer = () => {
        if (syncTimer) {
          clearInterval(syncTimer);
          syncTimer = null;
        }
        const intervalMs = settingsService.getSnapshot().syncIntervalMs;
        syncTimer = setInterval(() => {
          const snap = settingsService.getSnapshot();
          if (
            snap.connectionServiceEnabled &&
            transportClient.getState() === 'CONNECTED'
          ) {
            void syncEngine.runSyncCycle();
            void syncEngine.pullInboundEvents();
          }
        }, intervalMs);
      };

      restartTimer();
      unsubSettingsEndpoint = settingsService.subscribe(() => {
        transportClient.setBaseUrl(settingsService.getSnapshot().relayEndpoint);
        restartTimer();
      });
    },
    stop: async () => {
      if (syncTimer) {
        clearInterval(syncTimer);
        syncTimer = null;
      }
      if (unsubSettingsEndpoint) {
        unsubSettingsEndpoint();
        unsubSettingsEndpoint = null;
      }
    },
  };

  const lifecycleManager = new LifecycleManager(
    [bootstrapParticipant, deviceManager, syncEngine, schedulerParticipant],
    logger,
    errorManager
  );

  const getDataSource = (): IDataSource =>
    settingsService.getSnapshot().testFixtureModeEnabled
      ? fixtureSource
      : productionSource;

  const ensureIdentityReady = () => {
    const identity = deviceManager.getIdentity();
    if (!identity) {
      throw new Error('Device identity not initialized');
    }
    return identity;
  };

  return {
    logger,
    errorManager,
    crypto,
    database,
    settingsService,
    securityManager,
    transportClient,
    deviceManager,
    syncEngine,
    healthMonitor,
    backupProvider,
    lifecycleManager,
    getDataSource,

    async selectRole(role: DeviceRole): Promise<void> {
      const identity = ensureIdentityReady();
      const updated = await settingsService.update({ role });
      securityManager.issueSession(
        identity.publicId,
        identity.cryptoKeyId,
        updated.sessionTimeoutMinutes
      );
      await securityManager.recordAudit({
        action: 'ROLE_ASSIGNED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم تعيين دور الجهاز إلى ${role === 'admin' ? 'SUPER ADMIN' : 'BASIC DEVICE'}`,
      });
    },

    async changeRole(role: DeviceRole): Promise<void> {
      const identity = ensureIdentityReady();
      const updated = await settingsService.update({ role });
      securityManager.issueSession(
        identity.publicId,
        identity.cryptoKeyId,
        updated.sessionTimeoutMinutes
      );
      await securityManager.recordAudit({
        action: 'ROLE_CHANGED',
        actorRole: role,
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم تبديل الدور إلى ${role === 'admin' ? 'SUPER ADMIN' : 'BASIC DEVICE'}`,
      });
      if (updated.connectionServiceEnabled) {
        try {
          await deviceManager.connectRelay(role);
        } catch (err) {
          errorManager.capture(
            err,
            'TRANSPORT',
            'تم تغيير الدور محلياً، ولكن تعذّر تحديث التسجيل على خادم المرحل.'
          );
        }
      }
    },

    async resetInitialSetup(): Promise<void> {
      const prevRole = settingsService.getSnapshot().role ?? 'none';
      const identity = deviceManager.getIdentity();
      await deviceManager.revokeRelaySession();
      await settingsService.update({
        role: null,
        connectionServiceEnabled: false,
      });
      securityManager.clearSession();
      await securityManager.recordAudit({
        action: 'AUTHORIZATION_REVOKED',
        actorRole: prevRole,
        deviceId: identity?.publicId ?? 'unknown',
        outcome: 'INFO',
        details: 'تمت إعادة تعيين الإعداد الأولي ومسح الجلسة النشطة',
      });
    },

    async toggleConnectionService(enabled: boolean): Promise<void> {
      const current = settingsService.getSnapshot();
      await settingsService.update({ connectionServiceEnabled: enabled });
      if (enabled && current.role) {
        try {
          await deviceManager.connectRelay(current.role);
          await syncEngine.pullInboundEvents();
          await syncEngine.runSyncCycle();
        } catch (err) {
          errorManager.capture(
            err,
            'TRANSPORT',
            'تعذّر الاتصال بخادم المرحل حالياً. سيتم الاحتفاظ بالأحداث في طابور الانتظار.'
          );
        }
      } else {
        await deviceManager.disconnectRelay();
      }
    },

    async runSyncNow(): Promise<SyncRunSummary> {
      return syncEngine.runSyncCycle();
    },

    renewSession(): void {
      const identity = deviceManager.getIdentity();
      const current = settingsService.getSnapshot();
      if (!identity) return;
      securityManager.issueSession(
        identity.publicId,
        identity.cryptoKeyId,
        current.sessionTimeoutMinutes
      );
      void securityManager.recordAudit({
        action: 'SESSION_RENEWED',
        actorRole: current.role ?? 'none',
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم تجديد الجلسة لمدة ${current.sessionTimeoutMinutes} دقيقة`,
      });
    },

    expireSession(): void {
      const identity = deviceManager.getIdentity();
      const current = settingsService.getSnapshot();
      securityManager.expireSession();
      void securityManager.recordAudit({
        action: 'SESSION_EXPIRED',
        actorRole: current.role ?? 'none',
        deviceId: identity?.publicId ?? 'unknown',
        outcome: 'INFO',
        details: 'تم إنهاء الجلسة يدوياً وإيقاف العمليات الحساسة',
      });
    },

    async revokeAllAuthorizations(): Promise<void> {
      const current = settingsService.getSnapshot();
      const identity = deviceManager.getIdentity();
      await deviceManager.revokeRelaySession();
      await settingsService.update({
        connectionServiceEnabled: false,
        notificationAccessGranted: false,
        usageAccessGranted: false,
      });
      securityManager.expireSession();
      await securityManager.recordAudit({
        action: 'AUTHORIZATION_REVOKED',
        actorRole: current.role ?? 'none',
        deviceId: identity?.publicId ?? 'unknown',
        outcome: 'ALLOWED',
        details: 'تم سحب جميع التفويضات وإيقاف خدمة الاتصال وإنهاء الجلسة',
      });
    },

    async setNotificationAccess(granted: boolean): Promise<void> {
      const current = settingsService.getSnapshot();
      const identity = deviceManager.getIdentity();
      await settingsService.update({ notificationAccessGranted: granted });
      await securityManager.recordAudit({
        action: granted ? 'PERMISSION_GRANTED' : 'PERMISSION_REVOKED',
        actorRole: current.role ?? 'none',
        deviceId: identity?.publicId ?? 'unknown',
        outcome: 'ALLOWED',
        details: granted
          ? 'تم تفعيل صلاحية الوصول للإشعارات'
          : 'تم إلغاء صلاحية الوصول للإشعارات',
      });
    },

    async setUsageAccess(granted: boolean): Promise<void> {
      const current = settingsService.getSnapshot();
      const identity = deviceManager.getIdentity();
      await settingsService.update({ usageAccessGranted: granted });
      await securityManager.recordAudit({
        action: granted ? 'PERMISSION_GRANTED' : 'PERMISSION_REVOKED',
        actorRole: current.role ?? 'none',
        deviceId: identity?.publicId ?? 'unknown',
        outcome: 'ALLOWED',
        details: granted
          ? 'تم تفعيل صلاحية نشاط التطبيقات'
          : 'تم إلغاء صلاحية نشاط التطبيقات',
      });
    },

    async toggleSelectedApp(packageName: string, checked: boolean): Promise<void> {
      const cleanPkg = packageName.trim();
      if (!cleanPkg || cleanPkg === SELF_PACKAGE_NAME) return;
      const current = settingsService.getSnapshot();
      const set = new Set(current.selectedNotificationApps);
      if (checked) {
        set.add(cleanPkg);
      } else {
        set.delete(cleanPkg);
      }
      await settingsService.update({
        selectedNotificationApps: Array.from(set),
      });
    },

    async setTestFixtureMode(enabled: boolean): Promise<void> {
      await settingsService.update({ testFixtureModeEnabled: enabled });
      logger.info(
        'DATASOURCE',
        enabled
          ? 'تم تفعيل وضع بيانات الاختبار التجريبية (Test Fixtures)'
          : 'تمت العودة إلى مصدر قدرات المتصفح الإنتاجي'
      );
    },

    inspectBackupJson(rawJson: string): DetectedBackupFormat {
      return backupProvider.inspectBackupJson(rawJson);
    },

    async exportBackupJson(passphrase: string): Promise<string> {
      const current = settingsService.getSnapshot();
      const identity = ensureIdentityReady();
      await securityManager.assertAuthorized(
        current.role,
        identity.publicId,
        'exportBackups',
        'تصدير نسخة احتياطية مشفرة'
      );
      const summary = await backupProvider.exportBackup(passphrase);
      await securityManager.recordAudit({
        action: 'BACKUP_EXPORTED',
        actorRole: current.role ?? 'none',
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم تصدير نسخة احتياطية مشفرة v2 (${summary.eventCount} حدث، ${summary.linkedDeviceCount} جهاز)`,
      });
      return JSON.stringify(summary.archive, null, 2);
    },

    async restoreBackupJson(
      rawJson: string,
      passphrase: string
    ): Promise<BackupRestoreResult> {
      const current = settingsService.getSnapshot();
      const identity = ensureIdentityReady();
      await securityManager.assertAuthorized(
        current.role,
        identity.publicId,
        'exportBackups',
        'استعادة نسخة احتياطية مشفرة'
      );

      return executeRestoreWithPostCommitRecovery({
        restoreBackup: () => backupProvider.restoreBackup(rawJson, passphrase),
        stopSyncEngine: () => syncEngine.stop(),
        startSyncEngine: () => syncEngine.start(),
        reloadSettings: () => settingsService.initialize(),
        getSettingsSnapshot: () => settingsService.getSnapshot(),
        setRelayBaseUrl: (url) => transportClient.setBaseUrl(url),
        initializeSecurity: () => securityManager.initialize(),
        startDeviceManager: () => deviceManager.start(),
        getIdentity: () => deviceManager.getIdentity(),
        fallbackIdentity: identity,
        issueSession: (deviceId, cryptoKeyId, timeoutMinutes) =>
          securityManager.issueSession(deviceId, cryptoKeyId, timeoutMinutes),
        clearSession: () => securityManager.clearSession(),
        recordAudit: (entry) => securityManager.recordAudit(entry),
        captureError: (err, scope, msg) => errorManager.capture(err, scope, msg),
      });
    },

    async migrateLegacyBackupJson(
      rawJson: string,
      newPassphrase: string,
      userConfirmedLegacyImport: boolean
    ): Promise<string> {
      const current = settingsService.getSnapshot();
      const identity = ensureIdentityReady();
      await securityManager.assertAuthorized(
        current.role,
        identity.publicId,
        'exportBackups',
        'ترحيل نسخة احتياطية قديمة إلى صيغة v2 مشفرة'
      );
      const summary = await backupProvider.migrateLegacyBackup(rawJson, newPassphrase, {
        userConfirmedLegacyImport,
      });
      await securityManager.recordAudit({
        action: 'BACKUP_EXPORTED',
        actorRole: current.role ?? 'none',
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم ترحيل نسخة قديمة v1 إلى تنسيق v2 المشفر دون تعديل قاعدة البيانات (${summary.eventCount} حدث)`,
      });
      return JSON.stringify(summary.archive, null, 2);
    },
  };
}
