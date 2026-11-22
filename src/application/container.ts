import type { IBackupProvider } from '../domain/interfaces/repositories';
import type { IDataSource, ILifecycleParticipant } from '../domain/interfaces/services';
import type { DeviceRole } from '../domain/models/device';
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
  exportBackupJson(): Promise<string>;
  restoreBackupJson(rawJson: string): Promise<void>;
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

    async exportBackupJson(): Promise<string> {
      const current = settingsService.getSnapshot();
      const identity = ensureIdentityReady();
      await securityManager.assertAuthorized(
        current.role,
        identity.publicId,
        'exportBackups',
        'تصدير نسخة احتياطية كاملة'
      );
      const archive = await backupProvider.exportBackup();
      await securityManager.recordAudit({
        action: 'BACKUP_EXPORTED',
        actorRole: current.role ?? 'none',
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: `تم تصدير نسخة احتياطية (${archive.syncEvents.length} حدث، بصمة ${archive.checksumSha256.slice(0, 12)})`,
      });
      return JSON.stringify(archive, null, 2);
    },

    async restoreBackupJson(rawJson: string): Promise<void> {
      const current = settingsService.getSnapshot();
      const identity = ensureIdentityReady();
      await securityManager.assertAuthorized(
        current.role,
        identity.publicId,
        'exportBackups',
        'استعادة نسخة احتياطية'
      );
      const parsed = JSON.parse(rawJson);
      await backupProvider.restoreBackup(parsed);
      await settingsService.initialize();
      await securityManager.initialize();
      await deviceManager.start();
      await syncEngine.start();
      await securityManager.recordAudit({
        action: 'BACKUP_RESTORED',
        actorRole: current.role ?? 'none',
        deviceId: identity.publicId,
        outcome: 'ALLOWED',
        details: 'تم التحقق من البصمة واستعادة قاعدة البيانات بنجاح',
      });
    },
  };
}
