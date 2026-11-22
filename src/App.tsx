import { useCallback, useEffect, useState } from 'react';
import type { LogRecord } from './domain/interfaces/services';
import type {
  ConnectionState,
  DeviceIdentityProfile,
  DeviceRole,
  LinkedDevice,
  PairingRequest,
} from './domain/models/device';
import type { SystemHealthSnapshot } from './domain/models/health';
import type { RelayServerSession, SecurityAuditEntry } from './domain/models/security';
import type { AppSettings } from './domain/models/settings';
import type { SyncEvent, SyncRunSummary } from './domain/models/syncEvent';
import { ActionModal } from './presentation/components/ActionModal';
import { DashboardView } from './presentation/components/DashboardView';
import { NotificationAppSelectionView } from './presentation/components/NotificationAppSelectionView';
import { NotificationHistoryView } from './presentation/components/NotificationHistoryView';
import { RoleSelectionView } from './presentation/components/RoleSelectionView';
import { TopBar } from './presentation/components/TopBar';
import { useAppContainer } from './presentation/context/ContainerContext';
import type { AppView, DashboardModalType } from './presentation/types/ui';

export function App() {
  const { container, phase } = useAppContainer();

  const [settings, setSettings] = useState<AppSettings>(() =>
    container.settingsService.getSnapshot()
  );
  const [identity, setIdentity] = useState<DeviceIdentityProfile | null>(() =>
    container.deviceManager.getIdentity()
  );
  const [linkedDevices, setLinkedDevices] = useState<LinkedDevice[]>(() =>
    container.deviceManager.getLinkedDevices()
  );
  const [activePairingRequest, setActivePairingRequest] =
    useState<PairingRequest | null>(() =>
      container.deviceManager.getActivePairingRequest()
    );
  const [pendingPairingApprovals, setPendingPairingApprovals] = useState<
    PairingRequest[]
  >(() => container.deviceManager.getPendingPairingApprovals());
  const [serverSession, setServerSession] = useState<RelayServerSession | null>(() =>
    container.deviceManager.getServerSession()
  );
  const [connectionState, setConnectionState] = useState<ConnectionState>(() =>
    container.deviceManager.getConnectionState()
  );
  const [events, setEvents] = useState<SyncEvent[]>(() =>
    container.syncEngine.getEvents()
  );
  const [isSyncRunning, setIsSyncRunning] = useState<boolean>(() =>
    container.syncEngine.isSyncRunning()
  );
  const [lastSyncSummary, setLastSyncSummary] = useState<SyncRunSummary | null>(() =>
    container.syncEngine.getLastRunSummary()
  );
  const [auditEntries, setAuditEntries] = useState<SecurityAuditEntry[]>(() =>
    container.securityManager.getAuditLog()
  );
  const [systemLogs, setSystemLogs] = useState<LogRecord[]>(() =>
    container.logger.getLogs()
  );
  const [health, setHealth] = useState<SystemHealthSnapshot>(() =>
    container.healthMonitor.getSnapshot()
  );
  const [sessionValid, setSessionValid] = useState<boolean>(() =>
    container.securityManager.isSessionAuthenticated()
  );
  const [remainingSessionSeconds, setRemainingSessionSeconds] = useState<number>(() =>
    container.securityManager.getRemainingSessionSeconds()
  );

  const [currentView, setCurrentView] = useState<AppView>('role-selection');
  const [activeModal, setActiveModal] = useState<DashboardModalType>(null);

  useEffect(() => {
    const syncStateFromServices = () => {
      const nextSettings = container.settingsService.getSnapshot();
      setSettings(nextSettings);
      setIdentity(container.deviceManager.getIdentity());
      setLinkedDevices(container.deviceManager.getLinkedDevices());
      setActivePairingRequest(container.deviceManager.getActivePairingRequest());
      setPendingPairingApprovals(container.deviceManager.getPendingPairingApprovals());
      setServerSession(container.deviceManager.getServerSession());
      setConnectionState(container.deviceManager.getConnectionState());
      setEvents(container.syncEngine.getEvents());
      setIsSyncRunning(container.syncEngine.isSyncRunning());
      setLastSyncSummary(container.syncEngine.getLastRunSummary());
      setAuditEntries(container.securityManager.getAuditLog());
      setSystemLogs(container.logger.getLogs());
      setHealth(container.healthMonitor.getSnapshot());
      setSessionValid(container.securityManager.isSessionAuthenticated());
      setRemainingSessionSeconds(
        container.securityManager.getRemainingSessionSeconds()
      );
    };

    syncStateFromServices();

    const unsubs = [
      container.settingsService.subscribe(syncStateFromServices),
      container.deviceManager.subscribe(syncStateFromServices),
      container.syncEngine.subscribe(syncStateFromServices),
      container.securityManager.subscribe(syncStateFromServices),
      container.logger.subscribe(syncStateFromServices),
      container.healthMonitor.subscribe(syncStateFromServices),
    ];

    const sessionTicker = window.setInterval(() => {
      setSessionValid(container.securityManager.isSessionAuthenticated());
      setRemainingSessionSeconds(
        container.securityManager.getRemainingSessionSeconds()
      );
    }, 1000);

    return () => {
      unsubs.forEach((unsub) => unsub());
      window.clearInterval(sessionTicker);
    };
  }, [container]);

  // Synchronize initial route once bootstrap finishes
  useEffect(() => {
    if (phase === 'RUNNING') {
      if (settings.role && currentView === 'role-selection') {
        setCurrentView('dashboard');
      } else if (!settings.role && currentView !== 'role-selection') {
        setCurrentView('role-selection');
      }
    }
  }, [phase, settings.role, currentView]);

  const role = settings.role;
  const capabilities = container.securityManager.getCapabilities(role);
  const selectedAppsSet = new Set(settings.selectedNotificationApps);
  const dataSource = container.getDataSource();

  const loadInstalledApps = useCallback(
    () => container.getDataSource().getInstalledApps(),
    [container]
  );
  const loadUsageStats = useCallback(
    () => container.getDataSource().getUsageStatsLast24h(),
    [container]
  );

  if (phase === 'STOPPED' || phase === 'STARTING') {
    return (
      <div className="min-h-screen bg-[#0D121E] text-white flex items-center justify-center p-6">
        <div className="bg-[#192131] border border-white/10 rounded-xl px-6 py-5 text-center space-y-2">
          <p className="font-display text-lg font-bold text-white">NEXLINK</p>
          <p className="text-xs text-[#A5B1C6]">
            جاري تهيئة قاعدة البيانات المحلية ومحرك المزامنة...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0D121E] text-white">
      <TopBar
        role={role}
        currentView={currentView}
        serviceRunning={settings.connectionServiceEnabled}
        connectionState={connectionState}
        onNavigate={setCurrentView}
        onOpenPrivacy={() => setActiveModal('privacy-auth')}
        onToggleService={() =>
          void container.toggleConnectionService(!settings.connectionServiceEnabled)
        }
      />

      {currentView === 'role-selection' || !role ? (
        <RoleSelectionView
          onSelectRole={async (nextRole: DeviceRole) => {
            await container.selectRole(nextRole);
            setCurrentView('dashboard');
          }}
        />
      ) : currentView === 'dashboard' ? (
        <DashboardView
          role={role}
          serviceRunning={settings.connectionServiceEnabled}
          connectionState={connectionState}
          linkedDevices={linkedDevices}
          notificationAccess={settings.notificationAccessGranted}
          usageAccess={settings.usageAccessGranted}
          sessionValid={sessionValid}
          cryptoSupported={container.crypto.isSupported()}
          health={health}
          selectedAppsCount={selectedAppsSet.size}
          isSyncRunning={isSyncRunning}
          lastSyncSummary={lastSyncSummary}
          onStartService={() => void container.toggleConnectionService(true)}
          onStopService={() => void container.toggleConnectionService(false)}
          onRunSyncNow={() => void container.runSyncNow()}
          onRenewSession={() => container.renewSession()}
          onNavigate={setCurrentView}
          onOpenModal={setActiveModal}
        />
      ) : currentView === 'notification-apps' ? (
        <NotificationAppSelectionView
          selectedApps={selectedAppsSet}
          eventCount={events.length}
          testFixtureModeEnabled={settings.testFixtureModeEnabled}
          availability={dataSource.getAvailability()}
          loadApps={loadInstalledApps}
          onToggleTestFixtureMode={(enabled) => container.setTestFixtureMode(enabled)}
          onToggleApp={(pkg, checked) => container.toggleSelectedApp(pkg, checked)}
          onBackToDashboard={() => setCurrentView('dashboard')}
          onViewHistory={() => setCurrentView('notification-history')}
        />
      ) : (
        <NotificationHistoryView
          role={role}
          capabilities={capabilities}
          sessionValid={sessionValid}
          events={events}
          selectedApps={selectedAppsSet}
          notificationAccess={settings.notificationAccessGranted}
          isSyncRunning={isSyncRunning}
          loadApps={loadInstalledApps}
          onBackToSelection={() => setCurrentView('notification-apps')}
          onOpenNotificationPermission={() => setActiveModal('notification-permission')}
          onRenewSession={() => container.renewSession()}
          onEnqueueTestNotification={(input) =>
            container.syncEngine.enqueueNotification(input)
          }
          onRunSyncNow={() => container.runSyncNow()}
          onUpdateStatus={async (eventId, status) => {
            await container.syncEngine.updateEventStatus(eventId, status);
          }}
          onManualRetry={async (eventId) => {
            await container.syncEngine.manualRetryEvent(eventId);
          }}
          onDeleteEvent={async (eventId) => {
            await container.syncEngine.deleteEvent(eventId);
          }}
        />
      )}

      {role && (
        <ActionModal
          modal={activeModal}
          identity={identity}
          role={role}
          capabilities={capabilities}
          settings={settings}
          connectionState={connectionState}
          linkedDevices={linkedDevices}
          activePairingRequest={activePairingRequest}
          pendingPairingApprovals={pendingPairingApprovals}
          sessionValid={sessionValid}
          remainingSessionSeconds={remainingSessionSeconds}
          serverSession={serverSession}
          cryptoSupported={container.crypto.isSupported()}
          health={health}
          auditEntries={auditEntries}
          systemLogs={systemLogs}
          availability={dataSource.getAvailability()}
          loadUsageStats={loadUsageStats}
          onClose={() => setActiveModal(null)}
          onToggleNotificationAccess={(granted) =>
            container.setNotificationAccess(granted)
          }
          onToggleUsageAccess={(granted) => container.setUsageAccess(granted)}
          onToggleTestFixtureMode={(enabled) => container.setTestFixtureMode(enabled)}
          onChangeRole={(nextRole) => container.changeRole(nextRole)}
          onResetRole={async () => {
            await container.resetInitialSetup();
            setActiveModal(null);
            setCurrentView('role-selection');
          }}
          onRenewSession={() => container.renewSession()}
          onExpireSession={() => container.expireSession()}
          onRevokeAuthorization={() => container.revokeAllAuthorizations()}
          onVerifyCrypto={() =>
            container.securityManager.verifyCryptoIntegrity(
              role,
              identity?.publicId ?? 'unknown'
            )
          }
          onSecureWipe={() => container.syncEngine.clearAllEvents()}
          onUpdateSettings={async (patch) => {
            await container.settingsService.update(patch);
          }}
          onConnectRelay={() => container.toggleConnectionService(true)}
          onDisconnectRelay={() => container.toggleConnectionService(false)}
          onCreatePairingRequest={() => container.deviceManager.createPairingRequest()}
          onAcceptPairingCode={(code, label) =>
            container.deviceManager.acceptPairingCode(code, role, label)
          }
          onConfirmPairingApproval={(pairingId, approve, expectedCryptoKeyId) =>
            container.deviceManager.confirmPairingApproval(
              pairingId,
              approve,
              expectedCryptoKeyId
            )
          }
          onRefreshLinkedDevices={async () => {
            await container.deviceManager.refreshLinkedDevicesFromRelay();
            await container.deviceManager.refreshPendingPairingApprovals();
          }}
          onRevokeLinkedDevice={(publicId, revokeTrust) =>
            container.deviceManager.revokeLinkedDevice(publicId, revokeTrust)
          }
          onRemoveLinkedDevice={(publicId) =>
            container.deviceManager.removeLinkedDevice(publicId)
          }
          onExportBackupJson={() => container.exportBackupJson()}
          onRestoreBackupJson={(raw) => container.restoreBackupJson(raw)}
        />
      )}
    </div>
  );
}

export default App;
