import { useEffect, useState } from 'react';
import {
  Activity,
  Download,
  KeyRound,
  Link2,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { AppError } from '../../domain/errors/appError';
import type {
  DataSourceAppInfo,
  DataSourceAvailability,
  LogRecord,
} from '../../domain/interfaces/services';
import type {
  ConnectionState,
  DeviceIdentityProfile,
  DeviceRole,
  LinkedDevice,
  PairingRequest,
} from '../../domain/models/device';
import type { SystemHealthSnapshot } from '../../domain/models/health';
import type {
  RoleCapabilities,
  SecurityAuditAction,
  SecurityAuditEntry,
} from '../../domain/models/security';
import type { AppSettings } from '../../domain/models/settings';
import { formatForegroundDuration } from '../../infrastructure/datasources/deviceDataSources';
import type { DashboardModalType } from '../types/ui';

interface ActionModalProps {
  modal: DashboardModalType;
  identity: DeviceIdentityProfile | null;
  role: DeviceRole;
  capabilities: RoleCapabilities;
  settings: AppSettings;
  connectionState: ConnectionState;
  linkedDevices: LinkedDevice[];
  activePairingRequest: PairingRequest | null;
  sessionValid: boolean;
  remainingSessionSeconds: number;
  cryptoSupported: boolean;
  health: SystemHealthSnapshot;
  auditEntries: SecurityAuditEntry[];
  systemLogs: LogRecord[];
  availability: DataSourceAvailability;
  loadUsageStats: () => Promise<DataSourceAppInfo[]>;
  onClose: () => void;
  onToggleNotificationAccess: (granted: boolean) => Promise<void>;
  onToggleUsageAccess: (granted: boolean) => Promise<void>;
  onToggleTestFixtureMode: (enabled: boolean) => Promise<void>;
  onChangeRole: (role: DeviceRole) => Promise<void>;
  onResetRole: () => Promise<void>;
  onRenewSession: () => void;
  onExpireSession: () => void;
  onRevokeAuthorization: () => Promise<void>;
  onVerifyCrypto: () => Promise<{ ok: boolean; algorithm: string }>;
  onSecureWipe: () => Promise<void>;
  onUpdateSettings: (patch: Partial<AppSettings>) => Promise<void>;
  onConnectRelay: () => Promise<void>;
  onDisconnectRelay: () => Promise<void>;
  onCreatePairingRequest: () => Promise<PairingRequest>;
  onAcceptPairingCode: (code: string, label: string) => Promise<LinkedDevice>;
  onRefreshLinkedDevices: () => Promise<void>;
  onRevokeLinkedDevice: (publicId: string) => Promise<void>;
  onRemoveLinkedDevice: (publicId: string) => Promise<void>;
  onExportBackupJson: () => Promise<string>;
  onRestoreBackupJson: (raw: string) => Promise<void>;
}

type PrivacyTab = 'security' | 'settings' | 'backup' | 'logs';

function formatDurationSeconds(totalSeconds: number): string {
  const mins = Math.floor(totalSeconds / 60);
  const secs = totalSeconds % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function getAuditActionLabel(action: SecurityAuditAction): string {
  switch (action) {
    case 'ROLE_ASSIGNED':
      return 'تعيين الدور';
    case 'ROLE_CHANGED':
      return 'تبديل الدور';
    case 'AUTHORIZATION_REVOKED':
      return 'سحب التفويض';
    case 'SESSION_RENEWED':
      return 'تجديد الجلسة';
    case 'SESSION_EXPIRED':
      return 'انتهاء الجلسة';
    case 'PERMISSION_GRANTED':
      return 'منح صلاحية';
    case 'PERMISSION_REVOKED':
      return 'إلغاء صلاحية';
    case 'ACCESS_DENIED':
      return 'رفض وصول';
    case 'DUPLICATE_BLOCKED':
      return 'منع تكرار';
    case 'VAULT_VERIFIED':
      return 'فحص التشفير';
    case 'BACKUP_EXPORTED':
      return 'تصدير نسخة احتياطية';
    case 'BACKUP_RESTORED':
      return 'استعادة نسخة احتياطية';
    case 'DEVICE_PAIRED':
      return 'اقتران جهاز';
    case 'DEVICE_REVOKED':
      return 'سحب ثقة جهاز';
    case 'SECURE_WIPE':
      return 'مسح آمن';
  }
}

export function ActionModal({
  modal,
  identity,
  role,
  capabilities,
  settings,
  connectionState,
  linkedDevices,
  activePairingRequest,
  sessionValid,
  remainingSessionSeconds,
  cryptoSupported,
  health,
  auditEntries,
  systemLogs,
  availability,
  loadUsageStats,
  onClose,
  onToggleNotificationAccess,
  onToggleUsageAccess,
  onToggleTestFixtureMode,
  onChangeRole,
  onResetRole,
  onRenewSession,
  onExpireSession,
  onRevokeAuthorization,
  onVerifyCrypto,
  onSecureWipe,
  onUpdateSettings,
  onConnectRelay,
  onDisconnectRelay,
  onCreatePairingRequest,
  onAcceptPairingCode,
  onRefreshLinkedDevices,
  onRevokeLinkedDevice,
  onRemoveLinkedDevice,
  onExportBackupJson,
  onRestoreBackupJson,
}: ActionModalProps) {
  const [privacyTab, setPrivacyTab] = useState<PrivacyTab>('security');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Pairing inputs
  const [pairingCodeInput, setPairingCodeInput] = useState('');
  const [deviceLabelInput, setDeviceLabelInput] = useState('متصفح NEXLINK');
  const [pairingBusy, setPairingBusy] = useState(false);

  // Usage stats
  const [usageStats, setUsageStats] = useState<DataSourceAppInfo[]>([]);

  // Settings form state
  const [sessionTimeoutStr, setSessionTimeoutStr] = useState(
    String(settings.sessionTimeoutMinutes)
  );
  const [syncIntervalSecStr, setSyncIntervalSecStr] = useState(
    String(Math.round(settings.syncIntervalMs / 1000))
  );
  const [maxRetriesStr, setMaxRetriesStr] = useState(String(settings.maxSyncRetries));
  const [relayEndpointInput, setRelayEndpointInput] = useState(settings.relayEndpoint);

  // Backup state
  const [backupPreview, setBackupPreview] = useState('');

  useEffect(() => {
    setSessionTimeoutStr(String(settings.sessionTimeoutMinutes));
    setSyncIntervalSecStr(String(Math.round(settings.syncIntervalMs / 1000)));
    setMaxRetriesStr(String(settings.maxSyncRetries));
    setRelayEndpointInput(settings.relayEndpoint);
  }, [settings]);

  useEffect(() => {
    if (modal !== 'app-usage') return;
    let cancelled = false;
    void loadUsageStats().then((rows) => {
      if (!cancelled) setUsageStats(rows);
    });
    return () => {
      cancelled = true;
    };
  }, [modal, loadUsageStats, settings.testFixtureModeEnabled]);

  useEffect(() => {
    setStatusMessage(null);
    setErrorMessage(null);
  }, [modal, privacyTab]);

  if (!modal) return null;

  const runAction = async (work: () => Promise<void>) => {
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      await work();
    } catch (err) {
      if (err instanceof AppError) {
        setErrorMessage(err.userMessage);
      } else if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('تعذّر إكمال العملية المطلوبة.');
      }
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      onClick={onClose}
    >
      <div
        className="bg-[#192131] border border-white/10 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-4 mb-5">
          <h2 className="text-lg font-bold text-white">
            {modal === 'notification-permission' && 'إعداد صلاحية الإشعارات'}
            {modal === 'usage-permission' && 'إعداد صلاحية نشاط التطبيقات'}
            {modal === 'app-usage' && 'نشاط التطبيقات'}
            {modal === 'privacy-auth' &&
              'مركز الأمان والإعدادات والصحة والنسخ الاحتياطي'}
            {modal === 'pair-device' && 'ربط الأجهزة عبر خادم المرحل'}
            {modal === 'screen-share' && 'مشاركة الشاشة'}
            {modal === 'files-media' && 'الملفات والوسائط'}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="إغلاق"
            className="min-w-[40px] min-h-[40px] flex items-center justify-center rounded-lg bg-[#0D121E] text-[#A5B1C6] hover:text-white cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="mb-4 bg-red-950/50 border border-red-500/30 rounded-lg px-4 py-3 text-xs text-red-200"
          >
            {errorMessage}
          </div>
        )}
        {statusMessage && (
          <div
            role="status"
            className="mb-4 bg-[#0D121E] border border-[#4B91FF]/40 rounded-lg px-4 py-3 text-xs text-[#4B91FF]"
          >
            {statusMessage}
          </div>
        )}

        {modal === 'notification-permission' && (
          <div className="space-y-4">
            <p className="text-sm text-[#A5B1C6] leading-relaxed">
              تتحكم هذه الصلاحية في السماح لمحرك المزامنة (
              <span className="font-mono text-white">SyncEngine</span>) بقبول أحداث
              الإشعارات وتشفيرها محلياً عبر{' '}
              <span className="font-mono text-white">AES-256-GCM</span>.
            </p>
            <div className="bg-[#0D121E] rounded-lg p-4 flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">
                  حالة صلاحية الإشعارات
                </p>
                <p className="text-xs text-[#A5B1C6] mt-0.5">
                  {settings.notificationAccessGranted
                    ? 'مسموح بالوصول'
                    : 'غير مسموح حالياً'}
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  void runAction(() =>
                    onToggleNotificationAccess(!settings.notificationAccessGranted)
                  )
                }
                className={`min-h-[44px] px-4 py-2 text-sm font-bold rounded-lg whitespace-nowrap cursor-pointer ${
                  settings.notificationAccessGranted
                    ? 'bg-[#243047] text-white hover:bg-[#2c3a56]'
                    : 'bg-[#4B91FF] text-white hover:bg-[#3a7ee8]'
                }`}
              >
                {settings.notificationAccessGranted ? 'إلغاء الصلاحية' : 'منح الصلاحية'}
              </button>
            </div>
          </div>
        )}

        {modal === 'usage-permission' && (
          <div className="space-y-4">
            <p className="text-sm text-[#A5B1C6] leading-relaxed">
              تتحكم هذه الصلاحية في السماح بعرض إحصائيات نشاط التطبيقات عند توفر مصدر
              بيانات نظام التشغيل أو في وضع الاختبار.
            </p>
            <div className="bg-[#0D121E] rounded-lg p-4 flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">
                  حالة صلاحية نشاط التطبيقات
                </p>
                <p className="text-xs text-[#A5B1C6] mt-0.5">
                  {settings.usageAccessGranted ? 'مسموح بالوصول' : 'غير مسموح حالياً'}
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  void runAction(() =>
                    onToggleUsageAccess(!settings.usageAccessGranted)
                  )
                }
                className={`min-h-[44px] px-4 py-2 text-sm font-bold rounded-lg whitespace-nowrap cursor-pointer ${
                  settings.usageAccessGranted
                    ? 'bg-[#243047] text-white hover:bg-[#2c3a56]'
                    : 'bg-[#4B91FF] text-white hover:bg-[#3a7ee8]'
                }`}
              >
                {settings.usageAccessGranted ? 'إلغاء الصلاحية' : 'منح الصلاحية'}
              </button>
            </div>
          </div>
        )}

        {modal === 'app-usage' && (
          <div className="space-y-4">
            {!settings.usageAccessGranted ? (
              <div className="bg-[#0D121E] rounded-lg p-5 space-y-4">
                <p className="text-sm text-[#FFBE50] font-medium">
                  صلاحية نشاط التطبيقات غير مفعّلة حالياً.
                </p>
                <button
                  type="button"
                  onClick={() => void runAction(() => onToggleUsageAccess(true))}
                  className="min-h-[44px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-sm font-bold rounded-lg cursor-pointer"
                >
                  تفعيل الصلاحية الآن
                </button>
              </div>
            ) : !availability.usageStatsAvailable ? (
              <div className="bg-[#0D121E] rounded-lg p-5 space-y-4">
                <p className="text-sm font-semibold text-white">
                  إحصائيات استخدام التطبيقات غير متاحة في المتصفح
                </p>
                <p className="text-xs text-[#A5B1C6] leading-relaxed">
                  {availability.reason}
                </p>
                <button
                  type="button"
                  onClick={() => void runAction(() => onToggleTestFixtureMode(true))}
                  className="min-h-[44px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg cursor-pointer"
                >
                  معاينة عبر وضع بيانات الاختبار التجريبية (Test Fixtures)
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#A5B1C6]">
                  <span>وضع بيانات الاختبار التجريبية ({usageStats.length} تطبيق)</span>
                  <button
                    type="button"
                    onClick={() => void runAction(() => onToggleTestFixtureMode(false))}
                    className="text-[#4B91FF] hover:underline cursor-pointer"
                  >
                    العودة لوضع الإنتاج
                  </button>
                </div>
                <div className="divide-y divide-white/10 bg-[#0D121E] rounded-lg px-4">
                  {usageStats.map((app) => (
                    <div
                      key={app.packageName}
                      className="py-3 flex items-center justify-between gap-4"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-white truncate">
                          {app.appName}
                        </p>
                        <p className="font-mono text-xs text-[#A5B1C6] truncate">
                          {app.packageName}
                        </p>
                      </div>
                      <span className="text-sm font-semibold text-[#4B91FF] tabular-nums shrink-0">
                        {formatForegroundDuration(app.foregroundTimeMs)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {modal === 'pair-device' && (
          <div className="space-y-5">
            {/* Relay connection status & control */}
            <div className="bg-[#0D121E] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs text-[#A5B1C6]">حالة قناة المرحل</p>
                <p className="text-sm font-bold text-white mt-0.5">
                  {connectionState === 'CONNECTED'
                    ? 'متصل بخادم المرحل (HTTP + WebSocket)'
                    : connectionState === 'CONNECTING'
                      ? 'جاري الاتصال...'
                      : connectionState === 'RECONNECTING'
                        ? 'جاري إعادة الاتصال...'
                        : 'غير متصل بالمرحل'}
                </p>
              </div>
              <div className="flex gap-2">
                {connectionState === 'CONNECTED' ? (
                  <button
                    type="button"
                    onClick={() => void runAction(onDisconnectRelay)}
                    className="min-h-[40px] px-3.5 py-2 bg-[#243047] hover:bg-[#2c3a56] text-white text-xs font-semibold rounded-lg cursor-pointer"
                  >
                    قطع الاتصال
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => void runAction(onConnectRelay)}
                    className="min-h-[40px] px-3.5 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg cursor-pointer"
                  >
                    اتصال بالمرحل الآن
                  </button>
                )}
              </div>
            </div>

            {/* Generate Pairing Code (Admin only) */}
            <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-bold text-white">
                    إنشاء رمز اقتران من هذا الجهاز
                  </p>
                  <p className="text-xs text-[#A5B1C6] mt-0.5">
                    يتطلب دور Super Admin واتصالاً فعلياً بخادم المرحل
                  </p>
                </div>
                <button
                  type="button"
                  disabled={pairingBusy || !capabilities.manageDevices}
                  onClick={() =>
                    void runAction(async () => {
                      setPairingBusy(true);
                      try {
                        if (connectionState !== 'CONNECTED') {
                          await onConnectRelay();
                        }
                        const req = await onCreatePairingRequest();
                        setStatusMessage(
                          `تم إصدار رمز الاقتران من الخادم: ${req.pairingCode}`
                        );
                      } finally {
                        setPairingBusy(false);
                      }
                    })
                  }
                  className="min-h-[40px] px-3.5 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold rounded-lg inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  إصدار رمز اقتران
                </button>
              </div>

              {activePairingRequest && (
                <div className="p-3 bg-[#192131] rounded-lg border border-[#4B91FF]/40 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs text-[#A5B1C6]">رمز الاقتران المؤقت</p>
                    <p className="font-mono text-2xl font-bold tracking-widest text-white tabular-nums mt-0.5">
                      {activePairingRequest.pairingCode}
                    </p>
                  </div>
                  <span className="text-xs text-[#A5B1C6] tabular-nums">
                    ينتهي في{' '}
                    {new Intl.DateTimeFormat('ar', {
                      timeStyle: 'short',
                    }).format(new Date(activePairingRequest.expiresAt))}
                  </span>
                </div>
              )}
            </div>

            {/* Enter Pairing Code */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void runAction(async () => {
                  if (!pairingCodeInput.trim()) {
                    throw new Error('أدخل رمز الاقتران المكون من 6 أرقام.');
                  }
                  setPairingBusy(true);
                  try {
                    if (connectionState !== 'CONNECTED') {
                      await onConnectRelay();
                    }
                    const peer = await onAcceptPairingCode(
                      pairingCodeInput.trim(),
                      deviceLabelInput.trim() || 'متصفح NEXLINK'
                    );
                    setPairingCodeInput('');
                    setStatusMessage(
                      `تم تأكيد الاقتران الفعلي مع ${peer.label} (${peer.publicId.slice(0, 8)}...)`
                    );
                  } finally {
                    setPairingBusy(false);
                  }
                });
              }}
              className="bg-[#0D121E] rounded-lg p-4 space-y-3"
            >
              <p className="text-sm font-bold text-white">قبول اقتران عبر الرمز</p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <input
                  type="text"
                  value={pairingCodeInput}
                  onChange={(e) => setPairingCodeInput(e.target.value)}
                  placeholder="رمز من 6 أرقام"
                  aria-label="رمز الاقتران"
                  className="min-h-[44px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-sm font-mono text-white placeholder:font-sans placeholder:text-[#A5B1C6]/60"
                />
                <input
                  type="text"
                  value={deviceLabelInput}
                  onChange={(e) => setDeviceLabelInput(e.target.value)}
                  placeholder="اسم هذا الجهاز"
                  aria-label="اسم هذا الجهاز"
                  className="min-h-[44px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-sm text-white placeholder:text-[#A5B1C6]/60"
                />
                <button
                  type="submit"
                  disabled={pairingBusy}
                  className="min-h-[44px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] disabled:opacity-50 text-white text-xs font-bold rounded-lg inline-flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <Link2 className="w-4 h-4" />
                  تأكيد الاقتران
                </button>
              </div>
            </form>

            {/* Linked Devices List */}
            <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-bold text-white">
                  الأجهزة المرتبطة ({linkedDevices.length})
                </p>
                <button
                  type="button"
                  onClick={() => void runAction(onRefreshLinkedDevices)}
                  className="text-xs text-[#4B91FF] hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  تحديث من المرحل
                </button>
              </div>

              {linkedDevices.length === 0 ? (
                <p className="text-xs text-[#A5B1C6]">لا توجد أجهزة مقترنة بعد.</p>
              ) : (
                <div className="divide-y divide-white/10">
                  {linkedDevices.map((dev) => (
                    <div
                      key={dev.publicId}
                      className="py-3 flex flex-wrap items-center justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-white">
                          {dev.label} ·{' '}
                          <span className="font-mono text-xs text-[#4B91FF]">
                            {dev.role}
                          </span>
                        </p>
                        <p className="font-mono text-[11px] text-[#A5B1C6] truncate">
                          ID: {dev.publicId} | Key: {dev.cryptoKeyId}
                        </p>
                        <p
                          className={`text-xs mt-0.5 font-semibold ${
                            dev.pairingState === 'PAIRED' && dev.verifiedByRelay
                              ? 'text-emerald-400'
                              : 'text-red-400'
                          }`}
                        >
                          {dev.pairingState === 'PAIRED' && dev.verifiedByRelay
                            ? 'مقترن ومؤكد من المرحل'
                            : 'تم سحب التفويض'}
                        </p>
                      </div>

                      <div className="flex gap-2">
                        {dev.pairingState === 'PAIRED' && (
                          <button
                            type="button"
                            onClick={() =>
                              void runAction(() => onRevokeLinkedDevice(dev.publicId))
                            }
                            className="min-h-[36px] px-3 py-1.5 bg-[#243047] hover:bg-red-900/50 text-red-300 text-xs font-semibold rounded-lg cursor-pointer"
                          >
                            سحب الثقة
                          </button>
                        )}
                        {capabilities.manageDevices && (
                          <button
                            type="button"
                            onClick={() =>
                              void runAction(() => onRemoveLinkedDevice(dev.publicId))
                            }
                            aria-label="إزالة الجهاز"
                            className="min-h-[36px] px-3 py-1.5 bg-[#243047] hover:bg-[#2c3a56] text-[#A5B1C6] hover:text-white text-xs font-semibold rounded-lg cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {modal === 'privacy-auth' && (
          <div className="space-y-5">
            <div
              role="tablist"
              className="flex flex-wrap gap-1.5 p-1 bg-[#0D121E] rounded-lg"
            >
              {(
                [
                  ['security', 'الهوية والأمان'],
                  ['settings', 'الإعدادات والصحة'],
                  ['backup', 'النسخ الاحتياطي'],
                  ['logs', 'السجلات'],
                ] as [PrivacyTab, string][]
              ).map(([tabId, label]) => (
                <button
                  key={tabId}
                  type="button"
                  role="tab"
                  aria-selected={privacyTab === tabId}
                  onClick={() => setPrivacyTab(tabId)}
                  className={`flex-1 min-h-[38px] px-3 py-1.5 text-xs font-bold rounded-md whitespace-nowrap cursor-pointer ${
                    privacyTab === tabId
                      ? 'bg-[#4B91FF] text-white'
                      : 'text-[#A5B1C6] hover:text-white'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {privacyTab === 'security' && (
              <div className="space-y-4">
                <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
                  <div>
                    <p className="text-xs text-[#A5B1C6]">
                      المعرّف العام للجهاز (Public Device ID)
                    </p>
                    <p className="font-mono text-xs text-white break-all mt-1">
                      {identity?.publicId ?? 'غير مهيأ'}
                    </p>
                  </div>
                  <div className="pt-2 border-t border-white/10">
                    <p className="text-xs text-[#A5B1C6]">
                      بصمة الهوية التشفيرية المنفصلة (ECDSA P-256 Fingerprint)
                    </p>
                    <p className="font-mono text-xs text-[#4B91FF] break-all mt-1">
                      {identity?.cryptoKeyId ?? 'غير متاحة'}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-white/10 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs text-[#A5B1C6]">
                        صلاحية الجلسة (AuthN — في الذاكرة فقط)
                      </p>
                      <p
                        className={`text-sm font-bold tabular-nums mt-0.5 ${
                          sessionValid ? 'text-emerald-400' : 'text-[#FFBE50]'
                        }`}
                      >
                        {sessionValid
                          ? `نشطة · متبقي ${formatDurationSeconds(remainingSessionSeconds)}`
                          : 'منتهية الصلاحية — العمليات الحساسة متوقفة'}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={onRenewSession}
                        className="min-h-[40px] px-3.5 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg cursor-pointer"
                      >
                        تجديد الجلسة
                      </button>
                      {sessionValid && (
                        <button
                          type="button"
                          onClick={onExpireSession}
                          className="min-h-[40px] px-3.5 py-2 bg-[#243047] hover:bg-[#2c3a56] text-white text-xs font-semibold rounded-lg cursor-pointer"
                        >
                          إنهاء الجلسة
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[#4B91FF]" />
                    <p className="text-sm font-bold text-white">
                      حماية المفاتيح والتشفير (IndexedDB KeyStore)
                    </p>
                  </div>
                  <p className="text-xs text-[#A5B1C6] leading-relaxed">
                    {cryptoSupported
                      ? 'يتم حفظ مفتاح AES-256-GCM ومفتاح التوقيع ECDSA P-256 كعناصر غير قابلة للاستخراج داخل nexlink_keystore المنفصل دون أي تخزين للأسرار في localStorage.'
                      : 'واجهة Web Crypto غير مدعومة في هذا السياق.'}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        void runAction(async () => {
                          const res = await onVerifyCrypto();
                          setStatusMessage(
                            res.ok
                              ? `نجاح الفحص: ${res.algorithm}`
                              : `فشل الفحص: ${res.algorithm}`
                          );
                        })
                      }
                      className="min-h-[40px] px-3.5 py-2 bg-[#243047] hover:bg-[#2c3a56] text-white text-xs font-semibold rounded-lg cursor-pointer"
                    >
                      فحص سلامة التشفير والتوقيع
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        void runAction(async () => {
                          await onSecureWipe();
                          setStatusMessage('تم مسح جميع أحداث المزامنة المشفّرة بأمان.');
                        })
                      }
                      className="min-h-[40px] px-3.5 py-2 bg-[#243047] hover:bg-red-900/50 text-red-300 text-xs font-semibold rounded-lg cursor-pointer"
                    >
                      مسح أحداث المزامنة
                    </button>
                  </div>
                </div>

                <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs text-[#A5B1C6]">
                        الدور وتفويض الصلاحيات (AuthZ)
                      </p>
                      <p className="text-sm font-bold text-white mt-0.5">
                        {role === 'admin'
                          ? 'الجهاز الرئيسي • SUPER ADMIN'
                          : 'الجهاز التابع • BASIC DEVICE'}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          void runAction(() =>
                            onChangeRole(role === 'admin' ? 'basic' : 'admin')
                          )
                        }
                        className="min-h-[40px] px-3.5 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg cursor-pointer"
                      >
                        {role === 'admin'
                          ? 'التبديل إلى Basic'
                          : 'التبديل إلى Super Admin'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void runAction(onResetRole)}
                        className="min-h-[40px] px-3.5 py-2 bg-[#243047] hover:bg-[#2c3a56] text-white text-xs font-bold rounded-lg cursor-pointer"
                      >
                        إعادة الإعداد الأولي
                      </button>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-white/10">
                    <button
                      type="button"
                      onClick={() => void runAction(onRevokeAuthorization)}
                      className="w-full min-h-[44px] px-4 py-2 bg-red-900/40 hover:bg-red-900/60 border border-red-500/30 text-red-200 text-xs font-bold rounded-lg cursor-pointer"
                    >
                      سحب جميع التفويضات وإيقاف خدمة الاتصال فوراً
                    </button>
                  </div>
                </div>
              </div>
            )}

            {privacyTab === 'settings' && (
              <div className="space-y-4">
                <div className="bg-[#0D121E] rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#4B91FF]" />
                    <p className="text-sm font-bold text-white">
                      مراقبة صحة الأنظمة (HealthMonitor)
                    </p>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs tabular-nums">
                    <div className="bg-[#192131] rounded-lg p-3">
                      <p className="text-[#A5B1C6]">قاعدة البيانات</p>
                      <p className="text-white font-bold mt-1">
                        {health.databaseStatus}
                      </p>
                    </div>
                    <div className="bg-[#192131] rounded-lg p-3">
                      <p className="text-[#A5B1C6]">طبقة الاتصال</p>
                      <p className="text-white font-bold mt-1">
                        {health.transportStatus}
                      </p>
                    </div>
                    <div className="bg-[#192131] rounded-lg p-3">
                      <p className="text-[#A5B1C6]">محرك المزامنة</p>
                      <p className="text-white font-bold mt-1">{health.syncStatus}</p>
                    </div>
                  </div>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runAction(async () => {
                      await onUpdateSettings({
                        sessionTimeoutMinutes: Number(sessionTimeoutStr),
                        syncIntervalMs: Number(syncIntervalSecStr) * 1000,
                        maxSyncRetries: Number(maxRetriesStr),
                        relayEndpoint: relayEndpointInput,
                      });
                      setStatusMessage(
                        'تم التحقق من القيم وحفظ الإعدادات في قاعدة البيانات.'
                      );
                    });
                  }}
                  className="bg-[#0D121E] rounded-lg p-4 space-y-3"
                >
                  <p className="text-sm font-bold text-white">
                    إعدادات النظام المتحقق منها
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <label className="space-y-1">
                      <span className="text-[#A5B1C6] block">
                        مهلة الجلسة (بالدقائق 1 - 1440)
                      </span>
                      <input
                        type="number"
                        value={sessionTimeoutStr}
                        onChange={(e) => setSessionTimeoutStr(e.target.value)}
                        className="w-full min-h-[40px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-white tabular-nums"
                      />
                    </label>
                    <label className="space-y-1">
                      <span className="text-[#A5B1C6] block">
                        فاصل المزامنة (بالثواني 1 - 300)
                      </span>
                      <input
                        type="number"
                        value={syncIntervalSecStr}
                        onChange={(e) => setSyncIntervalSecStr(e.target.value)}
                        className="w-full min-h-[40px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-white tabular-nums"
                      />
                    </label>
                    <label className="space-y-1">
                      <span className="text-[#A5B1C6] block">
                        الحد الأقصى لإعادة المحاولة (1 - 20)
                      </span>
                      <input
                        type="number"
                        value={maxRetriesStr}
                        onChange={(e) => setMaxRetriesStr(e.target.value)}
                        className="w-full min-h-[40px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-white tabular-nums"
                      />
                    </label>
                    <label className="space-y-1">
                      <span className="text-[#A5B1C6] block">
                        مسار خادم المرحل (Relay Endpoint)
                      </span>
                      <input
                        type="text"
                        value={relayEndpointInput}
                        onChange={(e) => setRelayEndpointInput(e.target.value)}
                        className="w-full min-h-[40px] px-3 py-2 bg-[#192131] border border-white/10 rounded-lg text-white font-mono"
                      />
                    </label>
                  </div>
                  <button
                    type="submit"
                    className="min-h-[40px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg cursor-pointer"
                  >
                    حفظ الإعدادات
                  </button>
                </form>
              </div>
            )}

            {privacyTab === 'backup' && (
              <div className="bg-[#0D121E] rounded-lg p-4 space-y-4">
                <p className="text-xs text-[#A5B1C6] leading-relaxed">
                  يتم تصدير النسخة الاحتياطية مع بصمة سلامة SHA-256، ويتم التحقق من
                  التطابق قبل تنفيذ الاستعادة داخل معاملة ذرية في IndexedDB.
                </p>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={!capabilities.exportBackups}
                    onClick={() =>
                      void runAction(async () => {
                        const raw = await onExportBackupJson();
                        setBackupPreview(raw);
                        setStatusMessage('تم إنشاء نسخة احتياطية موقّعة ببصمة SHA-256.');
                      })
                    }
                    className="min-h-[40px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] disabled:opacity-50 text-white text-xs font-bold rounded-lg inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-4 h-4" />
                    تصدير نسخة احتياطية
                  </button>

                  <button
                    type="button"
                    disabled={!capabilities.exportBackups || !backupPreview.trim()}
                    onClick={() =>
                      void runAction(async () => {
                        await onRestoreBackupJson(backupPreview);
                        setStatusMessage(
                          'تمت استعادة البيانات والتحقق من البصمة بنجاح.'
                        );
                      })
                    }
                    className="min-h-[40px] px-4 py-2 bg-[#243047] hover:bg-[#2c3a56] disabled:opacity-50 text-white text-xs font-bold rounded-lg inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Upload className="w-4 h-4" />
                    استعادة من النص أدناه
                  </button>
                </div>

                <textarea
                  rows={8}
                  value={backupPreview}
                  onChange={(e) => setBackupPreview(e.target.value)}
                  placeholder="سيظهر هنا محتوى النسخة الاحتياطية بصيغة JSON، أو الصق نسخة سابقة للاستعادة..."
                  aria-label="محتوى النسخة الاحتياطية JSON"
                  className="w-full p-3 bg-[#192131] border border-white/10 rounded-lg text-xs font-mono text-white placeholder:font-sans placeholder:text-[#A5B1C6]/60"
                />
              </div>
            )}

            {privacyTab === 'logs' && (
              <div className="space-y-4">
                <div className="bg-[#0D121E] rounded-lg p-4 space-y-2">
                  <p className="text-sm font-bold text-white">
                    سجل الأمان ({auditEntries.length})
                  </p>
                  <div className="divide-y divide-white/10 max-h-44 overflow-y-auto">
                    {auditEntries.slice(0, 15).map((entry) => (
                      <div key={entry.id} className="py-2 text-xs">
                        <div className="flex justify-between gap-2">
                          <span className="font-semibold text-white">
                            {getAuditActionLabel(entry.action)} ({entry.actorRole})
                          </span>
                          <span
                            className={
                              entry.outcome === 'DENIED'
                                ? 'text-red-400'
                                : 'text-emerald-400'
                            }
                          >
                            {entry.outcome}
                          </span>
                        </div>
                        <p className="text-[#A5B1C6] mt-0.5">{entry.details}</p>
                      </div>
                    ))}
                    {auditEntries.length === 0 && (
                      <p className="text-xs text-[#A5B1C6] py-2">
                        لا توجد أحداث أمنية مسجلة بعد.
                      </p>
                    )}
                  </div>
                </div>

                <div className="bg-[#0D121E] rounded-lg p-4 space-y-2">
                  <p className="text-sm font-bold text-white">
                    سجل النظام الدوّار (RotatingLogger · خالٍ من الأسرار)
                  </p>
                  <div className="divide-y divide-white/10 max-h-44 overflow-y-auto font-mono text-[11px]">
                    {systemLogs.slice(0, 20).map((log) => (
                      <div key={log.id} className="py-1.5">
                        <span className="text-[#4B91FF]">[{log.level}]</span>{' '}
                        <span className="text-white">[{log.scope}]</span>{' '}
                        <span className="text-[#A5B1C6]">{log.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {(modal === 'screen-share' || modal === 'files-media') && (
          <div className="space-y-4">
            <p className="text-sm text-[#A5B1C6] leading-relaxed">
              {modal === 'screen-share'
                ? 'ميزة مشاركة الشاشة الفورية تتطلب قناة WebRTC MediaStream وتبادل إشارات (Signaling + TURN/STUN) غير مكتمل في هذا الإصدار؛ تم الإبقاء على الواجهة لتوثيق الحالة دون محاكاة وهمية.'
                : 'ميزة نقل الملفات والوسائط تتطلب قناة WebRTC DataChannel أو خدمة تخزين ثنائية مستقلة غير مفعّلة في هذا الإصدار.'}
            </p>
            <div className="bg-[#0D121E] rounded-lg p-4">
              <p className="text-xs text-[#A5B1C6]">المعرّف العام للجهاز</p>
              <p className="font-mono text-xs text-white mt-1 break-all">
                {identity?.publicId ?? 'غير مهيأ'}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
