import {
  Activity,
  Bell,
  ChevronLeft,
  FolderOpen,
  MonitorSmartphone,
  Plus,
  RefreshCw,
  Settings,
} from 'lucide-react';
import type {
  ConnectionState,
  DeviceRole,
  LinkedDevice,
} from '../../domain/models/device';
import type { SystemHealthSnapshot } from '../../domain/models/health';
import type { SyncRunSummary } from '../../domain/models/syncEvent';
import type { AppView, DashboardModalType } from '../types/ui';

interface DashboardViewProps {
  role: DeviceRole;
  serviceRunning: boolean;
  connectionState: ConnectionState;
  linkedDevices: LinkedDevice[];
  notificationAccess: boolean;
  usageAccess: boolean;
  sessionValid: boolean;
  cryptoSupported: boolean;
  health: SystemHealthSnapshot;
  selectedAppsCount: number;
  isSyncRunning: boolean;
  lastSyncSummary: SyncRunSummary | null;
  onStartService: () => void;
  onStopService: () => void;
  onRunSyncNow: () => void;
  onRenewSession: () => void;
  onNavigate: (view: AppView) => void;
  onOpenModal: (modal: DashboardModalType) => void;
}

export function DashboardView({
  role,
  serviceRunning,
  connectionState,
  linkedDevices,
  notificationAccess,
  usageAccess,
  sessionValid,
  cryptoSupported,
  health,
  selectedAppsCount,
  isSyncRunning,
  lastSyncSummary,
  onStartService,
  onStopService,
  onRunSyncNow,
  onRenewSession,
  onNavigate,
  onOpenModal,
}: DashboardViewProps) {
  const isAdmin = role === 'admin';
  const pairedDevices = linkedDevices.filter(
    (d) => d.pairingState === 'PAIRED' && d.verifiedByRelay
  );

  const connectionHeadline =
    connectionState === 'CONNECTED' && pairedDevices.length > 0
      ? `متصل فعلياً بـ ${pairedDevices.length} جهاز مرتبط`
      : connectionState === 'CONNECTED'
        ? 'متصل بخادم المرحل — بانتظار ربط جهاز'
        : connectionState === 'CONNECTING'
          ? 'جاري الاتصال بخادم المرحل...'
          : connectionState === 'RECONNECTING'
            ? 'انقطع الاتصال — جاري إعادة المحاولة'
            : connectionState === 'ERROR'
              ? 'تعذّر الاتصال بخادم المرحل'
              : 'غير متصل بخادم المرحل';

  const connectionSubtext =
    connectionState === 'CONNECTED' && pairedDevices.length > 0
      ? `الأجهزة الموثوقة: ${pairedDevices.map((d) => d.label).join('، ')}`
      : connectionState === 'CONNECTED'
        ? 'استخدم «ربط جهاز جديد» لإنشاء رمز اقتران أو إدخاله من جهاز آخر'
        : 'شغّل خدمة الاتصال للتسجيل في المرحل واستقبال الأحداث';

  const dotColorClass =
    connectionState === 'CONNECTED' && pairedDevices.length > 0
      ? 'text-emerald-400'
      : connectionState === 'CONNECTED'
        ? 'text-[#4B91FF]'
        : connectionState === 'ERROR'
          ? 'text-red-400'
          : 'text-[#FFBE50]';

  return (
    <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white mb-1">NEXLINK</h1>
          <p className="text-sm font-semibold text-[#4B91FF]">
            {isAdmin ? 'الجهاز الرئيسي • SUPER ADMIN' : 'الجهاز التابع • BASIC DEVICE'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {!sessionValid && (
            <button
              type="button"
              onClick={onRenewSession}
              className="min-h-[44px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs sm:text-sm font-bold rounded-lg whitespace-nowrap cursor-pointer"
            >
              انتهت الجلسة — تجديد الآن
            </button>
          )}
          <button
            type="button"
            onClick={onRunSyncNow}
            disabled={isSyncRunning}
            className="min-h-[44px] px-4 py-2 bg-[#192131] hover:bg-[#222d42] border border-white/10 disabled:opacity-60 text-white text-xs sm:text-sm font-semibold rounded-lg inline-flex items-center gap-2 whitespace-nowrap cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncRunning ? 'animate-spin' : ''}`} />
            {isSyncRunning ? 'جاري المزامنة...' : 'مزامنة الآن'}
          </button>
        </div>
      </div>

      {health.lastError && (
        <div
          role="alert"
          className="mb-6 bg-[#192131] border border-red-500/30 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3"
        >
          <p className="text-xs sm:text-sm text-red-300">
            [{health.lastError.source}] {health.lastError.message}
          </p>
          <button
            type="button"
            onClick={() => onOpenModal('privacy-auth')}
            className="text-xs font-semibold text-[#4B91FF] hover:underline whitespace-nowrap cursor-pointer"
          >
            فحص صحة النظام
          </button>
        </div>
      )}

      {lastSyncSummary && (
        <div
          role="status"
          className="mb-6 bg-[#192131] border border-white/10 rounded-xl px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs text-[#A5B1C6] tabular-nums"
        >
          <span>
            نتيجة آخر دورة مزامنة:{' '}
            {lastSyncSummary.skippedReason === 'OFFLINE'
              ? 'خادم المرحل غير متصل — بقيت الأحداث في الانتظار'
              : lastSyncSummary.skippedReason === 'SESSION_EXPIRED'
                ? 'الجلسة منتهية — جدّد الجلسة لإرسال الأحداث'
                : `تمت معالجة ${lastSyncSummary.attempted} · نجاح مؤكد ${lastSyncSummary.synced} · مكرر ${lastSyncSummary.duplicates} · فشل ${lastSyncSummary.failed}`}
          </span>
          <span className="text-white font-semibold">
            {new Intl.DateTimeFormat('ar', { timeStyle: 'medium' }).format(
              new Date(lastSyncSummary.completedAt)
            )}
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-10 items-stretch">
        <section className="lg:col-span-5 bg-[#192131] rounded-xl p-6 border border-white/5 flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-bold text-white mb-4">حالة الاتصال</h2>
            <div className="flex items-center gap-2.5 mb-2">
              <span
                aria-hidden="true"
                className={`text-sm leading-none ${dotColorClass}`}
              >
                ●
              </span>
              <p className="text-base font-medium text-white">{connectionHeadline}</p>
            </div>
            <p className="text-sm text-[#A5B1C6] mb-6 leading-relaxed">
              {connectionSubtext}
            </p>
          </div>

          <div className="pt-4 border-t border-white/10 space-y-2 text-xs text-[#A5B1C6] tabular-nums">
            <div className="flex items-center justify-between gap-4">
              <span>حالة خدمة الاتصال</span>
              <span
                className={`font-semibold ${
                  serviceRunning ? 'text-emerald-400' : 'text-[#A5B1C6]'
                }`}
              >
                {serviceRunning ? 'مفعّلة' : 'متوقفة'}
              </span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>طابور المزامنة (انتظار / مُزامَن / فشل)</span>
              <span className="font-semibold text-white">
                {health.pendingCount} / {health.syncedCount} / {health.failedCount}
              </span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>صلاحية الإشعارات</span>
              <span
                className={`font-semibold ${
                  notificationAccess ? 'text-emerald-400' : 'text-[#FFBE50]'
                }`}
              >
                {notificationAccess ? 'مفعّلة' : 'غير مفعّلة'}
              </span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>صلاحية نشاط التطبيقات</span>
              <span
                className={`font-semibold ${
                  usageAccess ? 'text-emerald-400' : 'text-[#FFBE50]'
                }`}
              >
                {usageAccess ? 'مفعّلة' : 'غير مفعّلة'}
              </span>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span>حماية البيانات والجلسة</span>
              <span
                className={`font-semibold ${
                  sessionValid && cryptoSupported
                    ? 'text-emerald-400'
                    : 'text-[#FFBE50]'
                }`}
              >
                {sessionValid
                  ? cryptoSupported
                    ? 'AES-256-GCM · ECDSA P-256'
                    : 'جلسة نشطة (التشفير غير مدعوم)'
                  : 'الجلسة منتهية'}
              </span>
            </div>
          </div>
        </section>

        <section className="lg:col-span-7 bg-[#192131] rounded-xl p-6 border border-white/5">
          <h2 className="text-lg font-bold text-white mb-1">خدمة الاتصال</h2>
          <p className="text-sm text-[#A5B1C6] mb-5">
            إدارة الاتصال بخادم المرحل والتحكم في أذونات النظام
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={onStartService}
              className="min-h-[44px] px-4 py-3 bg-[#4B91FF] hover:bg-[#3a7ee8] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
            >
              تشغيل خدمة الاتصال
            </button>

            <button
              type="button"
              onClick={onStopService}
              className="min-h-[44px] px-4 py-3 bg-[#243047] hover:bg-[#2c3a56] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
            >
              إيقاف خدمة الاتصال
            </button>

            <button
              type="button"
              onClick={() => onOpenModal('notification-permission')}
              className="min-h-[44px] px-4 py-3 bg-[#4B91FF] hover:bg-[#3a7ee8] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
            >
              إعداد صلاحية الإشعارات
            </button>

            <button
              type="button"
              onClick={() => onOpenModal('usage-permission')}
              className="min-h-[44px] px-4 py-3 bg-[#4B91FF] hover:bg-[#3a7ee8] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
            >
              إعداد صلاحية نشاط التطبيقات
            </button>
          </div>
        </section>
      </div>

      <section className="mb-10">
        <h2 className="text-xl font-bold text-white mb-4">إدارة الأجهزة</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <button
            type="button"
            onClick={() => onOpenModal('pair-device')}
            className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            <div className="flex items-center gap-4">
              <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
                <Plus className="w-5 h-5" />
              </span>
              <div>
                <p className="text-base font-bold text-white">ربط الأجهزة والاقتران</p>
                <p className="text-xs text-[#A5B1C6] mt-0.5 tabular-nums">
                  {pairedDevices.length > 0
                    ? `${pairedDevices.length} جهاز مقترن ومؤكد عبر المرحل`
                    : 'إنشاء أو إدخال رمز اقتران عبر خادم المرحل'}
                </p>
              </div>
            </div>
            <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('notification-apps')}
            className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            <div className="flex items-center gap-4">
              <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
                <Bell className="w-5 h-5" />
              </span>
              <div>
                <p className="text-base font-bold text-white">الإشعارات</p>
                <p className="text-xs text-[#A5B1C6] mt-0.5 tabular-nums">
                  {selectedAppsCount} تطبيق محدد ·{' '}
                  {health.pendingCount + health.syncedCount + health.failedCount} حدث في
                  القاعدة
                </p>
              </div>
            </div>
            <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onOpenModal('app-usage')}
            className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            <div className="flex items-center gap-4">
              <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
                <Activity className="w-5 h-5" />
              </span>
              <div>
                <p className="text-base font-bold text-white">نشاط التطبيقات</p>
                <p className="text-xs text-[#A5B1C6] mt-0.5">
                  مراقبة قدرات البيئة وبيانات الاستخدام
                </p>
              </div>
            </div>
            <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onOpenModal('screen-share')}
            className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            <div className="flex items-center gap-4">
              <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
                <MonitorSmartphone className="w-5 h-5" />
              </span>
              <div>
                <p className="text-base font-bold text-white">مشاركة الشاشة</p>
                <p className="text-xs text-[#A5B1C6] mt-0.5">
                  تتطلب قناة WebRTC أو خدمة النظام الأصلي
                </p>
              </div>
            </div>
            <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onOpenModal('files-media')}
            className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            <div className="flex items-center gap-4">
              <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
                <FolderOpen className="w-5 h-5" />
              </span>
              <div>
                <p className="text-base font-bold text-white">الملفات والوسائط</p>
                <p className="text-xs text-[#A5B1C6] mt-0.5">
                  تتطلب قناة نقل ثنائية مباشرة
                </p>
              </div>
            </div>
            <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
          </button>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-xl font-bold text-white mb-4">الخصوصية والأمان والنظام</h2>

        <button
          type="button"
          onClick={() => onOpenModal('privacy-auth')}
          className="w-full bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl p-4 sm:p-5 flex items-center justify-between gap-4 text-right transition-colors cursor-pointer min-h-[72px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
        >
          <div className="flex items-center gap-4">
            <span className="w-10 h-10 rounded-lg bg-[#0D121E] flex items-center justify-center text-[#4B91FF] shrink-0">
              <Settings className="w-5 h-5" />
            </span>
            <div>
              <p className="text-base font-bold text-white">
                مركز الأمان والإعدادات والصحة والنسخ الاحتياطي
              </p>
              <p className="text-xs text-[#A5B1C6] mt-0.5">
                إدارة الهوية التشفيرية، الجلسات، صحة النظام، النسخ الاحتياطي المتحقق
                منه، والسجلات
              </p>
            </div>
          </div>
          <ChevronLeft className="w-5 h-5 text-[#A5B1C6] shrink-0" />
        </button>
      </section>

      <footer className="text-center text-xs text-[#A5B1C6] pt-4 border-t border-white/5">
        NEXLINK • Clean Architecture + IndexedDB + SQLite Relay
      </footer>
    </main>
  );
}
