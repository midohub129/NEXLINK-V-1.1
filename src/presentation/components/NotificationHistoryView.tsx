import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Search, Send, ShieldAlert, Trash2, X } from 'lucide-react';
import type { EnqueueOutcome } from '../../application/sync/syncEngine';
import { AppError } from '../../domain/errors/appError';
import type { DataSourceAppInfo } from '../../domain/interfaces/services';
import type { DeviceRole } from '../../domain/models/device';
import type { RoleCapabilities } from '../../domain/models/security';
import type {
  NotificationPayload,
  SyncEvent,
  SyncEventStatus,
  SyncRunSummary,
} from '../../domain/models/syncEvent';

interface NotificationHistoryViewProps {
  role: DeviceRole;
  capabilities: RoleCapabilities;
  sessionValid: boolean;
  events: SyncEvent[];
  selectedApps: Set<string>;
  notificationAccess: boolean;
  isSyncRunning: boolean;
  loadApps: () => Promise<DataSourceAppInfo[]>;
  onBackToSelection: () => void;
  onOpenNotificationPermission: () => void;
  onRenewSession: () => void;
  onEnqueueTestNotification: (input: {
    packageName: string;
    title: string;
    text: string;
    notificationKey?: string;
  }) => Promise<EnqueueOutcome>;
  onRunSyncNow: () => Promise<SyncRunSummary>;
  onUpdateStatus: (eventId: number, status: SyncEventStatus) => Promise<void>;
  onManualRetry: (eventId: number) => Promise<void>;
  onDeleteEvent: (eventId: number) => Promise<void>;
}

type StatusFilter = 'ALL' | SyncEventStatus;

function parsePayload(raw: string): NotificationPayload | null {
  try {
    return JSON.parse(raw) as NotificationPayload;
  } catch {
    return null;
  }
}

function getStatusLabel(status: SyncEventStatus): string {
  switch (status) {
    case 'PENDING':
      return 'قيد الانتظار';
    case 'IN_PROGRESS':
      return 'قيد المزامنة';
    case 'SYNCED':
      return 'ناجح (مُزامَن)';
    case 'FAILED':
      return 'فشل';
  }
}

export function NotificationHistoryView({
  capabilities,
  sessionValid,
  events,
  selectedApps,
  notificationAccess,
  isSyncRunning,
  loadApps,
  onBackToSelection,
  onOpenNotificationPermission,
  onRenewSession,
  onEnqueueTestNotification,
  onRunSyncNow,
  onUpdateStatus,
  onManualRetry,
  onDeleteEvent,
}: NotificationHistoryViewProps) {
  const [sourceApps, setSourceApps] = useState<DataSourceAppInfo[]>([]);
  const [pkg, setPkg] = useState<string>(Array.from(selectedApps)[0] || 'com.whatsapp');
  const [title, setTitle] = useState('رسالة جديدة');
  const [text, setText] = useState('حدث اختباري عبر محرك المزامنة');
  const [notificationKey, setNotificationKey] = useState('');
  const [feedback, setFeedback] = useState<string | null>(null);
  const [actionWarning, setActionWarning] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL');
  const [appFilter, setAppFilter] = useState<string>('ALL');

  useEffect(() => {
    let cancelled = false;
    void loadApps().then((apps) => {
      if (!cancelled) {
        setSourceApps(apps);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [loadApps]);

  const appNameByPackage = useMemo(() => {
    const map = new Map<string, string>();
    sourceApps.forEach((a) => map.set(a.packageName, a.appName));
    return map;
  }, [sourceApps]);

  const getAppDisplayName = (packageName?: string): string => {
    if (!packageName) return 'تطبيق غير معروف';
    return appNameByPackage.get(packageName) ?? packageName;
  };

  const handleCaptureSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onEnqueueTestNotification({
      packageName: pkg.trim(),
      title,
      text,
      notificationKey: notificationKey.trim() || undefined,
    });

    if (res.status === 'SAVED') {
      setFeedback(
        `تم تشفير الحدث #${res.event.id} محلياً وإدراجه بحالة PENDING في طابور المزامنة.`
      );
      return;
    }

    switch (res.reason) {
      case 'SESSION_EXPIRED':
        setFeedback('تعذّر الإدراج: انتهت صلاحية الجلسة، جدّد الجلسة أولاً.');
        break;
      case 'PERMISSION_DENIED':
        setFeedback('تعذّر الإدراج: صلاحية الوصول للإشعارات غير مفعّلة.');
        break;
      case 'APP_NOT_SELECTED':
        setFeedback('تم التجاهل: هذه الحزمة غير محددة ضمن قائمة المشاركة.');
        break;
      case 'DUPLICATE':
        setFeedback('تم منع التكرار: الحدث محفوظ مسبقاً خلال نافذة 60 ثانية.');
        break;
      default:
        setFeedback('تم تجاهل الحدث.');
    }
  };

  const handleSyncClick = async () => {
    const summary = await onRunSyncNow();
    if (summary.skippedReason === 'OFFLINE') {
      setFeedback('خادم المرحل غير متصل؛ ستبقى الأحداث في طابور PENDING.');
    } else if (summary.skippedReason === 'SESSION_EXPIRED') {
      setFeedback('انتهت الجلسة؛ جدّد الجلسة لتنفيذ المزامنة.');
    } else if (summary.skippedReason === 'UNPAIRED') {
      setFeedback(
        'لا يوجد جهاز مقترن موثوق لإرسال الأحداث إليه عبر E2EE. اربط جهازاً أولاً.'
      );
    } else {
      setFeedback(
        `نتيجة المزامنة: تمت معالجة ${summary.attempted} · تسليم مؤكد ${summary.synced} · بانتظار الطرف المقابل ${summary.awaitingPeerAck} · مكرر ${summary.duplicates} · فشل ${summary.failed}`
      );
    }
  };

  const wrapMutation = async (fn: () => Promise<void>) => {
    try {
      setActionWarning(null);
      await fn();
    } catch (err) {
      if (err instanceof AppError) {
        setActionWarning(err.userMessage);
      } else {
        setActionWarning('تعذّر تنفيذ التعديل المطلوب.');
      }
    }
  };

  const appFilterOptions = useMemo(() => {
    const knownPackages = new Set<string>([
      ...selectedApps,
      ...sourceApps.map((app) => app.packageName),
    ]);
    events.forEach((event) => {
      const parsed = parsePayload(event.payload);
      if (parsed?.packageName) {
        knownPackages.add(parsed.packageName);
      }
    });

    return Array.from(knownPackages)
      .map((packageName) => ({
        packageName,
        appName: appNameByPackage.get(packageName) ?? packageName,
      }))
      .sort((a, b) => a.appName.localeCompare(b.appName));
  }, [events, selectedApps, sourceApps, appNameByPackage]);

  const statusCounts = useMemo(() => {
    return events.reduce(
      (acc, event) => {
        acc.ALL += 1;
        acc[event.status] += 1;
        return acc;
      },
      { ALL: 0, PENDING: 0, IN_PROGRESS: 0, SYNCED: 0, FAILED: 0 }
    );
  }, [events]);

  const filteredEvents = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase();

    return events.filter((event) => {
      if (statusFilter !== 'ALL' && event.status !== statusFilter) {
        return false;
      }

      const parsed = parsePayload(event.payload);
      const packageName = parsed?.packageName ?? '';
      const appName = appNameByPackage.get(packageName) ?? packageName;

      if (appFilter !== 'ALL' && packageName !== appFilter) {
        return false;
      }

      if (normalizedQuery.length > 0) {
        const searchableText = [
          appName,
          packageName,
          parsed?.title ?? '',
          parsed?.text ?? '',
          event.payload,
          event.type,
          String(event.id),
        ]
          .join(' ')
          .toLowerCase();

        if (!searchableText.includes(normalizedQuery)) {
          return false;
        }
      }

      return true;
    });
  }, [events, statusFilter, appFilter, searchQuery, appNameByPackage]);

  const hasActiveFilters =
    searchQuery.trim().length > 0 || statusFilter !== 'ALL' || appFilter !== 'ALL';

  const resetFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
    setAppFilter('ALL');
  };

  const statusTabs: { value: StatusFilter; label: string; count: number }[] = [
    { value: 'ALL', label: 'الكل', count: statusCounts.ALL },
    { value: 'PENDING', label: 'انتظار', count: statusCounts.PENDING },
    {
      value: 'IN_PROGRESS',
      label: 'جاري',
      count: statusCounts.IN_PROGRESS,
    },
    { value: 'SYNCED', label: 'مُزامَن', count: statusCounts.SYNCED },
    { value: 'FAILED', label: 'فشل', count: statusCounts.FAILED },
  ];

  const candidatePackages = Array.from(
    new Set([...selectedApps, ...sourceApps.map((a) => a.packageName), 'com.whatsapp'])
  );

  return (
    <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">
            سجل الإشعارات وطابور المزامنة
          </h1>
          <p className="text-xs text-[#A5B1C6] mt-1">
            {capabilities.deleteEvents
              ? 'صلاحية Super Admin: عرض وتعديل وحذف أحداث طابور المزامنة'
              : 'صلاحية Basic Device: عرض فقط (التعديل والحذف مقيد)'}
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={isSyncRunning}
            onClick={() => void handleSyncClick()}
            className="min-h-[44px] px-4 py-2.5 bg-[#192131] hover:bg-[#222d42] border border-white/10 text-white text-sm font-bold rounded-lg inline-flex items-center gap-2 whitespace-nowrap cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncRunning ? 'animate-spin' : ''}`} />
            مزامنة الطابور الآن
          </button>
          <button
            type="button"
            onClick={onBackToSelection}
            className="min-h-[44px] px-5 py-2.5 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-sm font-bold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            إعدادات التطبيقات
          </button>
        </div>
      </div>

      {!sessionValid && (
        <div
          role="alert"
          className="bg-[#192131] border border-[#FFBE50]/40 rounded-xl p-4 mb-6 flex flex-wrap items-center justify-between gap-3"
        >
          <div className="flex items-center gap-2.5 text-sm text-[#FFBE50]">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>
              انتهت صلاحية الجلسة الحالية. جدّد الجلسة لاستئناف المزامنة وإدارة الطابور.
            </span>
          </div>
          <button
            type="button"
            onClick={onRenewSession}
            className="min-h-[40px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-xs font-bold rounded-lg whitespace-nowrap cursor-pointer"
          >
            تجديد الجلسة
          </button>
        </div>
      )}

      {/* Manual Test Event Enqueue Harness */}
      <section className="bg-[#192131] border border-white/5 rounded-xl p-5 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-base font-bold text-white">
              إدراج حدث اختباري في طابور المزامنة
            </h2>
            <p className="text-xs text-[#A5B1C6] mt-0.5">
              أداة اختبار صريحة للتحقق من التشفير، منع التكرار (SHA-256)، وحالات
              SyncEngine — ليست التقاطاً تلقائياً من نظام التشغيل.
            </p>
          </div>
          {!notificationAccess && (
            <button
              type="button"
              onClick={onOpenNotificationPermission}
              className="min-h-[40px] px-3.5 py-2 text-xs font-semibold bg-[#243047] hover:bg-[#2c3a56] text-[#FFBE50] rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              تفعيل صلاحية الإشعارات
            </button>
          )}
        </div>

        <form
          onSubmit={(e) => void handleCaptureSubmit(e)}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3"
        >
          <select
            value={pkg}
            onChange={(e) => setPkg(e.target.value)}
            aria-label="حزمة التطبيق الاختباري"
            className="min-h-[44px] px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          >
            {candidatePackages.map((packageName) => (
              <option key={packageName} value={packageName}>
                {getAppDisplayName(packageName)} (
                {selectedApps.has(packageName) ? 'مشمول' : 'مستبعد'})
              </option>
            ))}
          </select>

          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="عنوان الإشعار"
            aria-label="عنوان الإشعار"
            className="min-h-[44px] px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white placeholder:text-[#A5B1C6]/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          />

          <input
            type="text"
            value={notificationKey}
            onChange={(e) => setNotificationKey(e.target.value)}
            placeholder="مفتاح الإشعار sbn.key (اختياري)"
            aria-label="مفتاح الإشعار"
            className="min-h-[44px] px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white placeholder:text-[#A5B1C6]/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          />

          <div className="flex gap-2">
            <input
              type="text"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="نص الإشعار"
              aria-label="نص الإشعار"
              className="min-h-[44px] flex-1 min-w-0 px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white placeholder:text-[#A5B1C6]/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
            />
            <button
              type="submit"
              className="min-h-[44px] px-4 py-2 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-sm font-bold rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Send className="w-4 h-4" />
              إدراج
            </button>
          </div>
        </form>

        {feedback && (
          <p className="text-xs text-[#4B91FF] mt-3" role="status">
            {feedback}
          </p>
        )}
      </section>

      {/* Search & Filter Toolbar */}
      <section
        aria-label="البحث والتصفية"
        className="bg-[#192131] border border-white/5 rounded-xl p-5 mb-6 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-7 relative">
            <Search
              aria-hidden="true"
              className="w-4 h-4 text-[#A5B1C6] absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
            />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="ابحث باسم التطبيق أو عنوان الإشعار أو النص..."
              aria-label="ابحث في سجل الإشعارات"
              className="w-full min-h-[44px] pr-10 pl-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white placeholder:text-[#A5B1C6]/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
            />
          </div>

          <div className="md:col-span-5">
            <select
              value={appFilter}
              onChange={(e) => setAppFilter(e.target.value)}
              aria-label="تصفية حسب اسم التطبيق"
              className="w-full min-h-[44px] px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
            >
              <option value="ALL">جميع التطبيقات</option>
              {appFilterOptions.map((app) => (
                <option key={app.packageName} value={app.packageName}>
                  {app.appName}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div
            role="group"
            aria-label="تصفية حسب الحالة"
            className="flex flex-wrap items-center gap-1.5 p-1 bg-[#0D121E] rounded-lg"
          >
            {statusTabs.map((tab) => {
              const active = statusFilter === tab.value;
              return (
                <button
                  key={tab.value}
                  type="button"
                  onClick={() => setStatusFilter(tab.value)}
                  aria-pressed={active}
                  className={`min-h-[36px] px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                    active
                      ? 'bg-[#4B91FF] text-white'
                      : 'text-[#A5B1C6] hover:text-white'
                  }`}
                >
                  {tab.label} ({tab.count})
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-3 text-xs text-[#A5B1C6] tabular-nums">
            <span>
              عرض <strong className="text-white">{filteredEvents.length}</strong> من أصل{' '}
              <strong className="text-white">{events.length}</strong>
            </span>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetFilters}
                className="min-h-[36px] px-3 py-1.5 text-xs font-semibold text-white bg-[#243047] hover:bg-[#2c3a56] rounded-lg inline-flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
                مسح التصفية
              </button>
            )}
          </div>
        </div>
      </section>

      {actionWarning && (
        <p className="text-xs text-[#FFBE50] mb-4" role="alert">
          {actionWarning}
        </p>
      )}

      {events.length === 0 ? (
        <div className="bg-[#192131] border border-white/5 rounded-xl p-8 text-center">
          <p className="text-sm text-[#A5B1C6] mb-2">طابور المزامنة فارغ حالياً.</p>
          <p className="text-xs text-[#A5B1C6]/80">
            أضف حزمة في إعدادات التطبيقات ثم أدرج حدثاً اختبارياً أو استقبل أحداثاً من جهاز
            مقترن عبر المرحل.
          </p>
        </div>
      ) : filteredEvents.length === 0 ? (
        <div className="bg-[#192131] border border-white/5 rounded-xl p-8 text-center space-y-4">
          <p className="text-sm text-[#A5B1C6]">
            لا توجد أحداث تطابق معايير البحث أو التصفية المحددة.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            className="min-h-[44px] px-5 py-2.5 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-sm font-bold rounded-lg transition-colors whitespace-nowrap cursor-pointer"
          >
            إعادة تعيين التصفية
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredEvents.map((event) => {
            const parsed = parsePayload(event.payload);
            const appName = getAppDisplayName(parsed?.packageName);
            const formattedDate = new Intl.DateTimeFormat('ar', {
              dateStyle: 'medium',
              timeStyle: 'short',
            }).format(new Date(event.createdAt));

            return (
              <article
                key={event.id}
                className="bg-[#192131] border border-white/5 rounded-xl p-5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-white">
                    <span>الحدث: {event.type}</span>
                    {parsed?.packageName && (
                      <>
                        <span aria-hidden="true" className="text-[#A5B1C6]">
                          ·
                        </span>
                        <span className="text-[#4B91FF]">{appName}</span>
                      </>
                    )}
                    <span aria-hidden="true" className="text-[#A5B1C6]">
                      ·
                    </span>
                    <span className="font-mono text-xs font-normal text-[#A5B1C6] tabular-nums">
                      #{event.id}
                    </span>
                    {event.e2eeProtected ? (
                      <>
                        <span aria-hidden="true" className="text-[#A5B1C6]">
                          ·
                        </span>
                        <span className="text-xs font-normal text-emerald-400">
                          E2EE (ECDH+HKDF+AES-GCM)
                        </span>
                      </>
                    ) : (event.localEncrypted ?? event.encrypted) ? (
                      <>
                        <span aria-hidden="true" className="text-[#A5B1C6]">
                          ·
                        </span>
                        <span className="text-xs font-normal text-[#4B91FF]">
                          مشفّر محلياً (AES-GCM)
                        </span>
                      </>
                    ) : event.encrypted ? (
                      <>
                        <span aria-hidden="true" className="text-[#A5B1C6]">
                          ·
                        </span>
                        <span className="text-xs font-normal text-[#FFBE50]">
                          مغلف مشفّر (بانتظار التحقق الطرفي)
                        </span>
                      </>
                    ) : (
                      <>
                        <span aria-hidden="true" className="text-[#A5B1C6]">
                          ·
                        </span>
                        <span className="text-xs font-normal text-[#A5B1C6]">
                          غير مشفّر
                        </span>
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-xs tabular-nums">
                    <span
                      className={
                        event.status === 'SYNCED'
                          ? 'text-emerald-400 font-semibold'
                          : event.status === 'FAILED'
                            ? 'text-red-400 font-semibold'
                            : event.status === 'IN_PROGRESS'
                              ? 'text-[#4B91FF] font-semibold'
                              : 'text-[#FFBE50] font-semibold'
                      }
                    >
                      الحالة: {getStatusLabel(event.status)}
                      {event.status === 'IN_PROGRESS' && event.relayAcceptedAt
                        ? ' (بانتظار تأكيد الطرف المقابل)'
                        : event.status === 'SYNCED' && event.deliveredAt
                          ? ' (استلمه الطرف المقابل)'
                          : ''}
                    </span>
                    <span aria-hidden="true" className="text-[#A5B1C6]">
                      ·
                    </span>
                    <span className="text-[#A5B1C6]">
                      المحاولات: {event.retryCount}
                    </span>
                  </div>
                </div>

                {parsed ? (
                  <div className="mb-3 space-y-1">
                    <p className="text-sm font-semibold text-white">
                      {parsed.title || 'بدون عنوان'}
                    </p>
                    <p className="text-sm text-[#A5B1C6]">{parsed.text || 'بدون نص'}</p>
                  </div>
                ) : (
                  <p className="font-mono text-xs text-[#A5B1C6] mb-3 break-all">
                    {event.payload}
                  </p>
                )}

                {event.lastError && (
                  <p className="text-xs text-red-300 mb-3">
                    آخر خطأ مزامنة: {event.lastError}
                  </p>
                )}

                <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/10">
                  <span className="text-xs text-[#A5B1C6] tabular-nums">
                    وقت الحفظ: {formattedDate}
                  </span>

                  <div className="flex flex-wrap items-center gap-2">
                    <select
                      value={event.status}
                      disabled={!capabilities.updateEventStatus}
                      onChange={(e) =>
                        void wrapMutation(() =>
                          onUpdateStatus(event.id, e.target.value as SyncEventStatus)
                        )
                      }
                      aria-label="تغيير حالة الحدث"
                      className="min-h-[40px] px-3 py-1.5 text-xs font-semibold bg-[#0D121E] border border-white/10 text-white rounded-lg cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <option value="PENDING">قيد الانتظار</option>
                      <option value="IN_PROGRESS">قيد المزامنة</option>
                      <option value="SYNCED">ناجح (مُزامَن)</option>
                      <option value="FAILED">فشل</option>
                    </select>

                    <button
                      type="button"
                      disabled={!capabilities.updateEventStatus}
                      onClick={() => void wrapMutation(() => onManualRetry(event.id))}
                      className="min-h-[40px] px-3 py-1.5 text-xs font-semibold bg-[#243047] hover:bg-[#2c3a56] disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      إعادة محاولة
                    </button>

                    <button
                      type="button"
                      disabled={!capabilities.deleteEvents}
                      onClick={() => void wrapMutation(() => onDeleteEvent(event.id))}
                      aria-label="حذف الحدث"
                      className="min-h-[40px] px-3 py-1.5 text-xs font-semibold bg-[#243047] hover:bg-red-900/50 disabled:opacity-50 disabled:cursor-not-allowed text-red-300 rounded-lg inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      حذف
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </main>
  );
}
