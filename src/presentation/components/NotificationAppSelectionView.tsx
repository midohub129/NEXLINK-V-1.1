import { useEffect, useState } from 'react';
import type {
  DataSourceAppInfo,
  DataSourceAvailability,
} from '../../domain/interfaces/services';
import { SELF_PACKAGE_NAME } from '../../infrastructure/datasources/deviceDataSources';

interface NotificationAppSelectionViewProps {
  selectedApps: Set<string>;
  eventCount: number;
  testFixtureModeEnabled: boolean;
  availability: DataSourceAvailability;
  loadApps: () => Promise<DataSourceAppInfo[]>;
  onToggleTestFixtureMode: (enabled: boolean) => Promise<void>;
  onToggleApp: (packageName: string, checked: boolean) => Promise<void>;
  onBackToDashboard: () => void;
  onViewHistory: () => void;
}

export function NotificationAppSelectionView({
  selectedApps,
  eventCount,
  testFixtureModeEnabled,
  availability,
  loadApps,
  onToggleTestFixtureMode,
  onToggleApp,
  onBackToDashboard,
  onViewHistory,
}: NotificationAppSelectionViewProps) {
  const [sourceApps, setSourceApps] = useState<DataSourceAppInfo[]>([]);
  const [customPackage, setCustomPackage] = useState('');
  const [packageNotice, setPackageNotice] = useState<string | null>(null);
  const [pendingToggleMap, setPendingToggleMap] = useState<Record<string, boolean>>({});

  const handleToggle = async (packageName: string, nextChecked: boolean) => {
    setPendingToggleMap((prev) => ({ ...prev, [packageName]: nextChecked }));
    try {
      await onToggleApp(packageName, nextChecked);
    } finally {
      setPendingToggleMap((prev) => {
        const next = { ...prev };
        delete next[packageName];
        return next;
      });
    }
  };

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
  }, [loadApps, testFixtureModeEnabled]);

  const combinedPackages = new Map<string, DataSourceAppInfo>();
  for (const app of sourceApps) {
    combinedPackages.set(app.packageName, app);
  }
  for (const pkg of selectedApps) {
    if (!combinedPackages.has(pkg) && pkg !== SELF_PACKAGE_NAME) {
      combinedPackages.set(pkg, {
        packageName: pkg,
        appName: pkg,
        foregroundTimeMs: null,
        sourceKind: 'BROWSER_CAPABILITY',
      });
    }
  }

  const displayedApps = Array.from(combinedPackages.values()).sort((a, b) =>
    a.appName.toLowerCase().localeCompare(b.appName.toLowerCase())
  );

  const handleAddCustomPackage = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = customPackage.trim();
    if (!cleaned || !cleaned.includes('.')) {
      setPackageNotice('أدخل اسم حزمة صالحاً مثل com.whatsapp');
      return;
    }
    if (cleaned === SELF_PACKAGE_NAME) {
      setPackageNotice('لا يمكن اختيار حزمة NEXLINK نفسها.');
      return;
    }
    await onToggleApp(cleaned, true);
    setCustomPackage('');
    setPackageNotice(`تمت إضافة الحزمة ${cleaned} إلى قائمة المشاركة.`);
  };

  return (
    <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
      <div className="mb-6">
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-2">
          مشاركة الإشعارات
        </h1>
        <p className="text-sm sm:text-base text-[#A5B1C6] leading-relaxed">
          اختر حزم التطبيقات المسموح بمشاركة إشعاراتها عبر محرك المزامنة.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-5">
        <button
          type="button"
          onClick={onBackToDashboard}
          className="min-h-[44px] px-5 py-2.5 bg-[#4B91FF] hover:bg-[#3a7ee8] text-white text-sm font-bold rounded-lg transition-colors whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
        >
          العودة إلى لوحة التحكم
        </button>

        <button
          type="button"
          onClick={onViewHistory}
          className="min-h-[44px] px-5 py-2.5 bg-[#192131] hover:bg-[#222d42] border border-white/10 text-white text-sm font-bold rounded-lg transition-colors whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
        >
          عرض سجل الإشعارات المحفوظة ({eventCount})
        </button>
      </div>

      {/* Honest data-source capability banner */}
      <section className="bg-[#192131] border border-white/10 rounded-xl p-4 mb-6 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-bold text-white">
              مصدر قائمة التطبيقات:{' '}
              {testFixtureModeEnabled
                ? 'بيانات اختبار تجريبية (Test Fixtures)'
                : 'قدرات المتصفح الإنتاجي'}
            </p>
            <p className="text-xs text-[#A5B1C6] mt-1 leading-relaxed">
              {availability.reason}
            </p>
          </div>

          <button
            type="button"
            onClick={() => void onToggleTestFixtureMode(!testFixtureModeEnabled)}
            className={`min-h-[40px] px-3.5 py-2 text-xs font-bold rounded-lg whitespace-nowrap shrink-0 cursor-pointer ${
              testFixtureModeEnabled
                ? 'bg-[#243047] text-[#FFBE50] hover:bg-[#2c3a56]'
                : 'bg-[#4B91FF] text-white hover:bg-[#3a7ee8]'
            }`}
          >
            {testFixtureModeEnabled
              ? 'إيقاف بيانات الاختبار التجريبية'
              : 'تفعيل بيانات الاختبار التجريبية'}
          </button>
        </div>

        <form
          onSubmit={(e) => void handleAddCustomPackage(e)}
          className="flex flex-wrap gap-2 pt-3 border-t border-white/10"
        >
          <input
            type="text"
            value={customPackage}
            onChange={(e) => setCustomPackage(e.target.value)}
            placeholder="أضف معرّف حزمة يدوياً (مثال: com.whatsapp)"
            aria-label="أضف معرّف حزمة يدوياً"
            className="flex-1 min-w-[220px] min-h-[44px] px-3 py-2 bg-[#0D121E] border border-white/10 rounded-lg text-sm text-white font-mono placeholder:font-sans placeholder:text-[#A5B1C6]/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF]"
          />
          <button
            type="submit"
            className="min-h-[44px] px-4 py-2 bg-[#243047] hover:bg-[#2c3a56] text-white text-xs font-bold rounded-lg whitespace-nowrap cursor-pointer"
          >
            إضافة حزمة
          </button>
        </form>
        {packageNotice && (
          <p className="text-xs text-[#4B91FF]" role="status">
            {packageNotice}
          </p>
        )}
      </section>

      {displayedApps.length === 0 ? (
        <div className="bg-[#192131] rounded-xl p-6 text-sm text-[#A5B1C6] leading-relaxed">
          لا توجد تطبيقات مقروءة تلقائياً في بيئة المتصفح. يمكنك إضافة معرّف حزمة يدوياً
          أعلاه أو تفعيل بيانات الاختبار التجريبية للمعاينة.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
          {displayedApps.map((app) => {
            const checked =
              pendingToggleMap[app.packageName] ?? selectedApps.has(app.packageName);
            return (
              <label
                key={app.packageName}
                className="bg-[#192131] hover:bg-[#1f293d] border border-white/5 rounded-xl px-4 py-3.5 min-h-[56px] flex items-center justify-between gap-4 cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) =>
                      void handleToggle(app.packageName, e.target.checked)
                    }
                    className="w-5 h-5 rounded accent-[#4B91FF] cursor-pointer shrink-0"
                  />
                  <div className="min-w-0">
                    <p className="text-base font-medium text-white truncate">
                      {app.appName}
                    </p>
                    <p className="font-mono text-xs text-[#A5B1C6] truncate">
                      {app.packageName}
                    </p>
                  </div>
                </div>
                <span className="text-xs text-[#A5B1C6] shrink-0">
                  {checked ? 'مشمول' : 'غير محدد'}
                </span>
              </label>
            );
          })}
        </div>
      )}
    </main>
  );
}
