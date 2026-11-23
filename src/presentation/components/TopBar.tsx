import type { ConnectionState, DeviceRole } from '../../domain/models/device';
import type { AppView } from '../types/ui';

interface TopBarProps {
  role: DeviceRole | null;
  currentView: AppView;
  serviceRunning: boolean;
  connectionState: ConnectionState;
  onNavigate: (view: AppView) => void;
  onOpenPrivacy: () => void;
  onToggleService: () => void;
}

export function TopBar({
  role,
  currentView,
  serviceRunning,
  connectionState,
  onNavigate,
  onOpenPrivacy,
  onToggleService,
}: TopBarProps) {
  return (
    <header className="border-b border-white/10 bg-[#0D121E]/95 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-6">
        <button
          type="button"
          onClick={() => onNavigate(role ? 'dashboard' : 'role-selection')}
          className="font-display text-xl font-bold tracking-tight text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF] rounded px-1"
        >
          NEXLINK
        </button>

        {role ? (
          <nav
            aria-label="التنقل الرئيسي"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-[#A5B1C6]"
          >
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors cursor-pointer hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF] rounded ${
                currentView === 'dashboard'
                  ? 'text-white underline decoration-[#4B91FF] decoration-2 underline-offset-8'
                  : ''
              }`}
            >
              لوحة التحكم
            </button>
            <button
              type="button"
              onClick={() => onNavigate('notification-apps')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors cursor-pointer hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF] rounded ${
                currentView === 'notification-apps'
                  ? 'text-white underline decoration-[#4B91FF] decoration-2 underline-offset-8'
                  : ''
              }`}
            >
              الإشعارات
            </button>
            <button
              type="button"
              onClick={() => onNavigate('notification-history')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors cursor-pointer hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF] rounded ${
                currentView === 'notification-history'
                  ? 'text-white underline decoration-[#4B91FF] decoration-2 underline-offset-8'
                  : ''
              }`}
            >
              سجل الإشعارات
            </button>
            <button
              type="button"
              onClick={onOpenPrivacy}
              className="whitespace-nowrap shrink-0 py-1 transition-colors cursor-pointer hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#4B91FF] rounded"
            >
              الأمان والنظام
            </button>
          </nav>
        ) : (
          <div className="hidden md:block" />
        )}

        <div className="flex items-center gap-3 shrink-0">
          {role && (
            <span
              className={`hidden sm:inline-block text-xs font-medium whitespace-nowrap ${
                connectionState === 'CONNECTED'
                  ? 'text-emerald-400'
                  : connectionState === 'CONNECTING' ||
                      connectionState === 'RECONNECTING'
                    ? 'text-[#FFBE50]'
                    : connectionState === 'ERROR'
                      ? 'text-red-400'
                      : 'text-[#A5B1C6]'
              }`}
            >
              {connectionState === 'CONNECTED'
                ? 'متصل بالمرحل'
                : connectionState === 'CONNECTING'
                  ? 'جاري الاتصال...'
                  : connectionState === 'RECONNECTING'
                    ? 'إعادة اتصال...'
                    : connectionState === 'ERROR'
                      ? 'تعذر الاتصال'
                      : 'غير متصل'}
            </span>
          )}

          {role ? (
            <button
              type="button"
              onClick={onToggleService}
              className={`min-h-[40px] px-4 py-2 text-xs sm:text-sm font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white ${
                serviceRunning
                  ? 'bg-[#192131] text-white border border-white/15 hover:bg-[#222c42]'
                  : 'bg-[#4B91FF] text-white hover:bg-[#3a7ee8]'
              }`}
            >
              {serviceRunning ? 'إيقاف خدمة الاتصال' : 'تشغيل خدمة الاتصال'}
            </button>
          ) : (
            <span className="text-xs text-[#A5B1C6] whitespace-nowrap shrink-0">
              الإصدار 1.1
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
