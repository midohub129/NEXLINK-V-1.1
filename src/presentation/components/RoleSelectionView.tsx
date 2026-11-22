import type { DeviceRole } from '../../domain/models/device';

interface RoleSelectionViewProps {
  onSelectRole: (role: DeviceRole) => Promise<void>;
}

export function RoleSelectionView({ onSelectRole }: RoleSelectionViewProps) {
  return (
    <main className="max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-16">
      <div className="mb-10">
        <p className="text-sm font-semibold text-[#4B91FF] mb-2">NEXLINK</p>
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-3">
          الإعداد الأولي
        </h1>
        <p className="text-base text-[#A5B1C6] max-w-2xl leading-relaxed">
          اختر دور هذا الجهاز في شبكة NEXLINK. يتم حفظ الإعدادات في قاعدة البيانات
          المحلية مع هوية تشفيرية مستقلة.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8 items-stretch">
        <section className="bg-[#192131] rounded-xl p-6 flex flex-col justify-between border border-white/5">
          <div>
            <p className="font-mono text-xs font-semibold tracking-wide text-[#4B91FF] mb-3">
              SUPER ADMIN
            </p>
            <h2 className="text-xl font-bold text-white mb-2">الجهاز الرئيسي</h2>
            <p className="text-sm text-[#A5B1C6] leading-relaxed mb-6">
              إدارة الأجهزة المرتبطة، إنشاء رموز الاقتران، تعديل سجلات المزامنة، وتصدير
              النسخ الاحتياطية.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void onSelectRole('admin')}
            className="w-full min-h-[44px] py-3 px-4 bg-[#4B91FF] hover:bg-[#3a7ee8] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
          >
            اختيار هذا الدور
          </button>
        </section>

        <section className="bg-[#192131] rounded-xl p-6 flex flex-col justify-between border border-white/5">
          <div>
            <p className="font-mono text-xs font-semibold tracking-wide text-[#4B91FF] mb-3">
              BASIC DEVICE
            </p>
            <h2 className="text-xl font-bold text-white mb-2">الجهاز التابع</h2>
            <p className="text-sm text-[#A5B1C6] leading-relaxed mb-6">
              استقبال رموز الربط، مراجعة الأذونات، ومشاركة الإشعارات الموافق عليها مع
              إمكانية سحب التفويض في أي وقت.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void onSelectRole('basic')}
            className="w-full min-h-[44px] py-3 px-4 bg-[#4B91FF] hover:bg-[#3a7ee8] active:scale-[0.99] text-white text-sm font-bold rounded-lg transition-all whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
          >
            اختيار هذا الدور
          </button>
        </section>
      </div>

      <p className="text-xs text-[#A5B1C6] leading-relaxed">
        اختيار الدور لا يمنح أي صلاحيات نظام أو اقتران عن بُعد تلقائياً. تتم جميع عمليات
        الاقتران والمزامنة عبر التحقق من خادم المرحل.
      </p>
    </main>
  );
}
