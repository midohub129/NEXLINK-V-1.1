import type {
  DataSourceAppInfo,
  DataSourceAvailability,
  IDataSource,
} from '../../domain/interfaces/services';

export const SELF_PACKAGE_NAME = 'com.nexlink.app';

export function formatForegroundDuration(durationMs: number | null): string {
  if (durationMs === null || durationMs < 0) {
    return 'غير متاح على المتصفح';
  }
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}س ${minutes}د`;
  }
  if (minutes > 0) {
    return `${minutes}د ${seconds}ث`;
  }
  return `${seconds}ث`;
}

/**
 * Honest production browser capability data source.
 * Never returns fabricated OS telemetry or static mock app lists as real OS data.
 */
export class BrowserDeviceDataSource implements IDataSource {
  readonly mode = 'PRODUCTION' as const;

  getAvailability(): DataSourceAvailability {
    return {
      installedAppsAvailable: false,
      usageStatsAvailable: false,
      backgroundNotificationCaptureAvailable: false,
      reason:
        'بيئة المتصفح لا تتيح قراءة قائمة تطبيقات نظام أندرويد (PackageManager) أو إحصائيات الاستخدام (UsageStatsManager) أو التقاط الإشعارات في الخلفية (NotificationListenerService). تتطلب هذه البيانات تطبيق أندرويد الأصلي المرفق أو تفعيل وضع بيانات الاختبار التجريبية صراحةً.',
    };
  }

  async getInstalledApps(): Promise<DataSourceAppInfo[]> {
    return [];
  }

  async getUsageStatsLast24h(): Promise<DataSourceAppInfo[]> {
    return [];
  }
}

/**
 * Isolated test-fixture data source strictly for testing and explicit QA inspection.
 * Never presented as live production OS data.
 */
const TEST_FIXTURE_APPS: DataSourceAppInfo[] = [
  {
    packageName: 'com.whatsapp',
    appName: 'WhatsApp',
    foregroundTimeMs: 4_920_000,
    sourceKind: 'TEST_FIXTURE',
  },
  {
    packageName: 'org.telegram.messenger',
    appName: 'Telegram',
    foregroundTimeMs: 3_180_000,
    sourceKind: 'TEST_FIXTURE',
  },
  {
    packageName: 'com.google.android.gm',
    appName: 'Gmail',
    foregroundTimeMs: 1_560_000,
    sourceKind: 'TEST_FIXTURE',
  },
  {
    packageName: 'com.android.chrome',
    appName: 'Chrome',
    foregroundTimeMs: 5_400_000,
    sourceKind: 'TEST_FIXTURE',
  },
  {
    packageName: 'com.slack',
    appName: 'Slack',
    foregroundTimeMs: 2_250_000,
    sourceKind: 'TEST_FIXTURE',
  },
  {
    packageName: 'com.instagram.android',
    appName: 'Instagram',
    foregroundTimeMs: 1_890_000,
    sourceKind: 'TEST_FIXTURE',
  },
];

export class TestFixtureDeviceDataSource implements IDataSource {
  readonly mode = 'TEST_FIXTURE' as const;

  getAvailability(): DataSourceAvailability {
    return {
      installedAppsAvailable: true,
      usageStatsAvailable: true,
      backgroundNotificationCaptureAvailable: false,
      reason:
        'وضع بيانات الاختبار التجريبية مفعّل: التطبيقات ومدة الاستخدام المعروضة هنا هي بيانات اختبار ثابتة (Test Fixtures) وليست قراءة فعلية من نظام التشغيل.',
    };
  }

  async getInstalledApps(): Promise<DataSourceAppInfo[]> {
    return TEST_FIXTURE_APPS.filter((app) => app.packageName !== SELF_PACKAGE_NAME).map(
      (app) => ({ ...app })
    );
  }

  async getUsageStatsLast24h(): Promise<DataSourceAppInfo[]> {
    return TEST_FIXTURE_APPS.filter(
      (app) => app.packageName !== SELF_PACKAGE_NAME && (app.foregroundTimeMs ?? 0) > 0
    )
      .sort((a, b) => (b.foregroundTimeMs ?? 0) - (a.foregroundTimeMs ?? 0))
      .map((app) => ({ ...app }));
  }
}
