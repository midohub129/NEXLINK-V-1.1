# NEXLINK V 1.1

منصة ربط الأجهزة ومزامنة الإشعارات المشفرة من طرف إلى طرف (**End-to-End Encrypted Device Relay & Sync**) عبر **تطبيق ويب (React + TypeScript + IndexedDB)** وخادم **Relay Server (Express + WebSocket + SQLite)**.

> **نطاق المرحلة الحالية:** تستهدف هذه المرحلة تطبيق الويب وخادم المرحل (Relay) والبنية التشفيرية والمزامنة المرتبطة بهما مع تجهيز بروتوكول مشترك موثق لدمج عميل Android لاحقاً في المرحلة المخصصة له (`/docs/PROTOCOL_SPEC.md`).

---

## 1. البنية المعمارية (Architecture Overview)

يتبع المشروع نمط **Layered Clean Architecture** مع فصل كامل بين الطبقات وحقن الاعتماديات عبر `src/application/container.ts`:

- **Domain Layer (`src/domain/`)**: النماذج (`DeviceIdentityProfile`, `LinkedDevice`, `SyncEvent`, `E2eeEnvelope`), الأخطاء الموحدة (`AppError`), وواجهات المستودعات والخدمات.
- **Application Layer (`src/application/`)**:
  - `DeviceManager`: تهيئة هوية الجهاز المنفصلة (`ECDSA P-256` + `ECDH P-256`)، الاقتران المتبادل، وإدارة الثقة وسحبها.
  - `SecurityManager`: فصل المصادقة (`LOCAL_UI` + `RELAY_SERVER`) عن التفويض (`RBAC`: `admin` مقابل `basic`) وسجل التدقيق الأمني.
  - `SyncEngine`: طابور مزامنة موثوق (FIFO) مع منع التكرار (`idempotencyKey` + نافذة 60 ثانية)، إعادة المحاولة بـ Exponential Backoff، وسياسة التسليم المؤكد من الطرف المقابل (`PEER_CONFIRMED`).
  - `LifecycleManager` / `SettingsService` / `HealthMonitor` / `RotatingLogger`.
- **Infrastructure Layer (`src/infrastructure/`)**:
  - `IndexedDbDatabase` + `repositories.ts`: تخزين محلي مشفّر (`AES-256-GCM`) مع ترحيلات ممرقمة (v1–v3).
  - `WebCryptoProvider`: مستودع مفاتيح غير قابل للاستخراج (`nexlink_keystore`) للتشفير المحلي والتوقيع واشتقاق مفاتيح E2EE.
  - `RelayTransportClient`: عميل HTTP موقّع بكل طلب (`X-Nexlink-Timestamp`, `X-Nexlink-Nonce`, `X-Nexlink-Signature`) + قناة WebSocket مصادق عليها بتذكرة استخدام واحد (`/ws/ticket`).
- **Presentation Layer (`src/presentation/`)**: واجهة React 19 + Tailwind CSS (RTL عربية) خالية من البيانات الوهمية.
- **Relay Server (`server.ts`, `server/relay/relayRouter.ts`, `server/db/sqliteRelayDb.ts`)**: خادم Express + `ws` + `node:sqlite` (ترحيلات v1–v5، نمط WAL، صفر نصوص واضحة على الخادم).

للاطلاع على القرارات المعمارية التفصيلية، راجع مجلد `docs/adr/` وملف `docs/SERVER_SETUP.md`.

---

## 2. المتطلبات ومتغيرات البيئة (Requirements & Environment)

- **Node.js `>= 22.0.0`** (مطلوب لواجهة `node:sqlite` المدمجة وWeb Crypto / Node Crypto P-256).
- **npm** (لتثبيت الحزم القابل للتكرار عبر `package-lock.json`).

أنشئ ملف `.env` محلياً انطلاقاً من `.env.example` (لا تضف `.env` إلى Git أبداً):

```env
NEXLINK_PORT=3000
NEXLINK_DB_PATH=.data/nexlink_relay.sqlite
NEXLINK_SESSION_SECRET=<random-secret-at-least-32-chars>
```

| المتغير | الوصف | الافتراضي |
| --- | --- | --- |
| `NEXLINK_PORT` | منفذ خادم HTTP وWebSocket | `3000` |
| `NEXLINK_DB_PATH` | مسار قاعدة بيانات SQLite التشغيلية للـ Relay | `.data/nexlink_relay.sqlite` |
| `NEXLINK_SESSION_SECRET` | مفتاح HMAC-SHA-256 لتوقيع جلسات Relay (يُولَّد عشوائياً عند التشغيل إن لم يُحدد) | عشوائي في الذاكرة |

> يتم إنشاء قاعدة البيانات وتطبيق الترحيلات (Schema v1 → v5) تلقائياً عند تشغيل الخادم إذا لم تكن موجودة مسبقاً.

---

## 3. التشغيل والبناء (Setup, Run & Production Build)

```bash
# 1. تثبيت الاعتماديات بشكل متطابق مع package-lock.json
npm ci

# 2. تشغيل بيئة التطوير (Express Relay + WebSocket + Vite Middleware على المنفذ 3000)
npm run dev

# 3. بناء نسخة الإنتاج
npm run build

# 4. تشغيل خادم الإنتاج
npm start
```

---

## 4. الفحوصات والاختبارات وCI (Verification & Testing)

يعمل سير العمل `.github/workflows/ci.yml` تلقائياً عند كل `push` أو `pull_request` على فرع `main` وينفذ جميع البوابات التالية (ويفشل فوراً عند تعثر أي خطوة):

| الفحص | الأمر |
| --- | --- |
| فحص الأنواع (TypeScript) | `npm run typecheck` |
| فحص القواعد البرمجية (ESLint) | `npm run lint` |
| فحص تنسيق الكود (Prettier) | `npm run format:check` |
| اختبارات الوحدة (Unit Tests) | `npm run test:unit` |
| اختبارات التكامل والأمان (Integration Tests) | `npm run test:integration` |
| جميع الاختبارات معاً | `npm test` |
| بناء الإنتاج | `npm run build` |
| فحص ثغرات الاعتماديات | `npm audit --audit-level=moderate` |

---

## 5. تدفقات المصادقة والاقتران وE2EE والمزامنة

1. **الهوية المنفصلة والتسجيل الموقّع**: يولّد كل جهاز زوجَي مفاتيح غير قابلين للاستخراج (`ECDSA P-256` للتوقيع + `ECDH P-256` لتبادل المفاتيح) مع بصمة `cryptoKeyId = "ecdsa-" + sha256(x + ":" + y)[0..24]`. عند الاتصال يوقّع الجهاز طلب `/devices/register` ثم يجتاز تحدي `/auth/challenge` → `/auth/session` ويحصل على جلسة Bearer وتذكرة WebSocket ذات استخدام واحد (`/ws/ticket`).
2. **توقيع كل طلب محمي**: يحمل كل طلب HTTP محمي ترويسة `Bearer` مع `X-Nexlink-Timestamp` (نافذة ±60 ثانية) و`X-Nexlink-Nonce` (مخزن في `used_nonces` لمنع Replay) و`X-Nexlink-Signature`.
3. **الاقتران المتبادل (Two-Phase Mutual Pairing)**:
   - يُنشئ `Super Admin` رمزاً من 6 أرقام عبر `/pairing/request` (صالح لمدة 5 دقائق؛ يُقفل `423 LOCKED` بعد 5 محاولات خاطئة).
   - يُرسل الطرف الثاني الرمز عبر `/pairing/accept` (يُرفض إعادة الاستخدام بـ `409 ALREADY_CONSUMED`).
   - يتحقق `Super Admin` من بصمة `responderCryptoKeyId` ويؤكد أو يرفض عبر `/pairing/confirm` قبل إنشاء ربط `PAIRED` في `device_links`.
4. **التشفير من طرف إلى طرف (E2EE)**:
   - يشتق `SyncEngine` مفتاحاً مشتركاً عبر `ECDH P-256` + `HKDF-SHA-256` مربوطاً بـ `senderDeviceId`, `recipientDeviceId`, `senderCryptoKeyId`, `recipientCryptoKeyId`, `sessionId`, `messageNonce`.
   - يُشفّر المحتوى بـ `AES-256-GCM` مع `AAD` تتضمن `idempotencyKey`، ويُوقَّع المغلف بـ `ECDSA P-256`.
   - يخزن خادم المرحل المغلف المشفر فقط (`[E2EE_CIPHERTEXT]`، صفر نصوص واضحة) ويتحقق من تطابق `senderCryptoKeyId` و`recipientCryptoKeyId`.
5. **المزامنة المؤكدة من الطرف المقابل (`PEER_CONFIRMED`)**:
   - استلام المرحل ينقل الحدث محلياً إلى `IN_PROGRESS` (`relayAcceptedAt` مضبوط، `deliveredAt = null`) ولا يُعدّ `SYNCED`.
   - عند استلام الطرف المقابل عبر WebSocket أو عبر `/sync/:deviceId/inbox` بعد عودته للاتصال، يتحقق من التوقيع وAAD ويفك التشفير، ويحفظ الحدث مع منع التكرار عبر `idempotencyKey`، ثم يرسل `/sync/ack` لتنتقل الحالة عند المرسل إلى `SYNCED` مع `deliveredAt`.

---

## 6. ما هو منفّذ حالياً وما هو مؤجّل

### منفّذ في المرحلة الحالية (Web + Relay)
- تطبيق ويب متكامل بإدارة الأدوار، الأذونات، اختيار حزم الإشعارات، سجل الإشعارات وطابور المزامنة (`NotificationHistoryView` + البحث والتصفية)، مركز الأمان والإعدادات والنسخ الاحتياطي المتحقق منه بـ SHA-256.
- خادم Relay متكامل مع قاعدة بيانات SQLite بترحيلات v1–v5، WebSocket فوري، E2EE إجباري، وسحب الثقة الفوري.
- اختبارات وحدة وتكامل تغطي الأمان السلبي، الاقتران، E2EE، ودورة المزامنة بين جهازين.

### مؤجّل للمرحلة اللاحقة أو يتطلب قدرات أصيلة
- **تطبيق Android الأصيل (`/app/`)**: ملفات Kotlin/Room الأولية موجودة مرجعياً؛ سيجري استكمال التنفيذ والربط مع `Android Keystore` و`NotificationListenerService` ومهام Gradle/CI في مرحلة Android اللاحقة وفق `docs/PROTOCOL_SPEC.md`.
- **الالتقاط التلقائي لإشعارات النظام وإحصاءات الاستخدام**: لا يوفر المتصفح وصولاً لإشعارات التطبيقات الأخرى؛ لذلك يوضح التطبيق قدرات المتصفح بصدق ويوفر وضع `Test Fixtures` + أداة إدراج اختبارية في سجل الإشعارات.
- **مشاركة الشاشة ونقل الملفات عبر WebRTC**: خارج نطاق هذا الإصدار وتمت إزالة بطاقاتها غير المكتملة من لوحة التحكم.

---

## 7. نظافة مستودع Git (Operational DB & Build Artifacts)

ملفات قاعدة البيانات التشغيلية (`.data/nexlink_relay.sqlite*`, `*-wal`, `*-shm`) وملفات البناء (`tsconfig.tsbuildinfo`, `dist/`) مستثناة في `.gitignore`. إذا كانت هذه الملفات متتبّعة مسبقاً في تاريخ فرع Git البعيد، أزل تتبّعها دون حذفها محلياً عبر:

```bash
git rm -r --cached .data tsconfig.tsbuildinfo
git commit -m "chore: stop tracking runtime sqlite files and tsbuildinfo"
```