# NEXLINK Shared Wire, Security & Sync Protocol Specification (V 1.1)

توثّق هذه المواصفة البروتوكول المشترك بين **تطبيق الويب (Web Client)** و**خادم المرحل (Relay Server)**، وتُعدّ العقد التقني الملزم لأي عميل **Android** يُدمج لاحقاً في المرحلة القادمة لضمان التوافق التام في الهوية والاقتران والتشفير والمزامنة.

---

## 1. Identity & Key Material

يمتلك كل جهاز هوية مستقلة تتكوّن من:
1. **`publicId`**: معرّف فريد (UUID v4، بطول ≥ 4 محارف).
2. **مفتاح التوقيع (`ECDSA P-256`)**:
   - الجيل على الويب: Web Crypto `ECDSA` (`namedCurve: "P-256"`, `hash: "SHA-256"`, `extractable: false`).
   - الجيل المقابل على Android: `AndroidKeyStore` (`KeyProperties.KEY_ALGORITHM_EC`, `secp256r1`, `DIGEST_SHA256`).
   - **بصمة المفتاح (`cryptoKeyId`)**:
     ```text
     cryptoKeyId = "ecdsa-" + hex(SHA-256(utf8(jwk.x + ":" + jwk.y))).slice(0, 24)
     ```
     حيث `jwk.x` و`jwk.y` هما الإحداثيان بصيغة Base64URL كما في JWK المعياري.
3. **مفتاح تبادل الأسرار (`ECDH P-256`)**:
   - JWK عام (`kty: "EC"`, `crv: "P-256"`, `x`, `y`) يُرسل عند التسجيل ويُربط بالهوية.
4. **مفتاح التخزين المحلي (`AES-256-GCM`)**: خاص بكل جهاز لتشفير البيانات المحلية فقط (`IndexedDB` / `Room + Keystore`) ولا يُرسل أبداً.

---

## 2. Relay Authentication & Signed Request Format

المسار الأساسي: `/api/relay` (HTTP) و`/ws/relay` (WebSocket).

### 2.1 Registration (`POST /devices/register`)
Body:
```json
{
  "publicId": "<uuid>",
  "cryptoKeyId": "ecdsa-...",
  "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "ecdhPublicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "role": "admin" | "basic",
  "label": "Device Name",
  "timestamp": 1700000000000,
  "nonce": "<>=16-char random hex>",
  "signature": "<Base64 IEEE-P1363 ECDSA-SHA256>"
}
```
السلسلة الموقّعة:
```text
REGISTER|{publicId}|{cryptoKeyId}|{sha256Hex(JSON.stringify(ecdhPublicKeyJwk))}|{role}|{timestamp}|{nonce}
```
- يرفض الخادم أي تعارض في `cryptoKeyId` لـ `publicId` مسجّل مسبقاً (`403 IDENTITY_CONFLICT`) أو جهازاً مسحوب الثقة (`403 DEVICE_REVOKED`).

### 2.2 Challenge-Response Session (`POST /auth/challenge` → `POST /auth/session`)
1. `POST /auth/challenge` مع `{ "publicId": "..." }` يعيد `{ "challenge": "<hex>", "expiresAt": <ms> }` (صالح 60 ثانية).
2. يوقّع العميل:
   ```text
   AUTH|{publicId}|{challenge}|{timestamp}|{nonce}
   ```
   ويرسلها إلى `POST /auth/session` ليستلم `{ sessionId, token, devicePublicId, cryptoKeyId, role, issuedAt, expiresAt }`.

### 2.3 Authenticated HTTP Request Proof
كل نقطة نهاية محمية تتطلب الترويسات التالية:
- `Authorization: Bearer <sessionId>.<hmacSha256Hex>`
- `X-Nexlink-Timestamp: <unixMs>` (ضمن نافذة ±60,000 ms)
- `X-Nexlink-Nonce: <unique >=16 chars>` (أحادي الاستخدام في `used_nonces`؛ التكرار يعيد `409 REPLAY_DETECTED`)
- `X-Nexlink-Signature: <Base64 IEEE-P1363 ECDSA-SHA256>` على:
  ```text
  {HTTP_METHOD}|{pathname + search}|{sha256Hex(rawJsonBody)}|{timestamp}|{nonce}
  ```

### 2.4 WebSocket Ticket Handshake
- يستدعي العميل `POST /ws/ticket` (موقّعاً) للحصول على `{ "ticket": "<hex>", "expiresAt": <ms> }` (صالح 30 ثانية ولمرة واحدة).
- يفتح الاتصال على `wss://<host>/ws/relay?ticket=<ticket>`. أي محاولة للاتصال دون تذكرة صالحة أو إعادة استخدام التذكرة تُغلق برمز `1008`.

---

## 3. Two-Phase Mutual Pairing Protocol

1. **`POST /pairing/request`** (`admin` فقط): ينشئ رمزاً رقمياً من 6 خانات (`pairingId`, `pairingCode`, `expiresAt = now + 5m`, حالة `PENDING`).
2. **`POST /pairing/accept`**: يرسل الجهاز الطرف `{ "pairingCode": "123456" }`:
   - يمنع الخادم الاقتران بالذات (`409 SELF_PAIRING`)، وإعادة استخدام الرمز (`409 ALREADY_CONSUMED`)، والرمز المنتهي (`404 EXPIRED`).
   - بعد 5 محاولات فاشلة (`NOT_FOUND`) على الطلبات النشطة، تتحول حالتها إلى `LOCKED` ويُرجع الخادم `423 LOCKED`.
   - عند النجاح تنتقل الحالة إلى `AWAITING_REQUESTER_CONFIRMATION` ويُدفع حدث WebSocket `pairing:pending_approval` للمنشئ.
3. **`POST /pairing/confirm`**: يرسل `Super Admin` `{ "pairingId": "...", "approve": true | false, "expectedResponderCryptoKeyId": "ecdsa-..." }`:
   - يتحقق الخادم من الملكية ومن مطابقة `expectedResponderCryptoKeyId` (`409 KEY_FINGERPRINT_MISMATCH`).
   - عند `approve: true` يتحول الربط إلى `PAIRED` ويُدفع `device:paired` للطرفين.
   - عند `approve: false` يتحول الطلب إلى `REJECTED` ولا يُنشأ أي ارتباط.
4. **سحب الثقة (`POST /devices/:deviceId/revoke`)**:
   - يضع حالة الارتباط `REVOKED`، وعند `revokeDeviceTrust: true` (للـ `admin`) يبطل جميع جلسات الهدف ويضبط حالته إلى `REVOKED` ويغلق اتصالات WebSocket فوراً (`1008`).

---

## 4. End-to-End Encryption (`E2eeEnvelope` v1)

يستخدم الطرفان نفس مواصفة `ECDH-P256+HKDF-SHA256+AES-256-GCM`:

1. **اشتقاق المفتاح**:
   - `sharedBits = ECDH(myEcdhPrivateKey, peerEcdhPublicKey)` (256 bits)
   - `salt = utf8("nexlink-e2ee-v1-salt")`
   - `info = utf8("nexlink-e2ee-v1|{senderDeviceId}|{recipientDeviceId}|{senderCryptoKeyId}|{recipientCryptoKeyId}|{sessionId}|{messageNonce}")`
   - `aesKey = HKDF-SHA-256(ikm = sharedBits, salt, info, length = 256 bits)`

2. **البيانات المرتبطة الموثّقة (`aad`)**:
   سلسلة JSON بالحقول التالية:
   ```json
   {
     "v": 1,
     "senderDeviceId": "...",
     "recipientDeviceId": "...",
     "senderCryptoKeyId": "ecdsa-...",
     "recipientCryptoKeyId": "ecdsa-...",
     "sessionId": "...",
     "messageNonce": "<>=16 chars>",
     "idempotencyKey": "<sha256>"
   }
   ```

3. **التشفير والتوقيع**:
   - `iv`: 12 بايت عشوائية لكل رسالة.
   - `ciphertext`: ناتج `AES-256-GCM(aesKey, iv, aad, utf8(plaintext))` بصيغة Base64.
   - `signature`: توقيع المرسل `ECDSA P-256 SHA-256` (IEEE-P1363 Base64) على:
     ```text
     E2EE|{sha256Hex(aad)}|{sha256Hex(ivBase64 + ":" + ciphertextBase64)}
     ```

4. **التحقق على الخادم والمستلم**:
   - يرفض خادم Relay أي حدث بلا `e2eeEnvelope` صحيح (`422 E2EE_ENVELOPE_REQUIRED`) أو عند عدم تطابق `senderCryptoKeyId` / `recipientCryptoKeyId` (`422 E2EE_KEY_ID_MISMATCH`).
   - يتحقق المستلم من ارتباطه بالمرسل (`PAIRED` وبصمة مطابقة)، ومن تطابق `aad` مع الغلاف ومع `remoteEvent.idempotencyKey`، ومن توقيع ECDSA قبل فك تشفير AES-GCM، ويرفض تكرار `messageNonce` أو `idempotencyKey`.

---

## 5. Delivery-Verified Sync State Machine

| الحالة المحلية | المعنى | الانتقالات |
| --- | --- | --- |
| `PENDING` | محفوظ ومشفّر محلياً بانتظار الإرسال أو إعادة المحاولة بعد Backoff | `→ IN_PROGRESS` عند بدء الإرسال |
| `IN_PROGRESS` | أُرسل وقَبِله Relay (`relayAcceptedAt != null`) وبانتظار تأكيد الطرف المقابل | `→ SYNCED` عند `/sync/ack` أو `sync:delivered`؛ `→ PENDING` عند إعادة التشغيل أو سحب الاقتران |
| `SYNCED` | للوارد: فُك تشفيره وحُفظ محلياً وأُرسل ACK. للصادر: تم استلام تأكيد المستلم (`deliveredAt != null`) في سياسة `PEER_CONFIRMED` | حالة نهائية |
| `FAILED` | تجاوز الحد الأقصى لإعادة المحاولة (`maxSyncRetries`) | `→ PENDING` عند إعادة المحاولة اليدوية |

- **نقاط نهاية المزامنة**:
  - `POST /sync`: إرسال دفعة أحداث مشفرة.
  - `GET /sync/:deviceId/inbox`: سحب الأحداث الواردة للأجهزة المقترنة عند الاتصال أو الاستعادة.
  - `POST /sync/ack`: تأكيد المستلم بعد نجاح التحقق التشفيري والحفظ المحلي.
  - `GET /sync/:deviceId/status?ids=1,2`: استعلام المرسل عن تأكيدات التسليم المعلّقة.
