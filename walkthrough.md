# Security & Reliability Audit Walkthrough — NEXLINK

## Security Summary

This walkthrough documents the P0 and P1 security and reliability remediations implemented across the NEXLINK Relay Server, Inter-Device End-to-End Encryption (E2EE), Mutual Pairing & Trust Management, Sync Engine, Key/Session Management, and Project Operations.

### 1. Relay Server Authentication, Anti-Spoofing & Authorization (P0)
- **Challenge-Response Device Authentication (`/devices/register`, `/auth/challenge`, `/auth/session`)**:
  - Devices generate non-extractable `ECDSA P-256` + `ECDH P-256` keys in the browser `nexlink_keystore` (`IndexedDB` KeyStore) and register their immutable `cryptoKeyId = "ecdsa-" + sha256(x + ":" + y).slice(0, 24)`.
  - Re-registering an existing `publicId` with a different `cryptoKeyId` is rejected with `409 IDENTITY_CONFLICT`.
  - Session creation requires signing an expiring single-use challenge (`AUTH|<publicId>|<challenge>|<timestamp>|<nonce>`), returning an `HMAC-SHA-256` signed Bearer token persisted as a SHA-256 `token_hash` in `device_sessions`.
- **Per-Request Cryptographic Proof & Anti-Replay**:
  - Every authenticated endpoint enforces `requireAuthenticatedDevice`:
    - Validates `Authorization: Bearer <token>` signature (`timingSafeEqual`) + active non-revoked SQLite session + `devices.status = 'ACTIVE'`.
    - Verifies `X-Nexlink-Timestamp` within `±60s`, single-use `X-Nexlink-Nonce` stored in `used_nonces` (`409 REPLAY_DETECTED` on reuse), and `ECDSA P-256` (`IEEE P1363`) signature over `METHOD|PATH+SEARCH|SHA256(BODY)|TIMESTAMP|NONCE`.
- **Server-Side Ownership & RBAC Enforcement**:
  - Path/body `deviceId` values are checked against `req.authDevice.publicId` (`403 FORBIDDEN_OWNERSHIP`).
  - Admin-only operations (`POST /pairing/request`, permanent device trust revocation) require `req.authDevice.role === 'admin'` (`403 FORBIDDEN_ROLE`).
- **WebSocket Anti-Spoofing**:
  - Direct `?deviceId=` query parameters are rejected; upgrades require a single-use, 30-second WS ticket issued via authenticated `POST /ws/ticket` (`401`/close `1008` otherwise).
- **Rate Limiting & Error Hygiene**:
  - Sliding-window HTTP rate limiting (`generalLimiter` + `strictAuthLimiter`) and 5-attempt pairing brute-force lockout (`423 LOCKED`).
  - Global Express error middleware handles malformed JSON (`400 MALFORMED_REQUEST`) and unexpected exceptions (`500 INTERNAL_SERVER_ERROR`) without exposing stack traces.

### 2. Inter-Device End-to-End Encryption (E2EE) (P0)
- **Cipher Suite**: `ECDH-P256+HKDF-SHA256+AES-256-GCM` with `ECDSA P-256` envelope signature.
- **Per-Message Session & Context Binding**:
  - Sender derives a shared secret via ECDH (`myEcdhPrivateKey`, `peerEcdhPublicKey`), expands it via `HKDF-SHA-256` with `info = nexlink-e2ee:<senderDeviceId>-><recipientDeviceId>:<sessionId>`, and encrypts UTF-8 JSON plaintext with `AES-256-GCM` using a CSPRNG 96-bit IV and bound AAD (`v1|<senderId>|<senderKeyId>|<recipientId>|<recipientKeyId>|<sessionId>|<messageNonce>|<idempotencyKey>`).
  - The envelope is signed with the sender's `ECDSA P-256` key over all envelope fields and ciphertext.
- **Zero Plaintext on Relay**:
  - `POST /sync` rejects unencrypted/missing/mismatched `e2eeEnvelope` payloads with `422 E2EE_ENVELOPE_REQUIRED`, stores only `payload = "[E2EE_CIPHERTEXT]"` + `e2eeEnvelope` in `relay_events`, and never inspects or stores notification plaintext.
- **Tamper & Replay Resistance**:
  - Inbound processing verifies sender trust (`PAIRED` + `verifiedByRelay` + pinned `cryptoKeyId`), rejects reused `messageNonce` (`REPLAY_BLOCKED`), verifies ECDSA signature, and enforces AES-GCM authentication tag + AAD binding (`E2EE_DECRYPT_FAILED`).

### 3. Two-Phase Mutual Pairing & Trust Revocation (P0)
- **Mutual Approval State Machine**:
  1. Super Admin requests a single-use 6-digit code (`PENDING`, 5-minute TTL).
  2. Responder submits the code via authenticated `POST /pairing/accept` -> transitions to `AWAITING_REQUESTER_CONFIRMATION` (single-use; replay returns `409 ALREADY_CONSUMED`).
  3. Requester inspects responder's `responderCryptoKeyId` fingerprint and confirms/rejects via `POST /pairing/confirm` (`409 KEY_FINGERPRINT_MISMATCH` if pinned fingerprint mismatches) -> `device_links` becomes `PAIRED`.
- **Full Trust Revocation**:
  - `POST /devices/:deviceId/revoke` updates `device_links` to `REVOKED` and (when `revokeDeviceTrust=true` by an admin) sets `devices.status = 'REVOKED'`, invalidates all `device_sessions`, broadcasts `device:revoked`, and closes active WebSockets with code `1008`.

### 4. Sync Engine Reliability, Keys & Sessions (P1)
- **Peer Verification & Delivery Policy**:
  - Outbound sync skips with `UNPAIRED` unless a verified `PAIRED` target peer with ECDH/ECDSA keys exists.
  - Supports `PEER_CONFIRMED` (remains `IN_PROGRESS` until recipient decrypts & sends `/sync/ack`, updating `delivered_at`) and `RELAY_QUEUED`.
  - Partial batch failures commit accepted items and schedule exponential backoff retries only for failed items; `recoverStuckEvents()` resets `IN_PROGRESS` items on restart.
- **CSPRNG & Session Scope Separation**:
  - Eliminated all `Math.random()` usage; IDs/nonces/session IDs use `crypto.getRandomValues` / `node:crypto.randomBytes`.
  - Separated `LOCAL_UI` in-memory session timers from `RELAY_SERVER` authenticated Bearer sessions.
- **Data Exposure Assessment**:
  - Sensitive private keys remain non-extractable in browser `nexlink_keystore` (or OS Android Keystore in native builds); secrets are redacted in `RotatingLogger`, and no plaintext sync content is logged or transmitted to the Relay.

---

## PoC Verification

### 1. Automated Verification Suite (`npm test`, `typecheck`, `lint`, `format:check`, `build`, `audit`)
Executed cleanly after all final edits:
- `npm run format:check`: **Passed** (`All matched files use Prettier code style!`)
- `npm run typecheck`: **Passed** (`tsc -b --noEmit`, 0 errors)
- `npm run lint`: **Passed** (`eslint .`, 0 errors, 0 warnings)
- `npm test`: **Passed — 7 suites, 16/16 tests passed (0 failed)**, covering all 12 required security/reliability scenarios in `tests/integration/securityAuditRemediation.test.ts`, `tests/integration/relayTransportAndSync.test.ts`, and `tests/unit/*.test.ts`:
  1. Unauthorized Device Registration rejected (`401 INVALID_DEVICE_SIGNATURE`)
  2. Forged Device Identity / key overwrite rejected (`409 IDENTITY_CONFLICT`)
  3. Unauthorized Device Revocation by non-owner/non-admin rejected (`403 FORBIDDEN_OWNERSHIP`)
  4. Pairing Replay Attack (reusing consumed 6-digit code) rejected (`409 ALREADY_CONSUMED`) + 5 failed guesses trigger `423 LOCKED`
  5. Invalid Request Signature & Nonce Replay rejected (`401 INVALID_REQUEST_SIGNATURE` / `409 REPLAY_DETECTED`)
  6. WebSocket Identity Spoofing without valid single-use ticket closed (`1008` / rejected)
  7. Unauthorized Sync Request (spoofed `deviceId` or unpaired target) rejected (`403 FORBIDDEN_OWNERSHIP` / `403 TARGET_NOT_PAIRED`)
  8. End-to-End Encryption Integrity verified (`relay_events.payload === "[E2EE_CIPHERTEXT]"`, zero plaintext on server, peer decrypts authentically)
  9. Tampered Ciphertext / AAD / Key Rejection verified (`E2EE_DECRYPT_FAILED`, audit logged, zero ACK sent)
  10. Duplicate Delivery Prevention verified (`idempotencyKey` dedup + inbound `messageNonce` `REPLAY_BLOCKED`)
  11. Partial Sync Failure Recovery verified (accepted subset committed, failed subset retried after backoff without duplicate dispatch)
  12. Revoked Device Session & WebSocket Rejection verified (post-revocation HTTP returns `401 SESSION_REVOKED_OR_EXPIRED`, revoked WS closed `1008`)
- `npm run build`: **Passed** (`tsc -b && vite build` clean output)
- `npm audit --audit-level=moderate`: **Passed** (`found 0 vulnerabilities`)

### 2. Live HTTP Server PoC (`http://127.0.0.1:3000`)
Verified against running Express + SQLite Relay Server on port 3000:
- `GET /api/relay/health` -> `HTTP 200` `{"ok":true,"schemaVersion":5,"connectedSockets":0,...}`
- `POST /api/relay/sync` (unauthenticated) -> `HTTP 401` `{"error":"مصادقة الجلسة مطلوبة.","code":"MISSING_BEARER_TOKEN"}`
- `POST /api/relay/devices/register` (malformed JSON) -> `HTTP 400` `{"error":"طلب JSON غير صالح.","code":"MALFORMED_REQUEST"}`

### 3. Headless Chromium UI Verification (`playwright-cli` on `http://localhost:3000`)
- Verified initial Role Selection screen, Super Admin selection, Dashboard transition, and live `POST /devices/register` -> `/auth/challenge` -> `/auth/session` -> `/ws/ticket` -> WebSocket connection (`متصل بخادم المرحل — بانتظار ربط جهاز`).
- Verified Pairing modal (`ربط الأجهزة عبر خادم المرحل`) and Security modal (`LOCAL_UI` vs `RELAY_SERVER` session scopes, `IndexedDB KeyStore` notice, `AES-256-GCM · ECDSA P-256`).
- Browser console check: **0 errors, 0 warnings**.
