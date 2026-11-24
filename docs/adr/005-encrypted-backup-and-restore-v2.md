# ADR-005: Encrypted Backup & Restore v2 (`EncryptedBackupArchive v2`)

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
NEXLINK V1.1 previously exported backups (`BackupArchive` v1) as unencrypted plaintext JSON protected only by an unkeyed SHA-256 digest (`checksumSha256`). That design had four critical flaws:
1. Decrypted notification titles, texts, device links, and settings were written and previewed in plaintext.
2. An unkeyed SHA-256 hash provided no integrity/authenticity guarantee against deliberate modification (anyone could alter data and recompute SHA-256).
3. Restore replaced `STORES.IDENTITY` with the source device's `publicId` while mismatching local `nexlink_keystore` private keys (`403 IDENTITY_CONFLICT`) and unconditionally trusted restored `PAIRED` devices.
4. `restoreBackup()` cleared IndexedDB stores before validating `settings` and silently accepted placeholder ciphertext `'[ENCRYPTED_AES_256_GCM]'` on local key loss during export.

## Decision
1. **Encrypted Container (`EncryptedBackupArchive v2`)**:
   - External envelope contains only non-sensitive metadata required for decryption: `format` (`'nexlink-encrypted-backup'`), `formatVersion` (`2`), `schemaVersion`, `exportedAt`, `kdf`, `encryption` (`{ algorithm: 'AES-256-GCM', iv }`), canonical `aad`, and `ciphertext`.
   - All user/application payloads (`settings`, `sourceDevice`, `linkedDevices`, `syncEvents`, `auditEntries`) live exclusively inside the AES-256-GCM ciphertext.
2. **Key Derivation (`PBKDF2-HMAC-SHA-256`) & Key Separation**:
   - Uses native Web Crypto `PBKDF2-HMAC-SHA-256` with `600,000` default iterations, a fresh `16`-byte CSPRNG salt per export, and `256`-bit ephemeral `AES-GCM` key derivation.
   - PBKDF2 was chosen over Argon2id because Argon2id is not supported natively in Web Crypto API and no audited Argon2id dependency is present in the project.
   - Restore enforces strict KDF bounds (`310,000 <= iterations <= 2,000,000`, `16 <= saltBytes <= 64`, `ivBytes === 12`) **before** key derivation to prevent weak-KDF downgrades and CPU DoS.
   - Backup encryption keys are ephemeral and completely isolated from `master_aes_gcm_key`, `ECDSA P-256`, and `ECDH P-256` keys in `nexlink_keystore`. Passphrases are never persisted to IndexedDB, `localStorage`, Relay, or logs.
   - Future extensibility: `formatVersion` and `kdf` header fields allow adding `formatVersion: 3` or new KDFs cleanly without breaking v2 verification.
3. **AEAD Binding (`AES-256-GCM` + Canonical `AAD`)**:
   - Canonical JSON of `format`, `formatVersion`, `schemaVersion`, `exportedAt`, `kdf`, and `encryption` is verified against `archive.aad` and passed as `additionalData` into `AES-256-GCM`. Any tampering with outer metadata, salt, IV, iterations, or ciphertext fails authentication uniformly (`BACKUP_AUTH_FAILED`) without oracle hints.
4. **Strict Export Failure on Unreadable Data**:
   - `IndexedDbBackupProvider.exportBackup()` uses strict decryption (`getAll({ throwOnDecryptError: true })`) and rejects unreadable encrypted records instead of silently exporting `'[ENCRYPTED_AES_256_GCM]'`.
5. **14-Step Atomic Restore & Identity/Trust Policy**:
   - Parses, validates header/KDF bounds, decrypts/authenticates AES-GCM, validates inner schema/versions/bounds/unique `idempotencyKey`/settings, applies Identity & Trust policies, and re-encrypts events under the current device's local AES-256-GCM key **before** starting an IndexedDB `readwrite` transaction.
   - **Identity & Role Preservation**: `STORES.IDENTITY` and `nexlink_keystore` are never modified or overwritten during restore; the current device keeps its own `publicId` and `ECDSA/ECDH` keys, and `settings.role` is strictly preserved from the target device's pre-restore settings (the backup archive's `role` is ignored).
   - **Audit Log Preservation & Provenance (`APP_DB_VERSION = 4`)**: `STORES.SECURITY_AUDIT` is never cleared during restore. Existing local audit entries (including `DEVICE_REVOKED`) remain untouched with `origin: 'LOCAL'`. Restored audit records are appended via auto-increment without preserving archive IDs (preventing ID collisions) and are authoritatively stamped by the restore pipeline with `origin: 'BACKUP_IMPORT'`, `importedAt`, and `importedFromDeviceId` (ignoring any archive-supplied provenance).
   - **Zero Inherited Peer Trust**: Restored `linkedDevices` are downgraded to `pairingState: 'UNPAIRED'` (`verifiedByRelay: false`, `pairedAt: null`) and cannot be used for E2EE/Sync until re-verified via the Relay. Any device revoked either in the backup or locally before restore remains `REVOKED` (`verifiedByRelay: false`).
   - **Cross-Device Queue Safety**: On cross-device restores (`sourceDevice !== currentIdentity`), `PENDING` and `IN_PROGRESS` events are frozen to `FAILED` while preserving `idempotencyKey`, `e2eeNonce`, and historical `SYNCED` records so dedup/replay protection remains intact.
6. **Legacy v1 Unencrypted Backup Handling**:
   - Unencrypted v1 backups are detected and **rejected by default** (`LEGACY_UNENCRYPTED_BACKUP`).
   - An explicit opt-in `migrateLegacyBackup()` workflow verifies legacy SHA-256 checksum, validates schemas, applies identity/trust sanitization in memory without mutating IndexedDB or deleting the original file, and immediately emits an encrypted `v2` archive.

## Consequences
- Backups are confidential, authenticated, portable across devices with different local keys, protect target device role and local audit evidence, and are immune to silent partial database wipes or backup-based trust elevation.
- Real Chromium + IndexedDB browser E2E tests (`tests/e2e/backupRestore.spec.ts`) verify export, restore, failure immutability, transaction rollback, and v3-to-v4 migration in CI and locally.
