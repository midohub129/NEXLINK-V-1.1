import type { DeviceRole, LinkedDevice } from './device';
import type { SecurityAuditEntry } from './security';
import type { AppSettings } from './settings';
import type { SyncEvent } from './syncEvent';

export const ENCRYPTED_BACKUP_FORMAT_ID = 'nexlink-encrypted-backup' as const;
export const ENCRYPTED_BACKUP_FORMAT_VERSION = 2 as const;
export const BACKUP_KDF_ALGORITHM = 'PBKDF2-HMAC-SHA-256' as const;
export const BACKUP_KDF_HASH = 'SHA-256' as const;
export const BACKUP_ENCRYPTION_ALGORITHM = 'AES-256-GCM' as const;

/**
 * PBKDF2-HMAC-SHA-256 parameters chosen for native browser + Node 22 WebCrypto compatibility:
 * - Default 600,000 iterations (OWASP 2023+ recommendation for PBKDF2-HMAC-SHA-256).
 * - Minimum 310,000 iterations enforced on restore to prevent downgrade attacks.
 * - Maximum 2,000,000 iterations enforced on restore BEFORE key derivation to prevent CPU DoS.
 */
export const BACKUP_KDF_DEFAULT_ITERATIONS = 600_000;
export const BACKUP_KDF_MIN_ITERATIONS = 310_000;
export const BACKUP_KDF_MAX_ITERATIONS = 2_000_000;
export const BACKUP_KDF_KEY_LENGTH_BITS = 256 as const;
export const BACKUP_SALT_BYTES = 16;
export const BACKUP_MIN_SALT_BYTES = 16;
export const BACKUP_MAX_SALT_BYTES = 64;
export const BACKUP_IV_BYTES = 12;

export const BACKUP_MIN_PASSPHRASE_LENGTH = 12;
export const BACKUP_MAX_PASSPHRASE_LENGTH = 512;

export const BACKUP_MAX_RAW_JSON_BYTES = 10 * 1024 * 1024; // 10 MiB
export const BACKUP_MAX_SYNC_EVENTS = 5_000;
export const BACKUP_MAX_LINKED_DEVICES = 200;
export const BACKUP_MAX_AUDIT_ENTRIES = 1_000;
export const BACKUP_MAX_SELECTED_APPS = 500;
export const BACKUP_MAX_STRING_LENGTH = 65_536;
export const BACKUP_MAX_SHORT_STRING_LENGTH = 256;
export const BACKUP_MAX_DETAIL_STRING_LENGTH = 1_024;

export interface BackupKdfParams {
  algorithm: typeof BACKUP_KDF_ALGORITHM;
  hash: typeof BACKUP_KDF_HASH;
  iterations: number;
  salt: string;
  keyLengthBits: typeof BACKUP_KDF_KEY_LENGTH_BITS;
}

export interface BackupEncryptionHeader {
  algorithm: typeof BACKUP_ENCRYPTION_ALGORITHM;
  iv: string;
}

export interface EncryptedBackupArchiveV2 {
  format: typeof ENCRYPTED_BACKUP_FORMAT_ID;
  formatVersion: typeof ENCRYPTED_BACKUP_FORMAT_VERSION;
  schemaVersion: number;
  exportedAt: number;
  kdf: BackupKdfParams;
  encryption: BackupEncryptionHeader;
  aad: string;
  ciphertext: string;
}

export interface BackupSourceDeviceMetadata {
  publicId: string;
  cryptoKeyId: string;
}

export interface BackupInnerPayloadV2 {
  payloadVersion: 2;
  schemaVersion: number;
  exportedAt: number;
  sourceDevice: BackupSourceDeviceMetadata | null;
  settings: AppSettings;
  linkedDevices: LinkedDevice[];
  syncEvents: SyncEvent[];
  auditEntries: SecurityAuditEntry[];
}

export interface LegacyBackupArchiveV1 {
  schemaVersion: number;
  exportedAt: number;
  checksumSha256: string;
  settings: AppSettings;
  identity: {
    publicId: string;
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
    ecdhPublicKeyJwk: JsonWebKey | null;
    createdAt: number;
  } | null;
  linkedDevices: LinkedDevice[];
  syncEvents: SyncEvent[];
  auditEntries: SecurityAuditEntry[];
}

export type DetectedBackupFormat =
  | {
      kind: 'ENCRYPTED_V2';
      formatVersion: number;
      schemaVersion: number | null;
      exportedAt: number | null;
    }
  | {
      kind: 'LEGACY_UNENCRYPTED_V1';
      schemaVersion: number | null;
      exportedAt: number | null;
    }
  | {
      kind: 'UNSUPPORTED_VERSION';
      formatVersion: number | null;
      schemaVersion: number | null;
    }
  | {
      kind: 'INVALID';
      reason: string;
    };

export interface BackupExportSummary {
  archive: EncryptedBackupArchiveV2;
  eventCount: number;
  linkedDeviceCount: number;
  auditCount: number;
}

export interface BackupRestoreResult {
  restoredEvents: number;
  restoredLinkedDevices: number;
  restoredAuditEntries: number;
  crossDeviceRestore: boolean;
  restoredRole: DeviceRole | null;
  postRestoreWarnings?: string[];
}

export function buildEncryptedBackupAad(header: {
  format: typeof ENCRYPTED_BACKUP_FORMAT_ID;
  formatVersion: typeof ENCRYPTED_BACKUP_FORMAT_VERSION;
  schemaVersion: number;
  exportedAt: number;
  kdf: BackupKdfParams;
  encryption: BackupEncryptionHeader;
}): string {
  return JSON.stringify({
    format: header.format,
    formatVersion: header.formatVersion,
    schemaVersion: header.schemaVersion,
    exportedAt: header.exportedAt,
    kdf: {
      algorithm: header.kdf.algorithm,
      hash: header.kdf.hash,
      iterations: header.kdf.iterations,
      salt: header.kdf.salt,
      keyLengthBits: header.kdf.keyLengthBits,
    },
    encryption: {
      algorithm: header.encryption.algorithm,
      iv: header.encryption.iv,
    },
  });
}
