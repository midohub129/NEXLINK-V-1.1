import {
  SecurityError,
  StorageError,
  ValidationError,
} from '../../domain/errors/appError';
import type {
  CreateSyncEventInput,
  IBackupProvider,
  IDeviceRepository,
  ISecurityAuditRepository,
  ISettingsRepository,
  ISyncEventRepository,
} from '../../domain/interfaces/repositories';
import type { ICryptoProvider } from '../../domain/interfaces/services';
import {
  BACKUP_MAX_AUDIT_ENTRIES,
  BACKUP_MAX_DETAIL_STRING_LENGTH,
  BACKUP_MAX_LINKED_DEVICES,
  BACKUP_MAX_RAW_JSON_BYTES,
  BACKUP_MAX_SELECTED_APPS,
  BACKUP_MAX_SHORT_STRING_LENGTH,
  BACKUP_MAX_STRING_LENGTH,
  BACKUP_MAX_SYNC_EVENTS,
  ENCRYPTED_BACKUP_FORMAT_ID,
  ENCRYPTED_BACKUP_FORMAT_VERSION,
  type BackupExportSummary,
  type BackupInnerPayloadV2,
  type BackupRestoreResult,
  type DetectedBackupFormat,
  type EncryptedBackupArchiveV2,
  type LegacyBackupArchiveV1,
} from '../../domain/models/backup';
import type {
  DeviceIdentityProfile,
  DeviceRole,
  LinkedDevice,
  PairingState,
} from '../../domain/models/device';
import type {
  E2eeEnvelope,
  EncryptedEnvelope,
  SecurityAuditAction,
  SecurityAuditEntry,
  SecurityAuditOrigin,
} from '../../domain/models/security';
import { type AppSettings, DEFAULT_APP_SETTINGS } from '../../domain/models/settings';
import type { SyncEvent, SyncEventStatus } from '../../domain/models/syncEvent';
import { validateAppSettings } from '../../application/settings/settingsService';
import {
  APP_DB_VERSION,
  IndexedDbDatabase,
  STORES,
  reqToPromise,
} from './indexedDbDatabase';

interface StoredSyncEventRecord {
  id?: number;
  type: string;
  payload: string;
  envelope?: EncryptedEnvelope;
  e2eeEnvelope?: E2eeEnvelope;
  createdAt: number;
  status: SyncEventStatus;
  retryCount: number;
  nextRetryAt: number | null;
  idempotencyKey: string;
  notificationKey?: string;
  payloadHash?: string;
  encrypted: boolean;
  localEncrypted?: boolean;
  e2eeProtected?: boolean;
  e2eeVerified?: boolean;
  e2eeNonce?: string | null;
  inboundAckProof?: string | null;
  relayEventId?: number | null;
  inboundAckConfirmed?: boolean;
  targetDeviceId?: string | null;
  sourceDeviceId?: string | null;
  relayAcceptedAt?: number | null;
  deliveredAt?: number | null;
  lastError?: string | null;
  syncedAt?: number | null;
}

interface StoredSettingsRecord {
  id: 'app_settings';
  settings: AppSettings;
}

interface StoredIdentityRecord {
  id: 'local_device';
  identity: DeviceIdentityProfile;
}

const VALID_SYNC_STATUSES = new Set<SyncEventStatus>([
  'PENDING',
  'IN_PROGRESS',
  'SYNCED',
  'FAILED',
]);

const VALID_PAIRING_STATES = new Set<PairingState>([
  'UNPAIRED',
  'PAIRING_PENDING',
  'AWAITING_APPROVAL',
  'PAIRED',
  'REVOKED',
]);

const VALID_DEVICE_ROLES = new Set<DeviceRole>(['admin', 'basic']);

const VALID_AUDIT_ACTIONS = new Set<SecurityAuditAction>([
  'ROLE_ASSIGNED',
  'ROLE_CHANGED',
  'AUTHORIZATION_REVOKED',
  'SESSION_RENEWED',
  'SESSION_EXPIRED',
  'PERMISSION_GRANTED',
  'PERMISSION_REVOKED',
  'ACCESS_DENIED',
  'DUPLICATE_BLOCKED',
  'VAULT_VERIFIED',
  'BACKUP_EXPORTED',
  'BACKUP_RESTORED',
  'DEVICE_PAIRED',
  'PAIRING_CONFIRMED',
  'PAIRING_REJECTED',
  'DEVICE_REVOKED',
  'E2EE_VERIFIED',
  'E2EE_DECRYPT_FAILED',
  'REPLAY_BLOCKED',
  'SECURE_WIPE',
]);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertBoundedString(
  value: unknown,
  field: string,
  maxLength: number,
  allowEmpty = false
): string {
  if (typeof value !== 'string') {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      `الحقل ${field} في النسخة الاحتياطية يجب أن يكون نصاً.`,
      `Backup field ${field} is not a string`
    );
  }
  if (!allowEmpty && value.length === 0) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      `الحقل المطلوب ${field} في النسخة الاحتياطية فارغ.`,
      `Backup field ${field} is empty`
    );
  }
  if (value.length > maxLength) {
    throw new ValidationError(
      'BACKUP_LIMIT_EXCEEDED',
      `الحقل ${field} يتجاوز الحد الأقصى المسموح به.`,
      `Backup field ${field} exceeds max length ${maxLength}`
    );
  }
  return value;
}

function assertOptionalNullableString(
  value: unknown,
  field: string,
  maxLength: number
): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return assertBoundedString(value, field, maxLength, true);
}

function assertOptionalNullableNumber(
  value: unknown,
  field: string
): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      `الحقل ${field} في النسخة الاحتياطية يجب أن يكون رقماً صالحاً.`,
      `Backup field ${field} is not a finite number`
    );
  }
  return value;
}

function validatePublicJwk(value: unknown, field: string): JsonWebKey | null {
  if (value === null || value === undefined) return null;
  if (!isPlainRecord(value)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      `المفتاح العام ${field} غير صالح.`,
      `Invalid JWK structure for ${field}`
    );
  }
  if ('d' in value && value.d !== undefined) {
    throw new SecurityError(
      'BACKUP_PRIVATE_KEY_REJECTED',
      'تم رفض النسخة لأنها تحتوي على حقل مفتاح خاص غير مسموح به.',
      `Private JWK parameter 'd' found in ${field}`
    );
  }
  return value as JsonWebKey;
}

function validateSettingsFromBackup(raw: unknown): AppSettings {
  if (!isPlainRecord(raw)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'قسم الإعدادات في النسخة الاحتياطية مفقود أو غير صالح.',
      'Backup settings missing or not an object'
    );
  }

  const role = raw.role;
  if (role !== null && role !== 'admin' && role !== 'basic') {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'قيمة دور الجهاز داخل الإعدادات غير صالحة.',
      'Invalid settings.role in backup'
    );
  }

  if (!Array.isArray(raw.selectedNotificationApps)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'قائمة التطبيقات المحددة غير صالحة.',
      'settings.selectedNotificationApps is not an array'
    );
  }
  if (raw.selectedNotificationApps.length > BACKUP_MAX_SELECTED_APPS) {
    throw new ValidationError(
      'BACKUP_LIMIT_EXCEEDED',
      'عدد التطبيقات المحددة في النسخة يتجاوز الحد المسموح.',
      'settings.selectedNotificationApps exceeds maximum'
    );
  }
  const selectedNotificationApps = raw.selectedNotificationApps.map((app, idx) =>
    assertBoundedString(
      app,
      `settings.selectedNotificationApps[${idx}]`,
      BACKUP_MAX_SHORT_STRING_LENGTH
    )
  );

  for (const boolField of [
    'connectionServiceEnabled',
    'notificationAccessGranted',
    'usageAccessGranted',
    'testFixtureModeEnabled',
  ] as const) {
    if (typeof raw[boolField] !== 'boolean') {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `الحقل ${boolField} داخل الإعدادات غير صالح.`,
        `Invalid boolean settings.${boolField}`
      );
    }
  }

  const relayEndpoint = assertBoundedString(
    raw.relayEndpoint,
    'settings.relayEndpoint',
    512
  );
  const targetDeviceId = assertOptionalNullableString(
    raw.targetDeviceId,
    'settings.targetDeviceId',
    BACKUP_MAX_SHORT_STRING_LENGTH
  );

  const syncDeliveryPolicy =
    raw.syncDeliveryPolicy === 'RELAY_QUEUED' ||
    raw.syncDeliveryPolicy === 'PEER_CONFIRMED'
      ? raw.syncDeliveryPolicy
      : null;
  if (!syncDeliveryPolicy) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'سياسة تسليم المزامنة داخل الإعدادات غير صالحة.',
      'Invalid settings.syncDeliveryPolicy'
    );
  }

  const candidate: AppSettings = {
    role,
    selectedNotificationApps,
    connectionServiceEnabled: raw.connectionServiceEnabled as boolean,
    notificationAccessGranted: raw.notificationAccessGranted as boolean,
    usageAccessGranted: raw.usageAccessGranted as boolean,
    sessionTimeoutMinutes: Number(raw.sessionTimeoutMinutes),
    syncIntervalMs: Number(raw.syncIntervalMs),
    maxSyncRetries: Number(raw.maxSyncRetries),
    relayEndpoint,
    syncDeliveryPolicy,
    targetDeviceId: targetDeviceId ?? null,
    testFixtureModeEnabled: raw.testFixtureModeEnabled as boolean,
  };

  return validateAppSettings(candidate);
}

function validateLinkedDevicesFromBackup(raw: unknown): LinkedDevice[] {
  if (!Array.isArray(raw)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'قائمة الأجهزة المرتبطة غير صالحة.',
      'linkedDevices must be an array'
    );
  }
  if (raw.length > BACKUP_MAX_LINKED_DEVICES) {
    throw new ValidationError(
      'BACKUP_LIMIT_EXCEEDED',
      `عدد الأجهزة المرتبطة يتجاوز الحد الأقصى (${BACKUP_MAX_LINKED_DEVICES}).`,
      'linkedDevices exceeds maximum limit'
    );
  }

  return raw.map((item, idx) => {
    if (!isPlainRecord(item)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `سجل الجهاز المرتبط #${idx} غير صالح.`,
        `linkedDevices[${idx}] is not an object`
      );
    }
    const publicId = assertBoundedString(
      item.publicId,
      `linkedDevices[${idx}].publicId`,
      128
    );
    const cryptoKeyId = assertBoundedString(
      item.cryptoKeyId,
      `linkedDevices[${idx}].cryptoKeyId`,
      128
    );
    const label = assertBoundedString(item.label, `linkedDevices[${idx}].label`, 128);
    if (!VALID_DEVICE_ROLES.has(item.role as DeviceRole)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `دور الجهاز المرتبط #${idx} غير صالح.`,
        `Invalid role on linkedDevices[${idx}]`
      );
    }
    if (!VALID_PAIRING_STATES.has(item.pairingState as PairingState)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `حالة الاقتران للجهاز #${idx} غير صالحة.`,
        `Invalid pairingState on linkedDevices[${idx}]`
      );
    }
    const publicKeyJwk = validatePublicJwk(
      item.publicKeyJwk,
      `linkedDevices[${idx}].publicKeyJwk`
    );
    const ecdhPublicKeyJwk = validatePublicJwk(
      item.ecdhPublicKeyJwk,
      `linkedDevices[${idx}].ecdhPublicKeyJwk`
    );
    const pairedAt = assertOptionalNullableNumber(
      item.pairedAt,
      `linkedDevices[${idx}].pairedAt`
    );
    const lastSeenAt = assertOptionalNullableNumber(
      item.lastSeenAt,
      `linkedDevices[${idx}].lastSeenAt`
    );

    return {
      publicId,
      cryptoKeyId,
      publicKeyJwk,
      ecdhPublicKeyJwk,
      label,
      role: item.role as DeviceRole,
      pairingState: item.pairingState as PairingState,
      pairedAt: pairedAt ?? null,
      lastSeenAt: lastSeenAt ?? null,
      verifiedByRelay: Boolean(item.verifiedByRelay),
    };
  });
}

function validateSyncEventsFromBackup(raw: unknown): SyncEvent[] {
  if (!Array.isArray(raw)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'قائمة أحداث المزامنة غير صالحة.',
      'syncEvents must be an array'
    );
  }
  if (raw.length > BACKUP_MAX_SYNC_EVENTS) {
    throw new ValidationError(
      'BACKUP_LIMIT_EXCEEDED',
      `عدد أحداث المزامنة يتجاوز الحد الأقصى (${BACKUP_MAX_SYNC_EVENTS}).`,
      'syncEvents exceeds maximum limit'
    );
  }

  const seenKeys = new Set<string>();
  const seenIds = new Set<number>();
  return raw.map((item, idx) => {
    if (!isPlainRecord(item)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `سجل الحدث #${idx} غير صالح.`,
        `syncEvents[${idx}] is not an object`
      );
    }

    const id = item.id;
    if (typeof id !== 'number' || !Number.isInteger(id) || id < 0) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `معرّف الحدث #${idx} غير صالح.`,
        `syncEvents[${idx}].id invalid`
      );
    }
    if (id > 0) {
      if (seenIds.has(id)) {
        throw new ValidationError(
          'INVALID_BACKUP_SCHEMA',
          `تحتوي النسخة على معرّف حدث مكرر (#${id}).`,
          `Duplicate sync event id ${id} in backup`
        );
      }
      seenIds.add(id);
    }
    const type = assertBoundedString(item.type, `syncEvents[${idx}].type`, 64);
    const payload = assertBoundedString(
      item.payload,
      `syncEvents[${idx}].payload`,
      BACKUP_MAX_STRING_LENGTH,
      true
    );
    if (item.encrypted === true && payload === '[ENCRYPTED_AES_256_GCM]') {
      throw new ValidationError(
        'BACKUP_UNREADABLE_EVENT_PAYLOAD',
        `الحدث #${idx} داخل النسخة الاحتياطية يحتوي نصاً مشفراً غير قابل للاستعادة.`,
        `syncEvents[${idx}] contains placeholder encrypted marker`
      );
    }

    if (
      typeof item.createdAt !== 'number' ||
      !Number.isFinite(item.createdAt) ||
      item.createdAt <= 0
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `طابع الوقت للحدث #${idx} غير صالح.`,
        `syncEvents[${idx}].createdAt invalid`
      );
    }
    if (!VALID_SYNC_STATUSES.has(item.status as SyncEventStatus)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `حالة الحدث #${idx} غير صالحة.`,
        `syncEvents[${idx}].status invalid`
      );
    }
    if (
      typeof item.retryCount !== 'number' ||
      !Number.isInteger(item.retryCount) ||
      item.retryCount < 0 ||
      item.retryCount > 1000
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `عدد محاولات الحدث #${idx} غير صالح.`,
        `syncEvents[${idx}].retryCount invalid`
      );
    }

    const idempotencyKey = assertBoundedString(
      item.idempotencyKey,
      `syncEvents[${idx}].idempotencyKey`,
      BACKUP_MAX_SHORT_STRING_LENGTH
    );
    if (seenKeys.has(idempotencyKey)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        'تحتوي النسخة الاحتياطية على مفاتيح idempotencyKey مكررة.',
        `Duplicate idempotencyKey in backup: ${idempotencyKey}`
      );
    }
    seenKeys.add(idempotencyKey);

    const nextRetryAt = assertOptionalNullableNumber(
      item.nextRetryAt,
      `syncEvents[${idx}].nextRetryAt`
    );
    const relayAcceptedAt = assertOptionalNullableNumber(
      item.relayAcceptedAt,
      `syncEvents[${idx}].relayAcceptedAt`
    );
    const deliveredAt = assertOptionalNullableNumber(
      item.deliveredAt,
      `syncEvents[${idx}].deliveredAt`
    );
    const syncedAt = assertOptionalNullableNumber(
      item.syncedAt,
      `syncEvents[${idx}].syncedAt`
    );
    const relayEventId = assertOptionalNullableNumber(
      item.relayEventId,
      `syncEvents[${idx}].relayEventId`
    );

    const notificationKey = assertOptionalNullableString(
      item.notificationKey,
      `syncEvents[${idx}].notificationKey`,
      BACKUP_MAX_SHORT_STRING_LENGTH
    );
    const payloadHash = assertOptionalNullableString(
      item.payloadHash,
      `syncEvents[${idx}].payloadHash`,
      BACKUP_MAX_SHORT_STRING_LENGTH
    );
    const targetDeviceId = assertOptionalNullableString(
      item.targetDeviceId,
      `syncEvents[${idx}].targetDeviceId`,
      128
    );
    const sourceDeviceId = assertOptionalNullableString(
      item.sourceDeviceId,
      `syncEvents[${idx}].sourceDeviceId`,
      128
    );
    const e2eeNonce = assertOptionalNullableString(
      item.e2eeNonce,
      `syncEvents[${idx}].e2eeNonce`,
      128
    );
    const inboundAckProof = assertOptionalNullableString(
      item.inboundAckProof,
      `syncEvents[${idx}].inboundAckProof`,
      1024
    );
    const lastError = assertOptionalNullableString(
      item.lastError,
      `syncEvents[${idx}].lastError`,
      BACKUP_MAX_DETAIL_STRING_LENGTH
    );

    const status = item.status as SyncEventStatus;
    const e2eeVerified = item.e2eeVerified === true;
    const inboundAckConfirmed = item.inboundAckConfirmed === true;

    if (
      status === 'PENDING' &&
      (syncedAt != null || deliveredAt != null || relayEventId != null || e2eeVerified)
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `بيانات حالة الحدث #${idx} متعارضة مع حقول التسليم أو التحقق.`,
        `Inconsistent PENDING state for syncEvents[${idx}]`
      );
    }

    if (inboundAckConfirmed && (relayEventId == null || !e2eeNonce || !e2eeVerified)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `حالة ACK المؤكدة للحدث #${idx} تفتقر لبيانات التحقق الإلزامية.`,
        `Inconsistent inboundAckConfirmed flags for syncEvents[${idx}]`
      );
    }

    return {
      id,
      type,
      payload,
      createdAt: item.createdAt,
      status,
      retryCount: item.retryCount,
      nextRetryAt: nextRetryAt ?? null,
      idempotencyKey,
      notificationKey: notificationKey ?? undefined,
      payloadHash: payloadHash ?? undefined,
      encrypted: Boolean(item.encrypted),
      localEncrypted:
        typeof item.localEncrypted === 'boolean'
          ? item.localEncrypted
          : Boolean(item.encrypted),
      e2eeProtected: Boolean(item.e2eeProtected),
      e2eeVerified,
      e2eeNonce: e2eeNonce ?? null,
      e2eeEnvelope: (() => {
        if (!isPlainRecord(item.e2eeEnvelope)) return undefined;
        if ('senderEcdhPublicKeyJwk' in item.e2eeEnvelope) {
          validatePublicJwk(
            item.e2eeEnvelope.senderEcdhPublicKeyJwk,
            `syncEvents[${idx}].e2eeEnvelope.senderEcdhPublicKeyJwk`
          );
        }
        return item.e2eeEnvelope as unknown as E2eeEnvelope;
      })(),
      inboundAckProof: inboundAckProof ?? null,
      relayEventId: relayEventId ?? null,
      inboundAckConfirmed,
      targetDeviceId: targetDeviceId ?? null,
      sourceDeviceId: sourceDeviceId ?? null,
      relayAcceptedAt: relayAcceptedAt ?? null,
      deliveredAt: deliveredAt ?? null,
      lastError: lastError ?? null,
      syncedAt: syncedAt ?? null,
    };
  });
}

function normalizeAuditEntry(entry: SecurityAuditEntry): SecurityAuditEntry {
  const origin: SecurityAuditOrigin =
    entry.origin === 'BACKUP_IMPORT' ? 'BACKUP_IMPORT' : 'LOCAL';
  return {
    ...entry,
    origin,
    importedAt: origin === 'BACKUP_IMPORT' ? (entry.importedAt ?? null) : null,
    importedFromDeviceId:
      origin === 'BACKUP_IMPORT' ? (entry.importedFromDeviceId ?? null) : null,
  };
}

function validateAuditEntriesFromBackup(raw: unknown): SecurityAuditEntry[] {
  if (!Array.isArray(raw)) {
    throw new ValidationError(
      'INVALID_BACKUP_SCHEMA',
      'سجل التدقيق الأمني في النسخة غير صالح.',
      'auditEntries must be an array'
    );
  }
  if (raw.length > BACKUP_MAX_AUDIT_ENTRIES) {
    throw new ValidationError(
      'BACKUP_LIMIT_EXCEEDED',
      `عدد سجلات التدقيق يتجاوز الحد الأقصى (${BACKUP_MAX_AUDIT_ENTRIES}).`,
      'auditEntries exceeds maximum limit'
    );
  }

  return raw.map((item, idx) => {
    if (!isPlainRecord(item)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `سجل التدقيق #${idx} غير صالح.`,
        `auditEntries[${idx}] is not an object`
      );
    }
    if (typeof item.id !== 'number' || !Number.isInteger(item.id) || item.id < 0) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `معرّف سجل التدقيق #${idx} غير صالح.`,
        `auditEntries[${idx}].id invalid`
      );
    }
    if (
      typeof item.timestamp !== 'number' ||
      !Number.isFinite(item.timestamp) ||
      item.timestamp <= 0
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `طابع وقت سجل التدقيق #${idx} غير صالح.`,
        `auditEntries[${idx}].timestamp invalid`
      );
    }
    if (!VALID_AUDIT_ACTIONS.has(item.action as SecurityAuditAction)) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `نوع الحدث في سجل التدقيق #${idx} غير مدعوم.`,
        `auditEntries[${idx}].action invalid`
      );
    }
    const actorRole = item.actorRole;
    if (actorRole !== 'admin' && actorRole !== 'basic' && actorRole !== 'none') {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `دور المنفذ في سجل التدقيق #${idx} غير صالح.`,
        `auditEntries[${idx}].actorRole invalid`
      );
    }
    const outcome = item.outcome;
    if (outcome !== 'ALLOWED' && outcome !== 'DENIED' && outcome !== 'INFO') {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        `نتيجة سجل التدقيق #${idx} غير صالحة.`,
        `auditEntries[${idx}].outcome invalid`
      );
    }

    // Security policy: ignore any archive-supplied provenance fields (origin, importedAt,
    // importedFromDeviceId). Restore pipeline strictly assigns BACKUP_IMPORT provenance.
    return {
      id: item.id,
      timestamp: item.timestamp,
      action: item.action as SecurityAuditAction,
      actorRole,
      deviceId: assertBoundedString(
        item.deviceId,
        `auditEntries[${idx}].deviceId`,
        128
      ),
      outcome,
      details: assertBoundedString(
        item.details,
        `auditEntries[${idx}].details`,
        BACKUP_MAX_DETAIL_STRING_LENGTH
      ),
    };
  });
}

function canonicalLegacyArchivePayload(
  archive: Omit<LegacyBackupArchiveV1, 'checksumSha256'>
): string {
  return JSON.stringify({
    schemaVersion: archive.schemaVersion,
    exportedAt: archive.exportedAt,
    settings: archive.settings,
    identity: archive.identity,
    linkedDevices: archive.linkedDevices,
    syncEvents: archive.syncEvents,
    auditEntries: archive.auditEntries,
  });
}

function detectParsedBackupFormat(parsed: unknown): DetectedBackupFormat {
  if (!isPlainRecord(parsed)) {
    return { kind: 'INVALID', reason: 'Backup JSON root is not an object' };
  }

  if (parsed.format === ENCRYPTED_BACKUP_FORMAT_ID) {
    const fv = typeof parsed.formatVersion === 'number' ? parsed.formatVersion : null;
    const sv = typeof parsed.schemaVersion === 'number' ? parsed.schemaVersion : null;
    const exp = typeof parsed.exportedAt === 'number' ? parsed.exportedAt : null;
    if (fv === ENCRYPTED_BACKUP_FORMAT_VERSION) {
      return {
        kind: 'ENCRYPTED_V2',
        formatVersion: fv,
        schemaVersion: sv,
        exportedAt: exp,
      };
    }
    return {
      kind: 'UNSUPPORTED_VERSION',
      formatVersion: fv,
      schemaVersion: sv,
    };
  }

  if (typeof parsed.formatVersion === 'number' || typeof parsed.format === 'string') {
    return {
      kind: 'UNSUPPORTED_VERSION',
      formatVersion:
        typeof parsed.formatVersion === 'number' ? parsed.formatVersion : null,
      schemaVersion:
        typeof parsed.schemaVersion === 'number' ? parsed.schemaVersion : null,
    };
  }

  if (
    typeof parsed.schemaVersion === 'number' &&
    typeof parsed.checksumSha256 === 'string' &&
    Array.isArray(parsed.syncEvents) &&
    isPlainRecord(parsed.settings) &&
    !('ciphertext' in parsed)
  ) {
    return {
      kind: 'LEGACY_UNENCRYPTED_V1',
      schemaVersion: parsed.schemaVersion,
      exportedAt: typeof parsed.exportedAt === 'number' ? parsed.exportedAt : null,
    };
  }

  return { kind: 'INVALID', reason: 'Unrecognized backup archive structure' };
}

export class IndexedDbSyncEventRepository implements ISyncEventRepository {
  private readonly db: IndexedDbDatabase;
  private readonly crypto: ICryptoProvider;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase, crypto: ICryptoProvider) {
    this.db = db;
    this.crypto = crypto;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  private async toDomainEvent(
    record: StoredSyncEventRecord,
    throwOnDecryptError = false
  ): Promise<SyncEvent> {
    let plaintext = record.payload;
    if (record.encrypted) {
      if (!record.envelope) {
        if (throwOnDecryptError) {
          throw new StorageError(
            'BACKUP_EVENT_DECRYPTION_FAILED',
            'تعذّر قراءة أحد أحداث المزامنة المشفرة محلياً لغياب المغلف التشفيري؛ تم إيقاف التصدير.',
            `Encrypted sync event #${record.id ?? 'unknown'} missing local AES envelope`
          );
        }
      } else {
        const decrypted = await this.crypto.decrypt(record.envelope);
        if (decrypted !== null) {
          plaintext = decrypted;
        } else if (throwOnDecryptError) {
          throw new StorageError(
            'BACKUP_EVENT_DECRYPTION_FAILED',
            'تعذّر فك تشفير أحد أحداث المزامنة المحلية؛ تم إيقاف التصدير لمنع إنشاء نسخة تالفة.',
            `AES-GCM decryption failed for sync event #${record.id ?? 'unknown'}`
          );
        }
      }
    }

    return {
      id: record.id ?? 0,
      type: record.type,
      payload: plaintext,
      createdAt: record.createdAt,
      status: record.status,
      retryCount: record.retryCount,
      nextRetryAt: record.nextRetryAt,
      idempotencyKey: record.idempotencyKey,
      notificationKey: record.notificationKey,
      payloadHash: record.payloadHash,
      encrypted: record.encrypted,
      localEncrypted: record.localEncrypted ?? record.encrypted,
      e2eeProtected: record.e2eeProtected ?? false,
      e2eeVerified: record.e2eeVerified ?? false,
      e2eeNonce: record.e2eeNonce ?? null,
      e2eeEnvelope: record.e2eeEnvelope,
      inboundAckProof: record.inboundAckProof ?? null,
      relayEventId: record.relayEventId ?? null,
      inboundAckConfirmed: record.inboundAckConfirmed ?? false,
      targetDeviceId: record.targetDeviceId ?? null,
      sourceDeviceId: record.sourceDeviceId ?? null,
      relayAcceptedAt: record.relayAcceptedAt ?? null,
      deliveredAt: record.deliveredAt ?? null,
      lastError: record.lastError ?? null,
      syncedAt: record.syncedAt ?? null,
    };
  }

  async insert(input: CreateSyncEventInput): Promise<SyncEvent> {
    const envelope = this.crypto.isSupported()
      ? await this.crypto.encrypt(input.payload)
      : null;

    const record: StoredSyncEventRecord = {
      type: input.type,
      payload: envelope ? '[ENCRYPTED_AES_256_GCM]' : input.payload,
      envelope: envelope ?? undefined,
      e2eeEnvelope: input.e2eeEnvelope,
      createdAt: input.createdAt ?? Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: input.idempotencyKey,
      notificationKey: input.notificationKey,
      payloadHash: input.payloadHash,
      encrypted: Boolean(envelope),
      localEncrypted: Boolean(envelope),
      e2eeProtected: input.e2eeProtected ?? false,
      e2eeVerified: input.e2eeVerified ?? false,
      e2eeNonce: input.e2eeNonce ?? null,
      inboundAckProof: input.inboundAckProof ?? null,
      relayEventId: input.relayEventId ?? null,
      inboundAckConfirmed: input.inboundAckConfirmed ?? false,
      targetDeviceId: input.targetDeviceId ?? null,
      sourceDeviceId: input.sourceDeviceId ?? null,
      relayAcceptedAt: null,
      deliveredAt: null,
      lastError: null,
      syncedAt: null,
    };

    let generatedId: IDBValidKey;
    try {
      generatedId = await this.db.add(STORES.SYNC_EVENTS, record);
    } catch (err) {
      if (err instanceof Error && err.name === 'ConstraintError') {
        throw new StorageError(
          'DUPLICATE_IDEMPOTENCY_KEY',
          'حدث مكرر بمفتاح عدم التكرار نفسه.',
          `Duplicate idempotencyKey ${input.idempotencyKey}`,
          err
        );
      }
      throw err;
    }
    const savedRecord: StoredSyncEventRecord = {
      ...record,
      id: Number(generatedId),
    };
    this.notify();
    return {
      ...(await this.toDomainEvent(savedRecord)),
      payload: input.payload,
    };
  }

  async findById(id: number): Promise<SyncEvent | null> {
    const rec = await this.db.readOne<StoredSyncEventRecord>(STORES.SYNC_EVENTS, id);
    return rec ? this.toDomainEvent(rec) : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<SyncEvent | null> {
    const rec = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readonly',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        if (store.indexNames.contains('by_idempotencyKey')) {
          const found = (await reqToPromise(
            store.index('by_idempotencyKey').get(idempotencyKey)
          )) as StoredSyncEventRecord | undefined;
          return found ?? null;
        }
        const all = (await reqToPromise(store.getAll())) as StoredSyncEventRecord[];
        return all.find((r) => r.idempotencyKey === idempotencyKey) ?? null;
      }
    );
    return rec ? this.toDomainEvent(rec) : null;
  }

  async findRecentDuplicate(
    type: string,
    notificationKey: string,
    payloadHash: string,
    windowMs: number,
    nowMs: number
  ): Promise<SyncEvent | null> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    const cutoff = nowMs - windowMs;
    const match = records.find(
      (r) =>
        r.type === type &&
        r.notificationKey === notificationKey &&
        r.payloadHash === payloadHash &&
        r.createdAt >= cutoff
    );
    return match ? this.toDomainEvent(match) : null;
  }

  async getAll(options?: { throwOnDecryptError?: boolean }): Promise<SyncEvent[]> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    records.sort((a, b) => b.createdAt - a.createdAt || (b.id ?? 0) - (a.id ?? 0));
    const strict = options?.throwOnDecryptError ?? false;
    return Promise.all(records.map((r) => this.toDomainEvent(r, strict)));
  }

  async getByStatus(status: SyncEventStatus): Promise<SyncEvent[]> {
    const all = await this.getAll();
    return all.filter((e) => e.status === status);
  }

  async getDuePendingEvents(nowMs: number): Promise<SyncEvent[]> {
    const records = await this.db.readAll<StoredSyncEventRecord>(STORES.SYNC_EVENTS);
    const due = records
      .filter(
        (r) =>
          r.status === 'PENDING' && (r.nextRetryAt === null || r.nextRetryAt <= nowMs)
      )
      .sort((a, b) => a.createdAt - b.createdAt || (a.id ?? 0) - (b.id ?? 0));
    return Promise.all(due.map((r) => this.toDomainEvent(r)));
  }

  async updateEvent(
    id: number,
    patch: Partial<
      Pick<
        SyncEvent,
        | 'status'
        | 'retryCount'
        | 'nextRetryAt'
        | 'lastError'
        | 'syncedAt'
        | 'relayAcceptedAt'
        | 'deliveredAt'
        | 'targetDeviceId'
        | 'e2eeProtected'
        | 'e2eeVerified'
        | 'inboundAckConfirmed'
      >
    >
  ): Promise<SyncEvent | null> {
    const updatedRecord = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readwrite',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        const existing = (await reqToPromise(store.get(id))) as
          StoredSyncEventRecord | undefined;
        if (!existing) return null;
        const merged: StoredSyncEventRecord = {
          ...existing,
          ...patch,
        };
        await reqToPromise(store.put(merged));
        return merged;
      }
    );

    if (!updatedRecord) return null;
    this.notify();
    return this.toDomainEvent(updatedRecord);
  }

  async resetInProgressToPending(): Promise<number> {
    const count = await this.db.runTransaction(
      [STORES.SYNC_EVENTS],
      'readwrite',
      async (tx) => {
        const store = tx.objectStore(STORES.SYNC_EVENTS);
        const all = (await reqToPromise(store.getAll())) as StoredSyncEventRecord[];
        let updated = 0;
        for (const rec of all) {
          const isOutboundInFlight = rec.relayEventId == null && !rec.e2eeVerified;
          if (rec.status === 'IN_PROGRESS' && isOutboundInFlight) {
            await reqToPromise(
              store.put({
                ...rec,
                status: 'PENDING',
                nextRetryAt: Date.now(),
              })
            );
            updated += 1;
          }
        }
        return updated;
      }
    );
    if (count > 0) this.notify();
    return count;
  }

  async delete(id: number): Promise<boolean> {
    const existing = await this.db.readOne<StoredSyncEventRecord>(
      STORES.SYNC_EVENTS,
      id
    );
    if (!existing) return false;
    await this.db.deleteKey(STORES.SYNC_EVENTS, id);
    this.notify();
    return true;
  }

  async clearAll(): Promise<void> {
    await this.db.clearStore(STORES.SYNC_EVENTS);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbDeviceRepository implements IDeviceRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async getIdentity(): Promise<DeviceIdentityProfile | null> {
    const record = await this.db.readOne<StoredIdentityRecord>(
      STORES.IDENTITY,
      'local_device'
    );
    return record?.identity ?? null;
  }

  async saveIdentity(identity: DeviceIdentityProfile): Promise<void> {
    await this.db.put(STORES.IDENTITY, {
      id: 'local_device',
      identity,
    } satisfies StoredIdentityRecord);
    this.notify();
  }

  async getLinkedDevices(): Promise<LinkedDevice[]> {
    const devices = await this.db.readAll<LinkedDevice>(STORES.LINKED_DEVICES);
    return devices.sort((a, b) => (b.pairedAt ?? 0) - (a.pairedAt ?? 0));
  }

  async upsertLinkedDevice(device: LinkedDevice): Promise<void> {
    await this.db.put(STORES.LINKED_DEVICES, device);
    this.notify();
  }

  async removeLinkedDevice(publicId: string): Promise<void> {
    await this.db.deleteKey(STORES.LINKED_DEVICES, publicId);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbAuditRepository implements ISecurityAuditRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async append(entry: Omit<SecurityAuditEntry, 'id'>): Promise<SecurityAuditEntry> {
    const localRecord: Omit<SecurityAuditEntry, 'id'> = {
      timestamp: entry.timestamp,
      action: entry.action,
      actorRole: entry.actorRole,
      deviceId: entry.deviceId,
      outcome: entry.outcome,
      details: entry.details,
      origin: 'LOCAL',
      importedAt: null,
      importedFromDeviceId: null,
    };
    const generatedId = await this.db.add(STORES.SECURITY_AUDIT, localRecord);
    const saved: SecurityAuditEntry = {
      ...localRecord,
      id: Number(generatedId),
    };
    this.notify();
    return saved;
  }

  async getAll(): Promise<SecurityAuditEntry[]> {
    const rows = await this.db.readAll<SecurityAuditEntry>(STORES.SECURITY_AUDIT);
    return rows
      .map(normalizeAuditEntry)
      .sort((a, b) => b.timestamp - a.timestamp || b.id - a.id);
  }

  async clear(): Promise<void> {
    await this.db.clearStore(STORES.SECURITY_AUDIT);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbSettingsRepository implements ISettingsRepository {
  private readonly db: IndexedDbDatabase;
  private listeners = new Set<() => void>();

  constructor(db: IndexedDbDatabase) {
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  async get(): Promise<AppSettings> {
    const record = await this.db.readOne<StoredSettingsRecord>(
      STORES.SETTINGS,
      'app_settings'
    );
    return record?.settings ?? { ...DEFAULT_APP_SETTINGS };
  }

  async save(settings: AppSettings): Promise<void> {
    await this.db.put(STORES.SETTINGS, {
      id: 'app_settings',
      settings,
    } satisfies StoredSettingsRecord);
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export class IndexedDbBackupProvider implements IBackupProvider {
  private readonly db: IndexedDbDatabase;
  private readonly crypto: ICryptoProvider;
  private readonly syncRepo: ISyncEventRepository;
  private readonly deviceRepo: IDeviceRepository;
  private readonly auditRepo: ISecurityAuditRepository;
  private readonly settingsRepo: ISettingsRepository;

  constructor(deps: {
    db: IndexedDbDatabase;
    crypto: ICryptoProvider;
    syncRepo: ISyncEventRepository;
    deviceRepo: IDeviceRepository;
    auditRepo: ISecurityAuditRepository;
    settingsRepo: ISettingsRepository;
  }) {
    this.db = deps.db;
    this.crypto = deps.crypto;
    this.syncRepo = deps.syncRepo;
    this.deviceRepo = deps.deviceRepo;
    this.auditRepo = deps.auditRepo;
    this.settingsRepo = deps.settingsRepo;
  }

  inspectBackupJson(rawJson: string): DetectedBackupFormat {
    if (typeof rawJson !== 'string' || rawJson.trim().length === 0) {
      return { kind: 'INVALID', reason: 'Empty backup payload' };
    }
    if (new TextEncoder().encode(rawJson).byteLength > BACKUP_MAX_RAW_JSON_BYTES) {
      return { kind: 'INVALID', reason: 'Backup JSON exceeds maximum allowed size' };
    }
    try {
      const parsed = JSON.parse(rawJson) as unknown;
      return detectParsedBackupFormat(parsed);
    } catch {
      return { kind: 'INVALID', reason: 'Malformed JSON' };
    }
  }

  private parseBoundedInput(
    rawInput: string | Record<string, unknown>
  ): Record<string, unknown> {
    if (typeof rawInput === 'string') {
      if (rawInput.trim().length === 0) {
        throw new ValidationError(
          'INVALID_BACKUP_FORMAT',
          'محتوى النسخة الاحتياطية فارغ.',
          'Empty backup JSON string'
        );
      }
      if (new TextEncoder().encode(rawInput).byteLength > BACKUP_MAX_RAW_JSON_BYTES) {
        throw new ValidationError(
          'BACKUP_LIMIT_EXCEEDED',
          'حجم ملف النسخة الاحتياطية يتجاوز الحد الأقصى المسموح (10 MiB).',
          'Backup raw JSON exceeds max byte limit'
        );
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawInput);
      } catch {
        throw new ValidationError(
          'BACKUP_CORRUPT_JSON',
          'ملف النسخة الاحتياطية تالف أو ليس بصيغة JSON صالحة.',
          'Backup JSON parse failed'
        );
      }
      if (!isPlainRecord(parsed)) {
        throw new ValidationError(
          'INVALID_BACKUP_FORMAT',
          'بنية ملف النسخة الاحتياطية غير صالحة.',
          'Parsed backup JSON root is not an object'
        );
      }
      return parsed;
    }

    if (!isPlainRecord(rawInput)) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'بنية ملف النسخة الاحتياطية غير صالحة.',
        'Backup archive input is not an object'
      );
    }
    return rawInput;
  }

  private applyLinkedDeviceTrustPolicy(
    backedUpDevices: LinkedDevice[],
    existingLocalDevices: LinkedDevice[],
    currentIdentity: DeviceIdentityProfile | null
  ): LinkedDevice[] {
    const locallyRevoked = new Map<string, LinkedDevice>();
    for (const localDev of existingLocalDevices) {
      if (localDev.pairingState === 'REVOKED') {
        locallyRevoked.set(localDev.publicId, {
          ...localDev,
          pairingState: 'REVOKED',
          verifiedByRelay: false,
          pairedAt: null,
        });
      }
    }

    const sanitizedMap = new Map<string, LinkedDevice>();
    for (const dev of backedUpDevices) {
      if (currentIdentity && dev.publicId === currentIdentity.publicId) {
        continue;
      }
      if (locallyRevoked.has(dev.publicId) || dev.pairingState === 'REVOKED') {
        sanitizedMap.set(dev.publicId, {
          ...dev,
          pairingState: 'REVOKED',
          verifiedByRelay: false,
          pairedAt: null,
        });
      } else {
        // Restored peers NEVER inherit PAIRED or verifiedByRelay trust from backup
        sanitizedMap.set(dev.publicId, {
          ...dev,
          pairingState: 'UNPAIRED',
          verifiedByRelay: false,
          pairedAt: null,
        });
      }
    }

    for (const [revokedId, revokedDev] of locallyRevoked.entries()) {
      if (!sanitizedMap.has(revokedId)) {
        sanitizedMap.set(revokedId, revokedDev);
      }
    }

    return Array.from(sanitizedMap.values());
  }

  private applySyncEventReplayAndIdentityPolicy(
    events: SyncEvent[],
    sourceDevice: { publicId: string; cryptoKeyId: string } | null,
    currentIdentity: DeviceIdentityProfile | null
  ): { events: SyncEvent[]; crossDeviceRestore: boolean } {
    const sameDevice = Boolean(
      currentIdentity &&
      sourceDevice &&
      sourceDevice.publicId === currentIdentity.publicId &&
      sourceDevice.cryptoKeyId === currentIdentity.cryptoKeyId
    );

    if (sameDevice) {
      return { events: events.map((e) => ({ ...e })), crossDeviceRestore: false };
    }

    const normalized = events.map((evt) => {
      if (evt.status === 'PENDING' || evt.status === 'IN_PROGRESS') {
        return {
          ...evt,
          status: 'FAILED' as const,
          nextRetryAt: null,
          inboundAckConfirmed: false,
          lastError:
            'حدث مُستعاد من جهاز آخر — أُوقف إعادة الإرسال أو تأكيد ACK لحماية الهوية ومنع التكرار.',
        };
      }
      return { ...evt };
    });

    return { events: normalized, crossDeviceRestore: true };
  }

  async exportBackup(passphrase: string): Promise<BackupExportSummary> {
    if (!this.crypto.isSupported()) {
      throw new SecurityError(
        'BACKUP_CRYPTO_UNAVAILABLE',
        'تعذّر تصدير نسخة مشفرة لعدم توفر Web Crypto API.',
        'Crypto provider unsupported during backup export'
      );
    }

    const [settings, identity, linkedDevices, syncEvents, auditEntries] =
      await Promise.all([
        this.settingsRepo.get(),
        this.deviceRepo.getIdentity(),
        this.deviceRepo.getLinkedDevices(),
        this.syncRepo.getAll({ throwOnDecryptError: true }),
        this.auditRepo.getAll(),
      ]);

    for (const evt of syncEvents) {
      if (
        evt.encrypted &&
        !evt.e2eeEnvelope &&
        evt.payload === '[ENCRYPTED_AES_256_GCM]'
      ) {
        throw new StorageError(
          'BACKUP_EVENT_DECRYPTION_FAILED',
          'تعذّر فك تشفير أحد أحداث المزامنة المحلية؛ تم إيقاف التصدير.',
          `Refusing to export unresolved encrypted placeholder for event #${evt.id}`
        );
      }
    }

    const boundedAudits =
      auditEntries.length > BACKUP_MAX_AUDIT_ENTRIES
        ? auditEntries.slice(0, BACKUP_MAX_AUDIT_ENTRIES)
        : auditEntries;

    const exportedAt = Date.now();
    const innerPayload: BackupInnerPayloadV2 = {
      payloadVersion: 2,
      schemaVersion: APP_DB_VERSION,
      exportedAt,
      sourceDevice: identity
        ? {
            publicId: identity.publicId,
            cryptoKeyId: identity.cryptoKeyId,
          }
        : null,
      settings: validateAppSettings({ ...DEFAULT_APP_SETTINGS, ...settings }),
      linkedDevices,
      syncEvents,
      auditEntries: boundedAudits.map(normalizeAuditEntry),
    };

    const archive = await this.crypto.encryptBackupPayload({
      plaintext: JSON.stringify(innerPayload),
      passphrase,
      schemaVersion: APP_DB_VERSION,
      exportedAt,
    });

    return {
      archive,
      eventCount: syncEvents.length,
      linkedDeviceCount: linkedDevices.length,
      auditCount: boundedAudits.length,
    };
  }

  async restoreBackup(
    rawInput: string | EncryptedBackupArchiveV2 | Record<string, unknown>,
    passphrase: string
  ): Promise<BackupRestoreResult> {
    if (!this.crypto.isSupported()) {
      throw new SecurityError(
        'BACKUP_CRYPTO_UNAVAILABLE',
        'تعذّر استعادة النسخة الاحتياطية لعدم توفر Web Crypto API.',
        'Crypto provider unsupported during backup restore'
      );
    }

    const parsed = this.parseBoundedInput(rawInput as string | Record<string, unknown>);
    const detected = detectParsedBackupFormat(parsed);

    if (detected.kind === 'LEGACY_UNENCRYPTED_V1') {
      throw new ValidationError(
        'LEGACY_UNENCRYPTED_BACKUP',
        'تم رفض النسخة الاحتياطية القديمة (v1) لأنها غير مشفرة وقد تحتوي على بيانات حساسة مكشوفة. استخدم مسار الترحيل الصريح لتحويلها إلى نسخة v2 مشفرة أولاً.',
        'Rejected legacy unencrypted v1 backup by default'
      );
    }

    if (detected.kind === 'UNSUPPORTED_VERSION') {
      throw new ValidationError(
        'UNSUPPORTED_BACKUP_VERSION',
        'إصدار تنسيق النسخة الاحتياطية غير مدعوم.',
        `Unsupported backup formatVersion: ${String(detected.formatVersion)}`
      );
    }

    if (detected.kind !== 'ENCRYPTED_V2') {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'بنية ملف النسخة الاحتياطية غير صالحة أو تالفة.',
        'Invalid v2 backup envelope'
      );
    }

    const archive = parsed as unknown as EncryptedBackupArchiveV2;
    if (
      !Number.isInteger(archive.schemaVersion) ||
      archive.schemaVersion < 1 ||
      archive.schemaVersion > APP_DB_VERSION
    ) {
      throw new ValidationError(
        'UNSUPPORTED_SCHEMA_VERSION',
        `إصدار مخطط البيانات (${String(archive.schemaVersion)}) غير متوافق مع هذا الإصدار من التطبيق.`,
        `Unsupported backup schemaVersion: ${String(archive.schemaVersion)}`
      );
    }

    if (
      typeof archive.exportedAt !== 'number' ||
      !Number.isFinite(archive.exportedAt) ||
      archive.exportedAt <= 0
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'تاريخ تصدير النسخة الاحتياطية غير صالح.',
        'Invalid backup exportedAt timestamp'
      );
    }

    if (
      typeof archive.ciphertext !== 'string' ||
      archive.ciphertext.length > BACKUP_MAX_RAW_JSON_BYTES
    ) {
      throw new ValidationError(
        'BACKUP_LIMIT_EXCEEDED',
        'حجم البيانات المشفرة في النسخة يتجاوز الحد المسموح.',
        'Encrypted backup ciphertext exceeds limit'
      );
    }

    // Steps 3-5: Validate KDF bounds & decrypt/authenticate AES-256-GCM + AAD
    const innerJson = await this.crypto.decryptBackupPayload({
      archive,
      passphrase,
    });

    // Steps 6-9: Parse and strictly validate entire inner archive BEFORE any DB mutation
    let innerRaw: unknown;
    try {
      innerRaw = JSON.parse(innerJson);
    } catch {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'بيانات الأرشيف المفكوك غير صالحة.',
        'Decrypted backup inner JSON failed to parse'
      );
    }

    if (!isPlainRecord(innerRaw) || innerRaw.payloadVersion !== 2) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'بنية الأرشيف الداخلي للنسخة غير صالحة.',
        'Inner payload missing payloadVersion=2'
      );
    }

    if (
      innerRaw.schemaVersion !== archive.schemaVersion ||
      innerRaw.exportedAt !== archive.exportedAt
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_SCHEMA',
        'عدم تطابق البيانات الوصفية للأرشيف الداخلي مع ترويسة النسخة.',
        'Inner payload schemaVersion/exportedAt mismatch with outer archive'
      );
    }

    let sourceDevice: { publicId: string; cryptoKeyId: string } | null = null;
    if (innerRaw.sourceDevice !== null && innerRaw.sourceDevice !== undefined) {
      if (!isPlainRecord(innerRaw.sourceDevice)) {
        throw new ValidationError(
          'INVALID_BACKUP_SCHEMA',
          'بيانات الجهاز المصدر داخل النسخة غير صالحة.',
          'Invalid sourceDevice inside backup inner payload'
        );
      }
      sourceDevice = {
        publicId: assertBoundedString(
          innerRaw.sourceDevice.publicId,
          'sourceDevice.publicId',
          128
        ),
        cryptoKeyId: assertBoundedString(
          innerRaw.sourceDevice.cryptoKeyId,
          'sourceDevice.cryptoKeyId',
          128
        ),
      };
    }

    const validatedSettings = validateSettingsFromBackup(innerRaw.settings);
    const validatedDevices = validateLinkedDevicesFromBackup(innerRaw.linkedDevices);
    const validatedEvents = validateSyncEventsFromBackup(innerRaw.syncEvents);
    const validatedAudits = validateAuditEntriesFromBackup(innerRaw.auditEntries);

    // Step 10: Identity & Trust Policy (read-only lookup of current device & revocations)
    const [currentIdentity, existingLocalDevices] = await Promise.all([
      this.deviceRepo.getIdentity(),
      this.deviceRepo.getLinkedDevices(),
    ]);

    const sanitizedDevices = this.applyLinkedDeviceTrustPolicy(
      validatedDevices,
      existingLocalDevices,
      currentIdentity
    );
    const { events: sanitizedEvents, crossDeviceRestore } =
      this.applySyncEventReplayAndIdentityPolicy(
        validatedEvents,
        sourceDevice,
        currentIdentity
      );

    // Step 11: Re-encrypt all events with CURRENT device local AES-256-GCM key BEFORE transaction
    const preparedEvents: StoredSyncEventRecord[] = [];
    for (const evt of sanitizedEvents) {
      const envelope = await this.crypto.encrypt(evt.payload);
      if (!envelope) {
        throw new SecurityError(
          'BACKUP_LOCAL_ENCRYPT_FAILED',
          'تعذّر تشفير البيانات المستعادة محلياً بمفتاح هذا الجهاز؛ لم يتم تعديل قاعدة البيانات.',
          'Local AES-256-GCM encryption returned null during backup restore'
        );
      }
      preparedEvents.push({
        id: evt.id > 0 ? evt.id : undefined,
        type: evt.type,
        payload: '[ENCRYPTED_AES_256_GCM]',
        envelope,
        e2eeEnvelope: evt.e2eeEnvelope,
        createdAt: evt.createdAt,
        status: evt.status,
        retryCount: evt.retryCount,
        nextRetryAt: evt.nextRetryAt,
        idempotencyKey: evt.idempotencyKey,
        notificationKey: evt.notificationKey,
        payloadHash: evt.payloadHash,
        encrypted: true,
        localEncrypted: true,
        e2eeProtected: evt.e2eeProtected ?? false,
        e2eeVerified: evt.e2eeVerified ?? false,
        e2eeNonce: evt.e2eeNonce ?? null,
        inboundAckProof: evt.inboundAckProof ?? null,
        relayEventId: evt.relayEventId ?? null,
        inboundAckConfirmed: evt.inboundAckConfirmed ?? false,
        targetDeviceId: evt.targetDeviceId ?? null,
        sourceDeviceId: evt.sourceDeviceId ?? null,
        relayAcceptedAt: evt.relayAcceptedAt ?? null,
        deliveredAt: evt.deliveredAt ?? null,
        lastError: evt.lastError ?? null,
        syncedAt: evt.syncedAt ?? null,
      });
    }

    // Steps 12-13: Atomic IndexedDB transaction AFTER all checks & crypto prep succeed.
    // - STORES.IDENTITY is intentionally excluded so device identity & keys NEVER change.
    // - Target device role is preserved strictly from current local settings (backup role is ignored).
    // - STORES.SECURITY_AUDIT is NEVER cleared; imported audits are appended with new autoIncrement IDs
    //   and authoritative origin='BACKUP_IMPORT' provenance assigned by this restore pipeline.
    const restoreTimestamp = Date.now();
    const importedFromDeviceId = sourceDevice?.publicId ?? null;
    let preservedRole: DeviceRole | null = DEFAULT_APP_SETTINGS.role;

    await this.db.runTransaction(
      [
        STORES.SETTINGS,
        STORES.LINKED_DEVICES,
        STORES.SYNC_EVENTS,
        STORES.SECURITY_AUDIT,
      ],
      'readwrite',
      async (tx) => {
        const settingsStore = tx.objectStore(STORES.SETTINGS);
        const devicesStore = tx.objectStore(STORES.LINKED_DEVICES);
        const syncStore = tx.objectStore(STORES.SYNC_EVENTS);
        const auditStore = tx.objectStore(STORES.SECURITY_AUDIT);

        const currentSettingsRecord = (await reqToPromise(
          settingsStore.get('app_settings')
        )) as StoredSettingsRecord | undefined;
        preservedRole =
          currentSettingsRecord?.settings?.role ?? DEFAULT_APP_SETTINGS.role;

        const settingsToPersist = validateAppSettings({
          ...validatedSettings,
          role: preservedRole,
        });

        await reqToPromise(settingsStore.clear());
        await reqToPromise(devicesStore.clear());
        await reqToPromise(syncStore.clear());

        await reqToPromise(
          settingsStore.put({
            id: 'app_settings',
            settings: settingsToPersist,
          } satisfies StoredSettingsRecord)
        );
        for (const device of sanitizedDevices) {
          await reqToPromise(devicesStore.put(device));
        }
        for (const evt of preparedEvents) {
          await reqToPromise(syncStore.put(evt));
        }
        for (const entry of validatedAudits) {
          const importedRecord: Omit<SecurityAuditEntry, 'id'> = {
            timestamp: entry.timestamp,
            action: entry.action,
            actorRole: entry.actorRole,
            deviceId: entry.deviceId,
            outcome: entry.outcome,
            details: entry.details,
            origin: 'BACKUP_IMPORT',
            importedAt: restoreTimestamp,
            importedFromDeviceId,
          };
          await reqToPromise(auditStore.add(importedRecord));
        }
      }
    );

    return {
      restoredEvents: preparedEvents.length,
      restoredLinkedDevices: sanitizedDevices.length,
      restoredAuditEntries: validatedAudits.length,
      crossDeviceRestore,
      restoredRole: preservedRole,
    };
  }

  async migrateLegacyBackup(
    rawInput: string | Record<string, unknown>,
    newPassphrase: string,
    options: { userConfirmedLegacyImport: boolean }
  ): Promise<BackupExportSummary> {
    if (!options?.userConfirmedLegacyImport) {
      throw new ValidationError(
        'LEGACY_MIGRATION_CONFIRMATION_REQUIRED',
        'يجب تأكيد المستخدم الصريح قبل ترحيل نسخة احتياطية قديمة غير مشفرة إلى صيغة v2.',
        'Legacy backup migration called without explicit user confirmation'
      );
    }

    if (!this.crypto.isSupported()) {
      throw new SecurityError(
        'BACKUP_CRYPTO_UNAVAILABLE',
        'تعذّر ترحيل النسخة لعدم توفر Web Crypto API.',
        'Crypto provider unsupported during legacy migration'
      );
    }

    const parsed = this.parseBoundedInput(rawInput);
    const detected = detectParsedBackupFormat(parsed);
    if (detected.kind !== 'LEGACY_UNENCRYPTED_V1') {
      throw new ValidationError(
        'INVALID_LEGACY_BACKUP',
        'الملف المحدد ليس نسخة احتياطية قديمة بصيغة v1 صالحة للترحيل.',
        `Expected legacy v1 backup, detected ${detected.kind}`
      );
    }

    const legacy = parsed as unknown as LegacyBackupArchiveV1;
    if (
      !Number.isInteger(legacy.schemaVersion) ||
      legacy.schemaVersion < 1 ||
      legacy.schemaVersion > APP_DB_VERSION
    ) {
      throw new ValidationError(
        'UNSUPPORTED_SCHEMA_VERSION',
        'إصدار مخطط النسخة القديمة غير مدعوم.',
        `Unsupported legacy schemaVersion: ${String(legacy.schemaVersion)}`
      );
    }

    if (
      typeof legacy.exportedAt !== 'number' ||
      !Number.isFinite(legacy.exportedAt) ||
      legacy.exportedAt <= 0
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'تاريخ تصدير النسخة القديمة غير صالح.',
        'Invalid legacy exportedAt'
      );
    }

    const expectedChecksum = await this.crypto.sha256Hex(
      canonicalLegacyArchivePayload({
        schemaVersion: legacy.schemaVersion,
        exportedAt: legacy.exportedAt,
        settings: legacy.settings,
        identity: legacy.identity ?? null,
        linkedDevices: legacy.linkedDevices,
        syncEvents: legacy.syncEvents,
        auditEntries: legacy.auditEntries,
      })
    );

    if (expectedChecksum !== legacy.checksumSha256) {
      throw new StorageError(
        'BACKUP_CHECKSUM_MISMATCH',
        'فشل التحقق من بصمة SHA-256 للنسخة القديمة؛ قد يكون الملف تالفاً أو معدّلاً.',
        'Legacy backup SHA-256 checksum mismatch'
      );
    }

    const validatedSettings = validateSettingsFromBackup(legacy.settings);
    const validatedDevices = validateLinkedDevicesFromBackup(legacy.linkedDevices);
    const validatedEvents = validateSyncEventsFromBackup(legacy.syncEvents);
    const validatedAudits = validateAuditEntriesFromBackup(legacy.auditEntries);

    let sourceDevice: { publicId: string; cryptoKeyId: string } | null = null;
    if (legacy.identity !== null && legacy.identity !== undefined) {
      if (!isPlainRecord(legacy.identity)) {
        throw new ValidationError(
          'INVALID_BACKUP_SCHEMA',
          'بيانات الهوية في النسخة القديمة غير صالحة.',
          'Invalid legacy identity object'
        );
      }
      sourceDevice = {
        publicId: assertBoundedString(
          legacy.identity.publicId,
          'identity.publicId',
          128
        ),
        cryptoKeyId: assertBoundedString(
          legacy.identity.cryptoKeyId,
          'identity.cryptoKeyId',
          128
        ),
      };
    }

    // Apply strict Identity & Trust policy inside isolated migration buffer (zero DB side effects!)
    const [currentIdentity, existingLocalDevices] = await Promise.all([
      this.deviceRepo.getIdentity(),
      this.deviceRepo.getLinkedDevices(),
    ]);

    const sanitizedDevices = this.applyLinkedDeviceTrustPolicy(
      validatedDevices,
      existingLocalDevices,
      currentIdentity
    );
    const { events: sanitizedEvents } = this.applySyncEventReplayAndIdentityPolicy(
      validatedEvents,
      sourceDevice,
      currentIdentity
    );

    const exportedAt = Date.now();
    const innerPayload: BackupInnerPayloadV2 = {
      payloadVersion: 2,
      schemaVersion: APP_DB_VERSION,
      exportedAt,
      sourceDevice,
      settings: validatedSettings,
      linkedDevices: sanitizedDevices,
      syncEvents: sanitizedEvents,
      auditEntries: validatedAudits,
    };

    const archive = await this.crypto.encryptBackupPayload({
      plaintext: JSON.stringify(innerPayload),
      passphrase: newPassphrase,
      schemaVersion: APP_DB_VERSION,
      exportedAt,
    });

    return {
      archive,
      eventCount: sanitizedEvents.length,
      linkedDeviceCount: sanitizedDevices.length,
      auditCount: validatedAudits.length,
    };
  }
}

/* -------------------------------------------------------------------------- */
/* In-Memory Repositories for Deterministic Node Unit & Integration Tests     */
/* -------------------------------------------------------------------------- */

export class InMemorySyncEventRepository implements ISyncEventRepository {
  private events: SyncEvent[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async insert(input: CreateSyncEventInput): Promise<SyncEvent> {
    if (this.events.some((e) => e.idempotencyKey === input.idempotencyKey)) {
      throw new StorageError(
        'DUPLICATE_IDEMPOTENCY_KEY',
        'حدث مكرر بمفتاح عدم التكرار نفسه.',
        `Duplicate idempotencyKey ${input.idempotencyKey}`
      );
    }

    const created: SyncEvent = {
      id: this.nextId++,
      type: input.type,
      payload: input.payload,
      createdAt: input.createdAt ?? Date.now(),
      status: 'PENDING',
      retryCount: 0,
      nextRetryAt: null,
      idempotencyKey: input.idempotencyKey,
      notificationKey: input.notificationKey,
      payloadHash: input.payloadHash,
      encrypted: false,
      localEncrypted: false,
      e2eeProtected: input.e2eeProtected ?? false,
      e2eeVerified: input.e2eeVerified ?? false,
      e2eeNonce: input.e2eeNonce ?? null,
      e2eeEnvelope: input.e2eeEnvelope,
      inboundAckProof: input.inboundAckProof ?? null,
      relayEventId: input.relayEventId ?? null,
      inboundAckConfirmed: input.inboundAckConfirmed ?? false,
      targetDeviceId: input.targetDeviceId ?? null,
      sourceDeviceId: input.sourceDeviceId ?? null,
      relayAcceptedAt: null,
      deliveredAt: null,
      lastError: null,
      syncedAt: null,
    };
    this.events.push(created);
    this.listeners.forEach((l) => l());
    return { ...created };
  }

  async findById(id: number): Promise<SyncEvent | null> {
    const found = this.events.find((e) => e.id === id);
    return found ? { ...found } : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<SyncEvent | null> {
    const found = this.events.find((e) => e.idempotencyKey === idempotencyKey);
    return found ? { ...found } : null;
  }

  async findRecentDuplicate(
    type: string,
    notificationKey: string,
    payloadHash: string,
    windowMs: number,
    nowMs: number
  ): Promise<SyncEvent | null> {
    const cutoff = nowMs - windowMs;
    const found = this.events.find(
      (e) =>
        e.type === type &&
        e.notificationKey === notificationKey &&
        e.payloadHash === payloadHash &&
        e.createdAt >= cutoff
    );
    return found ? { ...found } : null;
  }

  async getAll(): Promise<SyncEvent[]> {
    return [...this.events]
      .sort((a, b) => b.createdAt - a.createdAt || b.id - a.id)
      .map((e) => ({ ...e }));
  }

  async getByStatus(status: SyncEventStatus): Promise<SyncEvent[]> {
    return (await this.getAll()).filter((e) => e.status === status);
  }

  async getDuePendingEvents(nowMs: number): Promise<SyncEvent[]> {
    return this.events
      .filter(
        (e) =>
          e.status === 'PENDING' && (e.nextRetryAt === null || e.nextRetryAt <= nowMs)
      )
      .sort((a, b) => a.createdAt - b.createdAt || a.id - b.id)
      .map((e) => ({ ...e }));
  }

  async updateEvent(
    id: number,
    patch: Partial<
      Pick<
        SyncEvent,
        | 'status'
        | 'retryCount'
        | 'nextRetryAt'
        | 'lastError'
        | 'syncedAt'
        | 'relayAcceptedAt'
        | 'deliveredAt'
        | 'targetDeviceId'
        | 'e2eeProtected'
        | 'e2eeVerified'
        | 'inboundAckConfirmed'
      >
    >
  ): Promise<SyncEvent | null> {
    const idx = this.events.findIndex((e) => e.id === id);
    if (idx === -1) return null;
    this.events[idx] = { ...this.events[idx], ...patch };
    this.listeners.forEach((l) => l());
    return { ...this.events[idx] };
  }

  async resetInProgressToPending(): Promise<number> {
    let count = 0;
    this.events = this.events.map((e) => {
      const isOutboundInFlight = e.relayEventId == null && !e.e2eeVerified;
      if (e.status === 'IN_PROGRESS' && isOutboundInFlight) {
        count += 1;
        return { ...e, status: 'PENDING', nextRetryAt: Date.now() };
      }
      return e;
    });
    if (count > 0) this.listeners.forEach((l) => l());
    return count;
  }

  async delete(id: number): Promise<boolean> {
    const before = this.events.length;
    this.events = this.events.filter((e) => e.id !== id);
    if (this.events.length !== before) {
      this.listeners.forEach((l) => l());
      return true;
    }
    return false;
  }

  async clearAll(): Promise<void> {
    this.events = [];
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemoryDeviceRepository implements IDeviceRepository {
  private identity: DeviceIdentityProfile | null = null;
  private linked = new Map<string, LinkedDevice>();
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async getIdentity(): Promise<DeviceIdentityProfile | null> {
    return this.identity ? { ...this.identity } : null;
  }

  async saveIdentity(identity: DeviceIdentityProfile): Promise<void> {
    this.identity = { ...identity };
    this.listeners.forEach((l) => l());
  }

  async getLinkedDevices(): Promise<LinkedDevice[]> {
    return Array.from(this.linked.values()).map((d) => ({ ...d }));
  }

  async upsertLinkedDevice(device: LinkedDevice): Promise<void> {
    this.linked.set(device.publicId, { ...device });
    this.listeners.forEach((l) => l());
  }

  async removeLinkedDevice(publicId: string): Promise<void> {
    this.linked.delete(publicId);
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemoryAuditRepository implements ISecurityAuditRepository {
  private entries: SecurityAuditEntry[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async append(entry: Omit<SecurityAuditEntry, 'id'>): Promise<SecurityAuditEntry> {
    const created: SecurityAuditEntry = {
      timestamp: entry.timestamp,
      action: entry.action,
      actorRole: entry.actorRole,
      deviceId: entry.deviceId,
      outcome: entry.outcome,
      details: entry.details,
      origin: 'LOCAL',
      importedAt: null,
      importedFromDeviceId: null,
      id: this.nextId++,
    };
    this.entries = [created, ...this.entries];
    this.listeners.forEach((l) => l());
    return created;
  }

  async getAll(): Promise<SecurityAuditEntry[]> {
    return this.entries.map(normalizeAuditEntry);
  }

  async clear(): Promise<void> {
    this.entries = [];
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export class InMemorySettingsRepository implements ISettingsRepository {
  private current: AppSettings = { ...DEFAULT_APP_SETTINGS };
  private listeners = new Set<() => void>();

  async initialize(): Promise<void> {}

  async get(): Promise<AppSettings> {
    return {
      ...this.current,
      selectedNotificationApps: [...this.current.selectedNotificationApps],
    };
  }

  async save(settings: AppSettings): Promise<void> {
    this.current = {
      ...settings,
      selectedNotificationApps: [...settings.selectedNotificationApps],
    };
    this.listeners.forEach((l) => l());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
