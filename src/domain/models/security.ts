import type { DeviceRole } from './device';

export interface RoleCapabilities {
  manageDevices: boolean;
  manageAllowedApps: boolean;
  viewNotifications: boolean;
  updateEventStatus: boolean;
  deleteEvents: boolean;
  viewSecurityAudit: boolean;
  revokeAuthorization: boolean;
  exportBackups: boolean;
}

export interface SessionState {
  sessionId: string;
  authenticated: boolean;
  scope: 'LOCAL_UI' | 'RELAY_SERVER';
  issuedAt: number;
  expiresAt: number;
  devicePublicId: string;
  cryptoKeyId: string;
}

export interface RelayServerSession {
  sessionId: string;
  token: string;
  devicePublicId: string;
  cryptoKeyId: string;
  role: DeviceRole;
  issuedAt: number;
  expiresAt: number;
}

export interface EncryptedEnvelope {
  algorithm: 'AES-256-GCM';
  iv: string;
  ciphertext: string;
}

export interface E2eeEnvelope {
  version: 1;
  algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM';
  senderDeviceId: string;
  recipientDeviceId: string;
  senderCryptoKeyId: string;
  recipientCryptoKeyId: string;
  sessionId: string;
  messageNonce: string;
  iv: string;
  aad: string;
  ciphertext: string;
  signature: string;
}

export type SecurityAuditAction =
  | 'ROLE_ASSIGNED'
  | 'ROLE_CHANGED'
  | 'AUTHORIZATION_REVOKED'
  | 'SESSION_RENEWED'
  | 'SESSION_EXPIRED'
  | 'PERMISSION_GRANTED'
  | 'PERMISSION_REVOKED'
  | 'ACCESS_DENIED'
  | 'DUPLICATE_BLOCKED'
  | 'VAULT_VERIFIED'
  | 'BACKUP_EXPORTED'
  | 'BACKUP_RESTORED'
  | 'DEVICE_PAIRED'
  | 'PAIRING_CONFIRMED'
  | 'PAIRING_REJECTED'
  | 'DEVICE_REVOKED'
  | 'E2EE_VERIFIED'
  | 'E2EE_DECRYPT_FAILED'
  | 'REPLAY_BLOCKED'
  | 'SECURE_WIPE';

export type SecurityAuditOrigin = 'LOCAL' | 'BACKUP_IMPORT';

export interface SecurityAuditEntry {
  id: number;
  timestamp: number;
  action: SecurityAuditAction;
  actorRole: DeviceRole | 'none';
  deviceId: string;
  outcome: 'ALLOWED' | 'DENIED' | 'INFO';
  details: string;
  origin?: SecurityAuditOrigin;
  importedAt?: number | null;
  importedFromDeviceId?: string | null;
}
