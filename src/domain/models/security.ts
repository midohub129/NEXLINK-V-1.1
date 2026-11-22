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
  issuedAt: number;
  expiresAt: number;
  devicePublicId: string;
  cryptoKeyId: string;
}

export interface EncryptedEnvelope {
  algorithm: 'AES-256-GCM';
  iv: string;
  ciphertext: string;
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
  | 'DEVICE_REVOKED'
  | 'SECURE_WIPE';

export interface SecurityAuditEntry {
  id: number;
  timestamp: number;
  action: SecurityAuditAction;
  actorRole: DeviceRole | 'none';
  deviceId: string;
  outcome: 'ALLOWED' | 'DENIED' | 'INFO';
  details: string;
}
