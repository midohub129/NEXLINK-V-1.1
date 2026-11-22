import { SecurityError } from '../../domain/errors/appError';
import type { ISecurityAuditRepository } from '../../domain/interfaces/repositories';
import type { ICryptoProvider, ILogger } from '../../domain/interfaces/services';
import type { DeviceRole } from '../../domain/models/device';
import type {
  RoleCapabilities,
  SecurityAuditAction,
  SecurityAuditEntry,
  SessionState,
} from '../../domain/models/security';

export class SecurityManager {
  private readonly crypto: ICryptoProvider;
  private readonly auditRepo: ISecurityAuditRepository;
  private readonly logger: ILogger;
  private session: SessionState | null = null;
  private auditCache: SecurityAuditEntry[] = [];
  private listeners = new Set<() => void>();

  constructor(
    crypto: ICryptoProvider,
    auditRepo: ISecurityAuditRepository,
    logger: ILogger
  ) {
    this.crypto = crypto;
    this.auditRepo = auditRepo;
    this.logger = logger;
  }

  async initialize(): Promise<void> {
    await this.auditRepo.initialize();
    this.auditCache = await this.auditRepo.getAll();
    this.notify();
  }

  /**
   * Authorization (AuthZ): Pure capability matrix derived from role,
   * completely separated from Authentication (session & cryptographic identity).
   */
  getCapabilities(role: DeviceRole | null): RoleCapabilities {
    if (role === 'admin') {
      return {
        manageDevices: true,
        manageAllowedApps: true,
        viewNotifications: true,
        updateEventStatus: true,
        deleteEvents: true,
        viewSecurityAudit: true,
        revokeAuthorization: true,
        exportBackups: true,
      };
    }

    if (role === 'basic') {
      return {
        manageDevices: false,
        manageAllowedApps: true,
        viewNotifications: true,
        updateEventStatus: false,
        deleteEvents: false,
        viewSecurityAudit: true,
        revokeAuthorization: true,
        exportBackups: false,
      };
    }

    return {
      manageDevices: false,
      manageAllowedApps: false,
      viewNotifications: false,
      updateEventStatus: false,
      deleteEvents: false,
      viewSecurityAudit: false,
      revokeAuthorization: false,
      exportBackups: false,
    };
  }

  /**
   * Authentication (AuthN): Issues an explicit session bound to device & crypto identity.
   * Kept in-memory (not stored in localStorage).
   */
  issueSession(
    devicePublicId: string,
    cryptoKeyId: string,
    timeoutMinutes = 30
  ): SessionState {
    const now = Date.now();
    this.session = {
      sessionId: `sess-${this.crypto.randomHex(16)}`,
      authenticated: true,
      scope: 'LOCAL_UI',
      issuedAt: now,
      expiresAt: now + timeoutMinutes * 60 * 1000,
      devicePublicId,
      cryptoKeyId,
    };
    this.logger.info(
      'SECURITY',
      'تم إصدار جلسة واجهة محلية منفصلة بالمولد العشوائي التشفيري'
    );
    this.notify();
    return this.session;
  }

  expireSession(): void {
    if (this.session) {
      this.session = {
        ...this.session,
        authenticated: false,
        expiresAt: Date.now() - 1000,
      };
      this.notify();
    }
  }

  clearSession(): void {
    this.session = null;
    this.notify();
  }

  getSession(): SessionState | null {
    return this.session ? { ...this.session } : null;
  }

  isSessionAuthenticated(nowMs = Date.now()): boolean {
    return Boolean(
      this.session && this.session.authenticated && nowMs < this.session.expiresAt
    );
  }

  getRemainingSessionSeconds(nowMs = Date.now()): number {
    if (!this.session || !this.session.authenticated) return 0;
    return Math.max(0, Math.floor((this.session.expiresAt - nowMs) / 1000));
  }

  /**
   * Enforces BOTH Authentication (active session) and Authorization (role capability).
   */
  async assertAuthorized(
    role: DeviceRole | null,
    deviceId: string,
    capability: keyof RoleCapabilities,
    actionDescription: string
  ): Promise<void> {
    if (!this.isSessionAuthenticated()) {
      await this.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role ?? 'none',
        deviceId,
        outcome: 'DENIED',
        details: `رفض ${actionDescription}: الجلسة منتهية أو غير مصادق عليها`,
      });
      throw new SecurityError(
        'SESSION_UNAUTHENTICATED',
        'انتهت صلاحية الجلسة الحالية. يرجى تجديد الجلسة للمتابعة.',
        `Denied ${actionDescription}: unauthenticated or expired session`
      );
    }

    const caps = this.getCapabilities(role);
    if (!caps[capability]) {
      await this.recordAudit({
        action: 'ACCESS_DENIED',
        actorRole: role ?? 'none',
        deviceId,
        outcome: 'DENIED',
        details: `رفض ${actionDescription}: الصلاحية غير متاحة لدور ${role ?? 'none'}`,
      });
      throw new SecurityError(
        'AUTHORIZATION_DENIED',
        'هذه العملية تتطلب صلاحيات الجهاز الرئيسي (Super Admin).',
        `Denied ${actionDescription}: missing capability ${capability} for role ${String(role)}`
      );
    }
  }

  async recordAudit(
    entry: Omit<SecurityAuditEntry, 'id' | 'timestamp'> & { timestamp?: number }
  ): Promise<SecurityAuditEntry> {
    const saved = await this.auditRepo.append({
      timestamp: entry.timestamp ?? Date.now(),
      action: entry.action as SecurityAuditAction,
      actorRole: entry.actorRole,
      deviceId: entry.deviceId,
      outcome: entry.outcome,
      details: entry.details,
    });
    this.auditCache = await this.auditRepo.getAll();
    this.notify();
    return saved;
  }

  getAuditLog(): SecurityAuditEntry[] {
    return [...this.auditCache];
  }

  async clearAuditLog(role: DeviceRole | null, deviceId: string): Promise<void> {
    await this.assertAuthorized(role, deviceId, 'deleteEvents', 'مسح السجل الأمني');
    await this.auditRepo.clear();
    this.auditCache = [];
    this.notify();
  }

  async verifyCryptoIntegrity(
    role: DeviceRole | null,
    deviceId: string
  ): Promise<{ ok: boolean; algorithm: string }> {
    const result = await this.crypto.verifySelfIntegrity();
    await this.recordAudit({
      action: 'VAULT_VERIFIED',
      actorRole: role ?? 'none',
      deviceId,
      outcome: result.ok ? 'ALLOWED' : 'DENIED',
      details: result.ok
        ? `تم التحقق من التشفير: ${result.algorithm}`
        : `تعذر التحقق من التشفير: ${result.algorithm}`,
    });
    return result;
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
