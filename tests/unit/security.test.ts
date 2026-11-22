import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { RotatingLogger } from '../../src/application/logging/loggerService';
import { SecurityManager } from '../../src/application/security/securityManager';
import { SecurityError } from '../../src/domain/errors/appError';
import { InMemoryAuditRepository } from '../../src/infrastructure/storage/repositories';
import { NodeTestCryptoProvider } from '../helpers/nodeCryptoProvider';

describe('SecurityManager & RotatingLogger Tests', () => {
  it('separates Authentication (session) from Authorization (RBAC) and logs denied attempts', async () => {
    const logger = new RotatingLogger();
    const crypto = new NodeTestCryptoProvider();
    const auditRepo = new InMemoryAuditRepository();
    const security = new SecurityManager(crypto, auditRepo, logger);
    await security.initialize();

    // 1. Unauthenticated -> denied even for admin role
    await assert.rejects(
      () => security.assertAuthorized('admin', 'dev-1', 'manageDevices', 'ربط جهاز'),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'SESSION_UNAUTHENTICATED'
    );

    // 2. Authenticated as basic -> allowed for viewNotifications, denied for deleteEvents
    security.issueSession('dev-1', 'ecdsa-123', 30);
    await security.assertAuthorized(
      'basic',
      'dev-1',
      'viewNotifications',
      'عرض الإشعارات'
    );

    await assert.rejects(
      () => security.assertAuthorized('basic', 'dev-1', 'deleteEvents', 'حذف السجل'),
      (err: unknown) =>
        err instanceof SecurityError && err.code === 'AUTHORIZATION_DENIED'
    );

    // 3. Expired session -> denied again
    security.expireSession();
    assert.equal(security.isSessionAuthenticated(), false);
    await assert.rejects(() =>
      security.assertAuthorized('admin', 'dev-1', 'deleteEvents', 'حذف السجل')
    );

    const audits = security.getAuditLog();
    assert.equal(audits.length, 3);
    assert.ok(
      audits.every((a) => a.action === 'ACCESS_DENIED' && a.outcome === 'DENIED')
    );
  });

  it('rotates logs via ring buffer and redacts sensitive fields', () => {
    const logger = new RotatingLogger(20);
    for (let i = 0; i < 30; i += 1) {
      logger.info('SECURITY', `Event ${i}`, {
        secret: 'super-secret-value',
        token: 'jwt-token',
        privateKey: 'pem-key',
        payload: 'raw-body',
        safeCount: i,
      });
    }

    const logs = logger.getLogs();
    assert.equal(logs.length, 20);
    assert.equal(logs[0].metadata?.secret, '[REDACTED]');
    assert.equal(logs[0].metadata?.token, '[REDACTED]');
    assert.equal(logs[0].metadata?.privateKey, '[REDACTED]');
    assert.equal(logs[0].metadata?.payload, '[REDACTED]');
    assert.equal(logs[0].metadata?.safeCount, 29);
    assert.ok(logs[0].traceId.startsWith('security-'));
  });
});
