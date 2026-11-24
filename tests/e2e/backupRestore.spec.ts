import fs from 'node:fs/promises';
import { expect, test, type Page } from '@playwright/test';

const BACKUP_PASSPHRASE = 'Real-Browser-Backup-Passphrase-2026!';
const WRONG_PASSPHRASE = 'Wrong-Browser-Backup-Passphrase-9999!';

interface BrowserDbSnapshot {
  version: number;
  migrations: Array<{ version: number; name: string }>;
  settings: Record<string, unknown> | null;
  identity: Record<string, unknown> | null;
  linkedDevices: Array<Record<string, unknown>>;
  syncEvents: Array<Record<string, unknown>>;
  securityAudit: Array<Record<string, unknown>>;
}

async function clearBrowserIndexedDb(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const deleteDb = (name: string) =>
      new Promise<void>((resolve) => {
        const req = window.indexedDB.deleteDatabase(name);
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
        req.onblocked = () => resolve();
      });
    await deleteDb('nexlink_app_db');
    await deleteDb('nexlink_keystore');
  });
}

async function readBrowserDbSnapshot(page: Page): Promise<BrowserDbSnapshot> {
  return page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = window.indexedDB.open('nexlink_app_db');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const readStore = (storeName: string) =>
      new Promise<Array<Record<string, unknown>>>((resolve, reject) => {
        if (!db.objectStoreNames.contains(storeName)) {
          resolve([]);
          return;
        }
        const tx = db.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).getAll();
        req.onsuccess = () =>
          resolve((req.result ?? []) as Array<Record<string, unknown>>);
        req.onerror = () => reject(req.error);
      });

    const [migrations, settingsRows, identityRows, linkedDevices, syncEvents, securityAudit] =
      await Promise.all([
        readStore('schema_migrations'),
        readStore('settings'),
        readStore('device_identity'),
        readStore('linked_devices'),
        readStore('sync_events'),
        readStore('security_audit'),
      ]);

    const version = db.version;
    db.close();

    return {
      version,
      migrations: migrations.map((m) => ({
        version: Number(m.version),
        name: String(m.name),
      })),
      settings: (settingsRows[0]?.settings as Record<string, unknown>) ?? null,
      identity: (identityRows[0]?.identity as Record<string, unknown>) ?? null,
      linkedDevices,
      syncEvents,
      securityAudit,
    };
  });
}

async function initializeAdminWithNotification(
  page: Page,
  title: string,
  text: string
): Promise<void> {
  // Select SUPER ADMIN role
  await page.locator('section:has-text("SUPER ADMIN") button').click();
  await expect(page.getByText('الجهاز الرئيسي • SUPER ADMIN')).toBeVisible();

  // Enable notification permission
  await page.getByRole('button', { name: 'إعداد صلاحية الإشعارات' }).click();
  await page.getByRole('button', { name: 'منح الصلاحية' }).click();
  await page.getByRole('button', { name: 'إغلاق' }).click();

  // Add allowed package & enqueue sensitive notification
  await page.getByRole('button', { name: /تطبيقات الإشعارات المسموحة/ }).click();
  await page.getByLabel('أضف معرّف حزمة يدوياً').fill('com.bank.e2e');
  await page.getByRole('button', { name: 'إضافة حزمة' }).click();
  await page.getByRole('button', { name: /عرض سجل الإشعارات المحفوظة/ }).click();

  await page.getByLabel('عنوان الإشعار').fill(title);
  await page.getByLabel('نص الإشعار').fill(text);
  await page.getByRole('button', { name: 'إدراج' }).click();
  await expect(page.getByRole('status')).toContainText('تم تشفير الحدث');

  // Return to dashboard via topbar brand button
  await page.locator('header button:has-text("NEXLINK")').click();
  await expect(page.getByText('حالة الاتصال')).toBeVisible();
}

async function openBackupTab(page: Page): Promise<void> {
  await page
    .getByRole('button', { name: /مركز الأمان والإعدادات والصحة والنسخ الاحتياطي/ })
    .click();
  await page.getByRole('tab', { name: 'النسخ الاحتياطي' }).click();
}

test.describe('Encrypted Backup v2 E2E (Real Chromium + Browser IndexedDB)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await clearBrowserIndexedDb(page);
    await page.reload();
  });

  test('exports EncryptedBackupArchive v2 via UI without plaintext/secrets using real Chromium WebCrypto & IndexedDB', async ({
    page,
  }) => {
    const secretTitle = 'Browser-Secret-OTP-Alert';
    const secretBody = 'Sensitive browser payload code 918273';
    await initializeAdminWithNotification(page, secretTitle, secretBody);

    await openBackupTab(page);
    await page
      .getByLabel('عبارة مرور التصدير', { exact: true })
      .fill(BACKUP_PASSPHRASE);
    await page
      .getByLabel('تأكيد عبارة مرور التصدير', { exact: true })
      .fill(BACKUP_PASSPHRASE);
    await page.getByRole('button', { name: 'إنشاء نسخة مشفرة v2' }).click();

    await expect(page.getByRole('status')).toContainText(
      'تم إنشاء نسخة احتياطية مشفرة v2 بنجاح'
    );

    const previewJson = await page
      .getByLabel('معاينة النسخة الاحتياطية المشفرة v2')
      .inputValue();
    expect(previewJson).not.toContain(secretTitle);
    expect(previewJson).not.toContain(secretBody);
    expect(previewJson).not.toContain('com.bank.e2e');
    expect(previewJson).not.toContain(BACKUP_PASSPHRASE);

    const parsedPreview = JSON.parse(previewJson) as Record<string, unknown>;
    expect(parsedPreview.format).toBe('nexlink-encrypted-backup');
    expect(parsedPreview.formatVersion).toBe(2);
    expect(parsedPreview.schemaVersion).toBe(4);
    expect((parsedPreview.kdf as Record<string, unknown>).algorithm).toBe(
      'PBKDF2-HMAC-SHA-256'
    );
    expect((parsedPreview.encryption as Record<string, unknown>).algorithm).toBe(
      'AES-256-GCM'
    );

    // Verify real browser file download produces identical encrypted v2 file
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'تنزيل ملف .json المشفر' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^nexlink-backup-v2-\d{4}-\d{2}-\d{2}\.json$/);
    const downloadedPath = await download.path();
    expect(downloadedPath).toBeTruthy();
    const downloadedContent = await fs.readFile(downloadedPath!, 'utf8');
    expect(downloadedContent).toBe(previewJson);
  });

  test('restores backup into real IndexedDB, preserves target identity/role, downgrades paired peers, and distinguishes imported audits', async ({
    browser,
    page,
  }, testInfo) => {
    // 1. Source device creates notification + exports encrypted v2 backup
    const sourceSecretTitle = 'Cross-Browser-Restored-Alert';
    const sourceSecretBody = 'Decrypted cleanly by target browser AES key';
    await initializeAdminWithNotification(page, sourceSecretTitle, sourceSecretBody);

    // Update settings on source device before export to verify allowed settings restore
    await page
      .getByRole('button', { name: /مركز الأمان والإعدادات والصحة والنسخ الاحتياطي/ })
      .click();
    await page.getByRole('tab', { name: 'الإعدادات والصحة' }).click();
    await page.getByLabel(/مهلة الجلسة/).fill('75');
    await page.getByLabel(/الحد الأقصى لإعادة المحاولة/).fill('9');
    await page.getByRole('button', { name: 'حفظ الإعدادات' }).click();
    await expect(page.getByRole('status')).toContainText('تم التحقق من القيم');

    // Craft an encrypted v2 archive directly inside source browser WebCrypto from a 'basic' source role,
    // containing a PAIRED peer and a spoofed origin='LOCAL' audit entry with colliding id=1
    const sourceArchiveJson = await page.evaluate(async (passphrase: string) => {
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const b64 = (bytes: Uint8Array) => {
        let bin = '';
        for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
      };
      const exportedAt = Date.now();
      const kdf = {
        algorithm: 'PBKDF2-HMAC-SHA-256',
        hash: 'SHA-256',
        iterations: 600_000,
        salt: b64(salt),
        keyLengthBits: 256,
      };
      const encryption = {
        algorithm: 'AES-256-GCM',
        iv: b64(iv),
      };
      const aad = JSON.stringify({
        format: 'nexlink-encrypted-backup',
        formatVersion: 2,
        schemaVersion: 4,
        exportedAt,
        kdf,
        encryption,
      });
      const innerPayload = {
        payloadVersion: 2,
        schemaVersion: 4,
        exportedAt,
        sourceDevice: {
          publicId: 'source-device-basic-999',
          cryptoKeyId: 'ecdsa-source-999',
        },
        settings: {
          role: 'basic',
          selectedNotificationApps: ['com.bank.e2e'],
          connectionServiceEnabled: false,
          notificationAccessGranted: true,
          usageAccessGranted: false,
          sessionTimeoutMinutes: 75,
          syncIntervalMs: 12000,
          maxSyncRetries: 9,
          relayEndpoint: '/api/relay',
          syncDeliveryPolicy: 'PEER_CONFIRMED',
          targetDeviceId: null,
          testFixtureModeEnabled: false,
        },
        linkedDevices: [
          {
            publicId: 'peer-should-downgrade',
            cryptoKeyId: 'ecdsa-peer-down',
            publicKeyJwk: null,
            ecdhPublicKeyJwk: null,
            label: 'Source Paired Phone',
            role: 'basic',
            pairingState: 'PAIRED',
            pairedAt: exportedAt - 5000,
            lastSeenAt: exportedAt - 1000,
            verifiedByRelay: true,
          },
        ],
        syncEvents: [
          {
            id: 1,
            type: 'notification',
            payload: JSON.stringify({
              packageName: 'com.bank.e2e',
              title: 'Cross-Browser-Restored-Alert',
              text: 'Decrypted cleanly by target browser AES key',
              postedAt: exportedAt - 2000,
            }),
            createdAt: exportedAt - 2000,
            status: 'SYNCED',
            retryCount: 0,
            nextRetryAt: null,
            idempotencyKey: 'idem-e2e-restored-1',
            encrypted: true,
            sourceDeviceId: 'source-device-basic-999',
          },
        ],
        auditEntries: [
          {
            id: 1,
            timestamp: exportedAt - 3000,
            action: 'ROLE_CHANGED',
            actorRole: 'basic',
            deviceId: 'source-device-basic-999',
            outcome: 'ALLOWED',
            details: 'سجل مستورد يدّعي أنه محلي بمعرّف 1',
            origin: 'LOCAL',
          },
        ],
      };

      const baseKey = await crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      const cipherBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: enc.encode(aad) },
        aesKey,
        enc.encode(JSON.stringify(innerPayload))
      );

      return JSON.stringify({
        format: 'nexlink-encrypted-backup',
        formatVersion: 2,
        schemaVersion: 4,
        exportedAt,
        kdf,
        encryption,
        aad,
        ciphertext: b64(new Uint8Array(cipherBuf)),
      });
    }, BACKUP_PASSPHRASE);

    const backupFilePath = testInfo.outputPath('source-backup-v2.json');
    await fs.writeFile(backupFilePath, sourceArchiveJson, 'utf8');

    // 2. Open a completely separate target browser context (separate Chromium IndexedDB + keys)
    const targetContext = await browser.newContext();
    const targetPage = await targetContext.newPage();
    try {
      await targetPage.goto('/');
      await clearBrowserIndexedDb(targetPage);
      await targetPage.reload();

      // Target initializes as SUPER ADMIN (must remain 'admin' despite restoring 'basic' archive)
      await targetPage.locator('section:has-text("SUPER ADMIN") button').click();
      await expect(targetPage.getByText('الجهاز الرئيسي • SUPER ADMIN')).toBeVisible();

      const targetBefore = await readBrowserDbSnapshot(targetPage);
      const targetIdBefore = targetBefore.identity!.publicId;
      const targetKeyIdBefore = targetBefore.identity!.cryptoKeyId;
      expect(targetBefore.settings!.role).toBe('admin');
      expect(targetBefore.securityAudit.length).toBeGreaterThanOrEqual(1);
      const originalLocalAuditId = targetBefore.securityAudit[0].id;

      // Upload backup file via real file input in Backup tab
      await openBackupTab(targetPage);
      await targetPage.locator('input[type="file"]').setInputFiles(backupFilePath);
      await targetPage.getByLabel('عبارة مرور الاستعادة').fill(BACKUP_PASSPHRASE);
      await targetPage
        .locator('input[type="checkbox"]')
        .last()
        .check();
      await targetPage.getByRole('button', { name: 'التحقق والاستعادة الآمنة' }).click();

      await expect(targetPage.getByRole('status')).toContainText('تمت الاستعادة الآمنة');

      // Check UI audit log tab immediately: both LOCAL and BACKUP_IMPORT badges must be distinct
      await targetPage.getByRole('tab', { name: 'السجلات' }).click();
      await expect(targetPage.getByText('حدث محلي موثق').first()).toBeVisible();
      await expect(
        targetPage.getByText('مستورد من نسخة احتياطية · غير موثق محلياً')
      ).toBeVisible();
      await expect(
        targetPage.getByText(/لا يُعد دليلاً مستقلاً على حدوث الحدث محلياً/)
      ).toBeVisible();

      // Close modal & verify Dashboard preserves target role
      await targetPage.getByRole('button', { name: 'إغلاق' }).click();
      await expect(targetPage.getByText('الجهاز الرئيسي • SUPER ADMIN')).toBeVisible();

      // Verify restored peer was downgraded to UNPAIRED in Pairing modal
      await targetPage.getByRole('button', { name: /ربط الأجهزة والاقتران/ }).click();
      await expect(targetPage.getByText('Source Paired Phone')).toBeVisible();
      await expect(targetPage.getByText('تم سحب التفويض')).toBeVisible();
      await targetPage.getByRole('button', { name: 'إغلاق' }).click();

      // Verify restored event decrypted in UI & persists after full page reload
      await targetPage.getByRole('button', { name: /سجل الإشعارات وطابور المزامنة/ }).click();
      await expect(targetPage.getByText(sourceSecretTitle)).toBeVisible();
      await expect(targetPage.getByText(sourceSecretBody)).toBeVisible();

      await targetPage.reload();
      await expect(targetPage.getByText('الجهاز الرئيسي • SUPER ADMIN')).toBeVisible();

      // Inspect real browser IndexedDB directly to prove invariants
      const targetAfter = await readBrowserDbSnapshot(targetPage);
      expect(targetAfter.identity!.publicId).toBe(targetIdBefore);
      expect(targetAfter.identity!.cryptoKeyId).toBe(targetKeyIdBefore);
      expect(targetAfter.settings!.role).toBe('admin');
      expect(targetAfter.settings!.sessionTimeoutMinutes).toBe(75);
      expect(targetAfter.settings!.maxSyncRetries).toBe(9);

      expect(targetAfter.linkedDevices).toHaveLength(1);
      expect(targetAfter.linkedDevices[0].pairingState).toBe('UNPAIRED');
      expect(targetAfter.linkedDevices[0].verifiedByRelay).toBe(false);

      // Local audit entry kept untouched + imported audit entry got distinct ID & BACKUP_IMPORT
      const keptLocal = targetAfter.securityAudit.find(
        (a) => a.id === originalLocalAuditId
      );
      expect(keptLocal).toBeTruthy();
      expect(keptLocal!.origin).toBe('LOCAL');

      const importedAudit = targetAfter.securityAudit.find(
        (a) => a.details === 'سجل مستورد يدّعي أنه محلي بمعرّف 1'
      );
      expect(importedAudit).toBeTruthy();
      expect(importedAudit!.id).not.toBe(originalLocalAuditId);
      expect(importedAudit!.origin).toBe('BACKUP_IMPORT');
      expect(importedAudit!.importedFromDeviceId).toBe('source-device-basic-999');
    } finally {
      await targetContext.close();
    }
  });

  test('keeps browser IndexedDB completely unchanged on wrong passphrase, tampering, unsupported version, corrupt JSON, and mid-transaction failure', async ({
    page,
  }) => {
    await initializeAdminWithNotification(
      page,
      'Baseline-Event-Must-Stay',
      'Baseline secret body'
    );

    await openBackupTab(page);
    await page
      .getByLabel('عبارة مرور التصدير', { exact: true })
      .fill(BACKUP_PASSPHRASE);
    await page
      .getByLabel('تأكيد عبارة مرور التصدير', { exact: true })
      .fill(BACKUP_PASSPHRASE);
    await page.getByRole('button', { name: 'إنشاء نسخة مشفرة v2' }).click();
    await expect(page.getByRole('status')).toContainText('تم إنشاء نسخة احتياطية');

    const validArchiveText = await page
      .getByLabel('معاينة النسخة الاحتياطية المشفرة v2')
      .inputValue();
    const validArchive = JSON.parse(validArchiveText) as Record<string, unknown>;

    // Insert a second live event so restoring the older backup would clearly change DB if not rolled back
    await page.getByRole('button', { name: 'إغلاق' }).click();
    await page.getByRole('button', { name: /سجل الإشعارات وطابور المزامنة/ }).click();
    await page.getByLabel('عنوان الإشعار').fill('Live-Second-Event-Must-Survive');
    await page.getByLabel('نص الإشعار').fill('Second event body');
    await page.getByRole('button', { name: 'إدراج' }).click();
    await expect(page.getByRole('status')).toContainText('تم تشفير الحدث');
    await page.locator('header button:has-text("NEXLINK")').click();

    const snapshotBefore = await readBrowserDbSnapshot(page);
    expect(snapshotBefore.syncEvents).toHaveLength(2);

    await openBackupTab(page);

    const expectDbIdentical = async () => {
      const snap = await readBrowserDbSnapshot(page);
      expect(snap.settings).toEqual(snapshotBefore.settings);
      expect(snap.identity).toEqual(snapshotBefore.identity);
      expect(snap.linkedDevices).toEqual(snapshotBefore.linkedDevices);
      expect(snap.syncEvents).toEqual(snapshotBefore.syncEvents);
      expect(snap.securityAudit).toEqual(snapshotBefore.securityAudit);
    };

    const submitRestoreText = async (jsonText: string, passphrase: string) => {
      await page.getByLabel('نص أو ملف النسخة الاحتياطية للاستعادة').fill(jsonText);
      await page.getByLabel('عبارة مرور الاستعادة').fill(passphrase);
      const confirmBox = page.locator('input[type="checkbox"]').last();
      if (!(await confirmBox.isChecked())) {
        await confirmBox.check();
      }
      await page.getByRole('button', { name: 'التحقق والاستعادة الآمنة' }).click();
    };

    // 1. Wrong passphrase
    await submitRestoreText(validArchiveText, WRONG_PASSPHRASE);
    await expect(page.getByRole('alert').first()).toContainText(
      'فشل التحقق من عبارة المرور'
    );
    await expectDbIdentical();

    // 2. Tampered ciphertext
    const tampered = structuredClone(validArchive);
    tampered.ciphertext = `AAAA${String(tampered.ciphertext).slice(4)}`;
    await submitRestoreText(JSON.stringify(tampered), BACKUP_PASSPHRASE);
    await expect(page.getByRole('alert').first()).toContainText(
      'فشل التحقق من عبارة المرور'
    );
    await expectDbIdentical();

    // 3. Unsupported formatVersion
    const unsupported = { ...structuredClone(validArchive), formatVersion: 99 };
    await submitRestoreText(JSON.stringify(unsupported), BACKUP_PASSPHRASE);
    await expect(page.getByRole('alert').first()).toContainText('غير مدعوم');
    await expectDbIdentical();

    // 4. Corrupt JSON
    await submitRestoreText('{corrupt-json', BACKUP_PASSPHRASE);
    await expect(page.getByRole('alert').first()).toContainText('تالف');
    await expectDbIdentical();

    // 5. Simulated mid-transaction IndexedDB write failure on `sync_events` AFTER `settings` clear/put
    await page.evaluate(() => {
      const origPut = IDBObjectStore.prototype.put;
      (window as unknown as { __restoreOrigPut?: typeof origPut }).__restoreOrigPut =
        origPut;
      IDBObjectStore.prototype.put = function (value: unknown, key?: IDBValidKey) {
        if (this.name === 'sync_events') {
          throw new DOMException('Simulated IDB transaction failure', 'AbortError');
        }
        return origPut.call(this, value, key);
      };
    });

    await submitRestoreText(validArchiveText, BACKUP_PASSPHRASE);
    await expect(page.getByRole('alert').first()).toBeVisible();

    await page.evaluate(() => {
      const w = window as unknown as {
        __restoreOrigPut?: typeof IDBObjectStore.prototype.put;
      };
      if (w.__restoreOrigPut) {
        IDBObjectStore.prototype.put = w.__restoreOrigPut;
      }
    });

    // Real browser IndexedDB MUST roll back all stores cleanly (still 2 syncEvents, original settings/role/audits)
    await expectDbIdentical();
  });

  test('upgrades existing browser IndexedDB v3 audit records to v4 with origin=LOCAL and renders them in UI without data loss', async ({
    page,
  }) => {
    // Navigate to a lightweight same-origin page with zero open IndexedDB handles
    // before deleting and seeding a legacy v3 database.
    await page.route('**/__seed_v3__', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><html><body>seed-v3</body></html>',
      })
    );
    await page.goto('/__seed_v3__');
    await clearBrowserIndexedDb(page);

    // Seed a real browser IndexedDB database at version 3 lacking `origin` on security_audit
    await page.evaluate(async () => {
      await new Promise<void>((resolve, reject) => {
        const req = window.indexedDB.open('nexlink_app_db', 3);
        req.onupgradeneeded = () => {
          const db = req.result;
          const migStore = db.createObjectStore('schema_migrations', {
            keyPath: 'version',
          });
          migStore.put({ version: 1, name: 'v1_core_stores', appliedAt: Date.now() });
          migStore.put({
            version: 2,
            name: 'v2_device_identity_and_audit',
            appliedAt: Date.now(),
          });
          migStore.put({
            version: 3,
            name: 'v3_sync_idempotency_and_dedup_indexes',
            appliedAt: Date.now(),
          });

          const settingsStore = db.createObjectStore('settings', { keyPath: 'id' });
          settingsStore.put({
            id: 'app_settings',
            settings: {
              role: 'admin',
              selectedNotificationApps: [],
              connectionServiceEnabled: false,
              notificationAccessGranted: false,
              usageAccessGranted: false,
              sessionTimeoutMinutes: 30,
              syncIntervalMs: 10000,
              maxSyncRetries: 5,
              relayEndpoint: '/api/relay',
              syncDeliveryPolicy: 'PEER_CONFIRMED',
              targetDeviceId: null,
              testFixtureModeEnabled: false,
            },
          });

          db.createObjectStore('device_identity', { keyPath: 'id' });
          db.createObjectStore('linked_devices', { keyPath: 'publicId' });
          const syncStore = db.createObjectStore('sync_events', {
            keyPath: 'id',
            autoIncrement: true,
          });
          syncStore.createIndex('by_status', 'status', { unique: false });
          syncStore.createIndex('by_createdAt', 'createdAt', { unique: false });
          syncStore.createIndex('by_idempotencyKey', 'idempotencyKey', { unique: true });
          syncStore.createIndex('by_notificationKey', 'notificationKey', {
            unique: false,
          });

          const auditStore = db.createObjectStore('security_audit', {
            keyPath: 'id',
            autoIncrement: true,
          });
          auditStore.createIndex('by_timestamp', 'timestamp', { unique: false });
          auditStore.put({
            id: 77,
            timestamp: Date.now() - 10_000,
            action: 'DEVICE_REVOKED',
            actorRole: 'admin',
            deviceId: 'legacy-v3-browser-dev',
            outcome: 'ALLOWED',
            details: 'سجل v3 قديم يجب بقاؤه بعد الترقية إلى v4',
          });
        };
        req.onsuccess = () => {
          req.result.close();
          resolve();
        };
        req.onerror = () => reject(req.error);
      });
    });

    await page.goto('/');
    await expect(page.getByText('الجهاز الرئيسي • SUPER ADMIN')).toBeVisible();

    const snap = await readBrowserDbSnapshot(page);
    expect(snap.version).toBe(4);
    expect(
      snap.migrations.some(
        (m) => m.version === 4 && m.name === 'v4_audit_origin_provenance'
      )
    ).toBe(true);

    const upgradedAudit = snap.securityAudit.find((a) => a.id === 77);
    expect(upgradedAudit).toBeTruthy();
    expect(upgradedAudit!.origin).toBe('LOCAL');
    expect(upgradedAudit!.action).toBe('DEVICE_REVOKED');

    // Verify rendered in UI with local provenance badge
    await page
      .getByRole('button', { name: /مركز الأمان والإعدادات والصحة والنسخ الاحتياطي/ })
      .click();
    await page.getByRole('tab', { name: 'السجلات' }).click();
    await expect(
      page.getByText('سجل v3 قديم يجب بقاؤه بعد الترقية إلى v4')
    ).toBeVisible();
    await expect(page.getByText('حدث محلي موثق').first()).toBeVisible();
  });
});
