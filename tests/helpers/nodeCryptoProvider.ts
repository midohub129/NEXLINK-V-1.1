import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  pbkdf2Sync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { SecurityError, ValidationError } from '../../src/domain/errors/appError';
import type { ICryptoProvider } from '../../src/domain/interfaces/services';
import {
  BACKUP_ENCRYPTION_ALGORITHM,
  BACKUP_IV_BYTES,
  BACKUP_KDF_ALGORITHM,
  BACKUP_KDF_DEFAULT_ITERATIONS,
  BACKUP_KDF_HASH,
  BACKUP_KDF_KEY_LENGTH_BITS,
  BACKUP_KDF_MAX_ITERATIONS,
  BACKUP_KDF_MIN_ITERATIONS,
  BACKUP_MAX_PASSPHRASE_LENGTH,
  BACKUP_MAX_SALT_BYTES,
  BACKUP_MIN_PASSPHRASE_LENGTH,
  BACKUP_MIN_SALT_BYTES,
  BACKUP_SALT_BYTES,
  ENCRYPTED_BACKUP_FORMAT_ID,
  ENCRYPTED_BACKUP_FORMAT_VERSION,
  buildEncryptedBackupAad,
  type EncryptedBackupArchiveV2,
} from '../../src/domain/models/backup';
import type { E2eeEnvelope, EncryptedEnvelope } from '../../src/domain/models/security';

const HKDF_SALT = 'nexlink-e2ee-v1-salt';

export class NodeTestCryptoProvider implements ICryptoProvider {
  private readonly aesKey = randomBytes(32);
  private readonly keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  private readonly ecdhPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  private readonly keyId: string;

  constructor() {
    const jwk = this.keyPair.publicKey.export({ format: 'jwk' }) as JsonWebKey;
    const digest = createHash('sha256')
      .update(`${jwk.x ?? ''}:${jwk.y ?? ''}`)
      .digest('hex');
    this.keyId = `ecdsa-${digest.slice(0, 24)}`;
  }

  isSupported(): boolean {
    return true;
  }

  randomHex(byteLength = 16): string {
    return randomBytes(byteLength).toString('hex');
  }

  async sha256Hex(value: string): Promise<string> {
    return createHash('sha256').update(value, 'utf8').digest('hex');
  }

  async encrypt(plaintext: string): Promise<EncryptedEnvelope> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.aesKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      algorithm: 'AES-256-GCM',
      iv: iv.toString('base64'),
      ciphertext: Buffer.concat([encrypted, tag]).toString('base64'),
    };
  }

  async decrypt(envelope: EncryptedEnvelope): Promise<string | null> {
    try {
      const iv = Buffer.from(envelope.iv, 'base64');
      const raw = Buffer.from(envelope.ciphertext, 'base64');
      const data = raw.subarray(0, raw.length - 16);
      const tag = raw.subarray(raw.length - 16);
      const decipher = createDecipheriv('aes-256-gcm', this.aesKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    } catch {
      return null;
    }
  }

  async getOrCreateDeviceKeyPair(): Promise<{
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
    ecdhPublicKeyJwk: JsonWebKey | null;
  }> {
    return {
      cryptoKeyId: this.keyId,
      publicKeyJwk: this.keyPair.publicKey.export({
        format: 'jwk',
      }) as JsonWebKey,
      ecdhPublicKeyJwk: this.ecdhPair.publicKey.export({
        format: 'jwk',
      }) as JsonWebKey,
    };
  }

  async signPayload(payload: string): Promise<string> {
    return sign('sha256', Buffer.from(payload, 'utf8'), {
      key: this.keyPair.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
  }

  async verifySignatureWithJwk(
    publicKeyJwk: JsonWebKey,
    expectedCryptoKeyId: string,
    payload: string,
    signatureBase64: string
  ): Promise<boolean> {
    try {
      const digest = await this.sha256Hex(
        `${publicKeyJwk.x ?? ''}:${publicKeyJwk.y ?? ''}`
      );
      if (`ecdsa-${digest.slice(0, 24)}` !== expectedCryptoKeyId) {
        return false;
      }
      const key = createPublicKey({
        key: publicKeyJwk as Record<string, unknown>,
        format: 'jwk',
      });
      return verify(
        'sha256',
        Buffer.from(payload, 'utf8'),
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signatureBase64, 'base64')
      );
    } catch {
      return false;
    }
  }

  private deriveAesKey(params: {
    peerEcdhPublicKeyJwk: JsonWebKey;
    senderDeviceId: string;
    recipientDeviceId: string;
    senderCryptoKeyId: string;
    recipientCryptoKeyId: string;
    sessionId: string;
    messageNonce: string;
  }): Buffer {
    const peerPub = createPublicKey({
      key: params.peerEcdhPublicKeyJwk as Record<string, unknown>,
      format: 'jwk',
    });
    const sharedSecret = diffieHellman({
      privateKey: this.ecdhPair.privateKey,
      publicKey: peerPub,
    });
    const info = `nexlink-e2ee-v1|${params.senderDeviceId}|${params.recipientDeviceId}|${params.senderCryptoKeyId}|${params.recipientCryptoKeyId}|${params.sessionId}|${params.messageNonce}`;
    const derived = hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(HKDF_SALT, 'utf8'),
      Buffer.from(info, 'utf8'),
      32
    );
    return Buffer.from(derived);
  }

  async encryptForPeer(params: {
    plaintext: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    senderCryptoKeyId: string;
    recipientCryptoKeyId: string;
    recipientEcdhPublicKeyJwk: JsonWebKey;
    sessionId: string;
    idempotencyKey: string;
  }): Promise<E2eeEnvelope> {
    const messageNonce = this.randomHex(16);
    const iv = randomBytes(12);
    const aesKey = this.deriveAesKey({
      peerEcdhPublicKeyJwk: params.recipientEcdhPublicKeyJwk,
      senderDeviceId: params.senderDeviceId,
      recipientDeviceId: params.recipientDeviceId,
      senderCryptoKeyId: params.senderCryptoKeyId,
      recipientCryptoKeyId: params.recipientCryptoKeyId,
      sessionId: params.sessionId,
      messageNonce,
    });

    const aad = JSON.stringify({
      v: 1,
      senderDeviceId: params.senderDeviceId,
      recipientDeviceId: params.recipientDeviceId,
      senderCryptoKeyId: params.senderCryptoKeyId,
      recipientCryptoKeyId: params.recipientCryptoKeyId,
      sessionId: params.sessionId,
      messageNonce,
      idempotencyKey: params.idempotencyKey,
    });

    const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const encrypted = Buffer.concat([
      cipher.update(params.plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const ivB64 = iv.toString('base64');
    const ciphertextB64 = Buffer.concat([encrypted, tag]).toString('base64');
    const sigTarget = `E2EE|${await this.sha256Hex(aad)}|${await this.sha256Hex(`${ivB64}:${ciphertextB64}`)}`;
    const signature = await this.signPayload(sigTarget);

    return {
      version: 1,
      algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM',
      senderDeviceId: params.senderDeviceId,
      recipientDeviceId: params.recipientDeviceId,
      senderCryptoKeyId: params.senderCryptoKeyId,
      recipientCryptoKeyId: params.recipientCryptoKeyId,
      sessionId: params.sessionId,
      messageNonce,
      iv: ivB64,
      aad,
      ciphertext: ciphertextB64,
      signature,
    };
  }

  async decryptFromPeer(params: {
    envelope: E2eeEnvelope;
    senderEcdsaPublicKeyJwk: JsonWebKey;
    senderEcdhPublicKeyJwk: JsonWebKey;
    expectedRecipientDeviceId: string;
    expectedRecipientCryptoKeyId: string;
    expectedIdempotencyKey?: string;
  }): Promise<string> {
    const { envelope } = params;
    if (
      !envelope ||
      envelope.version !== 1 ||
      envelope.algorithm !== 'ECDH-P256+HKDF-SHA256+AES-256-GCM' ||
      !envelope.senderDeviceId ||
      !envelope.senderCryptoKeyId ||
      !envelope.sessionId ||
      !envelope.messageNonce ||
      envelope.recipientDeviceId !== params.expectedRecipientDeviceId ||
      envelope.recipientCryptoKeyId !== params.expectedRecipientCryptoKeyId
    ) {
      throw new SecurityError(
        'E2EE_BINDING_MISMATCH',
        'فشل التحقق من هوية المرسل أو المستلم.',
        'E2EE recipient binding mismatch'
      );
    }

    let parsedAad: Record<string, unknown>;
    try {
      parsedAad = JSON.parse(envelope.aad) as Record<string, unknown>;
    } catch {
      throw new SecurityError(
        'E2EE_INVALID_AAD',
        'بيانات السياق المرتبطة (AAD) تالفة.',
        'Invalid E2EE AAD JSON'
      );
    }

    if (
      parsedAad.v !== 1 ||
      parsedAad.senderDeviceId !== envelope.senderDeviceId ||
      parsedAad.recipientDeviceId !== envelope.recipientDeviceId ||
      parsedAad.senderCryptoKeyId !== envelope.senderCryptoKeyId ||
      parsedAad.recipientCryptoKeyId !== envelope.recipientCryptoKeyId ||
      parsedAad.sessionId !== envelope.sessionId ||
      parsedAad.messageNonce !== envelope.messageNonce ||
      typeof parsedAad.idempotencyKey !== 'string' ||
      parsedAad.idempotencyKey.length === 0 ||
      (params.expectedIdempotencyKey !== undefined &&
        parsedAad.idempotencyKey !== params.expectedIdempotencyKey)
    ) {
      throw new SecurityError(
        'E2EE_AAD_TAMPERED',
        'عدم تطابق بيانات السياق AAD.',
        'E2EE AAD mismatch'
      );
    }

    const sigTarget = `E2EE|${await this.sha256Hex(envelope.aad)}|${await this.sha256Hex(`${envelope.iv}:${envelope.ciphertext}`)}`;
    const sigOk = await this.verifySignatureWithJwk(
      params.senderEcdsaPublicKeyJwk,
      envelope.senderCryptoKeyId,
      sigTarget,
      envelope.signature
    );
    if (!sigOk) {
      throw new SecurityError(
        'E2EE_INVALID_SIGNATURE',
        'فشل التحقق من التوقيع الرقمي لـ E2EE.',
        'Invalid E2EE signature'
      );
    }

    try {
      const aesKey = this.deriveAesKey({
        peerEcdhPublicKeyJwk: params.senderEcdhPublicKeyJwk,
        senderDeviceId: envelope.senderDeviceId,
        recipientDeviceId: envelope.recipientDeviceId,
        senderCryptoKeyId: envelope.senderCryptoKeyId,
        recipientCryptoKeyId: envelope.recipientCryptoKeyId,
        sessionId: envelope.sessionId,
        messageNonce: envelope.messageNonce,
      });

      const iv = Buffer.from(envelope.iv, 'base64');
      const raw = Buffer.from(envelope.ciphertext, 'base64');
      const data = raw.subarray(0, raw.length - 16);
      const tag = raw.subarray(raw.length - 16);
      const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
      decipher.setAAD(Buffer.from(envelope.aad, 'utf8'));
      decipher.setAuthTag(tag);

      return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    } catch (err) {
      throw new SecurityError(
        'E2EE_DECRYPT_FAILED',
        'فشل فك التشفير بسبب تلاعب بالمحتوى أو المفتاح.',
        err instanceof Error ? err.message : 'AES-GCM tag mismatch',
        err
      );
    }
  }

  async encryptBackupPayload(params: {
    plaintext: string;
    passphrase: string;
    schemaVersion: number;
    exportedAt?: number;
    iterations?: number;
  }): Promise<EncryptedBackupArchiveV2> {
    const passphrase = params.passphrase;
    if (
      typeof passphrase !== 'string' ||
      passphrase.trim().length === 0 ||
      passphrase.length < BACKUP_MIN_PASSPHRASE_LENGTH ||
      passphrase.length > BACKUP_MAX_PASSPHRASE_LENGTH
    ) {
      throw new ValidationError(
        'BACKUP_PASSPHRASE_INVALID',
        `يجب أن تكون عبارة مرور النسخة الاحتياطية بين ${BACKUP_MIN_PASSPHRASE_LENGTH} و${BACKUP_MAX_PASSPHRASE_LENGTH} حرفاً.`,
        'Backup passphrase invalid'
      );
    }

    const iterations = params.iterations ?? BACKUP_KDF_DEFAULT_ITERATIONS;
    if (
      !Number.isInteger(iterations) ||
      iterations < BACKUP_KDF_MIN_ITERATIONS ||
      iterations > BACKUP_KDF_MAX_ITERATIONS
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_KDF_PARAMS',
        'معاملات اشتقاق المفتاح خارج الحدود الآمنة.',
        `Invalid PBKDF2 iterations: ${String(iterations)}`
      );
    }

    const salt = randomBytes(BACKUP_SALT_BYTES);
    const iv = randomBytes(BACKUP_IV_BYTES);
    const exportedAt = params.exportedAt ?? Date.now();
    const kdf = {
      algorithm: BACKUP_KDF_ALGORITHM,
      hash: BACKUP_KDF_HASH,
      iterations,
      salt: salt.toString('base64'),
      keyLengthBits: BACKUP_KDF_KEY_LENGTH_BITS,
    };
    const encryption = {
      algorithm: BACKUP_ENCRYPTION_ALGORITHM,
      iv: iv.toString('base64'),
    };
    const aad = buildEncryptedBackupAad({
      format: ENCRYPTED_BACKUP_FORMAT_ID,
      formatVersion: ENCRYPTED_BACKUP_FORMAT_VERSION,
      schemaVersion: params.schemaVersion,
      exportedAt,
      kdf,
      encryption,
    });

    const key = pbkdf2Sync(
      Buffer.from(passphrase, 'utf8'),
      salt,
      iterations,
      32,
      'sha256'
    );
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const encrypted = Buffer.concat([
      cipher.update(params.plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    return {
      format: ENCRYPTED_BACKUP_FORMAT_ID,
      formatVersion: ENCRYPTED_BACKUP_FORMAT_VERSION,
      schemaVersion: params.schemaVersion,
      exportedAt,
      kdf,
      encryption,
      aad,
      ciphertext: Buffer.concat([encrypted, tag]).toString('base64'),
    };
  }

  async decryptBackupPayload(params: {
    archive: EncryptedBackupArchiveV2;
    passphrase: string;
  }): Promise<string> {
    const { archive, passphrase } = params;
    if (
      typeof passphrase !== 'string' ||
      passphrase.length === 0 ||
      passphrase.length > BACKUP_MAX_PASSPHRASE_LENGTH
    ) {
      throw new ValidationError(
        'BACKUP_PASSPHRASE_REQUIRED',
        'يرجى إدخال عبارة مرور النسخة الاحتياطية.',
        'Empty or oversized backup passphrase'
      );
    }

    if (
      !archive ||
      archive.format !== ENCRYPTED_BACKUP_FORMAT_ID ||
      archive.formatVersion !== ENCRYPTED_BACKUP_FORMAT_VERSION
    ) {
      throw new ValidationError(
        'UNSUPPORTED_BACKUP_VERSION',
        'إصدار النسخة الاحتياطية غير مدعوم.',
        'Unsupported backup version'
      );
    }

    if (
      !archive.kdf ||
      archive.kdf.algorithm !== BACKUP_KDF_ALGORITHM ||
      archive.kdf.hash !== BACKUP_KDF_HASH ||
      archive.kdf.keyLengthBits !== BACKUP_KDF_KEY_LENGTH_BITS ||
      !Number.isInteger(archive.kdf.iterations) ||
      archive.kdf.iterations < BACKUP_KDF_MIN_ITERATIONS ||
      archive.kdf.iterations > BACKUP_KDF_MAX_ITERATIONS
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_KDF_PARAMS',
        'معاملات KDF غير صالحة أو خارج الحدود الآمنة.',
        'Backup KDF parameters invalid'
      );
    }

    const strictDecode = (val: unknown): Buffer | null => {
      if (typeof val !== 'string' || val.length === 0 || val.length % 4 !== 0) {
        return null;
      }
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(val)) return null;
      const buf = Buffer.from(val, 'base64');
      return buf.toString('base64') === val ? buf : null;
    };

    const salt = strictDecode(archive.kdf.salt);
    if (
      !salt ||
      salt.length < BACKUP_MIN_SALT_BYTES ||
      salt.length > BACKUP_MAX_SALT_BYTES
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'قيمة salt غير صالحة.',
        'Invalid backup salt'
      );
    }

    if (
      !archive.encryption ||
      archive.encryption.algorithm !== BACKUP_ENCRYPTION_ALGORITHM
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'خوارزمية التشفير غير مدعومة.',
        'Invalid backup encryption algorithm'
      );
    }

    const iv = strictDecode(archive.encryption.iv);
    if (!iv || iv.length !== BACKUP_IV_BYTES) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'قيمة nonce/IV غير صالحة.',
        'Invalid backup IV'
      );
    }

    const rawCipher = strictDecode(archive.ciphertext);
    if (!rawCipher || rawCipher.length < 16) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'محتوى التشفير غير صالح.',
        'Malformed backup ciphertext'
      );
    }

    const expectedAad = buildEncryptedBackupAad({
      format: archive.format,
      formatVersion: archive.formatVersion,
      schemaVersion: archive.schemaVersion,
      exportedAt: archive.exportedAt,
      kdf: archive.kdf,
      encryption: archive.encryption,
    });
    if (typeof archive.aad !== 'string' || archive.aad !== expectedAad) {
      throw new SecurityError(
        'BACKUP_AUTH_FAILED',
        'فشل التحقق من سلامة النسخة أو عبارة المرور.',
        'Backup AAD mismatch'
      );
    }

    try {
      const key = pbkdf2Sync(
        Buffer.from(passphrase, 'utf8'),
        salt,
        archive.kdf.iterations,
        32,
        'sha256'
      );
      const data = rawCipher.subarray(0, rawCipher.length - 16);
      const tag = rawCipher.subarray(rawCipher.length - 16);
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(expectedAad, 'utf8'));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    } catch (err) {
      throw new SecurityError(
        'BACKUP_AUTH_FAILED',
        'فشل التحقق من عبارة المرور أو سلامة النسخة المشفرة.',
        'Backup decryption or authentication failed',
        err
      );
    }
  }

  async verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }> {
    const probe = 'test-probe';
    const env = await this.encrypt(probe);
    const dec = await this.decrypt(env);
    const sig = await this.signPayload(probe);
    const okSig = verify(
      'sha256',
      Buffer.from(probe, 'utf8'),
      { key: this.keyPair.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(sig, 'base64')
    );
    return {
      ok: dec === probe && okSig,
      algorithm: 'Node AES-256-GCM + ECDSA P-256 + ECDH P-256',
    };
  }
}
