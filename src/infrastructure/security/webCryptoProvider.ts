import { SecurityError, ValidationError } from '../../domain/errors/appError';
import type { ICryptoProvider } from '../../domain/interfaces/services';
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
} from '../../domain/models/backup';
import type { E2eeEnvelope, EncryptedEnvelope } from '../../domain/models/security';

const KEYSTORE_DB_NAME = 'nexlink_keystore';
const KEYSTORE_DB_VERSION = 2;
const KEYSTORE_OBJECT_STORE = 'keys';
const AES_KEY_RECORD_ID = 'master_aes_gcm_key';
const DEVICE_ECDSA_RECORD_ID = 'device_ecdsa_p256_pair';
const DEVICE_ECDH_RECORD_ID = 'device_ecdh_p256_pair';
const HKDF_SALT = 'nexlink-e2ee-v1-salt';

interface StoredKeyRecord {
  id: string;
  key?: CryptoKey;
  privateKey?: CryptoKey;
  publicKey?: CryptoKey;
  publicKeyJwk?: JsonWebKey;
  cryptoKeyId?: string;
  createdAt: number;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  const buf = Buffer.from(b64, 'base64');
  const bytes = new Uint8Array(buf.length);
  bytes.set(buf);
  return bytes;
}

function decodeStrictBase64(value: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  try {
    const decoded = base64ToBytes(value);
    if (bytesToBase64(decoded) !== value) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function bufferToHex(buf: ArrayBuffer | Uint8Array): string {
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hasSubtleCrypto(): boolean {
  return (
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.subtle !== 'undefined'
  );
}

/**
 * Cryptographic provider backed by Web Crypto API + dedicated
 * non-extractable IndexedDB keystore (`nexlink_keystore`).
 * - Local rest encryption: AES-256-GCM
 * - Device authentication identity: ECDSA P-256 (SHA-256)
 * - End-to-End inter-device encryption: ECDH P-256 + HKDF-SHA-256 + AES-256-GCM + AAD + ECDSA P-256 signatures
 */
export class WebCryptoProvider implements ICryptoProvider {
  private memoryAesKey: CryptoKey | null = null;
  private memoryEcdsaPair: {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: JsonWebKey;
    cryptoKeyId: string;
  } | null = null;
  private memoryEcdhPair: {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: JsonWebKey;
  } | null = null;

  isSupported(): boolean {
    return hasSubtleCrypto();
  }

  randomHex(byteLength = 16): string {
    if (
      typeof globalThis.crypto === 'undefined' ||
      typeof globalThis.crypto.getRandomValues !== 'function'
    ) {
      throw new SecurityError(
        'CSPRNG_UNAVAILABLE',
        'مولّد الأرقام العشوائية التشفيري غير متاح في هذا السياق.',
        'crypto.getRandomValues is unavailable'
      );
    }
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
    return bufferToHex(bytes);
  }

  private openKeyStore(): Promise<IDBDatabase | null> {
    if (typeof indexedDB === 'undefined') {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      try {
        const request = indexedDB.open(KEYSTORE_DB_NAME, KEYSTORE_DB_VERSION);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(KEYSTORE_OBJECT_STORE)) {
            db.createObjectStore(KEYSTORE_OBJECT_STORE, { keyPath: 'id' });
          }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  }

  private async readKeyRecord(id: string): Promise<StoredKeyRecord | null> {
    const db = await this.openKeyStore();
    if (!db) return null;
    try {
      return await new Promise<StoredKeyRecord | null>((resolve) => {
        const tx = db.transaction(KEYSTORE_OBJECT_STORE, 'readonly');
        const req = tx.objectStore(KEYSTORE_OBJECT_STORE).get(id);
        req.onsuccess = () =>
          resolve((req.result as StoredKeyRecord | undefined) ?? null);
        req.onerror = () => resolve(null);
      });
    } finally {
      db.close();
    }
  }

  private async writeKeyRecord(record: StoredKeyRecord): Promise<void> {
    const db = await this.openKeyStore();
    if (!db) return;
    try {
      await new Promise<void>((resolve) => {
        const tx = db.transaction(KEYSTORE_OBJECT_STORE, 'readwrite');
        tx.objectStore(KEYSTORE_OBJECT_STORE).put(record);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      });
    } finally {
      db.close();
    }
  }

  private async getOrCreateAesKey(): Promise<CryptoKey | null> {
    if (!hasSubtleCrypto()) return null;
    if (this.memoryAesKey) return this.memoryAesKey;

    const existing = await this.readKeyRecord(AES_KEY_RECORD_ID);
    if (existing?.key) {
      this.memoryAesKey = existing.key;
      return existing.key;
    }

    const generated = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    this.memoryAesKey = generated;
    await this.writeKeyRecord({
      id: AES_KEY_RECORD_ID,
      key: generated,
      createdAt: Date.now(),
    });
    return generated;
  }

  private async getOrCreateEcdhPair(): Promise<{
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: JsonWebKey;
  } | null> {
    if (!hasSubtleCrypto()) return null;
    if (this.memoryEcdhPair) return this.memoryEcdhPair;

    const existing = await this.readKeyRecord(DEVICE_ECDH_RECORD_ID);
    if (existing?.privateKey && existing.publicKey && existing.publicKeyJwk) {
      this.memoryEcdhPair = {
        privateKey: existing.privateKey,
        publicKey: existing.publicKey,
        publicKeyJwk: existing.publicKeyJwk,
      };
      return this.memoryEcdhPair;
    }

    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits']
    );
    const publicKeyJwk = await globalThis.crypto.subtle.exportKey(
      'jwk',
      pair.publicKey
    );

    this.memoryEcdhPair = {
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      publicKeyJwk,
    };

    await this.writeKeyRecord({
      id: DEVICE_ECDH_RECORD_ID,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      publicKeyJwk,
      createdAt: Date.now(),
    });

    return this.memoryEcdhPair;
  }

  async sha256Hex(value: string): Promise<string> {
    if (hasSubtleCrypto()) {
      const encoded = new TextEncoder().encode(value);
      const digest = await globalThis.crypto.subtle.digest('SHA-256', encoded);
      return bufferToHex(digest);
    }

    throw new SecurityError(
      'CRYPTO_SHA256_UNAVAILABLE',
      'واجهة التشفير الآمنة غير متوفرة في هذا السياق.',
      'Web Crypto subtle.digest is unavailable'
    );
  }

  async encrypt(plaintext: string): Promise<EncryptedEnvelope | null> {
    const key = await this.getOrCreateAesKey();
    if (!key) return null;

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const cipherBuf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );

    return {
      algorithm: 'AES-256-GCM',
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(cipherBuf)),
    };
  }

  async decrypt(envelope: EncryptedEnvelope): Promise<string | null> {
    const key = await this.getOrCreateAesKey();
    if (!key) return null;

    try {
      const ivBytes = base64ToBytes(envelope.iv);
      const cipherBytes = base64ToBytes(envelope.ciphertext);
      const plainBuf = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(ivBytes),
        },
        key,
        new Uint8Array(cipherBytes)
      );
      return new TextDecoder().decode(plainBuf);
    } catch {
      return null;
    }
  }

  async getOrCreateDeviceKeyPair(): Promise<{
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
    ecdhPublicKeyJwk: JsonWebKey | null;
  }> {
    if (!hasSubtleCrypto()) {
      return {
        cryptoKeyId: 'unsupported-webcrypto-context',
        publicKeyJwk: null,
        ecdhPublicKeyJwk: null,
      };
    }

    const ecdhPair = await this.getOrCreateEcdhPair();

    if (this.memoryEcdsaPair) {
      return {
        cryptoKeyId: this.memoryEcdsaPair.cryptoKeyId,
        publicKeyJwk: this.memoryEcdsaPair.publicKeyJwk,
        ecdhPublicKeyJwk: ecdhPair?.publicKeyJwk ?? null,
      };
    }

    const existing = await this.readKeyRecord(DEVICE_ECDSA_RECORD_ID);
    if (
      existing?.privateKey &&
      existing.publicKey &&
      existing.publicKeyJwk &&
      existing.cryptoKeyId
    ) {
      this.memoryEcdsaPair = {
        privateKey: existing.privateKey,
        publicKey: existing.publicKey,
        publicKeyJwk: existing.publicKeyJwk,
        cryptoKeyId: existing.cryptoKeyId,
      };
      return {
        cryptoKeyId: existing.cryptoKeyId,
        publicKeyJwk: existing.publicKeyJwk,
        ecdhPublicKeyJwk: ecdhPair?.publicKeyJwk ?? null,
      };
    }

    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );

    const publicKeyJwk = await globalThis.crypto.subtle.exportKey(
      'jwk',
      pair.publicKey
    );
    const fingerprint = await this.sha256Hex(
      `${publicKeyJwk.x ?? ''}:${publicKeyJwk.y ?? ''}`
    );
    const cryptoKeyId = `ecdsa-${fingerprint.slice(0, 24)}`;

    this.memoryEcdsaPair = {
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      publicKeyJwk,
      cryptoKeyId,
    };

    await this.writeKeyRecord({
      id: DEVICE_ECDSA_RECORD_ID,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      publicKeyJwk,
      cryptoKeyId,
      createdAt: Date.now(),
    });

    return {
      cryptoKeyId,
      publicKeyJwk,
      ecdhPublicKeyJwk: ecdhPair?.publicKeyJwk ?? null,
    };
  }

  async signPayload(payload: string): Promise<string | null> {
    if (!hasSubtleCrypto()) return null;
    if (!this.memoryEcdsaPair) {
      await this.getOrCreateDeviceKeyPair();
    }
    if (!this.memoryEcdsaPair) return null;

    const encoded = new TextEncoder().encode(payload);
    const sig = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.memoryEcdsaPair.privateKey,
      encoded
    );
    return bytesToBase64(new Uint8Array(sig));
  }

  async verifySignatureWithJwk(
    publicKeyJwk: JsonWebKey,
    expectedCryptoKeyId: string,
    payload: string,
    signatureBase64: string
  ): Promise<boolean> {
    if (!hasSubtleCrypto()) return false;
    try {
      const fingerprint = await this.sha256Hex(
        `${publicKeyJwk.x ?? ''}:${publicKeyJwk.y ?? ''}`
      );
      if (`ecdsa-${fingerprint.slice(0, 24)}` !== expectedCryptoKeyId) {
        return false;
      }
      const key = await globalThis.crypto.subtle.importKey(
        'jwk',
        publicKeyJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
      return await globalThis.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        new Uint8Array(base64ToBytes(signatureBase64)),
        new TextEncoder().encode(payload)
      );
    } catch {
      return false;
    }
  }

  private async deriveE2eeAesKey(params: {
    peerEcdhPublicKeyJwk: JsonWebKey;
    senderDeviceId: string;
    recipientDeviceId: string;
    senderCryptoKeyId: string;
    recipientCryptoKeyId: string;
    sessionId: string;
    messageNonce: string;
    usage: 'encrypt' | 'decrypt';
  }): Promise<CryptoKey> {
    const ecdhPair = await this.getOrCreateEcdhPair();
    if (!ecdhPair) {
      throw new SecurityError(
        'E2EE_UNAVAILABLE',
        'واجهة تبادل المفاتيح ECDH غير متاحة.',
        'ECDH pair missing'
      );
    }

    const peerPublicKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      params.peerEcdhPublicKeyJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await globalThis.crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      ecdhPair.privateKey,
      256
    );

    const hkdfKey = await globalThis.crypto.subtle.importKey(
      'raw',
      sharedBits,
      'HKDF',
      false,
      ['deriveKey']
    );

    const encoder = new TextEncoder();
    const info = encoder.encode(
      `nexlink-e2ee-v1|${params.senderDeviceId}|${params.recipientDeviceId}|${params.senderCryptoKeyId}|${params.recipientCryptoKeyId}|${params.sessionId}|${params.messageNonce}`
    );

    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: encoder.encode(HKDF_SALT),
        info,
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      [params.usage]
    );
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
    if (!hasSubtleCrypto()) {
      throw new SecurityError(
        'E2EE_UNAVAILABLE',
        'التشفير الطرفي غير متوفر بدون Web Crypto API.',
        'Web Crypto unavailable for E2EE encryption'
      );
    }

    const messageNonce = this.randomHex(16);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await this.deriveE2eeAesKey({
      peerEcdhPublicKeyJwk: params.recipientEcdhPublicKeyJwk,
      senderDeviceId: params.senderDeviceId,
      recipientDeviceId: params.recipientDeviceId,
      senderCryptoKeyId: params.senderCryptoKeyId,
      recipientCryptoKeyId: params.recipientCryptoKeyId,
      sessionId: params.sessionId,
      messageNonce,
      usage: 'encrypt',
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

    const encoder = new TextEncoder();
    const cipherBuf = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encoder.encode(aad),
      },
      aesKey,
      encoder.encode(params.plaintext)
    );

    const ivB64 = bytesToBase64(iv);
    const ciphertextB64 = bytesToBase64(new Uint8Array(cipherBuf));
    const sigTarget = `E2EE|${await this.sha256Hex(aad)}|${await this.sha256Hex(`${ivB64}:${ciphertextB64}`)}`;
    const signature = await this.signPayload(sigTarget);
    if (!signature) {
      throw new SecurityError(
        'E2EE_SIGNING_FAILED',
        'فشل توقيع حزمة التشفير الطرفي.',
        'ECDSA signature returned null'
      );
    }

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
        'فشل التحقق من هوية المرسل أو المستلم لحزمة E2EE.',
        'E2EE envelope recipient binding mismatch'
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
        'تم رصد عدم تطابق أو تلاعب في بيانات السياق AAD.',
        'E2EE AAD metadata mismatch'
      );
    }

    const sigTarget = `E2EE|${await this.sha256Hex(envelope.aad)}|${await this.sha256Hex(`${envelope.iv}:${envelope.ciphertext}`)}`;
    const sigValid = await this.verifySignatureWithJwk(
      params.senderEcdsaPublicKeyJwk,
      envelope.senderCryptoKeyId,
      sigTarget,
      envelope.signature
    );
    if (!sigValid) {
      throw new SecurityError(
        'E2EE_INVALID_SIGNATURE',
        'فشل التحقق من التوقيع الرقمي لرسالة E2EE.',
        'E2EE envelope ECDSA signature verification failed'
      );
    }

    try {
      const aesKey = await this.deriveE2eeAesKey({
        peerEcdhPublicKeyJwk: params.senderEcdhPublicKeyJwk,
        senderDeviceId: envelope.senderDeviceId,
        recipientDeviceId: envelope.recipientDeviceId,
        senderCryptoKeyId: envelope.senderCryptoKeyId,
        recipientCryptoKeyId: envelope.recipientCryptoKeyId,
        sessionId: envelope.sessionId,
        messageNonce: envelope.messageNonce,
        usage: 'decrypt',
      });

      const plainBuf = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(base64ToBytes(envelope.iv)),
          additionalData: new TextEncoder().encode(envelope.aad),
        },
        aesKey,
        new Uint8Array(base64ToBytes(envelope.ciphertext))
      );

      return new TextDecoder().decode(plainBuf);
    } catch (err) {
      throw new SecurityError(
        'E2EE_DECRYPT_FAILED',
        'فشل فك تشفير الرسالة بسبب تلاعب بالمحتوى أو مفتاح غير متطابق.',
        err instanceof Error ? err.message : 'AES-GCM authentication failed',
        err
      );
    }
  }

  private async deriveBackupAesKey(
    passphrase: string,
    salt: Uint8Array<ArrayBuffer>,
    iterations: number,
    usage: 'encrypt' | 'decrypt'
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const baseKey = await globalThis.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: BACKUP_KDF_KEY_LENGTH_BITS },
      false,
      [usage]
    );
  }

  async encryptBackupPayload(params: {
    plaintext: string;
    passphrase: string;
    schemaVersion: number;
    exportedAt?: number;
    iterations?: number;
  }): Promise<EncryptedBackupArchiveV2> {
    if (!hasSubtleCrypto() || typeof globalThis.crypto.getRandomValues !== 'function') {
      throw new SecurityError(
        'BACKUP_CRYPTO_UNAVAILABLE',
        'تشفير النسخة الاحتياطية غير متاح بدون Web Crypto API.',
        'Web Crypto subtle or CSPRNG unavailable for backup encryption'
      );
    }

    const passphrase = params.passphrase;
    if (
      typeof passphrase !== 'string' ||
      passphrase.trim().length === 0 ||
      passphrase.length < BACKUP_MIN_PASSPHRASE_LENGTH ||
      passphrase.length > BACKUP_MAX_PASSPHRASE_LENGTH
    ) {
      throw new ValidationError(
        'BACKUP_PASSPHRASE_INVALID',
        `يجب أن تكون عبارة مرور النسخة الاحتياطية بين ${BACKUP_MIN_PASSPHRASE_LENGTH} و${BACKUP_MAX_PASSPHRASE_LENGTH} حرفاً وألا تكون مسافات فقط.`,
        'Backup passphrase did not satisfy length policy'
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
        'معاملات اشتقاق مفتاح النسخة الاحتياطية خارج الحدود الآمنة المسموحة.',
        `Invalid PBKDF2 iterations: ${String(iterations)}`
      );
    }

    const salt = new Uint8Array(BACKUP_SALT_BYTES);
    const iv = new Uint8Array(BACKUP_IV_BYTES);
    globalThis.crypto.getRandomValues(salt);
    globalThis.crypto.getRandomValues(iv);

    const exportedAt = params.exportedAt ?? Date.now();
    const kdf = {
      algorithm: BACKUP_KDF_ALGORITHM,
      hash: BACKUP_KDF_HASH,
      iterations,
      salt: bytesToBase64(salt),
      keyLengthBits: BACKUP_KDF_KEY_LENGTH_BITS,
    };
    const encryption = {
      algorithm: BACKUP_ENCRYPTION_ALGORITHM,
      iv: bytesToBase64(iv),
    };
    const aad = buildEncryptedBackupAad({
      format: ENCRYPTED_BACKUP_FORMAT_ID,
      formatVersion: ENCRYPTED_BACKUP_FORMAT_VERSION,
      schemaVersion: params.schemaVersion,
      exportedAt,
      kdf,
      encryption,
    });

    const encoder = new TextEncoder();
    const key = await this.deriveBackupAesKey(passphrase, salt, iterations, 'encrypt');
    const cipherBuf = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encoder.encode(aad),
      },
      key,
      encoder.encode(params.plaintext)
    );

    return {
      format: ENCRYPTED_BACKUP_FORMAT_ID,
      formatVersion: ENCRYPTED_BACKUP_FORMAT_VERSION,
      schemaVersion: params.schemaVersion,
      exportedAt,
      kdf,
      encryption,
      aad,
      ciphertext: bytesToBase64(new Uint8Array(cipherBuf)),
    };
  }

  async decryptBackupPayload(params: {
    archive: EncryptedBackupArchiveV2;
    passphrase: string;
  }): Promise<string> {
    if (!hasSubtleCrypto()) {
      throw new SecurityError(
        'BACKUP_CRYPTO_UNAVAILABLE',
        'فك تشفير النسخة الاحتياطية غير متاح بدون Web Crypto API.',
        'Web Crypto subtle unavailable for backup decryption'
      );
    }

    const { archive, passphrase } = params;
    if (
      typeof passphrase !== 'string' ||
      passphrase.length === 0 ||
      passphrase.length > BACKUP_MAX_PASSPHRASE_LENGTH
    ) {
      throw new ValidationError(
        'BACKUP_PASSPHRASE_REQUIRED',
        'يرجى إدخال عبارة مرور النسخة الاحتياطية للاستعادة.',
        'Empty or oversized backup passphrase during restore'
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
        'Unsupported encrypted backup format or formatVersion'
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
        'معاملات اشتقاق المفتاح (KDF) في النسخة الاحتياطية غير صالحة أو خارج الحدود الآمنة.',
        'Backup KDF parameters out of safe bounds'
      );
    }

    const saltBytes = decodeStrictBase64(archive.kdf.salt);
    if (
      !saltBytes ||
      saltBytes.byteLength < BACKUP_MIN_SALT_BYTES ||
      saltBytes.byteLength > BACKUP_MAX_SALT_BYTES
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'قيمة salt في النسخة الاحتياطية غير صالحة.',
        'Invalid or out-of-range base64 salt in backup'
      );
    }

    if (
      !archive.encryption ||
      archive.encryption.algorithm !== BACKUP_ENCRYPTION_ALGORITHM
    ) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'خوارزمية تشفير النسخة الاحتياطية غير مدعومة.',
        'Unsupported backup encryption algorithm'
      );
    }

    const ivBytes = decodeStrictBase64(archive.encryption.iv);
    if (!ivBytes || ivBytes.byteLength !== BACKUP_IV_BYTES) {
      throw new ValidationError(
        'INVALID_BACKUP_CRYPTO_PARAMS',
        'قيمة nonce/IV في النسخة الاحتياطية غير صالحة.',
        'Invalid AES-GCM IV length or encoding in backup'
      );
    }

    const cipherBytes = decodeStrictBase64(archive.ciphertext);
    if (!cipherBytes || cipherBytes.byteLength < 16) {
      throw new ValidationError(
        'INVALID_BACKUP_FORMAT',
        'محتوى التشفير (ciphertext) في النسخة الاحتياطية غير صالح أو تالف.',
        'Malformed base64 ciphertext in backup'
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
        'فشل التحقق من سلامة النسخة الاحتياطية أو عبارة المرور.',
        'Backup AAD mismatch against outer metadata'
      );
    }

    try {
      const key = await this.deriveBackupAesKey(
        passphrase,
        saltBytes,
        archive.kdf.iterations,
        'decrypt'
      );
      const plainBuf = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBytes,
          additionalData: new TextEncoder().encode(expectedAad),
        },
        key,
        cipherBytes
      );
      return new TextDecoder().decode(plainBuf);
    } catch (err) {
      throw new SecurityError(
        'BACKUP_AUTH_FAILED',
        'فشل التحقق من عبارة المرور أو سلامة النسخة الاحتياطية المشفرة.',
        'Backup decryption or authentication failed',
        err
      );
    }
  }

  async verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }> {
    if (!hasSubtleCrypto()) {
      return {
        ok: false,
        algorithm: 'Web Crypto API غير متوفر في هذا المتصفح',
      };
    }

    const probe = `nexlink-integrity-${Date.now()}-${this.randomHex(8)}`;
    const envelope = await this.encrypt(probe);
    if (!envelope) {
      return { ok: false, algorithm: 'تعذّر إنشاء مفتاح AES-256-GCM' };
    }
    const decrypted = await this.decrypt(envelope);
    if (decrypted !== probe) {
      return { ok: false, algorithm: 'فشل التحقق المتطابق لـ AES-256-GCM' };
    }

    const keys = await this.getOrCreateDeviceKeyPair();
    const signature = await this.signPayload(probe);
    if (!signature || !this.memoryEcdsaPair || !keys.ecdhPublicKeyJwk) {
      return {
        ok: false,
        algorithm: 'فشل فحص هوية ECDSA P-256 أو ECDH P-256',
      };
    }

    const verified = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.memoryEcdsaPair.publicKey,
      new Uint8Array(base64ToBytes(signature)),
      new TextEncoder().encode(probe)
    );

    return {
      ok: verified,
      algorithm: verified
        ? 'AES-256-GCM + ECDSA P-256 + ECDH P-256 (IndexedDB Non-Extractable KeyStore)'
        : 'فشل التحقق من توقيع ECDSA P-256',
    };
  }
}
