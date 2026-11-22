import { SecurityError } from '../../domain/errors/appError';
import type { ICryptoProvider } from '../../domain/interfaces/services';
import type { EncryptedEnvelope } from '../../domain/models/security';

const KEYSTORE_DB_NAME = 'nexlink_keystore';
const KEYSTORE_DB_VERSION = 1;
const KEYSTORE_OBJECT_STORE = 'keys';
const AES_KEY_RECORD_ID = 'master_aes_gcm_key';
const DEVICE_ECDSA_RECORD_ID = 'device_ecdsa_p256_pair';

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

function base64ToBytes(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
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
 * Isolated cryptographic provider backed by Web Crypto API + dedicated
 * non-extractable IndexedDB keystore (`nexlink_keystore`).
 * - Payload confidentiality: AES-256-GCM
 * - Device cryptographic identity & signatures: ECDSA P-256
 * - Content hashing & fingerprints: SHA-256
 */
export class WebCryptoProvider implements ICryptoProvider {
  private memoryAesKey: CryptoKey | null = null;
  private memoryEcdsaPair: {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: JsonWebKey;
    cryptoKeyId: string;
  } | null = null;

  isSupported(): boolean {
    return hasSubtleCrypto();
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
      false, // Non-extractable private symmetric key
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
  }> {
    if (!hasSubtleCrypto()) {
      return {
        cryptoKeyId: 'unsupported-webcrypto-context',
        publicKeyJwk: null,
      };
    }

    if (this.memoryEcdsaPair) {
      return {
        cryptoKeyId: this.memoryEcdsaPair.cryptoKeyId,
        publicKeyJwk: this.memoryEcdsaPair.publicKeyJwk,
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
      };
    }

    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // Non-extractable private signing key
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

    return { cryptoKeyId, publicKeyJwk };
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

  async verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }> {
    if (!hasSubtleCrypto()) {
      return {
        ok: false,
        algorithm: 'Web Crypto API غير متوفر في هذا المتصفح',
      };
    }

    const probe = `nexlink-integrity-${Date.now()}`;
    const envelope = await this.encrypt(probe);
    if (!envelope) {
      return { ok: false, algorithm: 'تعذّر إنشاء مفتاح AES-256-GCM' };
    }
    const decrypted = await this.decrypt(envelope);
    if (decrypted !== probe) {
      return { ok: false, algorithm: 'فشل التحقق المتطابق لـ AES-256-GCM' };
    }

    const signature = await this.signPayload(probe);
    if (!signature || !this.memoryEcdsaPair) {
      return {
        ok: false,
        algorithm: 'فشل فحص توقيع الهوية التشفيرية ECDSA P-256',
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
        ? 'AES-256-GCM + ECDSA P-256 (IndexedDB Non-Extractable KeyStore)'
        : 'فشل التحقق من توقيع ECDSA P-256',
    };
  }
}
