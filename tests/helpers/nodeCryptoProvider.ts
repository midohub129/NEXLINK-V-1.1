import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { SecurityError } from '../../src/domain/errors/appError';
import type { ICryptoProvider } from '../../src/domain/interfaces/services';
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
  }): Promise<string> {
    const { envelope } = params;
    if (
      !envelope ||
      envelope.version !== 1 ||
      envelope.algorithm !== 'ECDH-P256+HKDF-SHA256+AES-256-GCM' ||
      envelope.recipientDeviceId !== params.expectedRecipientDeviceId ||
      envelope.recipientCryptoKeyId !== params.expectedRecipientCryptoKeyId
    ) {
      throw new SecurityError(
        'E2EE_BINDING_MISMATCH',
        'فشل التحقق من هوية المرسل أو المستلم.',
        'E2EE recipient binding mismatch'
      );
    }

    const parsedAad = JSON.parse(envelope.aad) as Record<string, unknown>;
    if (
      parsedAad.v !== 1 ||
      parsedAad.senderDeviceId !== envelope.senderDeviceId ||
      parsedAad.recipientDeviceId !== envelope.recipientDeviceId ||
      parsedAad.senderCryptoKeyId !== envelope.senderCryptoKeyId ||
      parsedAad.recipientCryptoKeyId !== envelope.recipientCryptoKeyId ||
      parsedAad.sessionId !== envelope.sessionId ||
      parsedAad.messageNonce !== envelope.messageNonce
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
