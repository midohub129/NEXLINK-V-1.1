import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import type { ICryptoProvider } from '../../src/domain/interfaces/services';
import type { EncryptedEnvelope } from '../../src/domain/models/security';

export class NodeTestCryptoProvider implements ICryptoProvider {
  private readonly aesKey = randomBytes(32);
  private readonly keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
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

  async sha256Hex(value: string): Promise<string> {
    return createHash('sha256').update(value, 'utf8').digest('hex');
  }

  async encrypt(plaintext: string): Promise<EncryptedEnvelope> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.aesKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
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
      return Buffer.concat([
        decipher.update(data),
        decipher.final(),
      ]).toString('utf8');
    } catch {
      return null;
    }
  }

  async getOrCreateDeviceKeyPair(): Promise<{
    cryptoKeyId: string;
    publicKeyJwk: JsonWebKey | null;
  }> {
    return {
      cryptoKeyId: this.keyId,
      publicKeyJwk: this.keyPair.publicKey.export({
        format: 'jwk',
      }) as JsonWebKey,
    };
  }

  async signPayload(payload: string): Promise<string> {
    return sign('sha256', Buffer.from(payload, 'utf8'), this.keyPair.privateKey).toString(
      'base64'
    );
  }

  async verifySelfIntegrity(): Promise<{ ok: boolean; algorithm: string }> {
    const probe = 'test-probe';
    const env = await this.encrypt(probe);
    const dec = await this.decrypt(env);
    const sig = await this.signPayload(probe);
    const okSig = verify(
      'sha256',
      Buffer.from(probe, 'utf8'),
      this.keyPair.publicKey,
      Buffer.from(sig, 'base64')
    );
    return {
      ok: dec === probe && okSig,
      algorithm: 'Node AES-256-GCM + ECDSA P-256',
    };
  }
}
