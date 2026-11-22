export type DeviceRole = 'admin' | 'basic';

export type PairingState = 'UNPAIRED' | 'PAIRING_PENDING' | 'PAIRED' | 'REVOKED';

export type ConnectionState =
  'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'ERROR';

export interface DeviceIdentityProfile {
  /** Public shareable identifier used for discovery & relay routing */
  publicId: string;
  /** Separate cryptographic identity fingerprint (SHA-256 of ECDSA P-256 public key) */
  cryptoKeyId: string;
  /** Exported ECDSA P-256 public JWK for peer signature verification (never private key) */
  publicKeyJwk: JsonWebKey | null;
  createdAt: number;
}

export interface LinkedDevice {
  publicId: string;
  cryptoKeyId: string;
  label: string;
  role: DeviceRole;
  pairingState: PairingState;
  pairedAt: number | null;
  lastSeenAt: number | null;
  verifiedByRelay: boolean;
}

export interface PairingRequest {
  pairingCode: string;
  targetDeviceId: string;
  requesterDeviceId: string;
  requesterCryptoKeyId: string;
  expiresAt: number;
}
