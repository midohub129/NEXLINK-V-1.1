export type DeviceRole = 'admin' | 'basic';

export type PairingState =
  'UNPAIRED' | 'PAIRING_PENDING' | 'AWAITING_APPROVAL' | 'PAIRED' | 'REVOKED';

export type ConnectionState =
  'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'ERROR';

export interface DeviceIdentityProfile {
  /** Public shareable identifier used for discovery & relay routing */
  publicId: string;
  /** Separate cryptographic identity fingerprint (SHA-256 of ECDSA P-256 public key) */
  cryptoKeyId: string;
  /** Exported ECDSA P-256 public JWK for peer & server signature verification */
  publicKeyJwk: JsonWebKey | null;
  /** Exported ECDH P-256 public JWK for end-to-end key agreement (HKDF + AES-256-GCM) */
  ecdhPublicKeyJwk: JsonWebKey | null;
  createdAt: number;
}

export interface LinkedDevice {
  publicId: string;
  cryptoKeyId: string;
  publicKeyJwk: JsonWebKey | null;
  ecdhPublicKeyJwk: JsonWebKey | null;
  label: string;
  role: DeviceRole;
  pairingState: PairingState;
  pairedAt: number | null;
  lastSeenAt: number | null;
  verifiedByRelay: boolean;
}

export type PairingRequestStatus =
  | 'PENDING'
  | 'AWAITING_REQUESTER_CONFIRMATION'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'LOCKED';

export interface PairingRequest {
  pairingId: string;
  pairingCode: string;
  targetDeviceId: string;
  requesterDeviceId: string;
  requesterCryptoKeyId: string;
  responderDeviceId?: string;
  responderCryptoKeyId?: string;
  responderLabel?: string;
  status: PairingRequestStatus;
  expiresAt: number;
}
