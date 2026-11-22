# NEXLINK Relay Server & Security Operations Guide

## 1. Runtime Requirements
- **Node.js `>=22.0.0`** (required for built-in `node:sqlite` with `WAL` journal mode and Web Crypto / Node Crypto ECDSA P-256 + ECDH P-256 + HKDF-SHA-256).
- **npm** (or compatible package manager).

## 2. Environment Variables
Create a local `.env` (never commit `.env` to Git):

```env
NEXLINK_PORT=3000
NEXLINK_DB_PATH=.data/nexlink_relay.sqlite
NEXLINK_SESSION_SECRET=<generate-at-least-32-random-bytes-hex>
```

- `NEXLINK_PORT`: HTTP & WebSocket bind port (default `3000`).
- `NEXLINK_DB_PATH`: SQLite Relay database path (default `.data/nexlink_relay.sqlite`).
- `NEXLINK_SESSION_SECRET`: HMAC-SHA-256 secret signing relay session tokens. If omitted or shorter than 16 characters, the server generates an ephemeral CSPRNG secret on boot (existing Bearer sessions invalidate across restarts unless configured explicitly).

## 3. Running Locally & Production Build
```bash
npm install
npm run build
npm run start
```
For development with Vite middleware + Express + WebSocket upgrade:
```bash
npm run dev
```

## 4. Database Persistence & Operational Hygiene (WAL / SHM)
- SQLite runs with `PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`.
- `.data/`, `*.sqlite`, `*.sqlite-wal`, and `*.sqlite-shm` are excluded in `.gitignore` and `eslint.config.js` so transient WAL/SHM operational locks are never committed into source control.
- Use `npx tsc --noEmit`, `npm run lint`, `npm run format:check`, `npm test`, and `npm run build` as verification gates.

## 5. Production Deployment (HTTPS / WSS)
Deploy behind a TLS-terminating reverse proxy (Nginx / Caddy / Cloud Run) with WebSocket `Upgrade` / `Connection` forwarding on `/ws/relay` and HTTPS on `/api/relay/*`. Web Crypto APIs require a secure origin (`https://` or `localhost`).

## 6. Key Storage Assessment: Browser IndexedDB vs. OS Hardware Keystore
- **Web Client (`nexlink_keystore`)**: Stores AES-256-GCM, ECDSA P-256, and ECDH P-256 keys as `extractable: false` `CryptoKey` objects inside IndexedDB (isolated from `localStorage`). While non-extractable keys resist trivial script exfiltration, browser IndexedDB lacks hardware isolation (TEE/SE) and remains susceptible if an attacker achieves same-origin XSS.
- **Native Android Client (`/app/`)**: Should bind device asymmetric keys inside hardware-backed **Android Keystore** (`KeyGenParameterSpec` / StrongBox where available) and use `EncryptedSharedPreferences` / SQLCipher for sensitive metadata.
