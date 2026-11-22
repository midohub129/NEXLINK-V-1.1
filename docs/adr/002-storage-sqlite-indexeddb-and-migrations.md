# ADR-002: Storage Architecture (SQLite Relay + IndexedDB + Migrations)

- **Status**: Accepted
- **Date**: 2026-11-22

## Context
Previously, all events, preferences, audit entries, and session flags were persisted synchronously in `localStorage`. `localStorage` lacks transactions, schema migrations, concurrent write safety, and structured indexing, and is unsuitable for storing cryptographic material or sensitive metadata.

## Decision
1. **Browser Storage (`IndexedDbDatabase`)**: Use IndexedDB (`nexlink_app_db`) with versioned migrations (`v1_core_stores`, `v2_device_identity_and_audit`, `v3_sync_idempotency_and_dedup_indexes`) tracked in `schema_migrations`, a serialized async write queue, and atomic multi-store `readwrite` transactions.
2. **Secret Isolation**: Keep AES-256-GCM and ECDSA P-256 `CryptoKey` objects non-extractable inside a dedicated `nexlink_keystore` IndexedDB store; never write keys or session tokens to `localStorage`. Legacy `nexlink_*` keys in `localStorage` are explicitly purged on startup.
3. **Backend Relay Storage (`SqliteRelayDatabase`)**: Use Node 22 built-in `node:sqlite` (`DatabaseSync`) with WAL mode, `PRAGMA foreign_keys = ON`, `BEGIN IMMEDIATE` transactions, and tracked migrations in `schema_migrations`.
4. **Backup & Restore**: Export canonical JSON snapshots signed with a SHA-256 checksum and verify checksum integrity before executing atomic restore transactions.

## Consequences
- Data survives restarts with schema evolution guarantees and atomic writes.
- Sensitive cryptographic keys cannot be exfiltrated via `localStorage`.
