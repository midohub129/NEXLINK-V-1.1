# ADR-003: Relay Transport Layer and Stateful Sync Engine

- **Status**: Accepted
- **Date**: 2026-11-22

## Context
NEXLINK v1.0 lacked any network client or backend relay; events remained `PENDING` forever or had their status toggled manually without server delivery confirmation.

## Decision
1. **Express + WebSocket Relay (`/api/relay/*`, `/ws/relay`)**: Implemented a self-hosted relay server backed by `SqliteRelayDatabase` supporting device registration, ephemeral 6-digit pairing requests, device link queries/revocation, idempotent batch sync ingestion, and real-time WebSocket push to connected peers.
2. **Resilient `RelayTransportClient`**: Enforces `AbortController` timeouts, propagates `X-Idempotency-Batch` keys, tracks explicit `ConnectionState` (`DISCONNECTED`, `CONNECTING`, `CONNECTED`, `RECONNECTING`, `ERROR`), and applies exponential backoff on WebSocket drops.
3. **Stateful `SyncEngine`**: Maintains explicit lifecycle transitions (`PENDING -> IN_PROGRESS -> SYNCED | FAILED`), preserves chronological FIFO ordering, verifies server `SyncDispatchAck` before marking `SYNCED`, applies exponential backoff up to `maxSyncRetries`, and recovers interrupted `IN_PROGRESS` rows to `PENDING` on startup.

## Consequences
- No event is marked `SYNCED` without a confirmed relay acknowledgment.
- True peer-to-peer WebRTC screen sharing and binary file streaming remain explicitly scoped out as future P2P signaling extensions.
