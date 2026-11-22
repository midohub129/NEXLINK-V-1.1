# ADR-004: Security Identity, AuthN/AuthZ Separation, and Data Source Isolation

- **Status**: Accepted
- **Date**: 2026-11-22

## Context
Previously, a static `INSTALLED_DEVICE_APPS` array was displayed as live device apps and usage stats, while local role state and session metadata lived in `localStorage`.

## Decision
1. **Separated Identity**: `DeviceIdentityProfile` separates the shareable `publicId` (UUID) from `cryptoKeyId` (SHA-256 fingerprint of an `ECDSA P-256` public key).
2. **AuthN vs AuthZ**: `SecurityManager` manages in-memory `SessionState` (AuthN) independently from `RoleCapabilities` (AuthZ), requiring both valid authentication and role authorization on sensitive mutations and recording denied attempts to `ISecurityAuditRepository`.
3. **Honest Data Sources (`IDataSource`)**: `BrowserDeviceDataSource` (`PRODUCTION`) accurately reports that web browsers cannot enumerate Android packages, read `UsageStatsManager`, or run `NotificationListenerService`. `TestFixtureDeviceDataSource` (`TEST_FIXTURE`) is strictly isolated and only active when explicitly toggled by the user or under test.

## Consequences
- No mock/fixture data is ever presented as live OS telemetry.
- Original Android/Kotlin files under `/app/` remain untouched for native Android compilation where OS APIs are actually available.
