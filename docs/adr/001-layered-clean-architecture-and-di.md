# ADR-001: Layered Clean Architecture and Dependency Injection

- **Status**: Accepted
- **Date**: 2026-11-22

## Context
NEXLINK v1.0 coupled React UI components directly to `localStorage`, static mock datasets, and global service singletons. This prevented unit testing without a DOM, hid side effects inside UI render paths, and mixed domain rules with browser storage details.

## Decision
Reorganize the frontend codebase into four explicit layers:
1. `src/domain/`: Pure models, typed error hierarchy (`AppError` subclasses), and repository/service contracts (`ISyncEventRepository`, `IDeviceRepository`, `ITransportClient`, `ICryptoProvider`, `IDataSource`). Zero imports from React, IndexedDB, or `fetch`.
2. `src/application/`: Use-case coordinators (`SyncEngine`, `DeviceManager`, `SecurityManager`, `SettingsService`, `HealthMonitor`, `ErrorManager`, `RotatingLogger`, `LifecycleManager`) accepting interfaces via constructor injection and assembled in `src/application/container.ts`.
3. `src/infrastructure/`: Concrete browser adapters (`IndexedDbDatabase`, `WebCryptoProvider`, `RelayTransportClient`, `BrowserDeviceDataSource`, `TestFixtureDeviceDataSource`) plus `InMemory*` repositories for fast headless tests.
4. `src/presentation/`: React components consuming `useAppContainer()` exclusively via `ContainerContext`, with zero direct storage or network calls.

## Consequences
- Application rules and error paths are testable in Node via `tsx --test` without browser globals.
- Infrastructure engines can be swapped independently of domain and presentation code.
