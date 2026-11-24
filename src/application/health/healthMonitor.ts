import type { ITransportClient } from '../../domain/interfaces/services';
import type { SubsystemStatus, SystemHealthSnapshot } from '../../domain/models/health';
import type { ErrorManager } from '../errors/errorManager';
import type { SyncEngine } from '../sync/syncEngine';

export class HealthMonitor {
  private readonly syncEngine: SyncEngine;
  private readonly transport: ITransportClient;
  private readonly errorManager: ErrorManager;
  private databaseHealthy = false;
  private listeners = new Set<() => void>();

  constructor(deps: {
    syncEngine: SyncEngine;
    transport: ITransportClient;
    errorManager: ErrorManager;
  }) {
    this.syncEngine = deps.syncEngine;
    this.transport = deps.transport;
    this.errorManager = deps.errorManager;

    this.syncEngine.subscribe(() => this.notify());
    this.transport.subscribe(() => this.notify());
    this.errorManager.subscribe(() => this.notify());
  }

  setDatabaseReady(ready: boolean): void {
    this.databaseHealthy = ready;
    this.notify();
  }

  getSnapshot(): SystemHealthSnapshot {
    const events = this.syncEngine.getEvents();
    const pendingCount = events.filter((e) => e.status === 'PENDING').length;
    const inProgressCount = events.filter((e) => e.status === 'IN_PROGRESS').length;
    const syncedCount = events.filter((e) => e.status === 'SYNCED').length;
    const failedCount = events.filter((e) => e.status === 'FAILED').length;

    const transportStatus = this.transport.getState();
    const databaseStatus: SubsystemStatus = this.databaseHealthy
      ? 'HEALTHY'
      : 'UNAVAILABLE';

    const syncLifecycle = this.syncEngine.getLifecycleState();
    let syncStatus: SubsystemStatus = 'IDLE';
    if (syncLifecycle === 'ERROR') {
      syncStatus = 'UNAVAILABLE';
    } else if (syncLifecycle === 'STOPPED') {
      syncStatus = failedCount > 0 ? 'DEGRADED' : 'IDLE';
    } else if (failedCount > 0 && pendingCount === 0) {
      syncStatus = 'DEGRADED';
    } else if (this.syncEngine.isSyncRunning() || pendingCount > 0) {
      syncStatus = transportStatus === 'CONNECTED' ? 'HEALTHY' : 'DEGRADED';
    } else if (syncedCount > 0 && syncLifecycle === 'RUNNING') {
      syncStatus = 'HEALTHY';
    }

    const latestErr = this.errorManager.getLatestError();

    return {
      databaseStatus,
      transportStatus,
      syncStatus,
      pendingCount,
      inProgressCount,
      syncedCount,
      failedCount,
      lastSuccessfulConnectionAt: this.transport.getLastSuccessfulConnectionAt(),
      lastSuccessfulSyncAt: this.syncEngine.getLastSuccessfulSyncAt(),
      lastError: latestErr
        ? {
            code: latestErr.code,
            source: latestErr.source,
            message: latestErr.userMessage,
            timestamp: latestErr.timestamp,
          }
        : null,
      checkedAt: Date.now(),
    };
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener());
  }
}
