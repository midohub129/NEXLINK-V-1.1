import type { ILifecycleParticipant, ILogger } from '../../domain/interfaces/services';
import type { ErrorManager } from '../errors/errorManager';

export type LifecyclePhase = 'STOPPED' | 'STARTING' | 'RUNNING' | 'STOPPING' | 'ERROR';

export class LifecycleManager {
  private readonly participants: ILifecycleParticipant[];
  private readonly logger: ILogger;
  private readonly errorManager: ErrorManager;

  private phase: LifecyclePhase = 'STOPPED';
  private startPromise: Promise<void> | null = null;
  private stopPromise: Promise<void> | null = null;
  private listeners = new Set<() => void>();

  constructor(
    participants: ILifecycleParticipant[],
    logger: ILogger,
    errorManager: ErrorManager
  ) {
    this.participants = participants;
    this.logger = logger;
    this.errorManager = errorManager;
  }

  getPhase(): LifecyclePhase {
    return this.phase;
  }

  async startup(): Promise<void> {
    if (this.startPromise) {
      await this.startPromise;
    }
    if (this.stopPromise) {
      await this.stopPromise;
    }
    if (this.phase === 'RUNNING') return;

    this.phase = 'STARTING';
    this.notify();

    this.startPromise = (async () => {
      try {
        for (const participant of this.participants) {
          this.logger.debug('LIFECYCLE', `بدء تشغيل ${participant.name}`);
          await participant.start();
        }
        this.phase = 'RUNNING';
        this.logger.info('LIFECYCLE', 'تم تشغيل جميع خدمات التطبيق بنجاح');
      } catch (err) {
        this.phase = 'ERROR';
        this.errorManager.capture(
          err,
          'LIFECYCLE',
          'تعذّر إكمال بدء تشغيل الخدمات الأساسية.'
        );
        throw err;
      } finally {
        this.startPromise = null;
        this.notify();
      }
    })();

    return this.startPromise;
  }

  async shutdown(): Promise<void> {
    if (this.stopPromise) return this.stopPromise;

    this.stopPromise = (async () => {
      try {
        if (this.startPromise) {
          await this.startPromise.catch(() => undefined);
        }
        if (this.phase === 'STOPPED') return;

        this.phase = 'STOPPING';
        this.notify();

        const reversed = [...this.participants].reverse();
        for (const participant of reversed) {
          try {
            this.logger.debug('LIFECYCLE', `إيقاف ${participant.name}`);
            await participant.stop();
          } catch (err) {
            this.errorManager.capture(
              err,
              'LIFECYCLE',
              `حدث خطأ أثناء إيقاف ${participant.name}.`
            );
          }
        }
        this.phase = 'STOPPED';
        this.logger.info('LIFECYCLE', 'تم إيقاف الخدمات بشكل منظم');
      } finally {
        this.stopPromise = null;
        this.notify();
      }
    })();

    return this.stopPromise;
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
