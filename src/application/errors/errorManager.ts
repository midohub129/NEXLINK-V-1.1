import { AppError, type ErrorSource } from '../../domain/errors/appError';
import type { ILogger } from '../../domain/interfaces/services';
import { createTraceId } from '../logging/loggerService';

export interface RecordedError {
  id: number;
  code: string;
  source: ErrorSource;
  userMessage: string;
  technicalMessage: string;
  retryable: boolean;
  timestamp: number;
  traceId: string;
}

export class ErrorManager {
  private readonly logger: ILogger;
  private errors: RecordedError[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  constructor(logger: ILogger) {
    this.logger = logger;
  }

  capture(
    err: unknown,
    fallbackSource: ErrorSource = 'UNKNOWN',
    fallbackUserMessage = 'حدث خطأ غير متوقع أثناء تنفيذ العملية.'
  ): RecordedError {
    const traceId = createTraceId('err');
    const appError =
      err instanceof AppError
        ? err
        : new AppError({
            code: 'UNHANDLED_ERROR',
            source: fallbackSource,
            userMessage: fallbackUserMessage,
            technicalMessage:
              err instanceof Error ? err.message : String(err ?? 'Unknown error'),
            retryable: false,
            cause: err,
          });

    const recorded: RecordedError = {
      id: this.nextId++,
      code: appError.code,
      source: appError.source,
      userMessage: appError.userMessage,
      technicalMessage: appError.message,
      retryable: appError.retryable,
      timestamp: appError.timestamp,
      traceId,
    };

    this.errors = [recorded, ...this.errors].slice(0, 50);
    this.logger.error(
      appError.source,
      `${appError.code}: ${appError.message}`,
      appError.context,
      traceId
    );
    this.listeners.forEach((listener) => listener());
    return recorded;
  }

  getLatestError(): RecordedError | null {
    return this.errors[0] ?? null;
  }

  getAllErrors(): RecordedError[] {
    return [...this.errors];
  }

  clearLatest(): void {
    if (this.errors.length === 0) return;
    this.errors = [];
    this.listeners.forEach((listener) => listener());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
