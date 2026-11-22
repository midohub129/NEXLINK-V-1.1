export type ErrorSource =
  | 'STORAGE'
  | 'TRANSPORT'
  | 'SECURITY'
  | 'SYNC'
  | 'VALIDATION'
  | 'LIFECYCLE'
  | 'DATASOURCE'
  | 'UNKNOWN';

export class AppError extends Error {
  readonly code: string;
  readonly source: ErrorSource;
  readonly userMessage: string;
  readonly retryable: boolean;
  readonly timestamp: number;
  readonly context?: Record<string, unknown>;

  constructor(params: {
    code: string;
    source: ErrorSource;
    userMessage: string;
    technicalMessage: string;
    retryable?: boolean;
    context?: Record<string, unknown>;
    cause?: unknown;
  }) {
    super(params.technicalMessage, { cause: params.cause });
    this.name = 'AppError';
    this.code = params.code;
    this.source = params.source;
    this.userMessage = params.userMessage;
    this.retryable = params.retryable ?? false;
    this.timestamp = Date.now();
    this.context = params.context;
  }
}

export class StorageError extends AppError {
  constructor(
    code: string,
    userMessage: string,
    technicalMessage: string,
    cause?: unknown
  ) {
    super({
      code,
      source: 'STORAGE',
      userMessage,
      technicalMessage,
      retryable: false,
      cause,
    });
    this.name = 'StorageError';
  }
}

export class TransportError extends AppError {
  constructor(
    code: string,
    userMessage: string,
    technicalMessage: string,
    retryable = true,
    cause?: unknown
  ) {
    super({
      code,
      source: 'TRANSPORT',
      userMessage,
      technicalMessage,
      retryable,
      cause,
    });
    this.name = 'TransportError';
  }
}

export class SecurityError extends AppError {
  constructor(
    code: string,
    userMessage: string,
    technicalMessage: string,
    cause?: unknown
  ) {
    super({
      code,
      source: 'SECURITY',
      userMessage,
      technicalMessage,
      retryable: false,
      cause,
    });
    this.name = 'SecurityError';
  }
}

export class SyncError extends AppError {
  constructor(
    code: string,
    userMessage: string,
    technicalMessage: string,
    retryable = true,
    cause?: unknown
  ) {
    super({
      code,
      source: 'SYNC',
      userMessage,
      technicalMessage,
      retryable,
      cause,
    });
    this.name = 'SyncError';
  }
}

export class ValidationError extends AppError {
  constructor(
    code: string,
    userMessage: string,
    technicalMessage: string,
    context?: Record<string, unknown>
  ) {
    super({
      code,
      source: 'VALIDATION',
      userMessage,
      technicalMessage,
      retryable: false,
      context,
    });
    this.name = 'ValidationError';
  }
}
