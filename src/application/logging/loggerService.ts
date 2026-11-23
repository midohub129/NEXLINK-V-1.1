import type { ILogger, LogLevel, LogRecord } from '../../domain/interfaces/services';

const SENSITIVE_KEY_PATTERN =
  /secret|token|password|passwd|passphrase|private|key|ciphertext|authorization|cookie|payload|plaintext|salt|backup/i;

function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (value.length > 500) {
      return `${value.slice(0, 120)}...[REDACTED_LEN_${value.length}]`;
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactValue(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

let traceCounter = 0;

export function createTraceId(prefix = 'op'): string {
  traceCounter = (traceCounter + 1) % 1_000_000;
  let randHex = traceCounter.toString(36).padStart(4, '0');
  if (
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.getRandomValues === 'function'
  ) {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(4));
    randHex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return `${prefix}-${Date.now().toString(36)}-${randHex}`;
}

export class RotatingLogger implements ILogger {
  private readonly maxEntries: number;
  private logs: LogRecord[] = [];
  private nextId = 1;
  private listeners = new Set<() => void>();

  constructor(maxEntries = 200) {
    this.maxEntries = Math.max(20, maxEntries);
  }

  private append(
    level: LogLevel,
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void {
    const entry: LogRecord = {
      id: this.nextId++,
      timestamp: Date.now(),
      level,
      scope,
      traceId: traceId ?? createTraceId(scope.toLowerCase()),
      message,
      metadata: metadata
        ? (redactValue(metadata) as Record<string, unknown>)
        : undefined,
    };

    // Ring-buffer rotation
    this.logs = [entry, ...this.logs].slice(0, this.maxEntries);
    this.listeners.forEach((listener) => listener());
  }

  debug(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void {
    this.append('DEBUG', scope, message, metadata, traceId);
  }

  info(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void {
    this.append('INFO', scope, message, metadata, traceId);
  }

  warn(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void {
    this.append('WARN', scope, message, metadata, traceId);
  }

  error(
    scope: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string
  ): void {
    this.append('ERROR', scope, message, metadata, traceId);
  }

  getLogs(): LogRecord[] {
    return [...this.logs];
  }

  clear(): void {
    this.logs = [];
    this.listeners.forEach((listener) => listener());
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
