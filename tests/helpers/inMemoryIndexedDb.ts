type StoreConfig = {
  keyPath: string;
  autoIncrement: boolean;
  records: Map<IDBValidKey, Record<string, unknown>>;
  nextAutoId: number;
  indexes: Map<string, { keyPath: string; unique: boolean }>;
};

function isCryptoKeyLike(val: unknown): boolean {
  if (!val || typeof val !== 'object') return false;
  if (typeof CryptoKey !== 'undefined' && val instanceof CryptoKey) return true;
  const candidate = val as Record<string, unknown>;
  return (
    typeof candidate.type === 'string' &&
    typeof candidate.extractable === 'boolean' &&
    typeof candidate.algorithm === 'object' &&
    Array.isArray(candidate.usages)
  );
}

function cloneRecord<T>(val: T): T {
  if (val === null || typeof val !== 'object') {
    return val;
  }
  if (isCryptoKeyLike(val)) {
    return val;
  }
  if (val instanceof Uint8Array) {
    return new Uint8Array(val) as unknown as T;
  }
  if (val instanceof ArrayBuffer) {
    return val.slice(0) as unknown as T;
  }
  if (val instanceof Date) {
    return new Date(val.getTime()) as unknown as T;
  }
  if (Array.isArray(val)) {
    return val.map((item) => cloneRecord(item)) as unknown as T;
  }
  const copy: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(val as Record<string, unknown>)) {
    if (entry !== undefined) {
      copy[key] = cloneRecord(entry);
    }
  }
  return copy as T;
}

function makeRequest<T>(
  executor: () => { ok: true; value: T } | { ok: false; err: Error }
): IDBRequest<T> {
  const req: Record<string, unknown> = {
    result: undefined,
    error: null,
    onsuccess: null,
    onerror: null,
  };
  queueMicrotask(() => {
    let res: { ok: true; value: T } | { ok: false; err: Error };
    try {
      res = executor();
    } catch (err) {
      res = {
        ok: false,
        err: err instanceof Error ? err : new Error(String(err)),
      };
    }
    if (res.ok) {
      req.result = res.value;
      if (typeof req.onsuccess === 'function') {
        (req.onsuccess as (ev: unknown) => void)({});
      }
    } else {
      req.error = res.err;
      if (typeof req.onerror === 'function') {
        (req.onerror as (ev: unknown) => void)({});
      }
    }
  });
  return req as unknown as IDBRequest<T>;
}

export class InMemoryIndexedDbHarness {
  private databases = new Map<
    string,
    { version: number; stores: Map<string, StoreConfig> }
  >();
  public failOnPutStore: string | null = null;
  public putCount = 0;

  createFactory(): IDBFactory {
    const makeObjectStoreFacade = (
      storeName: string,
      cfg: StoreConfig,
      onOpDone: ((err?: Error) => void) | null,
      onOpStart?: () => void
    ): IDBObjectStore => {
      const runOp = <T>(
        fn: () => { ok: true; value: T } | { ok: false; err: Error }
      ): IDBRequest<T> => {
        onOpStart?.();
        return makeRequest<T>(() => {
          const result = fn();
          if (result.ok) {
            onOpDone?.();
          } else {
            onOpDone?.(result.err);
          }
          return result;
        });
      };

      const writeRecord = (
        rawVal: Record<string, unknown>,
        mustNotExist: boolean
      ): { ok: true; value: IDBValidKey } | { ok: false; err: Error } => {
        this.putCount += 1;
        if (this.failOnPutStore === storeName) {
          return {
            ok: false,
            err: new Error(`Simulated write failure in store ${storeName}`),
          };
        }
        const copy = cloneRecord(rawVal);
        let key = copy[cfg.keyPath] as IDBValidKey | undefined;
        if ((key === undefined || key === null) && cfg.autoIncrement) {
          key = cfg.nextAutoId++;
          copy[cfg.keyPath] = key;
        } else if (typeof key === 'number' && cfg.autoIncrement) {
          if (key >= cfg.nextAutoId) {
            cfg.nextAutoId = key + 1;
          }
        }
        if (key === undefined || key === null) {
          return {
            ok: false,
            err: new Error(`Missing keyPath ${cfg.keyPath} on ${storeName}`),
          };
        }
        if (mustNotExist && cfg.records.has(key)) {
          const err = new Error('Duplicate primary key');
          err.name = 'ConstraintError';
          return { ok: false, err };
        }
        for (const idx of cfg.indexes.values()) {
          if (idx.unique) {
            const idxVal = copy[idx.keyPath];
            if (idxVal !== undefined) {
              for (const [existingKey, existingRec] of cfg.records.entries()) {
                if (existingKey !== key && existingRec[idx.keyPath] === idxVal) {
                  const err = new Error(
                    `ConstraintError on unique index ${idx.keyPath}`
                  );
                  err.name = 'ConstraintError';
                  return { ok: false, err };
                }
              }
            }
          }
        }
        cfg.records.set(key, copy);
        return { ok: true, value: key };
      };

      return {
        get indexNames() {
          const names = Array.from(cfg.indexes.keys());
          return {
            contains: (n: string) => names.includes(n),
            length: names.length,
          } as unknown as DOMStringList;
        },
        createIndex(idxName: string, keyPath: string, opts?: IDBIndexParameters) {
          cfg.indexes.set(idxName, {
            keyPath,
            unique: Boolean(opts?.unique),
          });
          return {} as IDBIndex;
        },
        index(idxName: string) {
          const idx = cfg.indexes.get(idxName);
          if (!idx) throw new Error(`Index ${idxName} not found`);
          return {
            get(query: IDBValidKey) {
              return runOp(() => {
                for (const rec of cfg.records.values()) {
                  if (rec[idx.keyPath] === query) {
                    return { ok: true, value: cloneRecord(rec) };
                  }
                }
                return { ok: true, value: undefined };
              });
            },
          } as unknown as IDBIndex;
        },
        get(key: IDBValidKey) {
          return runOp(() => ({
            ok: true,
            value: cfg.records.has(key)
              ? cloneRecord(cfg.records.get(key))
              : undefined,
          }));
        },
        getAll() {
          return runOp(() => ({
            ok: true,
            value: Array.from(cfg.records.values()).map((r) => cloneRecord(r)),
          }));
        },
        put(val: Record<string, unknown>) {
          return runOp(() => writeRecord(val, false));
        },
        add(val: Record<string, unknown>) {
          return runOp(() => writeRecord(val, true));
        },
        delete(key: IDBValidKey) {
          return runOp(() => {
            cfg.records.delete(key);
            return { ok: true, value: undefined };
          });
        },
        clear() {
          return runOp(() => {
            cfg.records.clear();
            return { ok: true, value: undefined };
          });
        },
      } as unknown as IDBObjectStore;
    };

    const open = (name: string, version = 1): IDBOpenDBRequest => {
      const req: Record<string, unknown> = {
        result: undefined,
        error: null,
        transaction: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
      };

      queueMicrotask(() => {
        let entry = this.databases.get(name);
        const oldVersion = entry ? entry.version : 0;
        if (!entry) {
          entry = { version: oldVersion, stores: new Map() };
          this.databases.set(name, entry);
        }

        const createDbFacade = (targetEntry: {
          version: number;
          stores: Map<string, StoreConfig>;
        }): IDBDatabase => {
          return {
            name,
            get version() {
              return targetEntry.version;
            },
            get objectStoreNames() {
              const names = Array.from(targetEntry.stores.keys());
              return {
                contains: (n: string) => names.includes(n),
                length: names.length,
                item: (i: number) => names[i] ?? null,
              } as unknown as DOMStringList;
            },
            createObjectStore(
              storeName: string,
              opts?: IDBObjectStoreParameters
            ): IDBObjectStore {
              const cfg: StoreConfig = {
                keyPath: (opts?.keyPath as string) ?? 'id',
                autoIncrement: Boolean(opts?.autoIncrement),
                records: new Map(),
                nextAutoId: 1,
                indexes: new Map(),
              };
              targetEntry.stores.set(storeName, cfg);
              return makeObjectStoreFacade(storeName, cfg, null);
            },
            transaction(
              storeNames: string | string[],
              mode: IDBTransactionMode = 'readonly'
            ): IDBTransaction {
              const list = Array.isArray(storeNames) ? storeNames : [storeNames];
              const snapshots = new Map<string, StoreConfig>();
              for (const s of list) {
                const orig = targetEntry.stores.get(s);
                if (!orig) {
                  throw new Error(`ObjectStore not found: ${s}`);
                }
                snapshots.set(s, {
                  keyPath: orig.keyPath,
                  autoIncrement: orig.autoIncrement,
                  nextAutoId: orig.nextAutoId,
                  indexes: new Map(orig.indexes),
                  records: new Map(
                    Array.from(orig.records.entries()).map(([k, v]) => [
                      k,
                      cloneRecord(v),
                    ])
                  ),
                });
              }

              let settled = false;
              let pendingOps = 0;
              let commitTimer: ReturnType<typeof setTimeout> | null = null;

              const tryCommit = () => {
                commitTimer = null;
                if (settled || pendingOps > 0) return;
                settled = true;
                if (mode === 'readwrite') {
                  for (const [sName, working] of snapshots.entries()) {
                    targetEntry.stores.set(sName, working);
                  }
                }
                if (typeof tx.oncomplete === 'function') {
                  (tx.oncomplete as (ev: unknown) => void)({});
                }
              };

              const scheduleCommitCheck = () => {
                if (settled || pendingOps > 0) return;
                if (commitTimer !== null) {
                  clearTimeout(commitTimer);
                }
                commitTimer = setTimeout(tryCommit, 0);
              };

              const onOpStart = () => {
                pendingOps += 1;
                if (commitTimer !== null) {
                  clearTimeout(commitTimer);
                  commitTimer = null;
                }
              };

              const onOpDone = (failedErr?: Error) => {
                if (failedErr && !settled) {
                  settled = true;
                  if (commitTimer !== null) {
                    clearTimeout(commitTimer);
                    commitTimer = null;
                  }
                  tx.error = failedErr;
                  queueMicrotask(() => {
                    if (typeof tx.onerror === 'function') {
                      (tx.onerror as (ev: unknown) => void)({});
                    }
                  });
                  return;
                }
                pendingOps = Math.max(0, pendingOps - 1);
                scheduleCommitCheck();
              };

              const tx: Record<string, unknown> = {
                mode,
                error: null,
                oncomplete: null,
                onerror: null,
                onabort: null,
                objectStore(storeName: string) {
                  const working = snapshots.get(storeName);
                  if (!working) {
                    throw new Error(`Store ${storeName} not part of transaction`);
                  }
                  return makeObjectStoreFacade(storeName, working, onOpDone, onOpStart);
                },
                abort() {
                  if (settled) return;
                  settled = true;
                  if (commitTimer !== null) {
                    clearTimeout(commitTimer);
                    commitTimer = null;
                  }
                  tx.error = new Error('Transaction aborted');
                  queueMicrotask(() => {
                    if (typeof tx.onabort === 'function') {
                      (tx.onabort as (ev: unknown) => void)({});
                    }
                  });
                },
              };

              scheduleCommitCheck();
              return tx as unknown as IDBTransaction;
            },
            close() {},
          } as unknown as IDBDatabase;
        };

        const dbFacade = createDbFacade(entry);
        req.result = dbFacade;

        if (version > oldVersion) {
          entry.version = version;
          const upgradeTx = {
            objectStore(storeName: string) {
              const cfg = entry!.stores.get(storeName);
              if (!cfg) throw new Error(`Store ${storeName} not found in upgrade`);
              return makeObjectStoreFacade(storeName, cfg, null);
            },
          } as unknown as IDBTransaction;
          req.transaction = upgradeTx;
          if (typeof req.onupgradeneeded === 'function') {
            (req.onupgradeneeded as (ev: unknown) => void)({ oldVersion });
          }
          req.transaction = null;
        }

        if (typeof req.onsuccess === 'function') {
          (req.onsuccess as (ev: unknown) => void)({});
        }
      });

      return req as unknown as IDBOpenDBRequest;
    };

    return { open } as unknown as IDBFactory;
  }
}
