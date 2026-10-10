/** Key-value persistence for the pipeline (06-security § Appendix A). */

import { ACEError } from './errors.js';

/**
 * A durable key-value store. Keys match `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$` (≤ 200 chars).
 * Values are at most 64 MiB (`invalid_argument` on write). All I/O errors are
 * `ACEError('storage_failed')`. Lock names match `^[a-z0-9][a-z0-9_-]{0,63}$`; the default lock
 * timeout is 10 s. A lock not acquired in time is `receiver_busy` for the `receive` lock and
 * `lock_busy` otherwise.
 */
export interface StoreData {
  read(key: string): Promise<Uint8Array | null>;
  /** Atomic replace, durable when the promise resolves. A value over 64 MiB is `invalid_argument`. */
  write(key: string, value: Uint8Array): Promise<void>;
  /** A missing key is not an error. */
  delete(key: string): Promise<void>;
  /** Keys starting with `prefix`, sorted ascending. */
  list(prefix: string): Promise<string[]>;
}

/** The scoped data handle is valid only during this callback; do not retain it or detach work. */
export interface CoordinatedStore {
  coordinate<T>(name: string, body: (data: StoreData) => Promise<T>): Promise<T>;
}

export interface ACEStore extends StoreData {
  /** Exclusive, non-reentrant lock. Resolves to a release function. */
  lock(name: string, opts?: { timeoutMs?: number }): Promise<() => Promise<void>>;
}

/** Internal: run `body` under `store.lock(name)`, the plain-lock implementation of `CoordinatedStore.coordinate`. */
export async function withLock<T>(store: ACEStore, name: string, body: (data: ACEStore) => Promise<T>): Promise<T> {
  const release = await store.lock(name);
  try { return await body(store); } finally { await release(); }
}

const KEY_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/;
const LOCK_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export const DEFAULT_LOCK_TIMEOUT_MS = 10_000;
/** Internal: the largest value a store accepts (and reads back). */
export const MAX_VALUE_BYTES = 64 * 1024 * 1024;

export function checkKey(key: unknown): string {
  if (typeof key !== 'string' || key.length > 200 || KEY_RE.exec(key)?.[0] !== key) {
    throw new ACEError('invalid_argument', `invalid store key ${JSON.stringify(String(key).slice(0, 60))}`);
  }
  return key;
}

export function checkLockName(name: unknown): string {
  if (typeof name !== 'string' || LOCK_RE.exec(name)?.[0] !== name) {
    throw new ACEError('invalid_argument', 'invalid lock name');
  }
  return name;
}

export function lockTimeoutError(name: string): ACEError {
  return new ACEError(name === 'receive' ? 'receiver_busy' : 'lock_busy', `lock '${name}' is held`);
}

/** Internal: a write value must be bytes of at most MAX_VALUE_BYTES. */
export function checkValue(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new ACEError('invalid_argument', 'value must be bytes');
  if (value.length > MAX_VALUE_BYTES) throw new ACEError('invalid_argument', 'value exceeds 64 MiB');
  return value;
}

export function checkTimeout(timeoutMs: unknown): number {
  const t = timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
  if (typeof t !== 'number' || !Number.isFinite(t) || t < 0) throw new ACEError('invalid_argument', 'timeoutMs must be >= 0');
  return t;
}

/** An async mutex with a timeout. Internal. */
export class Mutex {
  #held = false;
  #waiters: Array<() => void> = [];

  get held(): boolean {
    return this.#held;
  }

  /** Resolves true when acquired, false on timeout. */
  acquire(timeoutMs: number): Promise<boolean> {
    if (!this.#held) {
      this.#held = true;
      return Promise.resolve(true);
    }
    if (timeoutMs <= 0) return Promise.resolve(false);
    return new Promise((resolve) => {
      const waiter = () => {
        clearTimeout(timer);
        resolve(true);
      };
      const timer = setTimeout(() => {
        const i = this.#waiters.indexOf(waiter);
        if (i >= 0) this.#waiters.splice(i, 1);
        resolve(false);
      }, timeoutMs);
      this.#waiters.push(waiter);
    });
  }

  release(): void {
    const next = this.#waiters.shift();
    if (next) next(); // ownership passes directly to the next waiter
    else this.#held = false;
  }
}

/** Serializes async calls in order. Internal. */
export class SerialQueue {
  #tail: Promise<unknown> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(fn, fn);
    this.#tail = result.catch(() => undefined);
    return result;
  }
}

/** In-memory store: a map plus an in-process mutex per lock name. */
export class MemoryStore implements ACEStore {
  readonly #data = new Map<string, Uint8Array>();
  readonly #locks = new Map<string, Mutex>();

  async read(key: string): Promise<Uint8Array | null> {
    const v = this.#data.get(checkKey(key));
    return v === undefined ? null : v.slice();
  }

  async write(key: string, value: Uint8Array): Promise<void> {
    checkKey(key);
    this.#data.set(key, checkValue(value).slice());
  }

  async delete(key: string): Promise<void> {
    this.#data.delete(checkKey(key));
  }

  async list(prefix: string): Promise<string[]> {
    if (typeof prefix !== 'string') throw new ACEError('invalid_argument', 'prefix must be a string');
    return [...this.#data.keys()].filter((k) => k.startsWith(prefix)).sort();
  }

  async lock(name: string, opts: { timeoutMs?: number } = {}): Promise<() => Promise<void>> {
    checkLockName(name);
    const timeout = checkTimeout(opts.timeoutMs);
    let m = this.#locks.get(name);
    if (m === undefined) {
      m = new Mutex();
      this.#locks.set(name, m);
    }
    if (!(await m.acquire(timeout))) throw lockTimeoutError(name);
    let released = false;
    const mutex = m;
    return async () => {
      if (released) return;
      released = true;
      mutex.release();
    };
  }

  coordinate<T>(name: string, body: (data: StoreData) => Promise<T>): Promise<T> { return withLock(this, name, body); }
}
