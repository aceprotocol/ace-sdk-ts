/**
 * Node.js-only exports (`@ace-protocol/sdk/node`).
 *
 * `postDirect` / `deliverDirectOrRelay`: the sending side of direct delivery
 * (08-relay § Direct Delivery), a transport for the secure delivery frames
 * (`SecureRelayReplies`): direct endpoint first, relay fallback.
 *
 * `FileStore(root)`: an `ACEStore` over a directory. Directories are 0700, files 0600.
 * Writes are atomic (temp file + fsync + rename + directory fsync). Locks use POSIX flock
 * over permanent files on a local filesystem; the kernel releases them on process exit.
 * Never unlink or replace a lock file. Network filesystems are unsupported.
 */

import { constants as fsc, promises as fs } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import * as https from 'node:https';
import { promises as dns } from 'node:dns';
import { ACEError } from './errors.js';
import { directOrRelayWith, postDirectWith, type DeliveryPath, type PostDirectOptions } from './direct.js';
import type { LookupFn } from './pinned-https.js';
import type { RelayClient } from './relay.js';
import type { ACEMessage } from './types.js';
import { checkKey, checkLockName, checkTimeout, checkValue, lockTimeoutError, MAX_VALUE_BYTES, Mutex, withLock, type ACEStore, type StoreData } from './store.js';

export type { ACEStore } from './store.js';
export { EtcdStore, type EtcdStoreOptions } from './etcd-store.js';
export type { DeliveryPath, PostDirectOptions } from './direct.js';

/**
 * POST `{"message": envelope}` to a peer's direct endpoint. The endpoint must be an ACE HTTPS
 * URL whose host resolves only to non-blocked addresses (`isBlockedAddress`); the connection
 * goes to the validated address (DNS pinned; SNI and certificate checks use the host name).
 * Redirects are not followed; the default timeout is 5 s. Succeeds iff the answer is 2xx with
 * JSON `{"ok": true}`.
 *
 * Errors: unsafe or malformed endpoint (or envelope) → `invalid_argument`; 400 or 413 →
 * `direct_rejected` (permanent; `remoteCode` is the receiver's `error` when it matches
 * `^[a-z0-9_]{1,64}$`; do not retry the envelope directly or through the relay); anything
 * else (network, timeout, 429, 503, other status or body) → `direct_unavailable` (fall back
 * to the relay).
 */
export async function postDirect(endpoint: string, envelope: ACEMessage, opts: PostDirectOptions = {}): Promise<void> {
  await postDirectWith(endpoint, envelope, opts, { lookup: dns.lookup as unknown as LookupFn, https });
}

/**
 * A transport for `SecureRelayReplies` / secure delivery frames: `postDirect` to `endpoint`
 * when one is given, falling back to `relay.send` on `direct_unavailable` or an unsafe
 * endpoint (`invalid_argument`). A `direct_rejected` is thrown (no relay fallback). Resolves
 * to the path that delivered. Application envelopes never travel through it: `Outbox.deliver`
 * takes `secure.deliver(envelope, peer, exchange)`, whose frames this transport carries.
 */
export function deliverDirectOrRelay(
  relay: Pick<RelayClient, 'send'>, endpoint?: string | null, opts: PostDirectOptions = {},
): (env: ACEMessage) => Promise<DeliveryPath> {
  return directOrRelayWith(relay, endpoint, (e, env) => postDirect(e, env, opts));
}

const LOCK_POLL_MS = 50;
const processMutexes = new Map<string, Mutex>();

function fail(what: string, e: unknown): ACEError {
  if (e instanceof ACEError) return e;
  const code = (e as NodeJS.ErrnoException)?.code ?? '';
  return new ACEError('storage_failed', `${what} failed${code ? ` (${code})` : ''}`, { cause: e });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function errno(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException)?.code;
}

export class FileStore implements ACEStore {
  coordinate<T>(name: string, body: (data: StoreData) => Promise<T>): Promise<T> { return withLock(this, name, body); }
  readonly root: string;
  #realRoot: Promise<string> | null = null;

  constructor(root: string) {
    if (typeof root !== 'string' || root.length === 0) throw new ACEError('invalid_argument', 'root must be a directory path');
    this.root = root;
  }

  async #base(): Promise<string> {
    if (this.#realRoot === null) {
      this.#realRoot = (async () => {
        try {
          const created = await fs.mkdir(this.root, { recursive: true, mode: 0o700 });
          const st = await fs.lstat(this.root);
          if (!st.isDirectory()) throw new ACEError('storage_failed', 'store root is not a directory');
          if (created) {
            const stop = dirname(resolve(created));
            let dir = dirname(resolve(this.root));
            for (;;) { await syncDir(dir); if (dir === stop) break; dir = dirname(dir); }
          }
          return await fs.realpath(this.root);
        } catch (e) {
          this.#realRoot = null;
          throw fail('opening the store root', e);
        }
      })();
    }
    return this.#realRoot;
  }

  /** Refuse symlinks anywhere below the root. Returns the absolute path. */
  async #path(key: string, create: boolean): Promise<string | null> {
    checkKey(key);
    if (key === 'locks' || key.startsWith('locks/')) throw new ACEError('invalid_argument', "the 'locks/' prefix is reserved");
    const base = await this.#base();
    const parts = key.split('/');
    let dir = base;
    for (const part of parts.slice(0, -1)) {
      dir = join(dir, part);
      try {
        const st = await fs.lstat(dir);
        if (!st.isDirectory()) throw new ACEError('storage_failed', `${part} is not a directory`);
      } catch (e) {
        if (errno(e) !== 'ENOENT') throw fail('checking a directory', e);
        if (!create) return null;
        try {
          await fs.mkdir(dir, { mode: 0o700 });
          await syncDir(dirname(dir));
        } catch (e2) {
          if (errno(e2) !== 'EEXIST') throw fail('creating a directory', e2);
        }
      }
    }
    return join(dir, parts[parts.length - 1]);
  }

  async read(key: string): Promise<Uint8Array | null> {
    const path = await this.#path(key, false);
    if (path === null) return null;
    try {
      const st = await fs.lstat(path);
      if (st.isSymbolicLink() || !st.isFile()) throw new ACEError('storage_failed', 'refusing a non-regular file');
      if (st.size > MAX_VALUE_BYTES) throw new ACEError('storage_failed', 'file exceeds 64 MiB');
      const fh = await fs.open(path, fsc.O_RDONLY | fsc.O_NOFOLLOW);
      try {
        const data = await fh.readFile();
        if (data.length > MAX_VALUE_BYTES) throw new ACEError('storage_failed', 'file exceeds 64 MiB');
        return new Uint8Array(data.buffer, data.byteOffset, data.length);
      } finally {
        await fh.close();
      }
    } catch (e) {
      if (errno(e) === 'ENOENT') return null;
      throw fail(`reading ${key}`, e);
    }
  }

  async write(key: string, value: Uint8Array): Promise<void> {
    checkValue(value);
    const path = (await this.#path(key, true))!;
    const dir = dirname(path);
    const tmp = join(dir, `.tmp-${randomBytes(8).toString('hex')}`);
    try {
      const fh = await fs.open(tmp, fsc.O_CREAT | fsc.O_EXCL | fsc.O_WRONLY | fsc.O_NOFOLLOW, 0o600);
      try {
        await fh.writeFile(value);
        await fh.sync();
      } finally {
        await fh.close();
      }
      await fs.rename(tmp, path);
      await syncDir(dir);
    } catch (e) {
      await fs.unlink(tmp).catch(() => {});
      throw fail(`writing ${key}`, e);
    }
  }

  async delete(key: string): Promise<void> {
    const path = await this.#path(key, false);
    if (path === null) return;
    try {
      await fs.unlink(path);
      await syncDir(dirname(path));
    } catch (e) {
      if (errno(e) === 'ENOENT') return;
      throw fail(`deleting ${key}`, e);
    }
  }

  async list(prefix: string): Promise<string[]> {
    if (typeof prefix !== 'string') throw new ACEError('invalid_argument', 'prefix must be a string');
    const base = await this.#base();
    const slash = prefix.lastIndexOf('/');
    const startRel = slash >= 0 ? prefix.slice(0, slash) : '';
    if (startRel !== '' && !/^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/.test(startRel)) return [];
    const out: string[] = [];
    const walk = async (rel: string): Promise<void> => {
      let entries;
      try {
        entries = await fs.readdir(rel ? join(base, rel) : base, { withFileTypes: true });
      } catch (e) {
        if (errno(e) === 'ENOENT' || errno(e) === 'ENOTDIR') return;
        throw fail('listing', e);
      }
      for (const ent of entries) {
        if (ent.name.startsWith('.')) continue;
        const key = rel ? `${rel}/${ent.name}` : ent.name;
        if (key === 'locks') continue;
        if (ent.isDirectory()) {
          if (key.startsWith(prefix) || prefix.startsWith(`${key}/`)) await walk(key);
        } else if (ent.isFile() && key.startsWith(prefix)) {
          out.push(key);
        }
      }
    };
    await walk(startRel);
    return out.sort();
  }

  async lock(name: string, opts: { timeoutMs?: number } = {}): Promise<() => Promise<void>> {
    checkLockName(name);
    const timeout = checkTimeout(opts.timeoutMs);
    const deadline = performance.now() + timeout;
    const base = await this.#base();
    const mkey = `${base}\u0000${name}`;
    let mutex = processMutexes.get(mkey);
    if (mutex === undefined) {
      mutex = new Mutex();
      processMutexes.set(mkey, mutex);
    }
    if (!(await mutex.acquire(timeout))) throw lockTimeoutError(name);
    try {
      const release = await this.#acquireFile(base, name, deadline);
      let released = false;
      const m = mutex;
      return async () => {
        if (released) return;
        released = true;
        try {
          await release();
        } finally {
          m.release();
        }
      };
    } catch (e) {
      mutex.release();
      throw e;
    }
  }

  async #acquireFile(base: string, name: string, deadline: number): Promise<() => Promise<void>> {
    const dir = join(base, 'locks');
    const path = join(dir, `${name}.lock`);
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    } catch (e) {
      throw fail('creating the locks directory', e);
    }
    const st = await fs.lstat(dir);
    if (!st.isDirectory()) throw new ACEError('storage_failed', 'locks path is not a directory');
    let fh;
    try { fh = await fs.open(path, fsc.O_CREAT | fsc.O_RDWR | fsc.O_NOFOLLOW | fsc.O_NONBLOCK, 0o600); }
    catch (e) { throw fail('opening a lock', e); }
    try {
      if (!(await fh.stat()).isFile()) throw new ACEError('storage_failed', 'lock is not a regular file');
      // Optional native dependency is loaded only for FileStore locking. No unsafe fallback.
      const native = await import('fs-ext');
      const flock = (flags: 'exnb'): Promise<void> => new Promise((resolve, reject) => {
        native.flock(fh.fd, flags, e => e ? reject(e) : resolve());
      });
      for (;;) {
        try { await flock('exnb'); break; }
        catch (e) {
          if (!['EAGAIN', 'EWOULDBLOCK', 'EINTR'].includes(errno(e) ?? '')) throw e;
          if (performance.now() >= deadline) throw lockTimeoutError(name);
          await sleep(Math.min(LOCK_POLL_MS, Math.max(1, deadline - performance.now())));
        }
      }
      // Closing the open description releases flock. Keep its inode forever.
      return async () => { try { await fh.close(); } catch (e) { throw fail('releasing a lock', e); } };
    } catch (e) {
      await fh.close(); throw fail('acquiring a lock', e);
    }
  }
}

async function syncDir(dir: string): Promise<void> {
  let fh;
  try {
    fh = await fs.open(dir, fsc.O_RDONLY);
    await fh.sync();
  } catch (e) {
    // Some platforms refuse fsync on directories; the rename itself is still atomic.
    if (errno(e) !== 'EINVAL' && errno(e) !== 'EISDIR' && errno(e) !== 'EPERM') throw e;
  } finally {
    await fh?.close();
  }
}

/** Load the source-built, packaged WASM core. Missing artifacts are a hard error; never downgrade. */
export async function loadMLSEngine(): Promise<import('./session.js').MLSEngine & { free(): void }> {
  const url = new URL('./session-core/ace_session_core.js', import.meta.url);
  const core = await import(url.href);
  await core.default({ module_or_path: await fs.readFile(new URL('./session-core/ace_session_core_bg.wasm', import.meta.url)) });
  return new core.SessionEngine();
}
