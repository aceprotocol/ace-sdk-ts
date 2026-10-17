/**
 * Node.js pieces: `FileStore(root)`, an `ACEStore` over a directory (directories 0700, files 0600, and any not owned by
 * this user or open to group/others refused as `storage_failed`; atomic writes via
 * temp file + fsync + rename + directory fsync; POSIX flock locks over permanent files on a local filesystem), and
 * `publicRelay(url)`, a RelayClient for peer-advertised relays with SSRF protection.
 */

import { constants as fsc, promises as fs } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import * as https from 'node:https';
import { promises as dns } from 'node:dns';
import { ACEError } from './errors.js';
import { isBlockedAddress, pinnedRequest } from './pinned-https.js';
import { MAX_PAGE_BYTES } from './limits.js';
import { DEFAULT_TIMEOUT_MS, RelayClient } from './relay.js';
import { isCanonicalRelayUrl } from './relay-url.js';
import { acquireMutex, checkKey, checkLockName, checkTimeout, checkValue, KEY_RE, lockTimeoutError, MAX_VALUE_BYTES, Mutex, withLock, type ACEStore, type StoreData } from './store.js';

const LOCK_POLL_MS = 50;
const processMutexes = new Map<string, Mutex>();

function fail(what: string, e: unknown): ACEError {
  if (e instanceof ACEError) return e;
  const code = errno(e) ?? '';
  return new ACEError('storage_failed', `${what} failed${code ? ` (${code})` : ''}`, { cause: e });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Fail closed: a store path must belong to this user and be closed to group and others (POSIX). The refusal names `path` and the fix. */
function checkPrivate(st: { uid: number; mode: number; isDirectory(): boolean }, path: string): void {
  const uid = process.getuid?.();
  if (uid === undefined) return; // no POSIX ownership (Windows)
  if (st.uid !== uid) throw new ACEError('storage_failed', `${path} is owned by another user (uid ${st.uid}); use a store root this user (uid ${uid}) owns`);
  if ((st.mode & 0o077) !== 0) {
    throw new ACEError('storage_failed', `${path} is accessible to group or others; run: chmod ${st.isDirectory() ? 700 : 600} ${path}`);
  }
}

function errno(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException)?.code;
}

type FsExt = typeof import('fs-ext');
let fsExt: Promise<FsExt> | null = null;

/**
 * FileStore's cross-process locks use POSIX flock from the optional native dependency `fs-ext` (there is no unsafe
 * fallback). It is optional so that browser/edge builds and MemoryStore users never compile a native addon; a FileStore
 * without it fails with this explicit `storage_failed` at the first lock.
 */
function loadFsExt(): Promise<FsExt> {
  fsExt ??= import('fs-ext').catch((cause: unknown) => {
    fsExt = null;
    throw new ACEError('storage_failed', 'FileStore locking needs the optional native dependency fs-ext; install it for this Node.js (npm install fs-ext / npm rebuild fs-ext)', { cause });
  });
  return fsExt;
}

export class FileStore implements ACEStore {
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
          checkPrivate(st, this.root);
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
        checkPrivate(st, dir);
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
      checkPrivate(st, path);
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
    if (startRel !== '' && !KEY_RE.test(startRel)) return [];
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
    const mutex = await acquireMutex(processMutexes, mkey, name, timeout);
    try {
      const release = await this.#acquireFile(base, name, deadline);
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        try {
          await release();
        } finally {
          mutex.release();
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
    checkPrivate(st, dir);
    let fh;
    try { fh = await fs.open(path, fsc.O_CREAT | fsc.O_RDWR | fsc.O_NOFOLLOW | fsc.O_NONBLOCK, 0o600); }
    catch (e) { throw fail('opening a lock', e); }
    try {
      const lst = await fh.stat();
      if (!lst.isFile()) throw new ACEError('storage_failed', 'lock is not a regular file');
      checkPrivate(lst, path);
      // Optional native dependency is loaded only for FileStore locking. No unsafe fallback.
      const native = await loadFsExt();
      const flock = (): Promise<void> => new Promise((resolve, reject) => {
        native.flock(fh.fd, 'exnb', e => e ? reject(e) : resolve());
      });
      for (;;) {
        try { await flock(); break; }
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

export interface PublicHttpsOptions {
  /** Only URLs of this origin are fetched (any https origin without it). */
  origin?: string;
  /** DNS and request timeout each (default the relay client timeout). */
  timeoutMs?: number;
  /** A larger body is refused (default the relay client limit). */
  maxResponseBytes?: number;
  /** The error for a network failure, timeout or oversized body (default `relay_unavailable`). */
  fail?: (message: string) => ACEError;
}

/**
 * A `fetch` for untrusted public HTTPS URLs: public DNS answers only (SSRF blocklist), a connection pinned to the
 * checked address, no redirects, no credentials, only `accept`, `content-type` and `x-ace-*` request headers, bounded
 * body. The outbound policy of `publicRelay`, reusable for other documents fetched on a remote party's word.
 */
export function publicHttpsFetch(o: PublicHttpsOptions = {}): typeof fetch {
  const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const limit = o.maxResponseBytes ?? MAX_PAGE_BYTES;
  const fail = o.fail ?? ((message: string) => new ACEError('relay_unavailable', message));
  return async (input, init) => {
    const target = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (target.protocol !== 'https:' || (o.origin !== undefined && target.origin !== o.origin) || target.username || target.password || target.hash) {
      throw new ACEError('invalid_argument', 'unexpected request origin');
    }
    const host = target.hostname.replace(/^\[|\]$/g, '');
    let timer: ReturnType<typeof setTimeout> | undefined;
    const answers = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(fail('DNS timeout')), Math.min(timeoutMs, 5000)); }),
    ]).finally(() => { if (timer) clearTimeout(timer); });
    if (!answers.length || answers.some(a => isBlockedAddress(a.address))) throw new ACEError('blocked_address', `${host} resolves to a blocked address`);
    const method = init?.method ?? 'GET';
    if (method !== 'GET' && method !== 'POST') throw new ACEError('invalid_argument', 'unsupported public HTTPS method');
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => { if (k === 'accept' || k === 'content-type' || k.startsWith('x-ace-')) headers[k] = v; });
    const body = init?.body == null ? undefined : new TextEncoder().encode(String(init.body));
    if (body) headers['content-length'] = String(body.length);
    if (init?.signal?.aborted) throw fail('request aborted');
    const response = await pinnedRequest(https, { host, addr: answers[0],
      port: Number(target.port || 443), path: target.pathname + target.search, method, headers, body,
      timeoutMs, limit: limit + 1, readBody: () => true, fail });
    const raw = await response.body();
    if (raw.length > limit) throw fail('response too large');
    return new Response(Buffer.from(raw), { status: response.status, headers: { 'content-type': response.contentType } });
  };
}

/**
 * A peer-advertised public relay: HTTPS, public DNS answers, pinned connection, no redirects or forwarded caller IP;
 * descriptors it returns are verified at `o.clock`. Only with `allowLoopbackRelays` (local development) is a loopback
 * `http://` relay reached directly.
 */
export function publicRelay(url: string, o: { clock?: () => number; allowLoopbackRelays?: boolean } = {}): RelayClient {
  const opts = { clock: o.clock, allowLoopbackRelays: o.allowLoopbackRelays };
  if (o.allowLoopbackRelays === true && url.startsWith('http://') && isCanonicalRelayUrl(url, { allowLoopback: true })) {
    return new RelayClient(url, opts);
  }
  const base = new URL(url);
  if (base.protocol !== 'https:') throw new ACEError('invalid_argument', 'foreign relays require HTTPS');
  return new RelayClient(url, { ...opts, fetch: publicHttpsFetch({ origin: base.origin }) });
}
