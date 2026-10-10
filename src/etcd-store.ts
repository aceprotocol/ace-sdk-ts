/** Private replicated state, never the public audit log. Requires a trusted etcd v3 quorum. */
import { randomBytes } from 'node:crypto';
import { ACEError } from './errors.js';
import { decodeB64, isObj, toBase64, utf8 } from './encoding.js';
import { readLimited } from './discovery.js';
import { checkKey, checkLockName, checkValue, DEFAULT_LOCK_TIMEOUT_MS, lockTimeoutError, MAX_VALUE_BYTES, Mutex, type CoordinatedStore, type StoreData } from './store.js';

export interface EtcdStoreOptions {
  /** One trusted HTTPS gateway/load balancer; plain HTTP is restricted to numeric loopback. */
  endpoint: string;
  namespace: string;
  /** Operator-pinned decimal cluster ID. Never discover or update this pin automatically. */
  clusterId: string;
  /** Local credential, not a message field. No automatic authentication or root credentials. */
  token?: string;
  timeoutMs?: number;
  /** No automatic renewal: an expired critical section fails its next fenced operation. */
  leaseSeconds?: number;
}
const fail = () => new ACEError('storage_failed', 'replicated store unavailable, changed or lock ownership lost');
const RESPONSE_LIMIT = Math.floor(MAX_VALUE_BYTES * 1.4 + 1_048_576);
const b64 = (v: string | Uint8Array) => toBase64(typeof v === 'string' ? utf8(v) : v);
const isU64Decimal = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,19}$/.test(v) && BigInt(v).toString() === v && BigInt(v) <= 18_446_744_073_709_551_615n;
function bytes(v: unknown): Uint8Array {
  if (v === undefined) return new Uint8Array(0); // protobuf omits empty bytes
  return decodeB64(v, 'storage_failed', 'replicated store bytes', MAX_VALUE_BYTES);
}
interface Held { key: string; value: string; lease: string }

/**
 * Every data operation is a linearizable etcd transaction comparing the scoped lock token.
 * A partitioned/stalled process cannot write after a new lease holder takes over. Any uncertain
 * RPC or fencing failure permanently poisons this instance; reconstruct it and reconcile durable
 * application state. Never retry an effect because a request/response or lock release was lost.
 * The quorum is authoritative: there is no local data cache, lock-file takeover or offline fallback.
 */
export class EtcdStore implements CoordinatedStore {
  readonly #options: Required<Omit<EtcdStoreOptions, 'token'>> & { token?: string };
  readonly #prefix: string;
  readonly #mutexes = new Map<string, Mutex>();
  #broken = false;
  constructor(options: EtcdStoreOptions) {
    let endpoint: URL;
    try { endpoint = new URL(options.endpoint); } catch { throw new ACEError('invalid_argument', 'invalid replicated store configuration'); }
    const timeoutMs = options.timeoutMs ?? 5000, leaseSeconds = options.leaseSeconds ?? 60;
    if ((endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(endpoint.hostname)))
      || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/'
      || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(options.namespace) || options.namespace.trim() !== options.namespace || !isU64Decimal(options.clusterId)
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000
      || !Number.isSafeInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 300
      || (options.token !== undefined && (typeof options.token !== 'string' || options.token.length < 1 || options.token.length > 4096 || /[^\x21-\x7e]/.test(options.token)))) {
      throw new ACEError('invalid_argument', 'invalid replicated store configuration');
    }
    this.#options = { ...options, endpoint: endpoint.origin, timeoutMs, leaseSeconds };
    this.#prefix = `/ace/${options.namespace}/data/`;
  }
  #assert(): void { if (this.#broken) throw fail(); }
  async #rpc(path: string, body: unknown): Promise<Record<string, unknown>> {
    this.#assert();
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), this.#options.timeoutMs);
    try {
      const response = await fetch(this.#options.endpoint + path, {
        method: 'POST', redirect: 'error', signal: controller.signal,
        headers: { 'content-type': 'application/json', ...(this.#options.token ? { authorization: this.#options.token } : {}) },
        body: JSON.stringify(body),
      });
      if (!response.ok || !response.body) throw fail();
      const raw = await readLimited(response, RESPONSE_LIMIT + 1);
      if (raw.length > RESPONSE_LIMIT) throw fail();
      const data: unknown = JSON.parse(Buffer.from(raw).toString('utf8'));
      if (!isObj(data) || !isObj(data.header) || data.header.cluster_id !== this.#options.clusterId || !isU64Decimal(data.header.revision)) throw fail();
      return data;
    } catch { this.#broken = true; throw fail(); } finally { clearTimeout(timer); }
  }
  #comparisons(held: Held): Record<string, string>[] {
    return [{ key: held.key, target: 'VALUE', result: 'EQUAL', value: held.value }];
  }
  async #txn(held: Held, op: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.#rpc('/v3/kv/txn', { compare: this.#comparisons(held), success: [op] });
    if (response.succeeded !== true || !Array.isArray(response.responses) || response.responses.length !== 1 || !isObj(response.responses[0])) {
      this.#broken = true; throw fail();
    }
    return response.responses[0];
  }
  async #read(held: Held, key: string): Promise<Uint8Array | null> {
    const encoded = b64(this.#prefix + checkKey(key));
    const { response_range: r } = await this.#txn(held, { request_range: { key: encoded, serializable: false } });
    if (!isObj(r) || (r.kvs !== undefined && !Array.isArray(r.kvs))) { this.#broken = true; throw fail(); }
    const rows = r.kvs as unknown[] | undefined;
    if (!rows?.length) return null;
    if (rows.length !== 1 || !isObj(rows[0]) || rows[0].key !== encoded) { this.#broken = true; throw fail(); }
    return bytes(rows[0].value);
  }
  async #write(held: Held, key: string, value: Uint8Array): Promise<void> {
    await this.#txn(held, { request_put: { key: b64(this.#prefix + checkKey(key)), value: b64(checkValue(value)) } });
  }
  async #delete(held: Held, key: string): Promise<void> {
    await this.#txn(held, { request_delete_range: { key: b64(this.#prefix + checkKey(key)) } });
  }
  async #list(held: Held, prefix: string): Promise<string[]> {
    if (typeof prefix !== 'string' || prefix.length > 200 || !/^[a-z0-9._/-]*$/.test(prefix)) throw new ACEError('invalid_argument', 'invalid store prefix');
    const first = Buffer.from(this.#prefix + prefix), end = Buffer.from(first); end[end.length - 1]++;
    let start = first, revision: string | undefined; const result: string[] = [];
    for (;;) {
      const { response_range: r } = await this.#txn(held, { request_range: { key: b64(start), range_end: b64(end), keys_only: true,
        limit: '1024', sort_order: 'ASCEND', sort_target: 'KEY', serializable: false, ...(revision ? { revision } : {}) } });
      if (!isObj(r) || !isObj(r.header) || !isU64Decimal(r.header.revision) || (r.kvs !== undefined && !Array.isArray(r.kvs))) throw fail();
      revision ??= r.header.revision;
      const rows = (r.kvs ?? []) as unknown[];
      if (rows.length > 1024 || (r.more === true && !rows.length)) throw fail();
      let last: Buffer | undefined;
      for (const row of rows) {
        if (!isObj(row)) throw fail(); const raw = Buffer.from(bytes(row.key)), key = raw.toString('utf8');
        if (!key.startsWith(this.#prefix + prefix) || raw.compare(start) < 0 || (last && raw.compare(last) <= 0)) throw fail();
        result.push(checkKey(key.slice(this.#prefix.length))); last = raw;
      }
      if (result.length > 100_000) throw new ACEError('storage_failed', 'replicated store listing exceeds limit');
      if (r.more !== true) return result;
      start = Buffer.concat([last!, Buffer.from([0])]);
    }
  }
  /** State coordination only. Long-lived Inbox locks and offline caches do not belong here. */
  async coordinate<T>(name: string, body: (data: StoreData) => Promise<T>): Promise<T> {
    checkLockName(name); this.#assert();
    const timeout = DEFAULT_LOCK_TIMEOUT_MS, started = performance.now();
    let mutex = this.#mutexes.get(name); if (!mutex) { mutex = new Mutex(); this.#mutexes.set(name, mutex); }
    if (!await mutex.acquire(timeout)) throw lockTimeoutError(name);
    let held: Held | undefined, active = false;
    try {
      const lease = await this.#rpc('/v3/lease/grant', { TTL: String(this.#options.leaseSeconds) });
      if (!isU64Decimal(lease.ID)) throw fail();
      const candidate: Held = { key: b64(`/ace/${this.#options.namespace}/locks/${name}`), value: b64(randomBytes(32)), lease: lease.ID };
      for (;;) {
        const r = await this.#rpc('/v3/kv/txn', { compare: [{ key: candidate.key, target: 'VERSION', result: 'EQUAL', version: '0' }],
          success: [{ request_put: { key: candidate.key, value: candidate.value, lease: candidate.lease } }] });
        if (r.succeeded === true) { held = candidate; break; }
        if (performance.now() - started >= timeout) throw lockTimeoutError(name);
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      active = true;
      const owned = held;
      const use = async <V>(fn: () => Promise<V>): Promise<V> => {
        if (!active) throw fail();
        try { return await fn(); } catch (error) {
          if (error instanceof ACEError && error.code === 'storage_failed') this.#broken = true;
          throw error;
        }
      };
      const view: StoreData = {
        read: key => use(() => this.#read(owned, key)),
        write: (key, value) => use(() => this.#write(owned, key, value)),
        delete: key => use(() => this.#delete(owned, key)),
        list: prefix => use(() => this.#list(owned, prefix)),
      };
      const result = await body(view); this.#assert(); return result;
    } finally {
      active = false;
      try {
        if (held && !this.#broken) {
          const r = await this.#rpc('/v3/kv/txn', { compare: this.#comparisons(held),
            success: [{ request_delete_range: { key: held.key } }] });
          if (r.succeeded !== true) { this.#broken = true; throw fail(); }
        }
      } finally { mutex.release(); }
    }
  }
}
