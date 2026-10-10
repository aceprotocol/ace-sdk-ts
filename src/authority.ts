/** All executors for a resource must reach the SAME durable authority state. */
import { ACEError } from './errors.js';
import { intentDigest } from './intent.js';
import { canonicalStateBytes, nowOf, isACEId, isConversationId, hasExactKeys, isMessageId, isObj, sha256Hex, toBase64, wireInt } from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { isMessageType, type JSONObject } from './types.js';
import type { CoordinatedStore, StoreData } from './store.js';
import { executionIntentDigest, isExecutionUnits, verifyExecutionGrantChain, type ExecutionGrant, type ExecutionIntent } from './grants.js';

/** Profile-defined dimensions (for example canonical asset IDs), in exact integer base units. */
export type ResourceUsage = Readonly<Record<string, string>>;
export interface AuthorityConfig {
  resource: string; authority: VerifiedPeer; executor: string; schemaDigest: string; actions: readonly string[];
  /** Installed deterministic profile: validate every effect field and return ALL worst-case costs. No effects or I/O. */
  validateIntent: (intent: Readonly<ExecutionIntent>) => ResourceUsage;
  clock?: () => number;
}
export interface ExecutionReservation { operationId: string; intentDigest: string; status: 'reserved' | 'existing' }
interface Entry { digest: string; sender: string; charges: ResourceUsage; released: boolean }
interface State { version: 1; configDigest: string; epoch: number; remaining: ResourceUsage; revoked: string[]; reserved: number }
interface Pending { previous: State; next: State; operationId: string; entry: Entry }
const bad = (s: string) => new ACEError('invalid_authorization', s);
const corrupt = () => new ACEError('storage_failed', 'authority state unavailable or corrupt');
const namespaced = (s: unknown): s is string => typeof s === 'string' && s.includes(':') && isMessageType(s);
function usage(value: unknown): asserts value is ResourceUsage {
  if (!isObj(value) || Object.keys(value).length < 1 || Object.keys(value).length > 32
    || !Object.entries(value).every(([k, v]) => namespaced(k) && isExecutionUnits(v))) throw bad('invalid resource accounting');
}
const same = (a: unknown, b: unknown) => intentDigest(a as JSONObject) === intentDigest(b as JSONObject);
function decode(b: Uint8Array | null): unknown {
  if (!b || b.length > 1_048_576) throw corrupt();
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b)); } catch { throw corrupt(); }
}
function subtract(budget: ResourceUsage, charges: ResourceUsage): ResourceUsage {
  const next = { ...budget };
  for (const [dimension, cost] of Object.entries(charges)) {
    if (!Object.hasOwn(next, dimension) || BigInt(cost) > BigInt(next[dimension])) throw bad('insufficient resource budget');
    next[dimension] = String(BigInt(next[dimension]) - BigInt(cost));
  }
  return next;
}

/**
 * Policy and all budget dimensions serialize with permanent operation IDs under one lock.
 * A write-ahead record recovers partial reservations. New reservations are durable before release.
 * Existing reservations, lost responses and crashes require reconciliation, never another effect or automatic refund.
 * FileStore is a local reference backend, not replicated storage or a defense against disk rollback.
 */
export class ExecutionAuthority {
  readonly #config: AuthorityConfig;
  readonly #store: CoordinatedStore;
  readonly #prefix: string;
  readonly #configDigest: string;
  constructor(config: AuthorityConfig, store: CoordinatedStore) {
    if (!isVerifiedPeer(config.authority) || !isACEId(config.executor) || !namespaced(config.resource)
      || !isConversationId(config.schemaDigest) || !Array.isArray(config.actions) || config.actions.length < 1 || config.actions.length > 32
      || !config.actions.every(namespaced) || new Set(config.actions).size !== config.actions.length
      || typeof config.validateIntent !== 'function') throw bad('invalid authority configuration');
    this.#config = { ...config, actions: [...config.actions] }; this.#store = store;
    this.#prefix = `authority/${sha256Hex(config.resource)}/`;
    this.#configDigest = intentDigest({ resource: config.resource, authority: config.authority.aceId, executor: config.executor,
      scheme: config.authority.scheme, publicKey: toBase64(config.authority.signingPublicKey), schemaDigest: config.schemaDigest,
      actions: [...config.actions].sort() });
  }
  async #locked<T>(fn: (store: StoreData) => Promise<T>): Promise<T> {
    return this.#store.coordinate('execution-authority', fn);
  }
  #state(v: unknown): asserts v is State {
    if (!hasExactKeys(v, ['configDigest', 'epoch', 'remaining', 'reserved', 'revoked', 'version'])) throw corrupt();
    const s = v as State;
    if (s.version !== 1 || s.configDigest !== this.#configDigest || wireInt(s.epoch) === null || wireInt(s.reserved) === null
      || !Array.isArray(s.revoked) || s.revoked.length > 10_000 || !s.revoked.every(isMessageId)
      || new Set(s.revoked).size !== s.revoked.length) throw corrupt();
    try { usage(s.remaining); } catch { throw corrupt(); }
  }
  #entry(v: unknown): asserts v is Entry {
    if (!hasExactKeys(v, ['charges', 'digest', 'released', 'sender'])) throw corrupt();
    const e = v as Entry;
    if (!isConversationId(e.digest) || !isACEId(e.sender) || typeof e.released !== 'boolean') throw corrupt();
    try { usage(e.charges); } catch { throw corrupt(); }
  }
  async #head(store: StoreData): Promise<State> {
    const s = decode(await store.read(this.#prefix + 'head')); this.#state(s); return s;
  }
  async #put(store: StoreData, key: string, v: unknown): Promise<void> { await store.write(this.#prefix + key, canonicalStateBytes(v)); }
  async #operation(store: StoreData, id: string): Promise<Entry | null> {
    const b = await store.read(this.#prefix + `operations/${id}`);
    if (!b) return null;
    const e = decode(b); this.#entry(e); return e;
  }
  /**
   * Apply a write-ahead record. A recovered record is untrusted and fully re-checked; `fresh` is set only by
   * `reserve`, which built it in this lock from the head it just recovered and an operation ID it found unbound.
   */
  async #commit(store: StoreData, p: Pending, fresh = false): Promise<void> {
    try {
      let old: Entry | null = null;
      if (!fresh) {
        if (!hasExactKeys(p, ['entry', 'next', 'operationId', 'previous']) || !isMessageId(p.operationId)) throw corrupt();
        this.#state(p.previous); this.#state(p.next); this.#entry(p.entry);
        if (p.entry.released) throw corrupt();
        const expected = { ...p.previous, reserved: p.previous.reserved + 1, remaining: subtract(p.previous.remaining, p.entry.charges) };
        if (!same(expected, p.next)) throw corrupt();
        const head = await this.#head(store);
        if (!same(head, p.previous) && !same(head, p.next)) throw corrupt();
        old = await this.#operation(store, p.operationId);
        if (old && !same(old, p.entry)) throw corrupt();
      }
      if (!old) await this.#put(store, `operations/${p.operationId}`, p.entry);
      await this.#put(store, 'head', p.next);
      await store.delete(this.#prefix + 'pending');
    } catch (e) {
      if (e instanceof ACEError && e.code === 'invalid_authorization') throw corrupt();
      throw e;
    }
  }
  async #recover(store: StoreData): Promise<State> {
    const p = await store.read(this.#prefix + 'pending');
    if (p) await this.#commit(store, decode(p) as Pending);
    return this.#head(store);
  }
  /** Trusted local provisioning only; ordinary requests never reset missing state. */
  async provision(epoch: number, budget: ResourceUsage): Promise<void> {
    if (wireInt(epoch) === null) throw bad('invalid initial policy'); usage(budget);
    const remaining = { ...budget };
    await this.#locked(async (store) => {
      if ((await store.list(this.#prefix)).length) throw bad('authority already provisioned');
      await this.#put(store, 'head', { version: 1, configDigest: this.#configDigest, epoch, remaining, revoked: [], reserved: 0 });
    });
  }
  /** Trusted administrator API. Epochs increase, retaining every budget and operation binding. */
  async advanceEpoch(epoch: number): Promise<void> {
    await this.#locked(async (store) => {
      const s = await this.#recover(store);
      if (wireInt(epoch) === null || epoch <= s.epoch) throw bad('epoch must increase');
      s.epoch = epoch; s.revoked = []; await this.#put(store, 'head', s);
    });
  }
  async revoke(grantId: string): Promise<void> {
    if (!isMessageId(grantId)) throw bad('invalid grant ID');
    await this.#locked(async (store) => {
      const s = await this.#recover(store);
      if (s.revoked.includes(grantId)) return;
      if (s.revoked.length >= 10_000) throw bad('revocation capacity reached; advance epoch');
      s.revoked.push(grantId); await this.#put(store, 'head', s);
    });
  }
  #now(): number { return nowOf(this.#config.clock); }
  /** Shape-checks and deep-copies caller input so later caller mutation cannot reach the locked section. */
  static #input(chain: readonly ExecutionGrant[], intent: ExecutionIntent): { chain: ExecutionGrant[]; intent: ExecutionIntent } {
    if (!Array.isArray(chain) || chain.length < 1 || chain.length > 8) throw bad('invalid grant chain length');
    executionIntentDigest(intent);
    return JSON.parse(JSON.stringify({ chain, intent }));
  }
  /** The intent digest, once the chain authorizes `sender` under the current policy state `s`. */
  #verify(s: State, input: { chain: ExecutionGrant[]; intent: ExecutionIntent }, sender: string): string {
    const c = this.#config;
    return verifyExecutionGrantChain(input.chain, input.intent, sender, c.executor,
      { resource: c.resource, authority: c.authority, epoch: s.epoch, revoked: s.revoked }, this.#now());
  }
  async reserve(chain: readonly ExecutionGrant[], intent: ExecutionIntent, authenticatedSender: string): Promise<ExecutionReservation> {
    const input = ExecutionAuthority.#input(chain, intent), i = input.intent;
    return this.#locked(async (store) => {
      const s = await this.#recover(store), c = this.#config;
      const hash = this.#verify(s, input, authenticatedSender);
      if (i.schemaDigest !== c.schemaDigest || !c.actions.includes(i.action)) throw bad('unsupported execution profile');
      const validation: unknown = c.validateIntent(i);
      if (isObj(validation) && typeof validation.then === 'function') {
        void Promise.resolve(validation).catch(() => undefined);
        throw bad('profile validator must finish synchronously');
      }
      usage(validation);
      if (executionIntentDigest(i) !== hash) throw bad('profile validator mutated intent');
      const charges = { ...validation }, old = await this.#operation(store, i.operationId);
      if (old) {
        if (old.digest !== hash || old.sender !== authenticatedSender || !same(old.charges, charges)) throw bad('operation ID already bound');
        return { operationId: i.operationId, intentDigest: hash, status: 'existing' };
      }
      if (s.reserved === Number.MAX_SAFE_INTEGER) throw bad('authority operation limit reached');
      const next = { ...s, reserved: s.reserved + 1, remaining: subtract(s.remaining, charges) };
      const pending = { previous: s, next, operationId: i.operationId, entry: { digest: hash, sender: authenticatedSender, charges, released: false } };
      await this.#put(store, 'pending', pending); await this.#commit(store, pending, true);
      return { operationId: i.operationId, intentDigest: hash, status: 'reserved' };
    });
  }
  /**
   * Executor-local gate immediately before releasing a signature/effect. Never expose as an RPC permit.
   * Rechecks current policy, then permanently consumes the release before returning. A lost acknowledgement
   * is unresolved; no caller may release again. Budgets are never automatically refunded.
   */
  async release(chain: readonly ExecutionGrant[], intent: ExecutionIntent, authenticatedSender: string): Promise<void> {
    const input = ExecutionAuthority.#input(chain, intent), i = input.intent;
    await this.#locked(async (store) => {
      const s = await this.#recover(store);
      const hash = this.#verify(s, input, authenticatedSender);
      const old = await this.#operation(store, i.operationId);
      if (!old || old.digest !== hash || old.sender !== authenticatedSender || old.released) throw bad('operation unavailable or already released');
      await this.#put(store, `operations/${i.operationId}`, { ...old, released: true });
    });
    // Durable writes and lock release may wait on a remote quorum. Never return a live permit
    // after that wait crossed the absolute deadline; the consumed release is intentionally retained.
    if (this.#now() >= input.intent.expiresAt) throw bad('intent expired during release');
  }
  /** Read an existing binding even after expiry/revocation. This never grants permission to execute. */
  async hasReservation(intent: ExecutionIntent, authenticatedSender: string): Promise<boolean> {
    const hash = executionIntentDigest(intent), id = intent.operationId;
    if (!isACEId(authenticatedSender) || intent.resource !== this.#config.resource || intent.audience !== this.#config.executor) throw bad('invalid operation lookup');
    return this.#locked(async (store) => {
      await this.#recover(store);
      const old = await this.#operation(store, id);
      if (old && (old.digest !== hash || old.sender !== authenticatedSender)) throw bad('operation ID already bound');
      return old !== null;
    });
  }
  /** Private administrative inspection, not an execution permit. */
  async inspect(): Promise<{ epoch: number; remaining: ResourceUsage; reserved: number }> {
    return this.#locked(async (store) => { const s = await this.#recover(store); return { epoch: s.epoch, remaining: s.remaining, reserved: s.reserved }; });
  }
}
