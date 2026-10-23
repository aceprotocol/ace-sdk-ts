/**
 * The sender side. Each entry stores `{messageId, to, privateContent, createdAt}` plus attempt state. Every attempt
 * re-encrypts the stored content to the peer's current prekey and re-signs it with the current time (the messageId
 * never changes); every attempt after the first refreshes the descriptor and lets the transport add `admission`
 * (05 § Admission recovery). Retries back off 60 s · 2^(n-1) up to 3600 s until a receipt arrives or OFFLINE_WINDOW_SECONDS
 * have passed since the first attempt (`expired`). A relay `{ok:true}` is not delivery. `expired` (also set by
 * `abandon`) only means attempts stopped: the outcome is unknown and a late receipt still settles the entry. Receipts and
 * contact packets never enter the Outbox.
 *
 * Profile rules (08 § Profile rules): `check` runs at enqueue, `commit` only when the `delivered` receipt arrives. While
 * a rule-governed entry is pending for `(to, threadId)`, enqueueing another rule-governed message on that thread fails
 * `thread_busy`; a `rejected` receipt, expiry or abandonment releases the thread without any state change.
 */
import type { ReceiptBody } from './core-messages.js';
import { ACEError, asACEError } from './errors.js';
import { canonicalStateBytes, isACEId, isMessageId, isObj, nowOf, pairKey, parseStateBytes, sha256Hex, wireInt } from './encoding.js';
import type { ACEIdentity } from './identity.js';
import { OFFLINE_WINDOW_SECONDS, OUTBOX_FIRST_RETRY_SECONDS, OUTBOX_MAX_RETRY_SECONDS } from './limits.js';
import { CONTACT_TYPE, RECEIPT_TYPE, type ProfileSet } from './manifest.js';
import { encodePrivateContent } from './packet.js';
import { checkRules, commitRules, ruleEvent, rulesFor, type ProfileRules } from './rules.js';
import { withLock, type ACEStore } from './store.js';
import type { JSONObject, PrivateContent } from './types.js';

export type OutboxStatus = 'pending' | 'delivered' | 'rejected' | 'expired';

export interface OutboxEntry {
  messageId: string;
  to: string;
  content: PrivateContent;
  createdAt: number;
  status: OutboxStatus;
  attempts: number;
  firstAttemptAt: number | null;
  nextAttemptAt: number;
  /** The prekey ID the last attempt encrypted to. */
  lastPrekey?: string;
  /** Set by `rejected:unknown_prekey`: refresh the descriptor; final if the peer still publishes this prekey. */
  rejectedPrekey?: string;
  /** Receipt code (`rejected`) or the last attempt's error code (`pending`). */
  code?: string;
  /** Another attempt holds the entry until then (Unix seconds). */
  inFlightUntil?: number;
  /** When the entry became `expired` (set exactly while it is `expired`; local state). */
  expiredAt?: number;
  /** When a receipt made it `delivered` or `rejected` (local state; `prune` keeps it OFFLINE_WINDOW_SECONDS). */
  settledAt?: number;
}

/** One attempt: encrypt to the current prekey, sign, post. Returns the prekey ID used. */
export type OutboxTransport = (attempt: {
  messageId: string; to: string; content: PrivateContent;
  /**
   * Refresh the peer's descriptor first (every retry: the peer may have lost its prekeys with its state, 06 § Outbox
   * step 1); throw `unknown_prekey` if its current prekey is still `avoidPrekey`.
   */
  refresh: boolean; avoidPrekey?: string;
  /**
   * An attempt after the first: the transport adds `admission` to this attempt's content when it holds `to` as
   * `admitted` (05 § Admission recovery). The stored content never carries it.
   */
  retry: boolean;
}) => Promise<{ prekey: string }>;

export interface OutboxOptions {
  identity: ACEIdentity;
  store: ACEStore;
  profiles: ProfileSet;
  transport: OutboxTransport;
  rules?: ProfileRules[];
  /**
   * Ensure a descriptor for `to` is held or can be resolved; called by `enqueue` before anything is stored. A
   * permanent failure makes `enqueue` fail with `unknown_peer`; a transient one is rethrown.
   */
  resolvePeer?: (to: string) => Promise<void>;
  clock?: () => number;
}

const IN_FLIGHT_SECONDS = 120;
const key = (messageId: string) => `outbox/${sha256Hex(messageId)}.json`;
/** The thread lock of a rule-governed pending entry: `{messageId}` (validated against the entry when read). */
const threadKey = (to: string, threadId: string) => `outbox-threads/${pairKey(to, threadId)}.json`;
const retryDelay = (attempts: number) => Math.min(OUTBOX_FIRST_RETRY_SECONDS * 2 ** Math.max(0, attempts - 1), OUTBOX_MAX_RETRY_SECONDS);

const STATUSES: ReadonlySet<unknown> = new Set(['pending', 'delivered', 'rejected', 'expired']);
const optInt = (v: unknown) => v === undefined || wireInt(v) !== null;
const optStr = (v: unknown) => v === undefined || typeof v === 'string';

/** Stop attempting `e`: `expired` at `now` (outcome unknown; a late receipt still settles it). */
function expire(e: OutboxEntry, now: number): OutboxEntry {
  const x: OutboxEntry = { ...e, status: 'expired', code: 'expired', expiredAt: now };
  delete x.inFlightUntil;
  return x;
}

/** A persisted entry, validated: a corrupt entry is `storage_failed`, never silently skipped or treated as absent. */
function checkEntry(v: unknown, k: string): OutboxEntry {
  const ok = isObj(v) && isMessageId(v.messageId) && key(v.messageId) === k && isACEId(v.to) && STATUSES.has(v.status)
    && isObj(v.content) && typeof v.content.type === 'string' && typeof v.content.schemaDigest === 'string' && isObj(v.content.body)
    && wireInt(v.createdAt) !== null && wireInt(v.attempts) !== null && wireInt(v.nextAttemptAt) !== null
    && (v.firstAttemptAt === null || wireInt(v.firstAttemptAt) !== null) && optInt(v.inFlightUntil)
    && optStr(v.lastPrekey) && optStr(v.rejectedPrekey) && optStr(v.code)
    && (v.status === 'expired' ? wireInt(v.expiredAt) !== null : v.expiredAt === undefined) && optInt(v.settledAt);
  if (!ok) throw new ACEError('storage_failed', `${k} is not a valid outbox entry`);
  return v as unknown as OutboxEntry;
}

export class Outbox {
  readonly #o: OutboxOptions;
  readonly #rules: ProfileRules[];
  readonly #inFlight = new Set<string>();
  constructor(o: OutboxOptions) { this.#o = o; this.#rules = o.rules ?? []; }

  #now(): number { return nowOf(this.#o.clock); }

  async get(messageId: string): Promise<OutboxEntry | null> {
    const raw = await this.#o.store.read(key(messageId));
    return raw === null ? null : checkEntry(parseStateBytes(raw, 'outbox entry'), key(messageId));
  }

  async list(status?: OutboxStatus): Promise<OutboxEntry[]> {
    const keys = await this.#o.store.list('outbox/');
    const raws = await Promise.all(keys.map((k) => this.#o.store.read(k)));
    const out: OutboxEntry[] = [];
    keys.forEach((k, i) => {
      const raw = raws[i];
      if (raw === null) return;
      const e = checkEntry(parseStateBytes(raw, k), k);
      if (status === undefined || e.status === status) out.push(e);
    });
    return out.sort((a, b) => a.createdAt - b.createdAt || (a.messageId < b.messageId ? -1 : 1));
  }

  async #write(e: OutboxEntry): Promise<void> {
    await this.#o.store.write(key(e.messageId), canonicalStateBytes(e));
    if (e.status !== 'pending') await this.#release(e);
  }

  #governed(e: Pick<OutboxEntry, 'content'>): e is { content: PrivateContent & { threadId: string } } {
    return e.content.threadId !== undefined && rulesFor(this.#rules, e.content.type).length > 0;
  }

  /** Free the thread an entry held (only if it still names this entry). */
  async #release(e: OutboxEntry): Promise<void> {
    if (!this.#governed(e)) return;
    const k = threadKey(e.to, e.content.threadId), raw = await this.#o.store.read(k);
    if (raw !== null && (parseStateBytes(raw, k) as { messageId?: unknown }).messageId === e.messageId) await this.#o.store.delete(k);
  }

  /**
   * The messageId of the rule-governed message in flight to `peer` on `threadId`, or null. While it is set, enqueueing
   * another rule-governed message on that thread fails `thread_busy`, and the Inbox rejects the peer's rule-governed
   * messages on it with `thread_busy`.
   */
  async busy(peer: string, threadId: string): Promise<string | null> {
    const k = threadKey(peer, threadId), raw = await this.#o.store.read(k);
    if (raw === null) return null;
    const v = parseStateBytes(raw, k) as { messageId?: unknown };
    if (!isMessageId(v.messageId)) throw new ACEError('storage_failed', `${k} is not a valid thread lock`);
    const e = await this.get(v.messageId);
    return e !== null && e.status === 'pending' && e.to === peer && e.content.threadId === threadId ? e.messageId : null;
  }

  /**
   * Validate (installed type, body schema, a resolvable descriptor for `to`, a free thread, profile rules `check`), then
   * persist the entry. Nothing is sent here: call `attempt` or `flush`. The rules' `commit` runs on the `delivered`
   * receipt.
   */
  async enqueue(m: { to: string; type: string; body: JSONObject; threadId?: string; messageId?: string }): Promise<OutboxEntry> {
    const from = this.#o.identity.getACEId();
    if (!isACEId(m.to) || m.to === from) throw new ACEError('invalid_argument', 'to must be another ACE ID');
    if (m.type === RECEIPT_TYPE || m.type === CONTACT_TYPE) throw new ACEError('invalid_argument', 'receipts and contact packets are never queued in the Outbox');
    const messageId = m.messageId ?? crypto.randomUUID();
    if (!isMessageId(messageId)) throw new ACEError('invalid_argument', 'messageId must be a lowercase UUIDv4');
    const schemaDigest = this.#o.profiles.digestOf(m.type);
    if (schemaDigest === undefined) throw new ACEError('unsupported_schema', `${m.type.slice(0, 64)} is not installed`);
    const content: PrivateContent = { type: m.type, schemaDigest, ...(m.threadId !== undefined ? { threadId: m.threadId } : {}), body: structuredClone(m.body) };
    encodePrivateContent(content);
    this.#o.profiles.validate(content.type, schemaDigest, content.body);
    const now = this.#now();
    const event = ruleEvent('send', { from, to: m.to, messageId, timestamp: now, type: m.type, threadId: m.threadId });
    if (this.#o.resolvePeer !== undefined) {
      try {
        await this.#o.resolvePeer(m.to);
      } catch (e) {
        const err = asACEError(e, 'relay_unavailable');
        if (err.isTransient) throw err;
        throw new ACEError('unknown_peer', 'no descriptor can be resolved for the recipient', { cause: err });
      }
    }
    return withLock(this.#o.store, 'outbox', async () => {
      if (await this.get(messageId) !== null) throw new ACEError('invalid_argument', 'messageId already queued');
      const entry: OutboxEntry = { messageId, to: m.to, content, createdAt: now, status: 'pending', attempts: 0, firstAttemptAt: null, nextAttemptAt: now };
      const thread = this.#governed(entry);
      if (thread && await this.busy(m.to, m.threadId!) !== null) throw new ACEError('thread_busy', 'a message on this thread is awaiting its receipt');
      await checkRules(this.#rules, event, content.body);
      // Thread lock first: a crash before the entry is written leaves a lock that `busy` reads as free.
      if (thread) await this.#o.store.write(threadKey(m.to, m.threadId!), canonicalStateBytes({ messageId }));
      await this.#write(entry);
      return entry;
    });
  }

  /**
   * One attempt for a pending entry (skipped while another attempt holds it). Returns the updated entry. A transport
   * failure reschedules; only expiry, a receipt or a content error ends the entry.
   */
  async attempt(messageId: string): Promise<OutboxEntry | null> {
    if (this.#inFlight.has(messageId)) return this.get(messageId);
    this.#inFlight.add(messageId);
    try {
      const claimed = await withLock(this.#o.store, 'outbox', async () => {
        const e = await this.get(messageId);
        const now = this.#now();
        if (e === null || e.status !== 'pending' || (e.inFlightUntil !== undefined && e.inFlightUntil > now)) return { e, go: false };
        if (e.firstAttemptAt !== null && now - e.firstAttemptAt > OFFLINE_WINDOW_SECONDS) {
          const expired = expire(e, now);
          await this.#write(expired);
          return { e: expired, go: false };
        }
        const held = { ...e, inFlightUntil: now + IN_FLIGHT_SECONDS };
        await this.#write(held);
        return { e: held, go: true };
      });
      if (!claimed.go || claimed.e === null) return claimed.e;
      const e = claimed.e;
      let prekey: string | undefined, error: ACEError | undefined;
      try {
        const retry = e.attempts > 0;
        ({ prekey } = await this.#o.transport({
          messageId, to: e.to, content: e.content, refresh: retry || e.rejectedPrekey !== undefined, retry,
          ...(e.rejectedPrekey !== undefined ? { avoidPrekey: e.rejectedPrekey } : {}),
        }));
      } catch (err) {
        error = asACEError(err, 'relay_unavailable');
      }
      return await withLock(this.#o.store, 'outbox', async () => {
        const cur = await this.get(messageId);
        if (cur === null) throw new ACEError('storage_failed', 'outbox entry vanished during an attempt');
        const now = this.#now();
        const next: OutboxEntry = { ...cur };
        delete next.inFlightUntil;
        if (cur.status !== 'pending') { await this.#write(next); return next; } // a receipt arrived meanwhile
        next.attempts = cur.attempts + 1;
        next.firstAttemptAt = cur.firstAttemptAt ?? now;
        if (cur.rejectedPrekey !== undefined && e.rejectedPrekey === undefined) {
          // A rejected:unknown_prekey receipt arrived while this attempt was in flight: merge, never overwrite it
          // (keep the rejected prekey, its code and the immediate retry).
          if (error === undefined) next.lastPrekey = prekey;
          await this.#write(next);
          return next;
        }
        if (error === undefined) {
          next.lastPrekey = prekey;
          delete next.rejectedPrekey;
          delete next.code;
        } else if (error.code === 'unknown_prekey' || error.code === 'invalid_argument' || error.code === 'invalid_body') {
          next.status = 'rejected';
          next.code = error.code;
          next.settledAt = now;
        } else {
          next.code = error.code;
        }
        const wait = Math.max(retryDelay(next.attempts), error?.retryAfterSeconds ?? 0);
        next.nextAttemptAt = now + Math.min(wait, OUTBOX_MAX_RETRY_SECONDS);
        await this.#write(next);
        return next;
      });
    } finally {
      this.#inFlight.delete(messageId);
    }
  }

  /** Attempt every pending entry that is due. */
  async flush(): Promise<OutboxEntry[]> {
    const now = this.#now(), out: OutboxEntry[] = [];
    for (const e of await this.list('pending')) {
      if (e.nextAttemptAt <= now) {
        const r = await this.attempt(e.messageId);
        if (r !== null) out.push(r);
      }
    }
    return out;
  }

  /**
   * Apply a receipt from `from` to a pending or expired entry (a late receipt settles an expired one); otherwise it is
   * ignored. `rejected:unknown_prekey` keeps a pending entry pending (refresh the descriptor and retry now) unless the
   * prekey used is still current, which the next attempt detects; for an expired entry it is ignored.
   */
  async onReceipt(from: string, body: ReceiptBody): Promise<OutboxEntry | null> {
    return withLock(this.#o.store, 'outbox', async () => {
      const e = await this.get(body.messageId);
      if (e === null || e.to !== from || (e.status !== 'pending' && e.status !== 'expired')) return null;
      if (e.status === 'expired' && body.outcome !== 'delivered' && body.code === 'unknown_prekey') return null;
      const next: OutboxEntry = { ...e };
      delete next.expiredAt;
      if (body.outcome === 'delivered') {
        // Commit the send-side rules now. A transient failure leaves the entry unchanged, so the receipt is processed
        // again; a permanent one cannot undo the receiver's delivery and is not retried.
        const c = e.content;
        try {
          await commitRules(this.#rules, ruleEvent('send', { from: this.#o.identity.getACEId(), to: e.to, messageId: e.messageId, timestamp: e.createdAt, type: c.type, threadId: c.threadId }), c.body);
        } catch (err) {
          if (asACEError(err).isTransient) throw err;
        }
        next.status = 'delivered';
        next.settledAt = this.#now();
        delete next.code;
      } else if (body.code === 'unknown_prekey') {
        // Counted only for the latest attempt's prekey, and once (06 § Outbox): a late or replayed receipt is ignored.
        if (body.prekey === undefined || body.prekey !== e.lastPrekey || e.rejectedPrekey === body.prekey) return null;
        next.rejectedPrekey = e.lastPrekey;
        next.nextAttemptAt = this.#now();
        next.code = 'unknown_prekey';
      } else {
        next.status = 'rejected';
        next.settledAt = this.#now();
        next.code = body.code ?? 'delivery_rejected';
      }
      await this.#write(next);
      return next;
    });
  }

  /** Stop attempting an entry locally: it becomes `expired` (outcome unknown; a late receipt still settles it). */
  async abandon(messageId: string): Promise<void> {
    await withLock(this.#o.store, 'outbox', async () => {
      const e = await this.get(messageId);
      if (e !== null && e.status === 'pending') await this.#write(expire(e, this.#now()));
    });
  }

  /**
   * Delete `delivered` and `rejected` entries OFFLINE_WINDOW_SECONDS after they settled, and `expired` ones
   * OFFLINE_WINDOW_SECONDS (the relay's retention: no receipt can arrive any more) after they expired, so `get` and
   * `list` report an outcome for that long. Returns the number deleted.
   */
  async prune(): Promise<number> {
    return withLock(this.#o.store, 'outbox', async () => {
      const now = this.#now();
      let n = 0;
      for (const e of await this.list()) {
        const doneAt = e.status === 'expired' ? e.expiredAt : e.settledAt;
        if (e.status !== 'pending' && now - (doneAt ?? 0) >= OFFLINE_WINDOW_SECONDS) {
          await this.#o.store.delete(key(e.messageId));
          n++;
        }
      }
      return n;
    });
  }
}
