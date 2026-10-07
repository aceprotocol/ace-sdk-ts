/** The receive engine: verify, commit durably, hand over exactly once (06-security § Durable Delivery). */

import { ACEError, errorDetail } from './errors.js';
import {
  canonicalStateBytes, codePointLength, isACEId, isConversationId, isMessageId, isObj, isStreamId, isThreadId, pairKey,
  parseStateBytes, utf8, wireInt,
} from './encoding.js';
import { computeConversationId } from './encryption.js';
import { decodeEnvelope, envelopeFingerprint, envelopeKnownFields } from './envelope.js';
import {
  DEFAULT_REPLAY_CAPACITY, MAX_DIRECT_BODY_BYTES, MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE, OFFLINE_WINDOW_SECONDS, TIMESTAMP_WINDOW_SECONDS,
} from './limits.js';
import { eventOf, parseMessage } from './messages.js';
import type { PeerStore } from './peer-store.js';
import { compareStreamIds, normalizeRelayUrl, type RelayClient } from './relay.js';
import { ReplayDetector, replayCovers } from './replay.js';
import { ThreadStateMachine, type ThreadSnapshot } from './state-machine.js';
import { SerialQueue, type ACEStore } from './store.js';
import { compareHistories, restoreMachine, ThreadRecords, type ThreadRecord } from './thread-store.js';
import type { ACEIdentity, ACEMessage, JSONObject, ParsedMessage, ReplayState } from './types.js';
import { isEconomicType, isMessageType } from './types.js';

export type ReceiveSource = { kind: 'relay'; relayUrl: string; streamId?: string } | { kind: 'direct' };

export type ReceiveOutcome =
  | { kind: 'delivered'; message: ParsedMessage }
  | { kind: 'duplicate'; from: string; messageId: string }
  | { kind: 'quarantined'; error: ACEError; fingerprint: string | null }
  | { kind: 'retryable'; error: ACEError };

/**
 * The HTTP answer to a direct-delivery request (08-relay § Direct Delivery). `outcome` is set
 * when the `message` member reached the pipeline.
 */
export interface DirectReply {
  status: 200 | 400 | 413 | 503;
  body: { ok: true; messageId: string } | { ok: false; error: string };
  outcome?: ReceiveOutcome;
}

/**
 * The result of `Inbox.pull`: every non-retryable outcome in relay order, the error that
 * stopped the drain (a retryable outcome, a fetch error or an invalid argument), or null, and
 * `hasMore` when `maxPages` or an abort stopped it before the inbox was drained.
 */
export class PullResult {
  readonly outcomes: ReceiveOutcome[];
  readonly blocked: ACEError | null;
  /** `maxPages` or `signal` stopped the pull early; more entries may be waiting. */
  readonly hasMore: boolean;

  constructor(outcomes: ReceiveOutcome[], blocked: ACEError | null, hasMore = false) {
    this.outcomes = outcomes;
    this.blocked = blocked;
    this.hasMore = hasMore;
  }

  /** The delivered messages, in order. */
  get messages(): ParsedMessage[] {
    return this.outcomes.flatMap((o) => (o.kind === 'delivered' ? [o.message] : []));
  }

  get delivered(): number {
    return countKind(this.outcomes, 'delivered');
  }

  get duplicates(): number {
    return countKind(this.outcomes, 'duplicate');
  }

  get quarantined(): number {
    return countKind(this.outcomes, 'quarantined');
  }
}

function countKind(outcomes: ReceiveOutcome[], kind: ReceiveOutcome['kind']): number {
  return outcomes.reduce((n, o) => n + (o.kind === kind ? 1 : 0), 0);
}

export interface InboxOptions {
  identity: ACEIdentity;
  store: ACEStore;
  peers: PeerStore;
  /**
   * Persist the host effect durably, idempotently keyed by (from, messageId), then return.
   * Throwing means "retry later" (`handler_failed`).
   */
  onMessage: (m: ParsedMessage) => void | Promise<void>;
  capacity?: number;
  offlineWindowSeconds?: number;
  clock?: () => number;
}

interface DeliveryRecord {
  fingerprint: string;
  message: ParsedMessage;
  receivedAt: number;
  source: 'relay' | 'direct';
  status: 'pending' | 'acked';
  thread: ThreadSnapshot | null;
}

const REPLAY_KEY = 'replay.json';
const CURSORS_KEY = 'cursors.json';
const QUARANTINE_CAP = 1000;
const QUARANTINE_FLOOR = 900;
const SWEEP_EVERY = 1024;
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

function deliveryKey(from: string, messageId: string): string {
  return `deliveries/${pairKey(from, messageId)}.json`;
}

function asError(e: unknown, code: 'storage_failed' | 'identity_unavailable', msg: string): ACEError {
  return e instanceof ACEError ? e : new ACEError(code, msg, { cause: e });
}

function encodeSnapshot(s: ThreadSnapshot): Record<string, unknown> {
  return {
    conversationId: s.conversationId,
    history: s.history.map((h) => ({ from: h.from, messageId: h.messageId, timestamp: h.timestamp, type: h.type })),
    localAceId: s.localAceId,
    peerAceId: s.peerAceId,
    state: s.state,
    threadId: s.threadId,
  };
}

/**
 * Receives envelopes from a relay (pull / follow) or directly, verifies them, commits them
 * durably in the normative order and hands each message to `onMessage` exactly once (at least
 * once across a crash between hand-over and acknowledgement). One open Inbox per store
 * (lock `receive`).
 */
export class Inbox {
  readonly #identity: ACEIdentity;
  readonly #store: ACEStore;
  readonly #peers: PeerStore;
  readonly #threads: ThreadRecords;
  readonly #onMessage: (m: ParsedMessage) => void | Promise<void>;
  readonly #offline: number;
  readonly #clock?: () => number;
  readonly #queue = new SerialQueue();
  readonly #releaseReceive: () => Promise<void>;
  #replay: ReplayDetector;
  #cursors: Record<string, string>;
  #failed: ACEError | null = null;
  #heldThreads: (() => Promise<void>) | null = null;
  #closed = false;
  #sinceSweep = 0;
  /** `quarantine/` keys: listed once, then maintained (this instance holds `receive`). */
  #quarantined: Set<string> | null = null;

  private constructor(o: InboxOptions, release: () => Promise<void>, replay: ReplayDetector, cursors: Record<string, string>) {
    this.#identity = o.identity;
    this.#store = o.store;
    this.#peers = o.peers;
    this.#onMessage = o.onMessage;
    this.#offline = o.offlineWindowSeconds ?? OFFLINE_WINDOW_SECONDS;
    this.#clock = o.clock;
    this.#releaseReceive = release;
    this.#replay = replay;
    this.#cursors = cursors;
    this.#threads = new ThreadRecords({ store: o.store, localAceId: o.identity.getACEId(), clock: o.clock });
  }

  /** Acquire the `receive` lock, load state and run recovery. */
  static async open(o: InboxOptions): Promise<Inbox> {
    if (typeof o !== 'object' || o === null || typeof o.store !== 'object' || o.store === null
      || typeof o.peers !== 'object' || o.peers === null || typeof o.onMessage !== 'function') {
      throw new ACEError('invalid_argument', 'identity, store, peers and onMessage are required');
    }
    const local = o.identity.getACEId();
    if (!isACEId(local)) throw new ACEError('invalid_argument', 'identity has an invalid ACE ID');
    const offline = o.offlineWindowSeconds ?? OFFLINE_WINDOW_SECONDS;
    if (wireInt(offline) === null || offline < 300) throw new ACEError('invalid_argument', 'offlineWindowSeconds must be an integer >= 300');
    const capacity = o.capacity ?? DEFAULT_REPLAY_CAPACITY;
    if (wireInt(capacity) === null || capacity < 1) throw new ACEError('invalid_argument', 'capacity must be an integer >= 1');
    const release = await o.store.lock('receive', { timeoutMs: 0 });
    try {
      const now = Math.floor(o.clock ? o.clock() : Date.now() / 1000);
      const threads = new ThreadRecords({ store: o.store, localAceId: local, clock: o.clock });
      const replay = await Inbox.#loadReplay(o.store, threads, capacity, now, offline, o.clock);
      const cursors = await Inbox.#loadCursors(o.store);
      const inbox = new Inbox(o, release, replay, cursors);
      await inbox.#recover();
      return inbox;
    } catch (e) {
      await release().catch(() => {});
      throw e;
    }
  }

  static async #loadReplay(
    store: ACEStore, threads: ThreadRecords, capacity: number, now: number, offline: number, clock?: () => number,
  ): Promise<ReplayDetector> {
    const raw = await store.read(REPLAY_KEY);
    if (raw !== null) {
      const doc = parseStateBytes(raw, REPLAY_KEY);
      if (typeof doc !== 'object' || doc === null || (doc as { version?: unknown }).version !== 1) {
        throw new ACEError('storage_failed', 'replay.json: unknown version');
      }
      try {
        return ReplayDetector.fromState(doc as ReplayState, { capacity, clock });
      } catch (e) {
        throw new ACEError('storage_failed', `replay.json is invalid (${e instanceof ACEError ? e.message : ''})`);
      }
    }
    // Missing replay state beside inbound history is corruption, never first use.
    if ((await store.list('deliveries/')).length > 0) throw new ACEError('storage_failed', 'replay state missing beside history');
    for (const rec of await threads.listRecords()) {
      if (rec.snapshot.history.some((h) => h.from !== threads.localAceId)) {
        throw new ACEError('storage_failed', 'replay state missing beside history');
      }
    }
    const replay = new ReplayDetector({ capacity, horizon: Math.max(0, now - offline - 1), clock });
    await store.write(REPLAY_KEY, canonicalStateBytes(replay.exportState()));
    return replay;
  }

  static async #loadCursors(store: ACEStore): Promise<Record<string, string>> {
    const raw = await store.read(CURSORS_KEY);
    if (raw === null) return {};
    const doc = parseStateBytes(raw, CURSORS_KEY) as Record<string, unknown>;
    if (typeof doc !== 'object' || doc === null || doc.version !== 1) throw new ACEError('storage_failed', 'cursors.json: unknown version');
    const c = doc.cursors;
    if (typeof c !== 'object' || c === null || Array.isArray(c)) throw new ACEError('storage_failed', 'cursors.json: invalid cursors');
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(c)) {
      if (!isStreamId(v)) throw new ACEError('storage_failed', 'cursors.json: invalid stream id');
      out[k] = v;
    }
    return out;
  }

  #now(): number {
    return Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
  }

  #floor(): number {
    return Math.max(0, this.#now() - this.#offline);
  }

  /** The persisted cursor for `relay` (keyed by its normalized `baseUrl`), or null. */
  cursor(relay: RelayClient): string | null {
    return this.#cursors[relay.baseUrl] ?? null;
  }

  /**
   * Verify and commit one message given as its raw bytes (UTF-8 JSON of an envelope). Bytes
   * that are oversize, not JSON or not an envelope are a `quarantined` outcome
   * (`invalid_envelope`). Calls are serialized. A closed inbox, non-bytes `message` or an
   * invalid `source` throws `invalid_argument`.
   */
  async receive(message: Uint8Array, source: ReceiveSource): Promise<ReceiveOutcome> {
    this.#checkOpen();
    if (!(message instanceof Uint8Array)) throw new ACEError('invalid_argument', 'message must be bytes');
    const relayUrl = checkSource(source);
    return this.#queue.run(() => this.#receive(message, source, relayUrl));
  }

  /**
   * Answer one direct-delivery request body (`POST <endpoint>` with `{"message": Envelope}`),
   * exactly as 08-relay § Direct Delivery specifies: 413 when larger than
   * `MAX_DIRECT_BODY_BYTES`, 400 `invalid_argument` unless it is UTF-8 JSON whose top level is
   * an object with a `message` member, otherwise the outcome of receiving `message` as a
   * direct-sourced message. HTTP serving, routing and rate limiting stay with the application.
   * A closed inbox answers 503 `internal_error`: not a fault of the request, so the sender
   * falls back to the relay.
   */
  async receiveDirect(body: Uint8Array): Promise<DirectReply> {
    if (!(body instanceof Uint8Array)) throw new ACEError('invalid_argument', 'body must be bytes');
    const fail = (status: 400 | 413 | 503, error: string, outcome?: ReceiveOutcome): DirectReply =>
      outcome === undefined ? { status, body: { ok: false, error } } : { status, body: { ok: false, error }, outcome };
    if (this.#closed) return fail(503, 'internal_error');
    if (body.length > MAX_DIRECT_BODY_BYTES) return fail(413, 'payload_too_large');
    let request: unknown;
    try {
      request = JSON.parse(strictUtf8.decode(body));
    } catch {
      return fail(400, 'invalid_argument');
    }
    if (!isObj(request) || !Object.hasOwn(request, 'message')) {
      return fail(400, 'invalid_argument');
    }
    let outcome: ReceiveOutcome;
    try {
      const message = request.message;
      outcome = await this.receive(utf8(JSON.stringify(message)), { kind: 'direct' });
    } catch (e) {
      if (this.#closed) return fail(503, 'internal_error'); // closed meanwhile
      if (e instanceof ACEError) return fail(e.isTransient ? 503 : 400, e.code);
      return fail(503, 'internal_error');
    }
    switch (outcome.kind) {
      case 'delivered':
        return { status: 200, body: { ok: true, messageId: outcome.message.messageId }, outcome };
      case 'duplicate':
        return { status: 200, body: { ok: true, messageId: outcome.messageId }, outcome };
      case 'quarantined':
        return fail(400, outcome.error.code, outcome);
      case 'retryable':
        return fail(503, outcome.error.code, outcome);
    }
  }

  #checkOpen(): void {
    if (this.#closed) throw new ACEError('invalid_argument', 'inbox is closed');
  }

  /**
   * Drain the relay inbox from the persisted cursor, page by page. Stops at the first retryable
   * outcome (or fetch error) and returns its error as `blocked`; `outcomes` holds every other
   * outcome. `maxPages` bounds the pages fetched and `signal` stops before the next entry; both
   * set `hasMore`. Never throws: an invalid `limit` (1–100) or `maxPages` (>= 1) is `blocked`
   * with `invalid_argument`. `outcomes` grows with the backlog; use `maxPages` or `follow` to
   * bound memory.
   */
  async pull(relay: RelayClient, o: { limit?: number; maxPages?: number; signal?: AbortSignal } = {}): Promise<PullResult> {
    if (o.maxPages !== undefined && (wireInt(o.maxPages) === null || o.maxPages < 1)) {
      return new PullResult([], new ACEError('invalid_argument', 'maxPages must be an integer >= 1'));
    }
    const outcomes: ReceiveOutcome[] = [];
    const drain = this.#drain(relay, o.limit ?? MAX_INBOX_PAGE, o.maxPages, o.signal);
    for (;;) {
      const next = await drain.next();
      if (next.done) {
        const end = next.value;
        return end === 'stopped' ? new PullResult(outcomes, null, true) : new PullResult(outcomes, end);
      }
      if (next.value.kind !== 'retryable') outcomes.push(next.value);
    }
  }

  /**
   * Yield each outcome of a drain (a retryable one last); return the blocking error, null when
   * drained, or 'stopped' when `maxPages` or `signal` ended it early.
   */
  async *#drain(
    relay: RelayClient, limit: number, maxPages?: number, signal?: AbortSignal,
  ): AsyncGenerator<ReceiveOutcome, ACEError | null | 'stopped', undefined> {
    let since = this.cursor(relay) ?? '-';
    for (let pages = 0; ; pages++) {
      if ((maxPages !== undefined && pages >= maxPages) || signal?.aborted) return 'stopped';
      let page;
      try {
        page = await relay.fetchInbox(this.#identity, { since, limit });
      } catch (e) {
        return e instanceof ACEError ? e : new ACEError('relay_unavailable', 'inbox fetch failed', { cause: e });
      }
      for (const entry of page.entries) {
        // an aborted caller stops before the next entry; the cursor marks the spot
        if (signal?.aborted) return 'stopped';
        // the page carries parsed JSON; the pipeline takes the message's bytes
        const out = await this.receive(utf8(JSON.stringify(entry.message)), { kind: 'relay', relayUrl: relay.baseUrl, streamId: entry.streamId });
        yield out;
        if (out.kind === 'retryable') return out.error;
        since = entry.streamId;
      }
      if (page.entries.length < limit) return null;
    }
  }

  /**
   * Yield the outcomes of an initial `pull`, then of live events. `onLive` runs once the initial
   * pull is done and the event stream is connected, and again after each reconnect. A retryable
   * outcome is yielded, then its error thrown; a failed inbox fetch is thrown. Outcomes are
   * streamed, not retained: the consumer's pace is the backpressure (nothing is read ahead).
   */
  async *follow(
    relay: RelayClient, o: { signal?: AbortSignal; onLive?: () => void } = {},
  ): AsyncGenerator<ReceiveOutcome, void, undefined> {
    const drain = this.#drain(relay, MAX_INBOX_PAGE, undefined, o.signal);
    for (;;) {
      const next = await drain.next();
      if (next.done) {
        if (next.value === 'stopped') return; // aborted (follow sets no maxPages)
        if (next.value !== null) throw next.value;
        break;
      }
      yield next.value;
      if (o.signal?.aborted) return;
    }
    const since = this.cursor(relay) ?? undefined;
    for await (const ev of relay.listen(this.#identity, { since, signal: o.signal, onOpen: o.onLive })) {
      const out = await this.receive(utf8(ev.data), { kind: 'relay', relayUrl: relay.baseUrl, streamId: ev.streamId });
      yield out;
      if (out.kind === 'retryable') throw out.error;
    }
  }

  /** Release the `receive` lock. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#queue.run(async () => undefined);
    const held = this.#heldThreads;
    this.#heldThreads = null;
    try {
      if (held !== null) await held();
    } finally {
      await this.#releaseReceive();
    }
  }

  // --- receive ---

  async #receive(raw: Uint8Array, source: ReceiveSource, relayUrl: string | null): Promise<ReceiveOutcome> {
    this.#checkOpen();
    if (this.#failed) return { kind: 'retryable', error: new ACEError('storage_failed', 'inbox is in a failed state; close and reopen to recover') };
    const outcome = await this.#process(raw, source);
    if (relayUrl !== null && source.kind === 'relay' && source.streamId !== undefined && outcome.kind !== 'retryable') {
      const cur = this.#cursors[relayUrl];
      if (cur === undefined || compareStreamIds(source.streamId, cur) > 0) {
        const next = { ...this.#cursors, [relayUrl]: source.streamId };
        try {
          await this.#store.write(CURSORS_KEY, canonicalStateBytes({ cursors: next, version: 1 }));
          this.#cursors = next;
        } catch (e) {
          return this.#fail(e);
        }
      }
    }
    if (outcome.kind === 'delivered' && ++this.#sinceSweep >= SWEEP_EVERY) {
      this.#sinceSweep = 0;
      try {
        await this.#sweep();
      } catch {
        // best effort; the next sweep or recovery retries
      }
    }
    return outcome;
  }

  #fail(e: unknown): ReceiveOutcome {
    this.#failed = asError(e, 'storage_failed', 'storage failed');
    return { kind: 'retryable', error: this.#failed };
  }

  async #process(raw: Uint8Array, source: ReceiveSource): Promise<ReceiveOutcome> {
    const relaySourced = source.kind === 'relay';
    // 1. decode
    let env: ACEMessage;
    try {
      if (raw.length > MAX_ENVELOPE_BYTES) throw new ACEError('invalid_envelope', `message exceeds ${MAX_ENVELOPE_BYTES} bytes`);
      let json: unknown;
      try {
        json = JSON.parse(strictUtf8.decode(raw));
      } catch {
        throw new ACEError('invalid_envelope', 'message is not UTF-8 JSON');
      }
      env = decodeEnvelope(json);
    } catch (e) {
      return { kind: 'quarantined', error: e as ACEError, fingerprint: null };
    }
    // 2. direct freshness
    if (!relaySourced && Math.abs(this.#now() - env.timestamp) > TIMESTAMP_WINDOW_SECONDS) {
      return { kind: 'quarantined', error: new ACEError('stale_timestamp', 'direct message outside the freshness window'), fingerprint: envelopeFingerprint(env) };
    }
    const quarantine = async (error: ACEError): Promise<ReceiveOutcome> => {
      if (!relaySourced) return { kind: 'quarantined', error, fingerprint: envelopeFingerprint(env) }; // not persisted
      try {
        return { kind: 'quarantined', error, fingerprint: await this.#writeQuarantine(env, error) };
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'quarantine write failed') };
      }
    };
    // 3. resolve the sender (before taking `threads`)
    let peer;
    try {
      peer = await this.#peers.resolve(env.from);
      const me = this.#identity.getEncryptionPublicKey();
      if (computeConversationId(peer.encryptionPublicKey, me) !== env.conversationId) {
        peer = await this.#peers.resolve(env.from, { maxAgeSeconds: 0 });
      }
    } catch (e) {
      const err = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'peer resolution failed', { cause: e });
      return err.isTransient ? { kind: 'retryable', error: err } : quarantine(err);
    }
    // 4. known delivery
    const dkey = deliveryKey(env.from, env.messageId);
    let existing: DeliveryRecord | null;
    try {
      existing = await this.#readDelivery(dkey);
    } catch (e) {
      return { kind: 'retryable', error: asError(e, 'storage_failed', 'delivery read failed') };
    }
    if (existing !== null) {
      if (existing.status !== 'pending') return { kind: 'duplicate', from: env.from, messageId: env.messageId };
      try {
        await this.#onMessage(existing.message);
      } catch (e) {
        return { kind: 'retryable', error: new ACEError('handler_failed', 'onMessage failed', { cause: e }) };
      }
      try {
        await this.#ack(dkey, existing);
      } catch (e) {
        return this.#fail(e);
      }
      return { kind: 'delivered', message: existing.message };
    }
    // 5-7 under `threads` for economic types
    const economic = isEconomicType(env.type);
    const run = async (): Promise<ReceiveOutcome | DeliveryRecord> => {
      const tr = this.#replay.clone();
      let record: ThreadRecord | null = null;
      let machine: ThreadStateMachine;
      try {
        if (economic) record = await this.#threads.loadRecord(env.conversationId, env.threadId!);
        machine = restoreMachine(this.#identity.getACEId(), record?.snapshot ?? null);
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'thread load failed') };
      }
      // 6. pipeline
      let parsed: ParsedMessage;
      try {
        parsed = await parseMessage(env, this.#identity, peer, {
          threads: machine, replay: tr, floor: this.#floor(), clock: this.#clock,
        });
        // a verified message that opens a thread is bounded per peer (04 § Open-thread bound)
        if (economic && record === null) await this.#threads.checkCanOpen(env.from);
      } catch (e) {
        const err = e instanceof ACEError ? e : new ACEError('identity_unavailable', 'receive failed', { cause: e });
        if (err.code === 'replay') return { kind: 'duplicate', from: env.from, messageId: env.messageId };
        if (err.isTransient) return { kind: 'retryable', error: err };
        const out = await quarantine(err);
        if (out.kind === 'retryable') return out;
        // a verified message stays one-shot: persist the tentative replay state if it changed
        if (!tr.accepts(env.messageId, env.from, env.timestamp) && this.#replay.accepts(env.messageId, env.from, env.timestamp)) {
          try {
            await this.#store.write(REPLAY_KEY, canonicalStateBytes(tr.exportState()));
          } catch (e2) {
            return { kind: 'retryable', error: asError(e2, 'storage_failed', 'replay write failed') };
          }
          this.#replay = tr;
        }
        return out;
      }
      // 7. durable commit
      const snapshot = economic ? machine.getSnapshot(env.conversationId, env.threadId!) : null;
      const delivery: DeliveryRecord = {
        fingerprint: envelopeFingerprint(env), message: parsed, receivedAt: this.#now(),
        source: relaySourced ? 'relay' : 'direct', status: 'pending', thread: snapshot,
      };
      try {
        await this.#writeDelivery(dkey, delivery); // 7.1 commit point
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'delivery write failed') };
      }
      try {
        if (snapshot !== null) await this.#threads.saveRecord({ snapshot, pending: clearedPending(record, snapshot) }); // 7.2
        await this.#store.write(REPLAY_KEY, canonicalStateBytes(tr.exportState())); // 7.3
        this.#replay = tr;
      } catch (e) {
        return this.#fail(e);
      }
      return delivery;
    };
    // The `threads` lock covers steps 5-7.3 only: onMessage runs unlocked, so a handler may stage a reply.
    let committed: ReceiveOutcome | DeliveryRecord;
    if (!economic) {
      committed = await run();
    } else {
      let release: () => Promise<void>;
      try {
        release = await this.#store.lock('threads');
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'threads lock failed') };
      }
      try {
        committed = await run();
      } finally {
        // A failure after the commit point keeps `threads` held until close(), so no concurrent
        // Outbox.stage can extend the thread before recovery repairs it.
        if (this.#failed !== null) this.#heldThreads = release;
        else await release();
      }
    }
    if ('kind' in committed) return committed;
    try {
      await this.#onMessage(committed.message); // 7.4
    } catch (e) {
      return { kind: 'retryable', error: new ACEError('handler_failed', 'onMessage failed', { cause: e }) };
    }
    try {
      await this.#ack(dkey, committed); // 7.5
    } catch (e) {
      return this.#fail(e);
    }
    return { kind: 'delivered', message: committed.message };
  }

  // --- records ---

  async #writeDelivery(key: string, d: DeliveryRecord): Promise<void> {
    const m = d.message;
    await this.#store.write(key, canonicalStateBytes({
      fingerprint: d.fingerprint,
      message: {
        body: m.body, conversationId: m.conversationId, from: m.from, messageId: m.messageId, threadId: m.threadId,
        timestamp: m.timestamp, to: m.to, type: m.type,
      },
      receivedAt: d.receivedAt,
      source: d.source,
      status: d.status,
      thread: d.thread === null ? null : encodeSnapshot(d.thread),
      version: 1,
    }));
  }

  #readDelivery(key: string): Promise<DeliveryRecord | null> {
    return readDelivery(this.#store, key, this.#identity.getACEId());
  }

  #covered(from: string, ts: number): boolean {
    return replayCovers(this.#replay, from, ts);
  }

  async #ack(key: string, d: DeliveryRecord): Promise<void> {
    if (this.#covered(d.message.from, d.message.timestamp)) await this.#store.delete(key);
    else await this.#writeDelivery(key, { ...d, status: 'acked' });
  }

  async #writeQuarantine(env: ACEMessage, error: ACEError): Promise<string> {
    const fingerprint = envelopeFingerprint(env);
    let reason = errorDetail(error);
    if (codePointLength(reason) > 1000) reason = [...reason].slice(0, 1000).join('');
    const key = `quarantine/${fingerprint}.json`;
    await this.#store.write(key, canonicalStateBytes({
      code: error.code, envelope: envelopeKnownFields(env), fingerprint, quarantinedAt: this.#now(), reason,
      source: 'relay', version: 1,
    }));
    // listed once per instance; the records are read only when the cap is crossed, which then
    // trims to QUARANTINE_FLOOR (so at most once per 100 inserts)
    const keys = this.#quarantined ??= new Set(await this.#store.list('quarantine/'));
    keys.add(key);
    if (keys.size > QUARANTINE_CAP) {
      const entries: Array<[number, string]> = [];
      for (const k of keys) {
        const raw = await this.#store.read(k);
        if (raw === null) {
          keys.delete(k);
          continue;
        }
        let at = 0;
        try {
          at = wireInt((parseStateBytes(raw, k) as { quarantinedAt?: unknown }).quarantinedAt) ?? 0;
        } catch {
          at = 0;
        }
        entries.push([at, k]);
      }
      entries.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
      for (const [, k] of entries.slice(0, Math.max(0, entries.length - QUARANTINE_FLOOR))) {
        await this.#store.delete(k);
        keys.delete(k);
      }
    }
    return fingerprint;
  }

  async #sweep(): Promise<void> {
    for (const key of await this.#store.list('deliveries/')) {
      const d = await this.#readDelivery(key);
      if (d !== null && d.status === 'acked' && this.#covered(d.message.from, d.message.timestamp)) await this.#store.delete(key);
    }
  }

  // --- recovery ---

  async #recover(): Promise<void> {
    // acked records covered by a horizon are only deleted: their threads may have been pruned
    const records: Array<[string, DeliveryRecord]> = [];
    for (const [key, d] of await readDeliveries(this.#store, this.#identity.getACEId())) {
      if (d.status === 'acked' && this.#covered(d.message.from, d.message.timestamp)) await this.#store.delete(key);
      else records.push([key, d]);
    }
    await this.#threads.withLock(() => repairThreads(this.#threads, records));
    let replayChanged = false;
    const floor = this.#floor();
    for (const [, d] of records) {
      const m = d.message;
      if (this.#replay.accepts(m.messageId, m.from, m.timestamp)) {
        this.#replay.commit(m.messageId, m.from, m.timestamp, floor);
        replayChanged = true;
      }
    }
    if (replayChanged) await this.#store.write(REPLAY_KEY, canonicalStateBytes(this.#replay.exportState()));
    for (const [key, d] of records) {
      if (d.status === 'pending') {
        try {
          await this.#onMessage(d.message);
        } catch (e) {
          // the record stays pending and is retried at the next open (or on redelivery)
          throw new ACEError('handler_failed', 'onMessage failed during recovery', { cause: e });
        }
        await this.#ack(key, d);
      } else if (this.#covered(d.message.from, d.message.timestamp)) {
        await this.#store.delete(key);
      }
    }
  }
}

async function readDelivery(store: ACEStore, key: string, localAceId: string): Promise<DeliveryRecord | null> {
  const raw = await store.read(key);
  if (raw === null) return null;
  const bad = (why: string) => new ACEError('storage_failed', `${key}: ${why}`);
  const doc = parseStateBytes(raw, key) as Record<string, unknown>;
  if (typeof doc !== 'object' || doc === null || doc.version !== 1) throw bad('unknown version');
  const m = doc.message as Record<string, unknown>;
  const receivedAt = wireInt(doc.receivedAt);
  if (
    typeof doc.fingerprint !== 'string' || receivedAt === null || (doc.source !== 'relay' && doc.source !== 'direct')
    || (doc.status !== 'pending' && doc.status !== 'acked') || typeof m !== 'object' || m === null
    || !isMessageId(m.messageId) || !isACEId(m.from) || !isACEId(m.to) || !isConversationId(m.conversationId)
    || !isMessageType(m.type) || (m.threadId !== null && !isThreadId(m.threadId)) || wireInt(m.timestamp) === null
    || typeof m.body !== 'object' || m.body === null || Array.isArray(m.body)
  ) {
    throw bad('invalid delivery record');
  }
  if (deliveryKey(m.from as string, m.messageId as string) !== key) throw bad('record does not match its key');
  let thread: ThreadSnapshot | null = null;
  if (doc.thread !== null) {
    const t = doc.thread as ThreadSnapshot;
    try {
      ThreadStateMachine.fromState([t], { localAceId: localAceId });
    } catch {
      throw bad('invalid thread snapshot');
    }
    thread = t;
  }
  return {
    fingerprint: doc.fingerprint,
    message: {
      messageId: m.messageId as string, from: m.from as string, to: m.to as string, conversationId: m.conversationId as string,
      type: m.type, threadId: (m.threadId as string | null), timestamp: m.timestamp as number, body: m.body as JSONObject,
    },
    receivedAt, source: doc.source, status: doc.status, thread,
  };
}


/** Internal: every delivery record, ordered by (timestamp, key). */
async function readDeliveries(store: ACEStore, localAceId: string): Promise<Array<[string, DeliveryRecord]>> {
  const records: Array<[string, DeliveryRecord]> = [];
  for (const key of await store.list('deliveries/')) {
    const d = await readDelivery(store, key, localAceId);
    if (d !== null) records.push([key, d]);
  }
  return records.sort((x, y) => x[1].message.timestamp - y[1].message.timestamp || (x[0] < y[0] ? -1 : 1));
}

/** Write every delivery snapshot that strictly extends its stored thread (caller holds `threads`). */
async function repairThreads(threads: ThreadRecords, records: Array<[string, DeliveryRecord]>): Promise<void> {
  for (const [, d] of records) {
    const snap = d.thread;
    if (snap === null) continue;
    const rec = await threads.loadRecord(snap.conversationId, snap.threadId);
    const cmp = rec === null ? -1 : compareHistories(rec.snapshot.history, snap.history);
    if (cmp === null) throw new ACEError('storage_failed', 'delivery record diverges from the stored thread');
    if (cmp === -1) await threads.saveRecord({ snapshot: snap, pending: clearedPending(rec, snap) });
  }
}

/**
 * Internal (Outbox.open): under lock `threads`, repair thread records from `deliveries/`,
 * skipping acked records covered by the persisted replay horizons (their threads may have
 * been pruned). Never hands messages over and never writes replay state.
 */
export async function repairThreadsFromDeliveries(store: ACEStore, threads: ThreadRecords): Promise<void> {
  await threads.withLock(async () => {
    const records = await readDeliveries(store, threads.localAceId);
    if (records.length === 0) return;
    // the persisted horizons, read as stored (no replay state: nothing is covered)
    const raw = await store.read(REPLAY_KEY);
    let covers = (_from: string, _ts: number): boolean => false;
    if (raw !== null) {
      const doc = parseStateBytes(raw, REPLAY_KEY) as Partial<ReplayState>;
      const h = wireInt(doc?.horizon);
      const sh = doc?.senderHorizons;
      if (h === null || typeof sh !== 'object' || sh === null) throw new ACEError('storage_failed', 'replay.json is invalid');
      covers = (from, ts) => ts <= Math.max(h, wireInt((sh as Record<string, unknown>)[from]) ?? h);
    }
    const live = records.filter(([, d]) => !(d.status === 'acked' && covers(d.message.from, d.message.timestamp)));
    await repairThreads(threads, live);
  });
}

/** Validate a receive source; returns the normalized relay URL (null for direct). */
function checkSource(source: ReceiveSource): string | null {
  if (typeof source !== 'object' || source === null || (source.kind !== 'relay' && source.kind !== 'direct')) {
    throw new ACEError('invalid_argument', 'source must be {kind: "relay" | "direct"}');
  }
  if (source.kind === 'direct') return null;
  if (source.streamId !== undefined && !isStreamId(source.streamId)) throw new ACEError('invalid_argument', 'invalid streamId');
  return normalizeRelayUrl(source.relayUrl);
}

/** Keep the stored pending send unless an inbound entry now follows it (delivery proven). */
function clearedPending(record: ThreadRecord | null, next: ThreadSnapshot): ThreadRecord['pending'] {
  const pending = record?.pending ?? null;
  if (pending === null) return null;
  const before = record!.snapshot.history;
  const head = before[before.length - 1];
  const proven = head?.messageId === pending.message.messageId && next.history.length > before.length
    && next.history.slice(before.length).some((h) => h.from !== record!.snapshot.localAceId);
  return proven ? null : pending;
}

