/** The receive engine: verify, commit durably, hand over exactly once (design §2.12, 06 § Durable Delivery). */

import { ACEError } from './errors.js';
import {
  canonicalStateBytes, codePointLength, isACEId, isConversationId, isMessageId, isThreadId, pairKey,
  parseStateBytes, wireInt,
} from './encoding.js';
import { computeConversationId } from './encryption.js';
import { decodeEnvelope, envelopeFingerprint, envelopeKnownFields } from './envelope.js';
import { MAX_INBOX_PAGE, OFFLINE_WINDOW_SECONDS, DEFAULT_REPLAY_CAPACITY } from './limits.js';
import { eventOf, parseMessage } from './messages.js';
import type { PeerStore } from './peer-store.js';
import { compareStreamIds, isStreamId, normalizeRelayUrl, type RelayClient } from './relay.js';
import { ReplayDetector } from './replay.js';
import { ThreadStateMachine, type ThreadSnapshot } from './state-machine.js';
import { SerialQueue, type ACEStore } from './store.js';
import { compareHistories, restoreMachine, ThreadStore, type ThreadRecord } from './thread-store.js';
import type { ACEIdentity, ACEMessage, JSONObject, ParsedMessage, ReplayState } from './types.js';
import { isEconomicType, isMessageType } from './types.js';

export type ReceiveSource = { kind: 'relay'; relayUrl: string; streamId?: string } | { kind: 'direct' };

export type ReceiveOutcome =
  | { kind: 'delivered'; message: ParsedMessage }
  | { kind: 'duplicate'; from: string; messageId: string }
  | { kind: 'quarantined'; error: ACEError; fingerprint: string | null }
  | { kind: 'retryable'; error: ACEError };

export interface PullResult {
  delivered: number;
  duplicates: number;
  quarantined: number;
  blocked: ACEError | null;
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
const DIRECT_WINDOW_SECONDS = 300;

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
  readonly #threads: ThreadStore;
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
    this.#threads = new ThreadStore({ store: o.store, localAceId: o.identity.getACEId(), clock: o.clock });
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
    const release = await o.store.lock('receive', { timeoutMs: 0 });
    try {
      const now = Math.floor(o.clock ? o.clock() : Date.now() / 1000);
      const threads = new ThreadStore({ store: o.store, localAceId: local, clock: o.clock });
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
    store: ACEStore, threads: ThreadStore, capacity: number, now: number, offline: number, clock?: () => number,
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

  /** The persisted cursor for a relay, or null. */
  cursor(relayUrl: string): string | null {
    return this.#cursors[normalizeRelayUrl(relayUrl)] ?? null;
  }

  /** Verify and commit one envelope. Calls are serialized. */
  receive(envelope: unknown, source: ReceiveSource): Promise<ReceiveOutcome> {
    return this.#queue.run(() => this.#receive(envelope, source));
  }

  /**
   * Drain the relay inbox from the persisted cursor. Stops at the first retryable outcome (or
   * fetch error) and returns it as `blocked`.
   */
  async pull(relay: RelayClient, o: { limit?: number } = {}): Promise<PullResult> {
    const limit = o.limit ?? MAX_INBOX_PAGE;
    const result: PullResult = { delivered: 0, duplicates: 0, quarantined: 0, blocked: null };
    let since = this.cursor(relay.baseUrl) ?? '-';
    for (;;) {
      let page;
      try {
        page = await relay.fetchInbox(this.#identity, { since, limit });
      } catch (e) {
        result.blocked = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'inbox fetch failed', { cause: e });
        return result;
      }
      for (const entry of page.entries) {
        const out = await this.receive(entry.message, { kind: 'relay', relayUrl: relay.baseUrl, streamId: entry.streamId });
        if (out.kind === 'delivered') result.delivered++;
        else if (out.kind === 'duplicate') result.duplicates++;
        else if (out.kind === 'quarantined') result.quarantined++;
        else {
          result.blocked = out.error;
          return result;
        }
        since = entry.streamId;
      }
      if (page.entries.length < limit) return result;
    }
  }

  /** `pull`, then stream live events; throws the error of a blocked pull or retryable outcome (after yielding it). */
  async *follow(relay: RelayClient, o: { signal?: AbortSignal } = {}): AsyncGenerator<ReceiveOutcome, void, undefined> {
    const r = await this.pull(relay);
    if (r.blocked) throw r.blocked;
    const since = this.cursor(relay.baseUrl) ?? undefined;
    for await (const ev of relay.listen(this.#identity, { since, signal: o.signal })) {
      const out = await this.receive(ev.message, { kind: 'relay', relayUrl: relay.baseUrl, streamId: ev.streamId });
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

  async #receive(envelope: unknown, source: ReceiveSource): Promise<ReceiveOutcome> {
    if (this.#closed) return { kind: 'retryable', error: new ACEError('storage_failed', 'inbox is closed') };
    if (this.#failed) return { kind: 'retryable', error: new ACEError('storage_failed', 'inbox is in a failed state; close and reopen to recover') };
    let relayUrl: string | null = null;
    if (typeof source !== 'object' || source === null || (source.kind !== 'relay' && source.kind !== 'direct')) {
      throw new ACEError('invalid_argument', 'source must be {kind: "relay" | "direct"}');
    }
    if (source.kind === 'relay') {
      relayUrl = normalizeRelayUrl(source.relayUrl);
      if (source.streamId !== undefined && !isStreamId(source.streamId)) throw new ACEError('invalid_argument', 'invalid streamId');
    }
    const outcome = await this.#process(envelope, source);
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
    if (outcome.kind !== 'retryable' && ++this.#sinceSweep >= SWEEP_EVERY) {
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

  async #process(envelope: unknown, source: ReceiveSource): Promise<ReceiveOutcome> {
    const relaySourced = source.kind === 'relay';
    // 1. decode
    let env: ACEMessage;
    try {
      env = decodeEnvelope(envelope);
    } catch (e) {
      return { kind: 'quarantined', error: e as ACEError, fingerprint: null };
    }
    // 2. direct freshness
    if (!relaySourced && Math.abs(this.#now() - env.timestamp) > DIRECT_WINDOW_SECONDS) {
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
    return ts <= Math.max(this.#replay.horizon, this.#replay.senderHorizon(from) ?? this.#replay.horizon);
  }

  async #ack(key: string, d: DeliveryRecord): Promise<void> {
    if (this.#covered(d.message.from, d.message.timestamp)) await this.#store.delete(key);
    else await this.#writeDelivery(key, { ...d, status: 'acked' });
  }

  async #writeQuarantine(env: ACEMessage, error: ACEError): Promise<string> {
    const fingerprint = envelopeFingerprint(env);
    let reason = error.message;
    if (codePointLength(reason) > 1000) reason = [...reason].slice(0, 1000).join('');
    await this.#store.write(`quarantine/${fingerprint}.json`, canonicalStateBytes({
      code: error.code, envelope: envelopeKnownFields(env), fingerprint, quarantinedAt: this.#now(), reason,
      source: 'relay', version: 1,
    }));
    const keys = await this.#store.list('quarantine/');
    if (keys.length > QUARANTINE_CAP) {
      const entries: Array<[number, string]> = [];
      for (const k of keys) {
        const raw = await this.#store.read(k);
        if (raw === null) continue;
        let at = 0;
        try {
          at = wireInt((parseStateBytes(raw, k) as { quarantinedAt?: unknown }).quarantinedAt) ?? 0;
        } catch {
          at = 0;
        }
        entries.push([at, k]);
      }
      entries.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
      for (const [, k] of entries.slice(0, Math.max(0, entries.length - QUARANTINE_FLOOR))) await this.#store.delete(k);
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
    const records = await readDeliveries(this.#store, this.#identity.getACEId());
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
async function repairThreads(threads: ThreadStore, records: Array<[string, DeliveryRecord]>): Promise<void> {
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
 * Internal (Outbox.open): under lock `threads`, repair thread records from `deliveries/`.
 * Never hands messages over and never touches replay state.
 */
export async function repairThreadsFromDeliveries(store: ACEStore, threads: ThreadStore): Promise<void> {
  await threads.withLock(async () => repairThreads(threads, await readDeliveries(store, threads.localAceId)));
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

