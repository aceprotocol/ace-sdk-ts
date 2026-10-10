/** The receive engine: verify, commit durably, hand over exactly once (06-security § Durable Delivery). */

import { ACEError, errorDetail } from './errors.js';
import {
  bytesEqual, canonicalStateBytes, codePointLength, isACEId, isConversationId, isMessageId, isObj, isThreadId, pairKey,
  parseStateBytes, wireInt,
} from './encoding.js';
import { computeConversationId } from './encryption.js';
import { decodeSigningKey, type VerifiedPeer } from './discovery.js';
import { decodeEnvelope, envelopeFingerprint, envelopeKnownFields } from './envelope.js';
import { DEFAULT_REPLAY_CAPACITY, MAX_ENVELOPE_BYTES, OFFLINE_WINDOW_SECONDS } from './limits.js';
import { applySchema, checkPrincipal, eventOf, installedSchemas, parseMessage, type SchemaValidator } from './messages.js';
import { refreshPeer, type PeerStore } from './peer-store.js';
import {
  fillDecision, isCaip10, openRequestTo, senderPrincipalUsable, validatePrincipalRecord, type PrincipalContext,
} from './principal.js';
import { ReplayDetector, replayCovers } from './replay.js';
import { ThreadStateMachine, type ThreadSnapshot } from './state-machine.js';
import { SerialQueue, type ACEStore } from './store.js';
import { compareHistories, restoreMachine, ThreadRecords, type ThreadRecord } from './thread-store.js';
import type { ACEIdentity, ACEMessage, JSONObject, ParsedMessage, PrincipalKey, PrincipalRecord, ReplayState } from './types.js';
import { isEconomicType, isMessageType, isPrincipalType } from './types.js';

export type ReceiveOutcome =
  | { kind: 'delivered'; message: ParsedMessage }
  | { kind: 'duplicate'; from: string; messageId: string }
  | { kind: 'quarantined'; error: ACEError; fingerprint: string | null }
  | { kind: 'retryable'; error: ACEError };

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
  /**
   * The receiver's principal (09): installs the account policy for `request` / `decision` / `report` (same-account
   * rules, `wrong_principal`). Without it they are delivered as plain data, unverified, and a `decision` never fills
   * `requests/`; their type is never authority.
   */
  principal?: InboxPrincipal;
  /** Explicit opt-in to the economic application state machine. */
  commerce?: boolean;
  /**
   * Installed deterministic validators keyed by `schemaDigest` (64 lowercase hex). One runs at the
   * body-validation step (06 § pipeline step 6) for every message carrying its digest, in addition to
   * the bundled validation; a rejection is quarantined. Without one a custom type stays authenticated data.
   */
  schemas?: Record<string, SchemaValidator>;
}

/**
 * The receiver's principal for 09 § Same-Account Rules: its CAIP-10 `account`, `selfSigner` (the signer of the host's
 * own principal record) and host-trusted `trustedSigners` (e.g. read from chain). With neither signer given only an
 * `eip155` account whose address is the signer's passes step 4 (fail closed).
 */
export interface InboxPrincipal {
  account: string;
  selfSigner?: PrincipalKey | null;
  trustedSigners?: readonly PrincipalKey[];
}

/**
 * The `InboxOptions.principal` for a host's own saved principal record (09, R-B12a): the record is P_self only
 * while it validates for `identity`'s signing key at `now` (default: the wall clock). A missing record is
 * `{ principal: undefined }`; an invalid or expired one never throws but is `{ principal: undefined, warning }`
 * (`'<code>: <detail>'`) so the host decides how to surface it; a valid one binds its `account` with the record's
 * `signer` as `selfSigner` and `opts.trustedSigners` (default none).
 */
export function inboxPrincipalFromOwnRecord(
  record: PrincipalRecord | null | undefined,
  identity: ACEIdentity,
  opts: { now?: number; trustedSigners?: PrincipalKey[] } = {},
): { principal: InboxPrincipal | undefined; warning?: string } {
  if (record === undefined || record === null) return { principal: undefined };
  let own: PrincipalRecord;
  try {
    own = validatePrincipalRecord(record, identity.getSigningPublicKey(), opts.now ?? Math.floor(Date.now() / 1000));
  } catch (err) {
    // An ACEError message is already `<code>: <detail>`.
    const warning = err instanceof ACEError ? err.message : `invalid_principal: ${err instanceof Error ? err.message : String(err)}`;
    return { principal: undefined, warning };
  }
  return { principal: { account: own.account, selfSigner: own.signer, trustedSigners: opts.trustedSigners ?? [] } };
}

interface PrincipalOption {
  account: string;
  selfSigner?: PrincipalKey;
  trustedSigners: PrincipalKey[];
}

const PRINCIPAL_OPTION_KEYS = new Set(['account', 'selfSigner', 'trustedSigners']);

function principalKeyOption(v: unknown, what: string): PrincipalKey {
  const bad = () => new ACEError('invalid_argument', `${what} must be {scheme, publicKey} with a valid signing key`);
  if (!isObj(v)) throw bad();
  const keys = Object.keys(v);
  if (keys.length !== 2 || !Object.hasOwn(v, 'scheme') || !Object.hasOwn(v, 'publicKey')) throw bad();
  try {
    decodeSigningKey(v.scheme, v.publicKey, 'invalid_argument');
  } catch {
    throw bad();
  }
  return { scheme: v.scheme as PrincipalKey['scheme'], publicKey: v.publicKey as string };
}

/** Validate `InboxOptions.principal` (`invalid_argument`); undefined → null. */
function principalOption(v: unknown): PrincipalOption | null {
  if (v === undefined) return null;
  if (!isObj(v) || !Object.keys(v).every((k) => PRINCIPAL_OPTION_KEYS.has(k)) || !isCaip10(v.account)) {
    throw new ACEError('invalid_argument', 'principal must be {account: <CAIP-10 account>, selfSigner?, trustedSigners?}');
  }
  const out: PrincipalOption = { account: v.account, trustedSigners: [] };
  if (v.selfSigner !== undefined && v.selfSigner !== null) out.selfSigner = principalKeyOption(v.selfSigner, 'principal.selfSigner');
  if (v.trustedSigners !== undefined && v.trustedSigners !== null) {
    if (!Array.isArray(v.trustedSigners)) throw new ACEError('invalid_argument', 'principal.trustedSigners must be an array');
    out.trustedSigners = v.trustedSigners.map((k) => principalKeyOption(k, 'principal.trustedSigners[]'));
  }
  return out;
}

interface DeliveryRecord {
  fingerprint: string;
  message: ParsedMessage;
  receivedAt: number;
  status: 'pending' | 'acked';
  thread: ThreadSnapshot | null;
}

const REPLAY_KEY = 'replay.json';
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
 * The application receive engine: verifies envelopes, commits them durably in the normative
 * order and hands each message to `onMessage` exactly once (at least once across a crash
 * between hand-over and acknowledgement). It knows nothing about transport: `SecureMailbox`
 * (the only network receive boundary) feeds it authenticated MLS plaintext; in-process code
 * and tests call `receive` directly. One open Inbox per store (lock `receive`). Commit order
 * per message: delivery record, `requests/` decision fill (`decision` only), thread state,
 * replay state, `onMessage`, ack.
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
  readonly #principal: PrincipalOption | null;
  /** The step-7 context, without `refreshSender`: the Inbox refreshes the sender itself (`#refreshPrincipalSender`). */
  readonly #principalCtx: PrincipalContext | undefined;
  readonly #commerce: boolean;
  readonly #schemas: ReadonlyMap<string, SchemaValidator>;
  #failed: ACEError | null = null;
  /** `threads` or `requests`, kept after a failure past the commit point until close(). */
  #heldLock: (() => Promise<void>) | null = null;
  #closed = false;
  #sinceSweep = 0;
  /** `quarantine/` keys: listed once, then maintained (this instance holds `receive`). */
  #quarantined: Set<string> | null = null;

  private constructor(
    o: InboxOptions, release: () => Promise<void>, replay: ReplayDetector, principal: PrincipalOption | null,
    schemas: ReadonlyMap<string, SchemaValidator>,
  ) {
    this.#identity = o.identity;
    this.#principal = principal;
    this.#commerce = o.commerce === true;
    this.#schemas = schemas;
    this.#store = o.store;
    if (principal !== null) {
      const store = o.store;
      this.#principalCtx = {
        account: principal.account,
        openRequestTo: (conversationId, requestId, now) => openRequestTo(store, conversationId, requestId, now),
        trustedSigners: principal.trustedSigners,
        ...(principal.selfSigner !== undefined ? { selfSigner: principal.selfSigner } : {}),
      };
    }
    this.#peers = o.peers;
    this.#onMessage = o.onMessage;
    this.#offline = o.offlineWindowSeconds ?? OFFLINE_WINDOW_SECONDS;
    this.#clock = o.clock;
    this.#releaseReceive = release;
    this.#replay = replay;
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
    const principal = principalOption(o.principal);
    const schemas = installedSchemas(o.schemas);
    const release = await o.store.lock('receive', { timeoutMs: 0 });
    try {
      const now = Math.floor(o.clock ? o.clock() : Date.now() / 1000);
      const threads = new ThreadRecords({ store: o.store, localAceId: local, clock: o.clock });
      const replay = await Inbox.#loadReplay(o.store, threads, capacity, now, offline, o.clock);
      const inbox = new Inbox(o, release, replay, principal, schemas);
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

  #now(): number {
    return Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
  }

  #floor(): number {
    return Math.max(0, this.#now() - this.#offline);
  }

  /**
   * Verify and commit one message given as its raw bytes (UTF-8 JSON of an envelope). Bytes
   * that are oversize, not JSON or not an envelope are a `quarantined` outcome
   * (`invalid_envelope`). Calls are serialized. A closed inbox or a non-bytes `message`
   * throws `invalid_argument`.
   */
  async receive(message: Uint8Array): Promise<ReceiveOutcome> {
    this.#checkOpen();
    if (!(message instanceof Uint8Array)) throw new ACEError('invalid_argument', 'message must be bytes');
    return this.#queue.run(() => this.#receive(message));
  }

  #checkOpen(): void {
    if (this.#closed) throw new ACEError('invalid_argument', 'inbox is closed');
  }

  /** Release the `receive` lock. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#queue.run(async () => undefined);
    const held = this.#heldLock;
    this.#heldLock = null;
    try {
      if (held !== null) await held();
    } finally {
      await this.#releaseReceive();
    }
  }

  // --- principal (09) ---

  /**
   * R-P20 (09 § Same-Account Rules, SDK note): when the pinned sender principal fails steps 2-5, refresh the sender's
   * binding from the relay once (rollback barrier) and return the binding the rules run on. Called only after
   * `parseMessage` accepted the envelope, so recipient, timestamp window, replay and the pinned-key signature already
   * hold (R-P30). Runs before any store lock (R-P29). A transient failure throws (the message is retryable); a non-ACE
   * error is `relay_unavailable`; a permanent error, no relay or a different binding leaves the pinned binding to decide.
   */
  async #refreshPrincipalSender(peer: VerifiedPeer, now: number): Promise<VerifiedPeer> {
    const ctx = this.#principalCtx;
    if (ctx === undefined || senderPrincipalUsable(peer.principal, peer.signingPublicKey, ctx, now)) return peer;
    let fresh: VerifiedPeer | null;
    try {
      fresh = await refreshPeer(this.#peers, peer.aceId);
    } catch (e) {
      if (!(e instanceof ACEError)) {
        throw new ACEError('relay_unavailable', `peer refresh failed: ${e instanceof Error ? e.name : typeof e}`, { cause: e });
      }
      if (e.isTransient) throw e;
      return peer;
    }
    if (fresh !== null && fresh.aceId === peer.aceId && bytesEqual(fresh.signingPublicKey, peer.signingPublicKey)) return fresh;
    return peer;
  }

  // --- receive ---

  async #receive(raw: Uint8Array): Promise<ReceiveOutcome> {
    this.#checkOpen();
    if (this.#failed) return { kind: 'retryable', error: new ACEError('storage_failed', 'inbox is in a failed state; close and reopen to recover') };
    const outcome = await this.#process(raw);
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

  async #process(raw: Uint8Array): Promise<ReceiveOutcome> {
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
    const quarantine = async (error: ACEError): Promise<ReceiveOutcome> => {
      try {
        return { kind: 'quarantined', error, fingerprint: await this.#writeQuarantine(env, error) };
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'quarantine write failed') };
      }
    };
    // 2. resolve the sender (before taking `threads`)
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
    // 3. known delivery
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
    const tr = this.#replay.clone();
    const rejected = async (e: unknown): Promise<ReceiveOutcome> => {
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
    };
    let parsed: ParsedMessage;
    try {
      parsed = await parseMessage(env, this.#identity, peer, { replay: tr, floor: this.#floor(), clock: this.#clock });
    } catch (e) { return rejected(e); }
    // 6. installed schema (deterministic; the bundled validation already ran inside parseMessage)
    const validator = this.#schemas.get(parsed.schemaDigest);
    if (validator !== undefined) {
      try { applySchema(validator, parsed); } catch (e) { return rejected(e); }
    }
    // Authentication/decryption precedes profile selection. No application metadata is public.
    if (this.#principal !== null && isPrincipalType(parsed.type)) {
      try { peer = await this.#refreshPrincipalSender(peer, this.#now()); }
      catch (e) {
        const err = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'peer refresh failed', { cause: e });
        return err.isTransient ? { kind: 'retryable', error: err } : rejected(err);
      }
    }
    const economic = this.#commerce && isEconomicType(parsed.type);
    if (economic && parsed.threadId === null) return rejected(new ACEError('invalid_envelope', 'commerce messages require a private threadId'));
    const principal = this.#principalCtx;
    const run = async (): Promise<ReceiveOutcome | DeliveryRecord> => {
      let record: ThreadRecord | null = null;
      let machine: ThreadStateMachine;
      try {
        if (economic) record = await this.#threads.loadRecord(env.conversationId, parsed.threadId!);
        machine = restoreMachine(this.#identity.getACEId(), record?.snapshot ?? null);
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'thread load failed') };
      }
      try {
        if (economic) {
          machine.apply(eventOf(parsed), parsed.body);
          if (record === null) await this.#threads.checkCanOpen(env.from);
        }
        if (principal !== undefined && isPrincipalType(parsed.type)) await checkPrincipal(parsed, peer, principal, this.#now());
      } catch (e) { return rejected(e); }
      // 7. durable commit
      const snapshot = economic ? machine.getSnapshot(env.conversationId, parsed.threadId!) : null;
      const delivery: DeliveryRecord = {
        fingerprint: envelopeFingerprint(env), message: parsed, receivedAt: this.#now(), status: 'pending', thread: snapshot,
      };
      try {
        await this.#writeDelivery(dkey, delivery); // 7.1 commit point
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', 'delivery write failed') };
      }
      try {
        if (principal !== undefined && parsed.type === 'decision') await fillDecision(this.#store, parsed); // 7.1a: mark the request decided
        if (snapshot !== null) await this.#threads.saveRecord({ snapshot, pending: clearedPending(record, snapshot) }, record); // 7.2
        await this.#store.write(REPLAY_KEY, canonicalStateBytes(tr.exportState())); // 7.3
        this.#replay = tr;
      } catch (e) {
        return this.#fail(e);
      }
      return delivery;
    };
    // The lock covers steps 5-7.3 only: onMessage runs unlocked, so a handler may stage a reply.
    const lockName = economic ? 'threads' : principal !== undefined && parsed.type === 'decision' ? 'requests' : null;
    let committed: ReceiveOutcome | DeliveryRecord;
    if (lockName === null) {
      committed = await run();
    } else {
      let release: () => Promise<void>;
      try {
        release = await this.#store.lock(lockName);
      } catch (e) {
        return { kind: 'retryable', error: asError(e, 'storage_failed', `${lockName} lock failed`) };
      }
      try {
        committed = await run();
      } finally {
        // A failure after the commit point keeps the lock held until close(), so no concurrent
        // Outbox.stage (or decision) can build on state that recovery has not repaired yet.
        if (this.#failed !== null) this.#heldLock = release;
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
        timestamp: m.timestamp, to: m.to, type: m.type, schemaDigest: m.schemaDigest,
      },
      receivedAt: d.receivedAt,
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
      code: error.code, envelope: envelopeKnownFields(env), fingerprint, quarantinedAt: this.#now(), reason, version: 1,
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
    // 1a: a decision's requests/ fill (no-op when already filled). A fill that throws bad_reference or
    // wrong_principal (only possible with a corrupted store: step 7 and the fill run under one lock) fails open().
    const decisions = records.filter(([, d]) => this.#principal !== null && d.message.type === 'decision');
    if (decisions.length > 0) {
      const release = await this.#store.lock('requests');
      try {
        for (const [, d] of decisions) await fillDecision(this.#store, d.message);
      } finally {
        await release();
      }
    }
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
    typeof doc.fingerprint !== 'string' || receivedAt === null || (doc.status !== 'pending' && doc.status !== 'acked') || typeof m !== 'object' || m === null
    || !isMessageId(m.messageId) || !isACEId(m.from) || !isACEId(m.to) || !isConversationId(m.conversationId)
    || typeof m.schemaDigest !== 'string' || !isConversationId(m.schemaDigest) || !isMessageType(m.type) || (m.threadId !== null && !isThreadId(m.threadId)) || wireInt(m.timestamp) === null
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
      type: m.type, schemaDigest: m.schemaDigest as string, threadId: (m.threadId as string | null), timestamp: m.timestamp as number, body: m.body as JSONObject,
    },
    receivedAt, status: doc.status, thread,
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
    if (cmp === -1) await threads.saveRecord({ snapshot: snap, pending: clearedPending(rec, snap) }, rec);
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

