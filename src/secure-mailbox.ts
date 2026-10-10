import { ACEError } from './errors.js';
import { canonicalStateBytes, isObj, isStreamId, parseEnvelopeJSON, parseStateBytes, sha256Hex, utf8 } from './encoding.js';
import { decodeEnvelope, envelopeFingerprint } from './envelope.js';
import { Inbox, type InboxOptions, type ReceiveOutcome } from './inbox.js';
import { MAX_DIRECT_BODY_BYTES, MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE, SECURE_DELIVERY_TTL_SECONDS } from './limits.js';
import type { Outbox } from './outbox.js';
import { PeerStore } from './peer-store.js';
import { compareStreamIds, type RelayClient } from './relay.js';
import { MLSError, type MLSEngine } from './session.js';
import { SecureTransport, type SecureRoute } from './secure-transport.js';
import { SerialQueue, type ACEStore } from './store.js';
import type { ACEIdentity, ACEMessage, ParsedMessage } from './types.js';
import type { VerifiedPeer } from './discovery.js';

const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
function errorOf(error: unknown): ACEError {
  if (error instanceof ACEError) return error;
  if (error instanceof MLSError) {
    const permanent = ['invalid_delivery_frame', 'invalid_session_input', 'invalid_session_message', 'invalid_session_members',
      'secure_delivery_required', 'delivery_expired', 'delivery_peer_disabled', 'session_closed', 'session_limit'];
    return new ACEError(permanent.includes(error.code) ? 'invalid_body' : 'storage_failed', error.code);
  }
  return new ACEError('storage_failed', 'secure delivery failed', { cause: error });
}
/** The direct-delivery `error` of a permanent frame refusal: the session-core code itself (08 § Receiver). */
function wireCode(error: unknown, e: ACEError): string {
  return error instanceof MLSError ? error.code : e.code;
}
/**
 * The HTTP answer to a direct-delivery request (08-relay § Direct Delivery). `outcome` is set
 * when the `message` member reached the pipeline. A `data` frame whose inner envelope the Inbox
 * rejected is still an accepted frame (200, `outcome.kind === 'quarantined'`): the rejection
 * travels to the sender inside the receipt. 400 is a frame-level failure.
 */
export interface DirectReply {
  status: 200 | 400 | 413 | 503;
  body: { ok: true; messageId: string } | { ok: false; error: string };
  outcome?: ReceiveOutcome;
}

/**
 * The result of `SecureMailbox.pull`: every non-retryable outcome in relay order, the error that
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

export interface SecureMailboxOptions {
  identity: ACEIdentity; store: ACEStore; peers: PeerStore; relay: RelayClient; secure: SecureTransport; inbox: Inbox;
  /** False when the caller owns a transport shared by several mailboxes in one scope. */
  closeTransport?: boolean;
  /** Releases the host engine after all contexts close. */
  dispose?: () => void;
}
const cursorKey = (baseUrl: string) => `secure/cursors/${sha256Hex(baseUrl)}.json`;
/** The only network receive boundary. The contained Inbox receives authenticated MLS plaintext only. */
export class SecureMailbox {
  readonly #queue = new SerialQueue();
  #closed = false;
  #cursor: string | undefined;
  #key: string;
  private constructor(readonly options: SecureMailboxOptions, readonly release: () => Promise<void>, key: string, cursor?: string) {
    this.#cursor = cursor; this.#key = key;
  }
  static async open(options: SecureMailboxOptions): Promise<SecureMailbox> {
    const release = await options.store.lock('secure-mailbox', { timeoutMs: 0 });
    try {
      const key = cursorKey(options.relay.baseUrl), raw = await options.store.read(key);
      let cursor: string | undefined;
      if (raw) {
        const row = parseStateBytes(raw, key);
        if (!isObj(row) || row.version !== 1 || row.identity !== options.identity.getACEId() || !isStreamId(row.cursor)) {
          throw new ACEError('storage_failed', 'invalid secure cursor');
        }
        cursor = row.cursor;
      }
      return new SecureMailbox(options, release, key, cursor);
    } catch (error) { await release(); throw error; }
  }
  cursor(relay: RelayClient): string | null { return relay.baseUrl === this.options.relay.baseUrl ? this.#cursor ?? null : null; }
  #check(relay = this.options.relay): void {
    if (this.#closed || relay.baseUrl !== this.options.relay.baseUrl) throw new ACEError('invalid_argument', 'secure mailbox closed or wrong relay');
  }
  async #advance(streamId: string): Promise<void> {
    if (this.#cursor && compareStreamIds(streamId, this.#cursor) <= 0) return;
    await this.options.store.write(this.#key, canonicalStateBytes({ version: 1, identity: this.options.identity.getACEId(), cursor: streamId }));
    this.#cursor = streamId;
  }
  async #ingest(envelope: ACEMessage): Promise<ReceiveOutcome[]> {
    this.#check();
    // Admission precedes any peer resolution: an unadmitted stranger costs no relay lookup and is never pinned.
    if (!await SecureTransport.isPeerAllowed(this.options.secure.store, envelope.from)) throw new MLSError('delivery_peer_disabled');
    const peer = await this.options.peers.resolve(envelope.from);
    const outcomes: ReceiveOutcome[] = [];
    const reply = await this.options.secure.receive(envelope, peer, async bytes => {
      const outcome = await this.options.inbox.receive(bytes);
      if (outcome.kind === 'retryable') throw outcome.error;
      outcomes.push(outcome);
      return outcome.kind === 'quarantined' ? { rejected: outcome.error.code } : outcome.kind;
    });
    // Sending processes read signed replies (offer/ack) using their own non-destructive cursor.
    if (reply === null) return [];
    // Do not call a peer's direct endpoint under the receive lock: simultaneous calls can deadlock.
    await this.options.relay.send(reply);
    return outcomes;
  }
  /**
   * `frame` is the wire code of a permanent frame-level failure (the frame itself was refused), as opposed
   * to an Inbox outcome. `input` is the relay entry's raw bytes, or an envelope the caller already decoded.
   */
  async #receive(input: Uint8Array | ACEMessage, streamId?: string): Promise<{ outcomes: ReceiveOutcome[]; frame: string | null }> {
    return this.#queue.run(async () => {
      this.#check();
      if (streamId && this.#cursor && compareStreamIds(streamId, this.#cursor) <= 0) return { outcomes: [], frame: null };
      let outcomes: ReceiveOutcome[];
      let frame: string | null = null;
      let envelope: ACEMessage | null = input instanceof Uint8Array ? null : input;
      try {
        if (envelope === null) {
          const raw = input as Uint8Array;
          if (raw.length > MAX_ENVELOPE_BYTES) throw new ACEError('invalid_envelope', 'envelope too large');
          envelope = decodeEnvelope(parseEnvelopeJSON(raw));
        } else if (canonicalStateBytes(envelope).length > MAX_ENVELOPE_BYTES) throw new ACEError('invalid_envelope', 'envelope too large');
        outcomes = await this.#ingest(envelope);
      } catch (error) {
        const e = errorOf(error);
        if (e.category !== 'permanent') throw e;
        outcomes = [{ kind: 'quarantined', error: e, fingerprint: envelope && envelopeFingerprint(envelope) }];
        frame = wireCode(error, e);
      }
      if (streamId) await this.#advance(streamId);
      return { outcomes, frame };
    });
  }
  async pull(relay: RelayClient, o: { limit?: number; maxPages?: number; signal?: AbortSignal } = {}): Promise<PullResult> {
    const outcomes: ReceiveOutcome[] = [];
    try {
      this.#check(relay);
      const limit = o.limit ?? MAX_INBOX_PAGE;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_INBOX_PAGE ||
        (o.maxPages !== undefined && (!Number.isSafeInteger(o.maxPages) || o.maxPages < 1))) throw new ACEError('invalid_argument', 'invalid page bounds');
      const deadline = Date.now() + SECURE_DELIVERY_TTL_SECONDS * 1000;
      let pages = 0;
      while (!o.signal?.aborted && Date.now() < deadline) {
        // Finish offers already issued before a short-lived tool invocation releases its keys.
        if (o.maxPages !== undefined && pages >= o.maxPages && !this.options.secure.pendingHandshakes()) return new PullResult(outcomes, null, true);
        const page = await relay.fetchInbox(this.options.identity, { since: this.#cursor, limit });
        if (page.entries.length) pages++;
        for (const entry of page.entries) {
          if (o.signal?.aborted) return new PullResult(outcomes, null, true);
          outcomes.push(...(await this.#receive(utf8(JSON.stringify(entry.message)), entry.streamId)).outcomes);
        }
        if (page.entries.length < limit && !this.options.secure.pendingHandshakes()) return new PullResult(outcomes, null);
        if (page.entries.length < limit) await pause(1000);
        if (outcomes.length >= 10_000) return new PullResult(outcomes, null, true);
      }
      return new PullResult(outcomes, null, true);
    } catch (error) { return new PullResult(outcomes, errorOf(error)); }
  }
  async *follow(relay: RelayClient, o: { signal?: AbortSignal; onLive?: () => void } = {}): AsyncGenerator<ReceiveOutcome> {
    const backlog = await this.pull(relay, { signal: o.signal });
    for (const outcome of backlog.outcomes) yield outcome;
    if (backlog.blocked) throw backlog.blocked;
    if (o.signal?.aborted) return;
    for await (const event of relay.listen(this.options.identity, { since: this.#cursor, signal: o.signal, onOpen: o.onLive })) {
      for (const outcome of (await this.#receive(utf8(event.data), event.streamId)).outcomes) yield outcome;
      if (o.signal?.aborted) return;
    }
  }
  async receiveDirect(body: Uint8Array): Promise<DirectReply> {
    const fail = (status: 400 | 413 | 503, error: string): DirectReply => ({ status, body: { ok: false, error } });
    // Not accepting (08 § Receiver): not a fault of the request, so the sender falls back to the relay.
    if (this.#closed) return fail(503, 'internal_error');
    if (body.length > MAX_DIRECT_BODY_BYTES) return fail(413, 'payload_too_large');
    try {
      let wrapper: unknown;
      try { wrapper = parseEnvelopeJSON(body); } catch { return fail(400, 'invalid_argument'); }
      if (!isObj(wrapper) || !('message' in wrapper)) return fail(400, 'invalid_argument');
      const env = decodeEnvelope(wrapper.message);
      const { outcomes, frame } = await this.#receive(env);
      // A rejected inner envelope is an accepted frame: the Inbox code reaches the sender inside the receipt.
      if (frame !== null && outcomes[0]) return { ...fail(400, frame), outcome: outcomes[0] };
      return { status: 200, body: { ok: true, messageId: env.messageId }, ...(outcomes[0] ? { outcome: outcomes[0] } : {}) };
    } catch (error) {
      if (this.#closed) return fail(503, 'internal_error'); // closed meanwhile
      const e = errorOf(error);
      return e.category === 'permanent' ? fail(400, wireCode(error, e)) : { ...fail(503, e.code), outcome: { kind: 'retryable', error: e } };
    }
  }
  async close(): Promise<void> {
    if (this.#closed) return; this.#closed = true;
    await this.#queue.run(async () => {
      try { if (this.options.closeTransport !== false) await this.options.secure.close(); }
      finally { try { await this.options.inbox.close(); } finally { try { this.options.dispose?.(); } finally { await this.release(); } } }
    });
  }
}

/** Independent reply reader for a sender while another process owns its receive mailbox. */
export class SecureRelayReplies {
  #cursor: string | undefined;
  constructor(readonly identity: ACEIdentity, readonly secure: SecureTransport, readonly relay: RelayClient,
    readonly peer: VerifiedPeer, readonly send: (packet: ACEMessage) => Promise<unknown>, since?: string) { this.#cursor = since; }
  async exchange(packet: ACEMessage, expected: SecureRoute): Promise<ACEMessage> {
    // Wait no longer than the attempt itself stays valid.
    const remaining = Math.min(SECURE_DELIVERY_TTL_SECONDS, expected.expiresAt - this.secure.clock());
    const deadline = Date.now() + Math.max(0, remaining) * 1000;
    if (Date.now() >= deadline) throw new MLSError('delivery_expired');
    await this.send(packet);
    while (Date.now() < deadline) {
      const page = await this.relay.fetchInbox(this.identity, { since: this.#cursor });
      for (const entry of page.entries) {
        this.#cursor = entry.streamId;
        try {
          const candidate = decodeEnvelope(entry.message);
          if (candidate.from !== this.peer.aceId) continue;
          const route = await this.secure.route(candidate, this.peer);
          if (route.attempt === expected.attempt && route.kind === expected.kind) return candidate;
        } catch { /* Unrelated/unverified frames cannot select this local pending attempt. */ }
      }
      if (page.entries.length < MAX_INBOX_PAGE) await pause(Math.min(1000, Math.max(0, deadline - Date.now())));
    }
    throw new MLSError('delivery_expired');
  }
}

/** Everything `openSecureMailbox` composes: the receive side of one identity on one relay. */
export interface SecureMailboxSetup {
  identity: ACEIdentity; store: ACEStore; peers: PeerStore; relay: RelayClient;
  /** The MLS engine (Node: `loadMLSEngine()` from `@ace-protocol/sdk/node`). The mailbox frees it at `close()` when it can. */
  engine: MLSEngine & { free?(): void };
  /** The Inbox options other than the shared identity, store and peers (onMessage, commerce, principal, schemas, clock, …). */
  inbox: Omit<InboxOptions, 'identity' | 'store' | 'peers'>;
  /** The secure transport's clock (seconds); default wall clock. */
  clock?: () => number;
}

/**
 * The recommended way to open the network receive boundary: `Inbox.open` → `new SecureTransport` →
 * `SecureMailbox.open` with `closeTransport: true` and `dispose: () => engine.free?.()`, so one `close()`
 * releases the receive lock, the transport and the engine. A failure after the Inbox opened closes it
 * (no leaked `receive` lock) before rethrowing; the engine is then still the caller's to free.
 */
export async function openSecureMailbox(setup: SecureMailboxSetup): Promise<SecureMailbox> {
  const { identity, store, peers, relay, engine } = setup;
  const inbox = await Inbox.open({ ...setup.inbox, identity, store, peers });
  try {
    const secure = new SecureTransport(identity, engine, store, setup.clock);
    return await SecureMailbox.open({ identity, store, peers, relay, secure, inbox, closeTransport: true, dispose: () => engine.free?.() });
  } catch (error) {
    try { await inbox.close(); } catch { /* the open failure is the error to surface */ }
    throw error;
  }
}

/** One secure delivery to one verified peer: the sender's transport, its relay and the frame transport. */
export interface SecureSend {
  identity: ACEIdentity; secure: SecureTransport; relay: RelayClient; peer: VerifiedPeer;
  /** Frame transport; default `relay.send`. Node hosts pass `deliverDirectOrRelay(relay, peer.profile?.endpoint)`. */
  send?: (packet: ACEMessage) => Promise<unknown>;
}

/**
 * The `Outbox.deliver` transport for `s.peer`: every frame of the handshake goes out through `s.send`
 * (the relay by default) and its signed reply is read back through the relay (`SecureRelayReplies`).
 */
export function secureTransportFor(s: SecureSend): (envelope: ACEMessage) => Promise<void> {
  const replies = new SecureRelayReplies(s.identity, s.secure, s.relay, s.peer, s.send ?? ((packet) => s.relay.send(packet)));
  return (envelope) => s.secure.deliver(envelope, s.peer, (packet, route) => replies.exchange(packet, route));
}

/**
 * `outbox.deliver(requestId, secureTransportFor(s))`: resolves once the peer's Inbox durably committed the
 * envelope. On failure the operation stays pending under `requestId`; retry that ID, never stage a new one.
 */
export async function deliverSecure(outbox: Outbox, requestId: string, s: SecureSend): Promise<void> {
  await outbox.deliver(requestId, secureTransportFor(s));
}
