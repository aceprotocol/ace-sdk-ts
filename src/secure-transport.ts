/** Authenticated, one-use MLS delivery. Network input always enters through parseMessage. */
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { MLS_MAX_KEY_PACKAGE_CHARS, MLS_MAX_MESSAGE_CHARS, OFFLINE_WINDOW_SECONDS, SECURE_DELIVERY_TTL_SECONDS } from './limits.js';
import { canonicalStateBytes, isACEId, isConversationId, hasExactKeys, isMessageId, isObj, nowOf, parseEnvelopeJSON, parseStateBytes, sha256Hex, utf8, wireInt } from './encoding.js';
import { decodeEnvelope, envelopeFingerprint, verifyEnvelopeSignature } from './envelope.js';
import { createMessage, parseMessage } from './messages.js';
import { ReplayDetector } from './replay.js';
import { PairwiseMLS, MLSError, type MLSEngine } from './session.js';
import { SerialQueue, withLock, type ACEStore, type CoordinatedStore } from './store.js';
import type { VerifiedPeer } from './discovery.js';
import type { ACEIdentity, ACEMessage, JSONObject } from './types.js';

export const SECURE_DELIVERY_TYPE = 'urn:ace:secure-delivery:2';
export const SECURE_DELIVERY_SCHEMA = sha256Hex('ace.secure-delivery.v2:hello,offer,data,ack;fresh-pairwise-mls;exact-envelope;outcome-receipt;120s');
const TTL = SECURE_DELIVERY_TTL_SECONDS;
const MAX_ACTIVE = 32;
const MAX_INBOUND_ROWS = 1024;
/** Expired `secure/in/` rows are never consulted (expired frames fail `#read`), so they are swept lazily. */
const SWEEP_SECONDS = 30;
const text = new TextDecoder('utf-8', { fatal: true });
type Frame = JSONObject & { kind: string; attempt: string; expiresAt: number; messageId: string; digest: string };
type Incoming = { peer: string; hello: Frame; nonce: string; response: ACEMessage; generation: number; session: PairwiseMLS };
/** `outcome` null: the inner envelope is decrypted but not yet handed over (no receipt exists). */
type Received = { version: 1; generation: number; expiresAt: number; peer: string; input: string; envelope: ACEMessage | null; response: ACEMessage | null; outcome: string | null };
export type SecureRoute = { attempt: string; kind: string; expiresAt: number };
export type SecureExchange = (request: ACEMessage, expected: SecureRoute) => Promise<ACEMessage>;
/** The receiver Inbox's verdict on the inner envelope; `rejected` carries its permanent error code. */
export type SecureOutcome = 'delivered' | 'duplicate' | { rejected: string };
/**
 * Must run the normal Inbox verification/profiles and durably, idempotently commit delivery, then RETURN
 * the outcome (it travels to the sender inside the receipt). Throw only for retryable/local failures:
 * no receipt is produced, the sender's attempt expires and it retries a fresh one.
 */
export type SecureAccept = (envelope: Uint8Array) => Promise<SecureOutcome>;
const REMOTE_CODE = /^[a-z0-9_]{1,64}$/;

function fail(code = 'invalid_delivery_frame'): never { throw new MLSError(code); }
function frame(value: JSONObject): Frame {
  const extra: Record<string, string[]> = { hello: [], offer: ['nonce', 'keyPackage'], data: ['nonce', 'welcome', 'ciphertext'], ack: ['nonce', 'ciphertext'] };
  if (typeof value.kind !== 'string' || !Object.hasOwn(extra, value.kind)) fail();
  if (!hasExactKeys(value, ['kind', 'attempt', 'expiresAt', 'messageId', 'digest', ...extra[value.kind]]) || !isConversationId(value.attempt) || !isConversationId(value.digest)
    || !isMessageId(value.messageId) || wireInt(value.expiresAt) === null) fail();
  if (value.kind !== 'hello' && !isConversationId(value.nonce)) fail();
  for (const field of ['keyPackage', 'welcome', 'ciphertext']) {
    if (field in value && (typeof value[field] !== 'string' || value[field].length > (field === 'keyPackage' ? MLS_MAX_KEY_PACKAGE_CHARS : MLS_MAX_MESSAGE_CHARS))) fail();
  }
  return value as Frame;
}
function matches(a: Frame, b: Frame): boolean {
  return ['attempt', 'expiresAt', 'messageId', 'digest'].every(k => a[k] === b[k]);
}
function receipt(f: Frame, outcome: string): string {
  return `ace.delivery.outcome.v1:${f.attempt}:${f.nonce}:${f.messageId}:${f.digest}:${outcome}`;
}
function outcomeText(outcome: SecureOutcome): string {
  if (outcome === 'delivered' || outcome === 'duplicate') return outcome;
  if (!hasExactKeys(outcome, ['rejected']) || typeof outcome.rejected !== 'string' || !REMOTE_CODE.test(outcome.rejected)) fail('invalid_session_input');
  return `rejected:${outcome.rejected}`;
}
/** A well-formed `secure/peers/` row for `peer`, or null. */
function peerRow(row: unknown, peer: string): { generation: number; allowed: boolean } | null {
  if (!isObj(row) || !hasExactKeys(row, ['allowed', 'generation', 'peer', 'version']) || row.version !== 1 || row.peer !== peer
    || typeof row.allowed !== 'boolean' || !Number.isSafeInteger(row.generation) || (row.generation as number) < 1) return null;
  return { generation: row.generation as number, allowed: row.allowed };
}
/** The admitted policy generation of a `secure/peers/` row, or null when missing, malformed or not allowed. */
function admitted(row: unknown, peer: string): number | null {
  const r = peerRow(row, peer);
  return r?.allowed ? r.generation : null;
}
const random = () => bytesToHex(randomBytes(32));
function coordinated(store: ACEStore): CoordinatedStore {
  return { coordinate: (name, body) => withLock(store, name, body) };
}
function peerKey(peer: string): string { return `secure/peers/${sha256Hex(peer)}.json`; }
function peerLock(peer: string): string { return `secure-peer-${sha256Hex(peer).slice(0, 48)}`; }

/**
 * Mandatory secure transport boundary, with no plaintext/static-message fallback.
 * A local administrator must explicitly enable each peer identity. Roles grant no access.
 * Applications retain their Inbox/Outbox and resource authority; this wraps their exact signed
 * envelopes. Each delivery consumes a fresh MLS group and erases it after confirmation.
 * exchange must carry request and response over an authenticated-addressed ACE transport;
 * both returned packets are independently verified here, so a malicious relay cannot enroll keys.
 */
export class SecureTransport {
  readonly #sessions = new Map<string, Incoming>();
  readonly #queue = new SerialQueue();
  #closed = false;
  #outgoing = 0;
  #nextSweep = 0;
  constructor(readonly identity: ACEIdentity, readonly engine: MLSEngine,
    readonly store: ACEStore, readonly clock: () => number = () => nowOf()) {}

  /** Local administrative decision. A discovery record or remote message must never call this. */
  static async setPeerAllowed(store: ACEStore, peer: string, allowed: boolean): Promise<void> {
    if (!isACEId(peer) || typeof allowed !== 'boolean') fail('invalid_session_input');
    await coordinated(store).coordinate(peerLock(peer), async data => {
      const raw = await data.read(peerKey(peer));
      const previous = raw ? peerRow(parseStateBytes(raw, peerKey(peer)), peer) ?? fail('invalid_delivery_policy') : { generation: 0 };
      if (previous.generation >= Number.MAX_SAFE_INTEGER) fail('session_limit');
      await data.write(peerKey(peer), canonicalStateBytes({ version: 1, peer, generation: previous.generation + 1, allowed }));
    });
  }

  /** Local admission read, before any peer resolution: no network, no pin. A missing or malformed row is false. */
  static async isPeerAllowed(store: ACEStore, peer: string): Promise<boolean> {
    if (!isACEId(peer)) return false;
    const raw = await store.read(peerKey(peer));
    if (!raw) return false;
    try { return admitted(parseStateBytes(raw, peerKey(peer)), peer) !== null; } catch { return false; }
  }

  async #allowed(peer: string): Promise<number> {
    if (this.#closed) fail('session_closed');
    const raw = await this.store.read(peerKey(peer));
    const generation = admitted(raw && parseStateBytes(raw, peerKey(peer)), peer);
    if (generation === null) fail('delivery_peer_disabled');
    return generation;
  }
  async #packet(peer: VerifiedPeer, body: Frame): Promise<ACEMessage> {
    return createMessage({ sender: this.identity, recipient: peer, type: SECURE_DELIVERY_TYPE,
      schemaDigest: SECURE_DELIVERY_SCHEMA, body, timestamp: this.clock() });
  }
  async #read(packet: ACEMessage, peer: VerifiedPeer): Promise<Frame> {
    await this.#allowed(peer.aceId);
    const parsed = await parseMessage(packet, this.identity, peer, { replay: new ReplayDetector({ clock: this.clock }), clock: this.clock });
    if (parsed.type !== SECURE_DELIVERY_TYPE || parsed.schemaDigest !== SECURE_DELIVERY_SCHEMA || parsed.threadId != null) fail('secure_delivery_required');
    const f = frame(parsed.body), now = this.clock();
    if (f.expiresAt <= now || f.expiresAt > now + TTL || f.expiresAt > parsed.timestamp + TTL) fail('delivery_expired');
    return f;
  }

  pendingHandshakes(): boolean { return [...this.#sessions.values()].some(s => s.hello.expiresAt > this.clock()); }
  async route(packet: ACEMessage, peer: VerifiedPeer): Promise<SecureRoute> {
    const f = await this.#read(packet, peer);
    return { attempt: f.attempt, kind: f.kind, expiresAt: f.expiresAt };
  }
  /**
   * Called from Outbox.deliver. A timeout/lost response throws; the Outbox must retain its operation.
   * A receipt carrying `rejected:<code>` is `ACEError('delivery_rejected')` (permanent, `remoteCode` = the Inbox code).
   * Nothing is journaled here: an interrupted attempt always starts a fresh one.
   */
  async deliver(envelope: ACEMessage, peer: VerifiedPeer, exchange: SecureExchange): Promise<void> {
    const inner = decodeEnvelope(envelope);
    if (inner.from !== this.identity.getACEId() || inner.to !== peer.aceId) fail();
    verifyEnvelopeSignature(inner, { scheme: this.identity.getSigningScheme(), signingPublicKey: this.identity.getSigningPublicKey() });
    if (inner.timestamp < this.clock() - OFFLINE_WINDOW_SECONDS) throw new ACEError('envelope_expired', 'original application envelope exceeds the offline retention window');
    const bytes = canonicalStateBytes(inner);
    if (bytes.length > 40_000) fail('session_limit');
    // Do not hold a peer lock while waiting for a reply: simultaneous sends must not deadlock.
    if (this.#outgoing >= MAX_ACTIVE) fail('session_limit');
    this.#outgoing++;
    let deadline = this.clock();
    let session: PairwiseMLS | undefined;
    try {
      const generation = await this.#allowed(peer.aceId);
      const hello: Frame = { kind: 'hello', attempt: random(), expiresAt: this.clock() + TTL,
        messageId: inner.messageId, digest: envelopeFingerprint(inner) };
      deadline = hello.expiresAt;
      const wallDeadline = Date.now() + TTL * 1000;
      const request = async (packet: ACEMessage, kind: string): Promise<ACEMessage> => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try { return await Promise.race([exchange(packet, { attempt: hello.attempt, kind, expiresAt: hello.expiresAt }), new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new MLSError('delivery_expired')), Math.max(0, wallDeadline - Date.now()));
        })]); } catch (error) {
          // Only the original application envelope can require re-signing.
          if (error instanceof ACEError && error.code === 'envelope_expired') fail('delivery_expired');
          throw error;
        } finally { clearTimeout(timer); }
      };
      const offer = await this.#read(await request(await this.#packet(peer, hello), 'offer'), peer);
      if (offer.kind !== 'offer' || !matches(hello, offer)) fail();
      session = await PairwiseMLS.open(this.engine, coordinated(this.store), inner.from, inner.to);
      const welcome = (await session.create(offer.keyPackage as string)).message!;
      const ciphertext = (await session.send(bytes)).message!;
      const data: Frame = { ...hello, kind: 'data', nonce: offer.nonce, welcome, ciphertext };
      // An interrupted operation starts a fresh attempt, while the host Outbox keeps exactly
      // the same application envelope / ID.
      const packet = await this.#packet(peer, data);
      if (await this.#allowed(peer.aceId) !== generation) fail('delivery_peer_disabled');
      if (this.clock() >= hello.expiresAt) fail('delivery_expired');
      const ack = await this.#read(await request(packet, 'ack'), peer);
      if (ack.kind !== 'ack' || !matches(hello, ack) || ack.nonce !== offer.nonce) fail();
      let received: string;
      try { received = text.decode(PairwiseMLS.plaintext(await session.receive(ack.ciphertext as string))); }
      catch (error) { if (error instanceof MLSError || error instanceof ACEError) throw error; fail('invalid_delivery_receipt'); }
      const prefix = receipt(data, '');
      const outcome = received.startsWith(prefix) ? received.slice(prefix.length) : '';
      const rejected = /^rejected:([a-z0-9_]{1,64})$/.exec(outcome);
      if (outcome !== 'delivered' && outcome !== 'duplicate' && rejected === null) fail('invalid_delivery_receipt');
      if (await this.#allowed(peer.aceId) !== generation) fail('delivery_peer_disabled');
      if (rejected !== null) throw new ACEError('delivery_rejected', `the receiver's Inbox rejected the envelope: ${rejected[1]}`, { remoteCode: rejected[1] });
    } finally {
      this.#outgoing--;
      await session?.close();
    }
    if (this.clock() >= deadline) fail('delivery_expired');
  }

  /**
   * Only hello/data packets are accepted. Responses are durable before returning to transport.
   * The receipt encodes the Inbox outcome, so the Inbox runs while the attempt's MLS context is
   * still alive; a replayed data frame of a completed attempt re-sends the same receipt. After
   * process loss the context is gone: the attempt is `session_closed` and the sender retries a fresh one.
   */
  respond(packet: ACEMessage, peer: VerifiedPeer, accept: SecureAccept): Promise<ACEMessage> {
    return this.#queue.run(async () => this.#respond(await this.#read(packet, peer), peer, accept));
  }
  /**
   * @internal SecureMailbox ingress: `route` and `respond` with one parse. An offer/ack (a reply to this
   * process's own send, read by the sending process) returns null.
   */
  async receive(packet: ACEMessage, peer: VerifiedPeer, accept: SecureAccept): Promise<ACEMessage | null> {
    const f = await this.#read(packet, peer);
    if (f.kind === 'offer' || f.kind === 'ack') return null;
    return this.#queue.run(() => this.#respond(f, peer, accept));
  }
  async #respond(f: Frame, peer: VerifiedPeer, accept: SecureAccept): Promise<ACEMessage> {
    if (f.kind !== 'hello' && f.kind !== 'data') fail();
    const release = await this.store.lock(peerLock(peer.aceId));
    try {
      const generation = await this.#allowed(peer.aceId);
      await this.#sweep();
      const key = `secure/in/${f.attempt}.json`;
      if (f.kind === 'hello') {
        const active = this.#sessions.get(f.attempt);
        if (active) {
          if (active.peer !== peer.aceId || active.generation !== generation || !matches(active.hello, f)) fail();
          return active.response;
        }
        // A prior attempt never gets a replacement key package after process loss.
        if (await this.store.read(key) !== null) fail('session_closed');
        if (this.#sessions.size >= MAX_ACTIVE || !await this.#inboundRoom()) fail('session_limit');
        const session = await PairwiseMLS.open(this.engine, coordinated(this.store), this.identity.getACEId(), peer.aceId);
        try {
          const offer: Frame = { ...f, kind: 'offer', nonce: random(), keyPackage: session.state.keyPackage };
          const response = await this.#packet(peer, offer);
          await this.store.write(key, canonicalStateBytes({ version: 1, peer: peer.aceId, expiresAt: f.expiresAt, generation, response }));
          this.#sessions.set(f.attempt, { peer: peer.aceId, hello: f, nonce: offer.nonce as string, response, generation, session });
          return response;
        } catch (error) { await session.close(); throw error; }
      }
      const input = sha256Hex(canonicalStateBytes(f));
      const raw = await this.store.read(key);
      if (!raw) fail('session_closed');
      const saved = parseStateBytes(raw, key) as Received;
      let response: ACEMessage;
      if (saved.input !== undefined) {
        if (saved.version !== 1 || saved.peer !== peer.aceId || saved.generation !== generation || saved.input !== input) fail();
        if (saved.outcome === null) fail(saved.envelope === null ? 'invalid_delivery_journal' : 'session_closed');
        if (saved.response === null) fail('invalid_delivery_journal');
        response = saved.response;
      } else {
        const active = this.#sessions.get(f.attempt);
        if (!active || active.peer !== peer.aceId || active.generation !== generation || !matches(active.hello, f) || active.nonce !== f.nonce) fail('session_closed');
        try {
          await active.session.join(f.welcome as string);
          const decoded = PairwiseMLS.plaintext(await active.session.receive(f.ciphertext as string));
          const envelope = decodeEnvelope(parseEnvelopeJSON(decoded));
          if (envelope.from !== peer.aceId || envelope.to !== this.identity.getACEId()
            || envelope.messageId !== f.messageId || envelopeFingerprint(envelope) !== f.digest) fail();
          const received: Received = { version: 1, generation, expiresAt: f.expiresAt, peer: peer.aceId, input, envelope, response: null, outcome: null };
          await this.store.write(key, canonicalStateBytes(received));
          // The receipt is NEVER produced before the Inbox commits; its outcome is the Inbox's verdict.
          const outcome = outcomeText(await accept(canonicalStateBytes(envelope)));
          const ciphertext = (await active.session.send(utf8(receipt(f, outcome)))).message!;
          response = await this.#packet(peer, { kind: 'ack', attempt: f.attempt, expiresAt: f.expiresAt,
            messageId: f.messageId, digest: f.digest, nonce: f.nonce, ciphertext });
          await this.store.write(key, canonicalStateBytes({ ...received, envelope: null, response, outcome }));
        } finally { this.#sessions.delete(f.attempt); await active.session.close(); }
      }
      if (this.clock() >= f.expiresAt) fail('delivery_expired');
      await this.#allowed(peer.aceId);
      return response;
    } finally { await release(); }
  }
  /** Room for another inbound attempt row; a full table is swept before it is refused. */
  async #inboundRoom(): Promise<boolean> {
    if ((await this.store.list('secure/in/')).length < MAX_INBOUND_ROWS) return true;
    await this.#sweep(true);
    return (await this.store.list('secure/in/')).length < MAX_INBOUND_ROWS;
  }
  async #sweep(force = false): Promise<void> {
    const now = this.clock();
    if (force || now >= this.#nextSweep) {
      this.#nextSweep = now + SWEEP_SECONDS;
      for (const key of await this.store.list('secure/in/')) {
        const raw = await this.store.read(key);
        if (raw && (parseStateBytes(raw, key) as Received).expiresAt <= now) await this.store.delete(key);
      }
    }
    for (const [id, active] of this.#sessions) if (active.hello.expiresAt <= now) {
      this.#sessions.delete(id); await active.session.close();
    }
  }
  async close(): Promise<void> {
    this.#closed = true;
    await this.#queue.run(async () => {
      const results = await Promise.allSettled([...this.#sessions.values()].map(active => active.session.close()));
      this.#sessions.clear();
      const failed = results.find(result => result.status === 'rejected');
      if (failed?.status === 'rejected') throw failed.reason;
    });
  }
}
