/**
 * The receive pipeline (06 § Receive pipeline). For an admitted sender:
 *   1 packet shape → 2 admission → 3 sender KEL pin (refreshed at most once) → 4 operational signature (delegation
 *   seq, signed while live, usable now) → 5 time window → 6 decrypt with the referenced prekey → 7 `(type,
 *   schemaDigest)` installed → 8 body schema → 9 dedupe → 10 profile rules and persist → 11 receipt, then relay ack.
 * A sender outside the admission table is processed only as a contact candidate (this identity's card record is `open`
 * and the packet is an `ace:contact:1` request; that path never queries the network and never writes a pin) or as a
 * recovery candidate (its content presents a permit this identity issued it and its PublishedAgent, 05 § Admission
 * recovery; pinned only once every check passed). Neither path queries the network; both decrypt first.
 *
 * Outcomes: signature, decryption and admission failures are silently dropped (and acknowledged); schema and rule
 * failures are answered with `rejected:<code>`; a duplicate is answered `delivered`; a message beyond the replay
 * horizon is dropped (`replay_horizon`) without a receipt; storage failures and capacity back-pressure are `deferred`
 * (not acknowledged). A packet fetched MAX_FETCH_ATTEMPTS times without a final disposition is quarantined and
 * acknowledged; one already delivered whose receipt send keeps failing is acknowledged without a quarantine record.
 */
import { AdmissionBook, type PeerRecord } from './admission.js';
import { checkContactBody, checkReceiptBody, type ContactBody, type ReceiptBody } from './core-messages.js';
import { checkStrangerSource, verifyPermit, verifyPublishedAgent, type DeliveryPermit, type VerifiedAgent } from './descriptor.js';
import type { Contact } from './card-record.js';
import { ACEError, asACEError } from './errors.js';
import { canonicalStateBytes, conversationKey, fromBase64, isACEId, isMessageId, isObj, nowOf, pairKey, parseJSONBytes, parseStateBytes, sha256Hex, wireInt } from './encoding.js';
import { checkUsable, type ACEIdentity } from './identity.js';
import type { KelState } from './kel.js';
import { DEFAULT_REPLAY_CAPACITY, MAX_FETCH_ATTEMPTS, OFFLINE_WINDOW_SECONDS, PIN_REFRESH_INTERVAL_SECONDS } from './limits.js';
import { CONTACT_TYPE, RECEIPT_TYPE, type ProfileSet } from './manifest.js';
import {
  checkPacketTime, decodePacket, decodePrivateContent, openPacketPlaintext, parsePacket, verifyPacketSignature, type Packet,
} from './packet.js';
import { PeerStore } from './peer-store.js';
import { prekeyId, type PrekeyVault } from './prekey.js';
import type { RelayClient } from './relay.js';
import { ReplayDetector, SEEN_FLOOR_SECONDS, type ReplayState } from './replay.js';
import { checkRules, commitRules, ruleEvent, rulesFor, type ProfileRules, type RuleEvent } from './rules.js';
import { SerialQueue, type ACEStore } from './store.js';
import type { Admission, ParsedMessage, PrivateContent } from './types.js';

export interface ContactEvent {
  from: string;
  messageId: string;
  timestamp: number;
  body: ContactBody;
  /** The verified source descriptor. */
  source: VerifiedAgent;
  /** The verified reply permit (absent for `rejected`). */
  permit?: DeliveryPermit;
  /** True when the sender was not in the admission table (a stranger's request to an `open` identity). */
  stranger: boolean;
}

export type ReceiveOutcome =
  | { kind: 'delivered'; message: ParsedMessage }
  | { kind: 'duplicate'; from: string; messageId: string }
  | { kind: 'rejected'; from: string; messageId: string; error: ACEError }
  | { kind: 'receipt'; from: string; body: ReceiptBody }
  | { kind: 'contact'; event: ContactEvent }
  | { kind: 'dropped'; error: ACEError }
  | { kind: 'deferred'; error: ACEError };

export interface InboxOptions {
  identity: ACEIdentity;
  store: ACEStore;
  vault: PrekeyVault;
  profiles: ProfileSet;
  peers?: PeerStore;
  admission?: AdmissionBook;
  rules?: ProfileRules[];
  /**
   * This identity's published card record `contact`; strangers' contact requests are processed only when `open`.
   * Default `closed` (no card record is `closed`).
   */
  contact?: () => Contact | Promise<Contact>;
  /** Persist the message durably and idempotently keyed by (from, messageId). Throwing defers the packet. */
  onMessage: (m: ParsedMessage) => void | Promise<void>;
  /** Effect-free capacity check; throw `receiver_capacity` to leave the packet on the relay. */
  checkCapacity?: (m: ParsedMessage) => void | Promise<void>;
  onReceipt?: (from: string, body: ReceiptBody) => void | Promise<void>;
  onContact?: (event: ContactEvent) => void | Promise<void>;
  /**
   * Encrypt and send a receipt to `to` (receipts are never queued in the Outbox; a permit renewal is the sender's to
   * add). One attempt: a transient failure defers the packet.
   */
  sendReceipt?: (to: string, body: ReceiptBody) => Promise<void>;
  /**
   * True while a rule-governed message of ours to `peer` on `threadId` awaits its receipt (`Outbox.busy`). The peer's
   * rule-governed messages on that thread are then rejected with `thread_busy` (08 § Profile rules).
   */
  threadBusy?: (peer: string, threadId: string) => Promise<boolean>;
  /** Fetch an admitted peer's current descriptor and adopt its KEL into `peers`. */
  refreshPeer?: (aceId: string) => Promise<void>;
  /**
   * Internal (NetworkClient): pin a recovery candidate's `source`, already verified (05 § Admission recovery), and cache
   * its descriptor, so a reply can reach a sender homed at another relay. Default: adopt its KEL into `peers` only.
   */
  importSource?: (source: VerifiedAgent) => Promise<void>;
  capacity?: number;
  clock?: () => number;
  /** Development only: accept loopback `http://` relays in contact sources. */
  allowLoopbackRelays?: boolean;
}

/**
 * A delivery record (06 § Crash recovery). `pending` carries the message: it is the only copy recovery can hand over.
 * `done` keeps just the seen entry until the next snapshot, never the delivered plaintext; receipts and contacts write
 * only `done`, after their hand-over.
 */
type Journal = { from: string; messageId: string; timestamp: number } & ({ status: 'pending'; message: ParsedMessage } | { status: 'done' });

/**
 * The store lock an open Inbox holds for its lifetime (one receiver per store). A host that must exclude a receiver,
 * e.g. while replacing the identity, takes it with `timeoutMs: 0`.
 */
export const RECEIVE_LOCK = 'receive';
const REPLAY_KEY = 'inbox/replay.json';
const SNAPSHOT_EVERY = 256;
const journalKey = (from: string, id: string) => `inbox/journal/${pairKey(from, id)}.json`;
const attemptsKey = (fp: string) => `inbox/attempts/${fp}.json`;
const QUARANTINE_PREFIX = 'inbox/quarantine/';
/** Quarantine records are a few hundred bytes; past the cap the oldest are pruned down to QUARANTINE_KEEP. */
const QUARANTINE_CAP = 1000;
const QUARANTINE_KEEP = 900;

/** The scalar header fields of a (possibly malformed) packet, strings cut to 256 characters; never the ciphertext. */
function packetHeader(value: unknown): Record<string, string | number> | null {
  if (!isObj(value)) return null;
  const fields: Record<string, unknown> = { ...value, prekey: isObj(value.encryption) ? value.encryption.prekey : undefined };
  const out: Record<string, string | number> = {};
  for (const k of ['ace', 'from', 'to', 'messageId', 'timestamp', 'prekey']) {
    const v = fields[k];
    if (typeof v === 'string') out[k] = v.slice(0, 256);
    else if (wireInt(v) !== null) out[k] = v as number;
  }
  return out;
}

const drop = (error: ACEError): ReceiveOutcome => ({ kind: 'dropped', error });
const defer = (error: ACEError): ReceiveOutcome => ({ kind: 'deferred', error });
/** A transient failure is retried later; anything else is dropped. */
const settle = (error: ACEError): ReceiveOutcome => error.isTransient ? defer(error) : drop(error);
/**
 * Whether content bytes that failed step 7 name a receipt or contact type (peeked with the strict JSON parser before
 * validation): such packets are never receipted, only dropped (06 § Receive pipeline). Bytes the strict parser refuses
 * (duplicate keys, excess depth, ...) are not core content, so they are rejected.
 */
function isCoreContent(plaintext: Uint8Array): boolean {
  let c: unknown;
  try { c = parseJSONBytes(plaintext, 'invalid_body', 'plaintext'); } catch { return false; }
  return isObj(c) && (c.type === RECEIPT_TYPE || c.type === CONTACT_TYPE);
}
/**
 * Deferrals of a packet already delivered (or a duplicate) whose `delivered` receipt failed to send, mapped to the
 * outcome it had: past the fetch budget it is acknowledged as that, without a quarantine record (06 § Acknowledgement).
 */
/**
 * Strip the carried `prekey` from decoded `content` (it is never validated as part of the body nor handed over) and
 * return it.
 */
function takeOffer(content: PrivateContent): string {
  const offered = content.prekey!; // decodePrivateContent checked it
  delete content.prekey;
  return offered;
}
const RECEIPT_ONLY = new WeakMap<ReceiveOutcome, ReceiveOutcome>();

/** A persisted journal entry, validated: anything malformed is `storage_failed`, never read as done. */
function checkJournal(v: unknown, key: string): Journal {
  const m = isObj(v) ? v.message : undefined;
  const ok = isObj(v) && isACEId(v.from) && isMessageId(v.messageId) && journalKey(v.from, v.messageId) === key && wireInt(v.timestamp) !== null
    && (v.status === 'done' ? m === undefined : v.status === 'pending' && isObj(m) && m.from === v.from && m.messageId === v.messageId
      && m.timestamp === v.timestamp && typeof m.type === 'string' && isObj(m.body));
  if (!ok) throw new ACEError('storage_failed', `${key} is not a valid journal entry`);
  return v as unknown as Journal;
}

/** One open Inbox per store (lock `receive`, held until `close`). */
export class Inbox {
  readonly #o: InboxOptions;
  readonly #me: string;
  readonly #peers: PeerStore;
  readonly #admission: AdmissionBook;
  readonly #rules: ProfileRules[];
  readonly #queue = new SerialQueue();
  readonly #release: () => Promise<void>;
  readonly #lastRefresh = new Map<string, number>();
  #replay: ReplayDetector;
  #dirty = 0;
  #closed = false;

  private constructor(o: InboxOptions, release: () => Promise<void>, replay: ReplayDetector) {
    this.#o = o;
    this.#me = o.identity.getACEId();
    this.#peers = o.peers ?? new PeerStore({ store: o.store, clock: o.clock });
    this.#admission = o.admission ?? new AdmissionBook(o.store);
    this.#rules = o.rules ?? [];
    this.#release = release;
    this.#replay = replay;
  }

  static async open(o: InboxOptions): Promise<Inbox> {
    if (typeof o?.onMessage !== 'function' || !o.store || !o.vault || !o.profiles) throw new ACEError('invalid_argument', 'identity, store, vault, profiles and onMessage are required');
    const release = await o.store.lock(RECEIVE_LOCK, { timeoutMs: 0 });
    try {
      const capacity = o.capacity ?? DEFAULT_REPLAY_CAPACITY;
      const raw = await o.store.read(REPLAY_KEY);
      // 06 § Deduplication: missing state beside existing delivery history is a storage failure, not a new store.
      if (raw === null && (await o.store.list('inbox/journal/')).length > 0) throw new ACEError('storage_failed', `${REPLAY_KEY} is missing beside the inbox journal`);
      const replay = raw === null
        ? new ReplayDetector({ capacity, clock: o.clock })
        : ReplayDetector.fromState(parseStateBytes(raw, REPLAY_KEY) as ReplayState, { capacity, clock: o.clock });
      const inbox = new Inbox(o, release, replay);
      await inbox.#recover();
      return inbox;
    } catch (e) {
      await release().catch(() => {});
      throw e instanceof ACEError ? e : new ACEError('storage_failed', 'inbox state is invalid', { cause: e });
    }
  }

  #now(): number { return nowOf(this.#o.clock); }
  #floor(): number { return Math.max(0, this.#now() - SEEN_FLOOR_SECONDS); }

  /**
   * Restore the seen entries of finished journal entries and finish interrupted ones. A failing entry stays pending (it
   * never blocks opening the Inbox): its packet was not acknowledged, so the redelivered duplicate retries it, and the
   * poison counter quarantines it if it keeps failing. An aborted entry is gone, and its redelivery is processed anew.
   */
  async #recover(): Promise<void> {
    for await (const [key, j] of this.#journals()) {
      if (j.status === 'done') this.#see(j);
      else await this.#finish(key, j).catch(() => undefined);
    }
    await this.#snapshot();
  }

  #see(j: Journal): void {
    if (this.#replay.accepts(j.messageId, j.from, j.timestamp)) this.#replay.commit(j.messageId, j.from, j.timestamp, this.#floor());
  }

  /**
   * Complete step 10 from a `pending` journal entry (06 § Crash recovery): the rules commit, seen store, hand-over, then
   * `done`. Live delivery, recovery and a deduplicated redelivery all take this one path. The seen entry, delivery
   * record and rules commit form one transaction (06 step 10): a permanent commit failure aborts it (the entry is
   * deleted, nothing is handed over or seen) and is returned for a `rejected:<code>` answer; since `commit` is idempotent,
   * a commit that already applied never fails on a re-run. Any other failure is thrown and leaves the entry pending.
   */
  async #finish(key: string, j: Journal & { status: 'pending' }): Promise<ACEError | undefined> {
    const m = j.message;
    try {
      await commitRules(this.#rules, ruleEvent('receive', m), m.body);
    } catch (e) {
      const err = asACEError(e);
      if (err.isTransient) throw err;
      await this.#o.store.delete(key);
      return err;
    }
    this.#see(j);
    await this.#o.onMessage(m);
    await this.#o.store.write(key, canonicalStateBytes({ from: j.from, messageId: j.messageId, timestamp: j.timestamp, status: 'done' }));
    return undefined;
  }

  /** Write the seen store, then drop the journal entries it now holds and fetch-attempt counters the relay no longer holds. */
  async #snapshot(): Promise<void> {
    await this.#o.store.write(REPLAY_KEY, canonicalStateBytes(this.#replay.exportState()));
    this.#dirty = 0;
    for await (const [key, j] of this.#journals()) if (j.status === 'done') await this.#o.store.delete(key);
    const now = this.#now();
    for (const key of await this.#o.store.list('inbox/attempts/')) {
      const raw = await this.#o.store.read(key);
      const at = raw === null ? null : wireInt((parseStateBytes(raw, key) as { at?: unknown }).at);
      if (at === null || now - at >= OFFLINE_WINDOW_SECONDS) await this.#o.store.delete(key);
    }
  }

  async *#journals(): AsyncGenerator<[string, Journal]> {
    for (const key of await this.#o.store.list('inbox/journal/')) {
      const raw = await this.#o.store.read(key);
      if (raw !== null) yield [key, checkJournal(parseStateBytes(raw, key), key)];
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#queue.run(async () => undefined);
    try {
      if (this.#dirty > 0) await this.#snapshot().catch(() => {});
    } finally {
      await this.#release();
    }
  }

  /** Process one packet (a decoded JSON value or its UTF-8 bytes). Calls are serialized. */
  receive(packet: unknown): Promise<ReceiveOutcome> {
    if (this.#closed) throw new ACEError('invalid_argument', 'inbox is closed');
    return this.#queue.run(() => this.#receive(packet).catch((e) => defer(asACEError(e, 'storage_failed'))));
  }

  async #receive(value: unknown): Promise<ReceiveOutcome> {
    // 1. shape
    let packet: Packet;
    try {
      packet = value instanceof Uint8Array ? parsePacket(value) : decodePacket(value);
    } catch (e) {
      return drop(asACEError(e, 'invalid_packet'));
    }
    if (packet.to !== this.#me) return drop(new ACEError('wrong_recipient', 'packet is not addressed to this identity'));
    // 2. admission, before any lookup
    const record = await this.#admission.get(packet.from);
    if (record?.status === 'blocked') return drop(new ACEError('not_permitted', 'sender is blocked'));
    // A stranger (05 § Receiver admission): decrypted without any lookup or pin write; only a recovery candidate or an
    // `open` identity's contact request continues.
    if (record === null) return this.#candidate(packet, true, true);
    // 3. pin. A peer in the table without a pin is authenticated by a contact packet's `source` or by admission recovery.
    let state: KelState | null;
    try {
      state = await this.#peers.get(packet.from);
      if (state === null) return this.#candidate(packet, false, true);
      if (state.signing === null || packet.signature.seq > state.signing.seq) {
        state = await this.#refresh(packet.from) ?? state;
        // Still behind the packet's delegation: only a contact whose source extends the pin can authenticate it.
        if (state.signing === null || packet.signature.seq > state.signing.seq) return this.#candidate(packet, false);
      }
    } catch (e) {
      const err = asACEError(e, 'relay_unavailable');
      if (err.isTransient) return defer(err);
      // 06 step 3: a permanent refresh failure (e.g. a peer after a signing-key change that has not republished its
      // descriptor yet) continues as a contact candidate.
      return this.#candidate(packet, false);
    }
    // 4. operational signature against the pin (step 3 already made the one permitted refresh)
    try {
      verifyPacketSignature(packet, state, this.#now());
    } catch (e) {
      return drop(asACEError(e, 'invalid_signature'));
    }
    // 5. time window
    try { checkPacketTime(packet, this.#now()); } catch (e) { return drop(asACEError(e)); }
    // 6. decrypt: a failure is a drop
    let plaintext: Uint8Array;
    try {
      plaintext = await openPacketPlaintext(packet, this.#o.vault);
    } catch (e) {
      const err = asACEError(e, 'decryption_failed');
      if (err.code === 'unknown_prekey') return this.#reject(packet, err, packet.encryption.prekey);
      return settle(err);
    }
    try { await this.#used(packet); } catch (e) { return settle(asACEError(e, 'storage_failed')); }
    // 7. content shape (a missing or malformed `prekey` included): rejected `invalid_body`, except that receipts and
    // contact packets are never receipted, only dropped
    let content: PrivateContent;
    try {
      content = decodePrivateContent(plaintext);
    } catch (e) {
      const err = asACEError(e, 'invalid_body');
      return isCoreContent(plaintext) ? drop(err) : this.#reject(packet, err);
    }
    // 06 § Receive pipeline, peer prekeys: the sender is pinned at step 3, so its offer is held under that pin (contact
    // packets excepted), whatever the disposition from step 7 on (duplicates and rejections included).
    try {
      const offered = takeOffer(content);
      if (content.type !== CONTACT_TYPE) await this.#holdOffer(packet, offered, state);
    } catch (e) {
      return settle(asACEError(e, 'storage_failed'));
    }
    const core = content.type === RECEIPT_TYPE || content.type === CONTACT_TYPE;
    // 7-8. installed (type, schemaDigest), then body schema
    try {
      this.#o.profiles.validate(content.type, content.schemaDigest, content.body);
    } catch (e) {
      return core ? drop(asACEError(e, 'invalid_body')) : this.#reject(packet, asACEError(e, 'invalid_body'));
    }
    if (content.type === RECEIPT_TYPE) return this.#receipt(packet, content, state);
    if (content.type === CONTACT_TYPE) return this.#contact(packet, content, false);
    // 05 § Admission recovery step 4: an authenticated sender's `proof` is ignored; its reply permit is held like a
    // receipt renewal when it verifies, and an invalid one is ignored.
    if (content.admission !== undefined) {
      let permit: DeliveryPermit | undefined;
      try { permit = verifyPermit(content.admission.permit, state, this.#me, this.#now()); } catch { /* ignored */ }
      if (permit !== undefined) await this.#hold(permit, state, (r) => r !== null && r.status !== 'blocked');
    }
    return this.#application(packet, content);
  }

  /**
   * Hold a permit the sender issued us, verified under its pinned `state`: the newest wins, and a held one from a
   * superseded key never shadows it (as `NetworkClient` holds permits).
   */
  async #hold(permit: DeliveryPermit, state: KelState, when: (r: PeerRecord | null) => boolean): Promise<void> {
    const now = this.#now();
    const live = (held: DeliveryPermit) => { try { verifyPermit(held, state, this.#me, now); return true; } catch { return false; } };
    await this.#admission.holdPermit(permit, { when, keep: (held) => held.issuedAt > permit.issuedAt && live(held) });
  }

  /**
   * Right after step 6 on every path (04 § Peer prekeys, issuer rule): the packet opened under the key referenced,
   * which becomes the in-use key when it is the one offered to the sender, whatever the disposition from step 7 on.
   */
  async #used(packet: Packet): Promise<void> {
    await this.#o.vault.used(packet.from, packet.encryption.prekey);
  }

  /** The holder rule: hold the key a pinned sender offered, bound to its pin `state` (newer timestamps win). */
  async #holdOffer(packet: Packet, offered: string, state: KelState): Promise<void> {
    const id = prekeyId(fromBase64(offered)); // step 7 decoded it (1216 bytes, canonical Base64)
    await this.#o.vault.hold(packet.from, { id, publicKey: offered }, packet.timestamp, state.lastHash);
  }

  /** Refresh a sender at most once per PIN_REFRESH_INTERVAL_SECONDS (06 step 3), a failed attempt included. */
  async #refresh(aceId: string): Promise<KelState | null> {
    if (this.#o.refreshPeer === undefined) return null;
    const now = this.#now();
    for (const [id, t] of this.#lastRefresh) if (now - t >= PIN_REFRESH_INTERVAL_SECONDS) this.#lastRefresh.delete(id);
    // 06 step 3: a suppressed refresh is a retry, never a drop.
    if (this.#lastRefresh.has(aceId)) throw new ACEError('relay_unavailable', 'sender refresh suppressed; retry later');
    this.#lastRefresh.set(aceId, now);
    await this.#o.refreshPeer(aceId);
    return this.#peers.get(aceId);
  }

  /**
   * A sender without a pin that authenticates the packet (06 § Contact candidates, § Recovery candidates): steps 1, 2,
   * 5, 6, 7, then an `ace:contact:1` packet takes the contact-candidate path and, with `recover` (no pin at all), any
   * other packet carrying `admission` the recovery path. Anything else is dropped `not_permitted`.
   */
  async #candidate(packet: Packet, stranger: boolean, recover = false): Promise<ReceiveOutcome> {
    let plaintext: Uint8Array;
    try {
      checkPacketTime(packet, this.#now());
      plaintext = await openPacketPlaintext(packet, this.#o.vault);
    } catch (e) {
      return settle(asACEError(e, 'not_permitted'));
    }
    try { await this.#used(packet); } catch (e) { return settle(asACEError(e, 'storage_failed')); }
    let content: PrivateContent;
    try {
      content = decodePrivateContent(plaintext);
    } catch (e) {
      return settle(asACEError(e, 'not_permitted'));
    }
    const offered = takeOffer(content); // held only once the recovery path pins the sender
    if (content.type === CONTACT_TYPE) return this.#contactCandidate(packet, content, stranger);
    if (recover && content.admission !== undefined) return this.#restore(packet, content, content.admission, offered);
    return drop(new ACEError('not_permitted', stranger ? 'sender is not admitted' : 'an unpinned sender may only send contact packets'));
  }

  /**
   * The contact-candidate path (06): no pinned KEL, so steps 1, 2, 5, 6, 7, 8, then authentication by the embedded
   * `source`, then 9 and 10. A stranger's packet continues only to an `open` identity and only as `request`; a peer
   * already in the admission table (e.g. `pending`, not yet pinned) may send any kind. Every failure is a drop.
   */
  async #contactCandidate(packet: Packet, content: PrivateContent, stranger: boolean): Promise<ReceiveOutcome> {
    try {
      if (stranger && ((await this.#o.contact?.()) ?? 'closed') !== 'open') throw new ACEError('not_permitted', 'sender is not admitted');
      this.#o.profiles.validate(content.type, content.schemaDigest, content.body);
      if (stranger && content.body.kind !== 'request') throw new ACEError('not_permitted', 'a stranger may only send a contact request');
      if (stranger) checkStrangerSource(content.body.source);
      return await this.#contact(packet, content, stranger);
    } catch (e) {
      return settle(asACEError(e, 'not_permitted'));
    }
  }

  /**
   * The recovery-candidate path (05 § Admission recovery, 06 § Recovery candidates), after steps 1, 2, 5, 6: step 7,
   * then `proof` checked locally (a permit this identity issued the sender, valid under its current KEL), `source`
   * verified as a contact's is (a PublishedAgent naming the sender, under the pin rules; no network lookup), step 4 and
   * `admission.permit` under it; only then the source pinned, the sender recorded `admitted` (no profile; never over a
   * block) with `proof` as the newest permit issued to it, and its permit held; then steps 8-11 as for any admitted
   * sender. Every failure before the sender is recorded is a drop, and nothing is pinned.
   */
  async #restore(packet: Packet, content: PrivateContent, admission: Admission, offered: string): Promise<ReceiveOutcome> {
    const from = packet.from;
    // 7. installed (type, schemaDigest); a body schema failure (8) is answered once the sender is admitted
    if (this.#o.profiles.digestOf(content.type) !== content.schemaDigest) return drop(new ACEError('unsupported_schema', 'message type is not installed'));
    let proof: DeliveryPermit;
    try {
      const now = this.#now();
      proof = verifyPermit(admission.proof, checkUsable(this.#o.identity, now), from, now);
    } catch {
      return drop(new ACEError('not_permitted', 'sender is not admitted'));
    }
    // `source` as a contact's (no stranger bounds: the proof shows we admitted the sender), then step 4 and the reply
    // permit under it.
    let source: VerifiedAgent, permit: DeliveryPermit;
    try {
      ({ source, permit } = await this.#verifySource(packet, admission.source, admission.permit, this.#now()) as { source: VerifiedAgent; permit: DeliveryPermit });
    } catch (e) {
      return drop(asACEError(e, 'invalid_authorization'));
    }
    try {
      // Recorded under lock `admission`, where a block decided meanwhile wins; only then is the source pinned (as a
      // contact's, after its checks), so a blocked sender changes no pin.
      await this.#admission.update(from, (old) => {
        if (old?.status === 'blocked') throw new ACEError('not_permitted', 'sender is blocked');
        const base = old?.status === 'admitted' ? old : { ...(old ?? { aceId: from }), status: 'admitted' as const, updatedAt: this.#now() };
        // The proof is a permit we issued the sender: the newest one issued to it unless a newer one is recorded.
        return old?.issued !== undefined && old.issued.issuedAt >= proof.issuedAt ? base : { ...base, issued: proof };
      });
      if (this.#o.importSource !== undefined) await this.#o.importSource(source);
      else await this.#peers.adopt(structuredClone(source.state.events));
      await this.#hold(permit, source.state, (r) => r?.status === 'admitted');
      // Pinned by this path: the sender's offer is held under the adopted pin (04 § Peer prekeys).
      await this.#holdOffer(packet, offered, source.state);
    } catch (e) {
      return settle(asACEError(e, 'storage_failed'));
    }
    // 8. body schema; from here the dispositions of an admitted sender apply
    try {
      this.#o.profiles.validate(content.type, content.schemaDigest, content.body);
    } catch (e) {
      return this.#reject(packet, asACEError(e, 'invalid_body'));
    }
    return this.#application(packet, content);
  }

  /**
   * Authenticate an embedded `source` (a contact's, or a recovery candidate's `admission.source`): a PublishedAgent naming
   * the sender, never older than a log already pinned (01 § Pinning; a stranger may still have a pin, e.g. an imported
   * descriptor: reading it is local, and it must bind the source too), the packet signature under it (step 4), and the
   * sender's `permit` issued to us under it, when given. Pins nothing.
   */
  async #verifySource(packet: Packet, raw: unknown, permit: unknown, now: number): Promise<{ source: VerifiedAgent; permit?: DeliveryPermit }> {
    if (!isObj(raw) || !isObj(raw.descriptor) || raw.descriptor.aceId !== packet.from) throw new ACEError('invalid_authorization', 'source is not the sender');
    const pinned = await this.#peers.get(packet.from);
    const source = verifyPublishedAgent(raw, now, { allowLoopbackRelays: this.#o.allowLoopbackRelays, pinned });
    verifyPacketSignature(packet, source.state, now);
    return { source, ...(permit !== undefined ? { permit: verifyPermit(permit, source.state, this.#me, now) } : {}) };
  }

  /** A contact packet whose steps 1-8 passed: authenticate its `source`, then dedupe (9) and hand it over (10). */
  async #contact(packet: Packet, content: PrivateContent, stranger: boolean): Promise<ReceiveOutcome> {
    try {
      const body = checkContactBody(content.body);
      const { source, permit } = await this.#verifySource(packet, body.source, body.kind === 'rejected' ? undefined : body.permit, this.#now());
      // 9. a duplicate or beyond-horizon contact is dropped (contacts are never receipted)
      if (this.#replay.hasSeen(packet.messageId, packet.from)) throw new ACEError('invalid_packet', 'contact packet already processed');
      if (this.#replay.covers(packet.from, packet.timestamp)) throw new ACEError('replay_horizon', 'contact packet is beyond the replay horizon');
      await checkRules(this.#rules, this.#event(packet, content), content.body);
      // An admitted peer's newer KEL may be pinned; a stranger's never is.
      if (!stranger) await this.#peers.adopt(structuredClone(source.state.events));
      const event: ContactEvent = { from: packet.from, messageId: packet.messageId, timestamp: packet.timestamp, body, source, stranger, ...(permit ? { permit } : {}) };
      await this.#o.onContact?.(event);
      await this.#commitSeen(packet);
      return { kind: 'contact', event };
    } catch (e) {
      return settle(asACEError(e, 'invalid_body'));
    }
  }

  async #receipt(packet: Packet, content: PrivateContent, state: KelState): Promise<ReceiveOutcome> {
    // 9. dedupe like every packet (a duplicate receipt is never answered); then 10. the core rules, hand-over, seen store
    if (this.#replay.hasSeen(packet.messageId, packet.from)) return { kind: 'duplicate', from: packet.from, messageId: packet.messageId };
    if (this.#replay.covers(packet.from, packet.timestamp)) return drop(new ACEError('replay_horizon', 'receipt is beyond the replay horizon'));
    let body: ReceiptBody;
    try {
      body = checkReceiptBody(content.body);
      if (body.permit !== undefined) body = { ...body, permit: verifyPermit(body.permit, state, this.#me, this.#now()) };
    } catch (e) {
      return drop(asACEError(e, 'invalid_body'));
    }
    try {
      await this.#o.onReceipt?.(packet.from, body);
      await this.#commitSeen(packet);
    } catch (e) {
      return defer(asACEError(e, 'storage_failed'));
    }
    return { kind: 'receipt', from: packet.from, body };
  }

  #event(p: Packet, c: PrivateContent): RuleEvent {
    return ruleEvent('receive', { messageId: p.messageId, from: p.from, to: p.to, timestamp: p.timestamp, type: c.type, threadId: c.threadId });
  }

  async #application(packet: Packet, content: PrivateContent): Promise<ReceiveOutcome> {
    const { from, messageId, timestamp } = packet;
    const jkey = journalKey(from, messageId);
    // 9. dedupe, before the rules: a duplicate must not re-run state transitions. Only the seen store, or a pending
    // journal entry (crash recovery), makes a packet a duplicate.
    const raw = await this.#o.store.read(jkey);
    const j = raw === null ? null : checkJournal(parseStateBytes(raw, jkey), jkey);
    if (j?.status === 'pending') {
      const aborted = await this.#finish(jkey, j);
      if (aborted) return this.#reject(packet, aborted);
      await this.#bump();
      return this.#duplicate(packet);
    }
    if (this.#replay.hasSeen(messageId, from)) return this.#duplicate(packet);
    if (this.#replay.covers(from, timestamp)) return drop(new ACEError('replay_horizon', 'message is beyond the replay horizon'));
    const event = this.#event(packet, content);
    // 10. profile rules (a thread with our own rule-governed message in flight is busy)
    if (content.threadId !== undefined && rulesFor(this.#rules, content.type).length > 0 && await this.#o.threadBusy?.(from, content.threadId)) {
      return this.#reject(packet, new ACEError('thread_busy', 'a message of ours on this thread awaits its receipt'));
    }
    try {
      await checkRules(this.#rules, event, content.body);
    } catch (e) {
      const err = asACEError(e, 'invalid_body');
      return err.isTransient ? defer(err) : this.#reject(packet, err);
    }
    // Never `admission` (03 § Private content): it reaches neither the host nor the journal.
    const message: ParsedMessage = {
      messageId, from, to: packet.to, timestamp, conversation: conversationKey(from, packet.to),
      type: content.type, schemaDigest: content.schemaDigest, threadId: content.threadId ?? null, body: content.body,
    };
    try {
      await this.#o.checkCapacity?.(message);
    } catch (e) {
      return defer(asACEError(e, 'receiver_capacity'));
    }
    // 10. persist: the journal entry is the commit point; then rules commit, seen store, hand-over
    const journal = { from, messageId, timestamp, status: 'pending', message } as const;
    await this.#o.store.write(jkey, canonicalStateBytes(journal));
    const aborted = await this.#finish(jkey, journal);
    if (aborted) return this.#reject(packet, aborted);
    await this.#bump();
    // 11. receipt (a transient failure is retried: the re-fetched packet is a duplicate and is answered again)
    const delivered: ReceiveOutcome = { kind: 'delivered', message };
    return this.#delivered(await this.#sendReceipt(from, { messageId, outcome: 'delivered' }), delivered);
  }

  /**
   * The seen entry of a handed-over receipt or contact, as durable as an application message's: a `done` journal entry
   * first (restored by `#recover` after a crash before the next snapshot), then the in-memory seen store.
   */
  async #commitSeen(packet: Packet): Promise<void> {
    const { from, messageId, timestamp } = packet;
    await this.#o.store.write(journalKey(from, messageId), canonicalStateBytes({ from, messageId, timestamp, status: 'done' }));
    this.#replay.commit(messageId, from, timestamp, this.#floor());
    await this.#bump();
  }

  async #bump(): Promise<void> {
    if (++this.#dirty >= SNAPSHOT_EVERY) await this.#snapshot();
  }

  async #duplicate(packet: Packet): Promise<ReceiveOutcome> {
    const duplicate: ReceiveOutcome = { kind: 'duplicate', from: packet.from, messageId: packet.messageId };
    return this.#delivered(await this.#sendReceipt(packet.from, { messageId: packet.messageId, outcome: 'delivered' }), duplicate);
  }

  /** `outcome` after the `delivered` receipt; a deferral of the receipt alone remembers that the message was processed. */
  #delivered(failed: ReceiveOutcome | undefined, outcome: ReceiveOutcome): ReceiveOutcome {
    if (failed === undefined) return outcome;
    RECEIPT_ONLY.set(failed, outcome);
    return failed;
  }

  /** `rejected:<code>`; a rejected message is not added to the seen store. */
  async #reject(packet: Packet, error: ACEError, prekey?: string): Promise<ReceiveOutcome> {
    return await this.#sendReceipt(packet.from, { messageId: packet.messageId, outcome: 'rejected', code: error.code, ...(prekey !== undefined ? { prekey } : {}) })
      ?? { kind: 'rejected', from: packet.from, messageId: packet.messageId, error };
  }

  /** One receipt attempt. A transient failure defers the packet; a permanent one (no route to the sender) sends nothing. */
  async #sendReceipt(to: string, body: ReceiptBody): Promise<ReceiveOutcome | undefined> {
    if (this.#o.sendReceipt === undefined) return undefined;
    try {
      await this.#o.sendReceipt(to, body);
    } catch (e) {
      const err = asACEError(e, 'relay_unavailable');
      if (err.isTransient) return defer(err);
    }
    return undefined;
  }

  /**
   * Drain one relay inbox page: process in order, acknowledge through the last consumed packet. Capacity
   * back-pressure stops without acknowledging; any other deferral counts an attempt, and the third failed attempt
   * quarantines the packet (header and failure only, `inbox/quarantine/`, at most 1000) and acknowledges it.
   */
  async pull(relay: RelayClient, o: { limit?: number } = {}): Promise<ReceiveOutcome[]> {
    const page = await relay.fetchInbox(this.#o.identity, { limit: o.limit });
    const outcomes: ReceiveOutcome[] = [];
    let through: string | null = null;
    for (const m of page.messages) {
      const out = await this.#consume(m.packet);
      outcomes.push(out);
      if (out.kind === 'deferred') break;
      through = m.streamId;
    }
    if (through !== null) await relay.ackInbox(this.#o.identity, through);
    return outcomes;
  }

  /** Follow the relay's SSE stream; each consumed packet is acknowledged. Stops on capacity back-pressure. */
  async *follow(relay: RelayClient, o: { signal?: AbortSignal } = {}): AsyncGenerator<ReceiveOutcome, void, undefined> {
    for await (const ev of relay.listen(this.#o.identity, { signal: o.signal })) {
      let value: unknown;
      try { value = (JSON.parse(ev.data) as { packet?: unknown }).packet ?? null; } catch { value = null; }
      const out = await this.#consume(value);
      yield out;
      if (out.kind === 'deferred') return;
      await relay.ackInbox(this.#o.identity, ev.streamId);
    }
  }

  /** Record a poison packet's fingerprint, header and failure (never its ciphertext), bounded by QUARANTINE_CAP. */
  async #quarantine(fp: string, value: unknown, error: ACEError): Promise<void> {
    const store = this.#o.store;
    await store.write(`${QUARANTINE_PREFIX}${fp}.json`, canonicalStateBytes({
      fingerprint: fp, code: error.code, reason: error.message.slice(0, 1000), quarantinedAt: this.#now(), packet: packetHeader(value),
    }));
    const keys = await store.list(QUARANTINE_PREFIX);
    if (keys.length <= QUARANTINE_CAP) return;
    const aged: Array<[number, string]> = [];
    for (const k of keys) {
      let at = 0;
      try { const raw = await store.read(k); at = wireInt((raw && parseStateBytes(raw, k) as { quarantinedAt?: unknown })?.quarantinedAt) ?? 0; } catch { /* unreadable: oldest */ }
      aged.push([at, k]);
    }
    aged.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : 1));
    for (const [, k] of aged.slice(0, keys.length - QUARANTINE_KEEP)) await store.delete(k);
  }

  /** `receive` plus the poison counter; a quarantined packet is reported as `dropped`. */
  async #consume(value: unknown): Promise<ReceiveOutcome> {
    const out = await this.receive(value);
    if (out.kind !== 'deferred' || out.error.code === 'receiver_capacity') return out;
    const fp = sha256Hex(isObj(value) ? canonicalStateBytes(value) : String(value));
    try {
      const key = attemptsKey(fp), raw = await this.#o.store.read(key);
      const prior = raw === null ? null : parseStateBytes(raw, key) as { attempts?: unknown; at?: unknown };
      const attempts = (wireInt(prior?.attempts) ?? 0) + 1;
      if (attempts < MAX_FETCH_ATTEMPTS) {
        await this.#o.store.write(key, canonicalStateBytes({ attempts, at: wireInt(prior?.at) ?? this.#now() }));
        return out;
      }
      const processed = RECEIPT_ONLY.get(out);
      if (processed !== undefined) {
        await this.#o.store.delete(key);
        return processed;
      }
      await this.#quarantine(fp, value, out.error);
      await this.#o.store.delete(key);
      return drop(out.error);
    } catch {
      return out;
    }
  }
}
