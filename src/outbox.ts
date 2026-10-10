/** Sender durability: stage, deliver, re-sign, abandon (06-security § Durable Delivery, Sender). */

import { ACEError } from './errors.js';
import { intentDigest as digestIntent } from './intent.js';
import {
  canonicalStateBytes, checkJsonValue, dumpsBody, encodeSignature, isACEId, isConversationId, loadsBody, parseStateBytes, sha256Hex, wireInt,
} from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { computeConversationId } from './encryption.js';
import { messageSignData } from './envelope.js';
import { applySchema, buildMessage, installedSchemas, knownSchemaDigest, type SchemaValidator } from './messages.js';
import { repairThreadsFromDeliveries } from './inbox.js';
import { recordRequest } from './principal.js';
import type { ACEStore } from './store.js';
import {
  archiveSent, decodePendingSend, encodePendingSend, isRequestId, sentKey, restoreMachine, snapshotWithHistory, ThreadRecords,
  type PendingSend, type ThreadRecord,
} from './thread-store.js';
import type { ACEIdentity, ACEMessage, JSONObject, MessageType } from './types.js';
import { isEconomicType } from './types.js';

export type { PendingSend };

function outboxKey(requestId: string): string {
  return `outbox/${sha256Hex(requestId)}.json`;
}

type StageInput = { recipient: VerifiedPeer; type: MessageType; body: JSONObject; threadId?: string; schemaDigest?: string; requestId?: string };

/** `schemas`: installed deterministic validators keyed by `schemaDigest`; `stage` refuses a rejected body before anything is persisted. */
type OutboxOptions = { identity: ACEIdentity; store: ACEStore; clock?: () => number; commerce?: boolean; schemas?: Record<string, SchemaValidator> };

type Located =
  | { kind: 'outbox'; pending: PendingSend }
  | { kind: 'thread'; pending: PendingSend; record: ThreadRecord };

/**
 * Durable outbound messages. A staged message is persisted (with its thread transition)
 * before it is sent, retried with the same envelope until acknowledged, and never
 * auto-abandoned.
 */
export class Outbox {
  readonly #identity: ACEIdentity;
  readonly #store: ACEStore;
  readonly #threads: ThreadRecords;
  readonly #clock?: () => number;
  readonly #commerce: boolean;
  readonly #schemas: ReadonlyMap<string, SchemaValidator>;

  private constructor(o: OutboxOptions) {
    if (typeof o !== 'object' || o === null || typeof o.store !== 'object' || o.store === null || typeof o.identity !== 'object') {
      throw new ACEError('invalid_argument', 'identity and store are required');
    }
    this.#identity = o.identity;
    this.#commerce = o.commerce === true;
    this.#schemas = installedSchemas(o.schemas);
    this.#store = o.store;
    this.#clock = o.clock;
    const local = o.identity.getACEId();
    if (!isACEId(local)) throw new ACEError('invalid_argument', 'identity has an invalid ACE ID');
    this.#threads = new ThreadRecords({ store: o.store, localAceId: local, clock: o.clock });
  }

  /**
   * Open an outbox. Under lock `threads`, thread records are first repaired from `deliveries/`
   * records whose thread snapshot strictly extends the stored history (an Inbox that crashed
   * between its delivery and thread writes), so staging never diverges from received history.
   * Messages are not handed over and replay state is not touched.
   */
  static async open(o: OutboxOptions): Promise<Outbox> {
    const outbox = new Outbox(o);
    await repairThreadsFromDeliveries(o.store, outbox.#threads);
    return outbox;
  }

  #now(): number {
    return Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
  }

  /**
   * Create, persist and return a pending send. If a pending send with `requestId` already
   * exists it is returned unchanged (idempotent staging). An economic message on a thread that
   * already has a different pending send is `pending_send_conflict`.
   */
  async stage(o: StageInput): Promise<PendingSend> {
    if (typeof o !== 'object' || o === null) throw new ACEError('invalid_argument', 'options are required');
    checkJsonValue(o.body);
    // Own the intent before waiting on another process or a hardware signer. Caller mutation
    // must not make the operation digest describe different bytes from the signed message.
    const input = { ...o, body: loadsBody(dumpsBody(o.body)) };
    return this.#threads.withLock(() => this.#stage(input));
  }

  async #stage(o: StageInput): Promise<PendingSend> {
    const requestId = o.requestId ?? crypto.randomUUID();
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'requestId must be 1-256 characters without control characters');
    if (!isVerifiedPeer(o.recipient)) throw new ACEError('invalid_argument', 'recipient must be a VerifiedPeer');
    const local = this.#identity.getACEId();
    const schemaDigest = o.schemaDigest ?? knownSchemaDigest(o.type);
    if (typeof schemaDigest !== 'string' || !isConversationId(schemaDigest)) throw new ACEError('invalid_body', 'schemaDigest is required');
    const validator = this.#schemas.get(schemaDigest);
    if (validator !== undefined) applySchema(validator, { type: o.type, schemaDigest, threadId: o.threadId ?? null, body: o.body });
    const metadata = { type: o.type, schemaDigest, ...(o.threadId === undefined ? {} : { threadId: o.threadId }) };
    const intentDigest = digestIntent({ schemaDigest, from: local, to: o.recipient.aceId, type: o.type, threadId: o.threadId ?? null, body: o.body });
    const existing = await this.#locate(requestId);
    const prior = existing?.pending ?? await this.#readOutboxKey(sentKey(requestId));
    if (prior !== null) {
      if (prior.intentDigest !== intentDigest) throw new ACEError('pending_send_conflict', 'requestId is already bound to different parameters');
      // Retrying a completed send uses the original signed envelope, never a new operation.
      if (existing === null) await this.#writeOutbox(prior);
      return prior;
    }
    if (!this.#commerce || !isEconomicType(o.type)) {
      const message = await buildMessage({
        sender: this.#identity, recipient: o.recipient, type: o.type, body: o.body, schemaDigest,
        threadId: o.threadId, timestamp: this.#now(),
      });
      const pending: PendingSend = { ...metadata, requestId, status: 'pending', stagedAt: this.#now(), message, intentDigest };
      // a principal request keeps its body ttl: the retry needs it for the requests/ record (06 Appendix A)
      const ttl = o.type === 'request' ? wireInt(o.body.ttl) : null;
      if (ttl !== null) pending.requestTtl = ttl;
      await this.#writeOutbox(pending);
      return pending;
    }
    if (o.threadId === undefined) throw new ACEError('invalid_argument', 'economic messages require threadId');
    const conversationId = computeConversationId(this.#identity.getEncryptionPublicKey(), o.recipient.encryptionPublicKey);
    const record = await this.#threads.loadRecord(conversationId, o.threadId!);
    if (record?.pending) {
      if (record.pending.requestId === requestId) return record.pending;
      throw new ACEError('pending_send_conflict', 'the thread already has a different pending send');
    }
    const machine = restoreMachine(local, record?.snapshot ?? null);
    // a message that opens a thread is bounded per peer (pre-checked before any crypto)
    if (record === null && machine.allowedTypes(conversationId, o.threadId!, local).includes(o.type)) {
      await this.#threads.checkCanOpen(o.recipient.aceId);
    }
    const message = await buildMessage({
      sender: this.#identity, recipient: o.recipient, type: o.type, body: o.body, threads: machine,
      threadId: o.threadId, schemaDigest, timestamp: this.#now(),
    });
    const pending: PendingSend = { ...metadata, requestId, status: 'pending', stagedAt: this.#now(), message, intentDigest };
    await this.#threads.saveRecord({ snapshot: machine.getSnapshot(conversationId, o.threadId!)!, pending });
    return pending;
  }

  /**
   * Hand the pending envelope to `transport` and return what it returns. The transport is the
   * secure delivery, `envelope => secure.deliver(envelope, peer, exchange)` (a `SecureTransport`
   * with a `SecureRelayReplies.exchange`): it resolves only once the peer's Inbox durably
   * committed the envelope. On success the send is acknowledged (economic: the thread's pending
   * is cleared; otherwise the outbox file is deleted). An `expired` send is refused with `envelope_expired` before any transport call;
   * `envelope_expired` from the transport marks it `expired` (then `resign`); any other error
   * leaves it unchanged. Before transport, a principal `request` is recorded in `requests/` (lock `requests`).
   * A failed write prevents sending. A lost transport acknowledgement retains the request
   * correlation, so a controller decision is still accepted.
   */
  async deliver<T>(requestId: string, transport: (env: ACEMessage) => Promise<T>): Promise<T> {
    if (typeof transport !== 'function') throw new ACEError('invalid_argument', 'transport must be a function');
    const found = await this.#threads.withLock(() => this.#require(requestId));
    if (found.pending.status === 'expired') throw new ACEError('envelope_expired', 'the pending send expired; resign it first');
    const message = found.pending.message;
    // Persist the correlation before any transport can deliver the request or its reply.
    if (found.pending.type === 'request') {
      const release = await this.#store.lock('requests');
      try {
        await recordRequest(this.#store, message, this.#now(), found.pending.requestTtl);
      } finally {
        await release();
      }
    }
    let result: T;
    try {
      result = await transport(message);
    } catch (e) {
      if (e instanceof ACEError && e.code === 'envelope_expired') await this.#markExpired(requestId, message.messageId);
      throw e;
    }
    await this.#acknowledge(requestId, message.messageId);
    return result;
  }

  /**
   * Re-sign an `expired` send with the same messageId and `timestamp = now`. The ciphertext is
   * reused (the plaintext is not persisted; the AEAD binds the conversationId, the new signature
   * binds the new timestamp). Economic: the head entry is rebuilt with the new timestamp.
   */
  async resign(requestId: string): Promise<PendingSend> {
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'invalid requestId');
    return this.#threads.withLock(async () => {
      if (await this.#store.read(sentKey(requestId)) !== null) throw new ACEError('invalid_argument', 'a completed operation cannot be renewed');
      const found = await this.#require(requestId);
      if (found.pending.status !== 'expired') throw new ACEError('invalid_argument', 'only an expired send can be re-signed');
      if (found.pending.requestTtl !== undefined) throw new ACEError('invalid_argument', 'a request deadline cannot be extended by transport retry');
      const pending = await this.#resigned(found.pending);
      if (found.kind === 'outbox') {
        await this.#writeOutbox(pending);
        return pending;
      }
      const rec = found.record;
      const h = rec.snapshot.history.slice();
      const head = h[h.length - 1];
      if (head?.messageId !== pending.message.messageId) throw new ACEError('storage_failed', 'pending send is not the thread head');
      h[h.length - 1] = { ...head, timestamp: pending.message.timestamp };
      await this.#threads.saveRecord({ snapshot: snapshotWithHistory(rec.snapshot, h)!, pending });
      return pending;
    });
  }

  /** Stop retrying and retain the operation binding. This does not revoke a delivered request. */
  async abandon(requestId: string): Promise<void> {
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'invalid requestId');
    await this.#threads.withLock(async () => {
      const found = await this.#locate(requestId);
      if (found === null) return;
      if (found.kind === 'outbox') {
        await archiveSent(this.#store, found.pending);
        await this.#store.delete(outboxKey(requestId));
        return;
      }
      const rec = found.record;
      const h = rec.snapshot.history;
      const isHead = h[h.length - 1]?.messageId === found.pending.message.messageId;
      const snapshot = isHead ? snapshotWithHistory(rec.snapshot, h.slice(0, -1)) : rec.snapshot;
      if (snapshot === null) {
        await archiveSent(this.#store, found.pending);
        await this.#threads.deleteRecord(rec.snapshot);
      } else {
        await this.#threads.saveRecord({ snapshot, pending: null }, rec); // archives found.pending
      }
    });
  }

  /** Every pending send (outbox files and thread records). */
  async pending(): Promise<PendingSend[]> {
    const out: PendingSend[] = [];
    for (const key of await this.#store.list('outbox/')) {
      const p = await this.#readOutboxKey(key);
      if (p !== null) out.push(p);
    }
    for (const rec of await this.#threads.listRecords()) if (rec.pending) out.push(rec.pending);
    return out.sort((a, b) => a.stagedAt - b.stagedAt || (a.requestId < b.requestId ? -1 : 1));
  }

  // --- internals ---

  async #resigned(p: PendingSend): Promise<PendingSend> {
    const message: ACEMessage = { ...p.message, encryption: { ...p.message.encryption }, timestamp: this.#now() };
    const scheme = this.#identity.getSigningScheme();
    if (message.signature.scheme !== scheme) throw new ACEError('invalid_argument', 'identity scheme changed');
    const sig = await this.#identity.sign(messageSignData(message));
    message.signature = { scheme, value: encodeSignature(sig, scheme) };
    return { ...p, status: 'pending', message };
  }

  async #writeOutbox(p: PendingSend): Promise<void> {
    await this.#store.write(outboxKey(p.requestId), canonicalStateBytes({ ...encodePendingSend(p), version: 1 }));
  }

  async #readOutboxKey(key: string): Promise<PendingSend | null> {
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const doc = parseStateBytes(raw, key);
    if (typeof doc !== 'object' || doc === null || (doc as { version?: unknown }).version !== 1) {
      throw new ACEError('storage_failed', `${key}: unknown version`);
    }
    const p = decodePendingSend(doc, key);
    if (outboxKey(p.requestId) !== key && sentKey(p.requestId) !== key) throw new ACEError('storage_failed', `${key}: record does not match its key`);
    return p;
  }

  async #locate(requestId: string): Promise<Located | null> {
    const p = await this.#readOutboxKey(outboxKey(requestId));
    if (p !== null) return { kind: 'outbox', pending: p };
    for (const record of await this.#threads.listRecords()) {
      if (record.pending?.requestId === requestId) return { kind: 'thread', pending: record.pending, record };
    }
    return null;
  }

  async #require(requestId: string): Promise<Located> {
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'invalid requestId');
    const found = await this.#locate(requestId);
    if (found === null) throw new ACEError('invalid_argument', 'no pending send with this requestId');
    return found;
  }

  async #acknowledge(requestId: string, messageId: string): Promise<void> {
    await this.#threads.withLock(async () => {
      const found = await this.#locate(requestId);
      if (found === null || found.pending.message.messageId !== messageId) return;
      if (found.kind === 'thread') {
        // saveRecord archives the prior pending operation before clearing it.
        await this.#threads.saveRecord({ snapshot: found.record.snapshot, pending: null }, found.record);
      } else {
        await archiveSent(this.#store, found.pending);
        await this.#store.delete(outboxKey(requestId));
      }
    });
  }

  async #markExpired(requestId: string, messageId: string): Promise<void> {
    await this.#threads.withLock(async () => {
      const found = await this.#locate(requestId);
      if (found === null || found.pending.message.messageId !== messageId) return;
      const pending: PendingSend = { ...found.pending, status: 'expired' };
      if (found.kind === 'outbox') await this.#writeOutbox(pending);
      else await this.#threads.saveRecord({ snapshot: found.record.snapshot, pending });
    });
  }
}
