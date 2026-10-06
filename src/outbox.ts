/** Sender durability: stage, deliver, re-sign, abandon (design §2.13, 06 § Durable Delivery, Sender). */

import { ACEError } from './errors.js';
import {
  canonicalStateBytes, encodeSignature, isACEId, parseStateBytes, sha256Hex,
} from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { computeConversationId } from './encryption.js';
import { messageSignData } from './envelope.js';
import { buildMessage } from './messages.js';
import { repairThreadsFromDeliveries } from './inbox.js';
import { ThreadStateMachine } from './state-machine.js';
import type { ACEStore } from './store.js';
import {
  decodePendingSend, encodePendingSend, isRequestId, restoreMachine, snapshotWithHistory, ThreadStore,
  type PendingSend, type ThreadRecord,
} from './thread-store.js';
import type { ACEIdentity, ACEMessage, JSONObject, MessageType } from './types.js';
import { isEconomicType } from './types.js';

export type { PendingSend };

function outboxKey(requestId: string): string {
  return `outbox/${sha256Hex(requestId)}.json`;
}

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
  readonly #threads: ThreadStore;
  readonly #clock?: () => number;

  private constructor(o: { identity: ACEIdentity; store: ACEStore; clock?: () => number }) {
    if (typeof o !== 'object' || o === null || typeof o.store !== 'object' || o.store === null || typeof o.identity !== 'object') {
      throw new ACEError('invalid_argument', 'identity and store are required');
    }
    this.#identity = o.identity;
    this.#store = o.store;
    this.#clock = o.clock;
    const local = o.identity.getACEId();
    if (!isACEId(local)) throw new ACEError('invalid_argument', 'identity has an invalid ACE ID');
    this.#threads = new ThreadStore({ store: o.store, localAceId: local, clock: o.clock });
  }

  /**
   * Open an outbox. Under lock `threads`, thread records are first repaired from `deliveries/`
   * records whose thread snapshot strictly extends the stored history (an Inbox that crashed
   * between its delivery and thread writes), so staging never diverges from received history.
   * Messages are not handed over and replay state is not touched.
   */
  static async open(o: { identity: ACEIdentity; store: ACEStore; clock?: () => number }): Promise<Outbox> {
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
  async stage(o: { recipient: VerifiedPeer; type: MessageType; body: JSONObject; threadId?: string; requestId?: string }): Promise<PendingSend> {
    if (typeof o !== 'object' || o === null) throw new ACEError('invalid_argument', 'options are required');
    const requestId = o.requestId ?? crypto.randomUUID();
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'requestId must be 1-256 characters without control characters');
    if (!isVerifiedPeer(o.recipient)) throw new ACEError('invalid_argument', 'recipient must be a VerifiedPeer');
    const existing = await this.#locate(requestId);
    if (existing !== null) return existing.pending;
    const local = this.#identity.getACEId();
    if (!isEconomicType(o.type)) {
      const message = await buildMessage({
        sender: this.#identity, recipient: o.recipient, type: o.type, body: o.body,
        threads: new ThreadStateMachine({ localAceId: local }), threadId: o.threadId, timestamp: this.#now(),
      });
      const pending: PendingSend = { requestId, status: 'pending', stagedAt: this.#now(), message };
      await this.#writeOutbox(pending);
      return pending;
    }
    if (o.threadId === undefined) throw new ACEError('invalid_argument', 'economic messages require threadId');
    return this.#threads.withLock(async () => {
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
        threadId: o.threadId, timestamp: this.#now(),
      });
      const pending: PendingSend = { requestId, status: 'pending', stagedAt: this.#now(), message };
      await this.#threads.saveRecord({ snapshot: machine.getSnapshot(conversationId, o.threadId!)!, pending });
      return pending;
    });
  }

  /**
   * Hand the pending envelope to `transport`. On success the send is acknowledged
   * (economic: the thread's pending is cleared; otherwise the outbox file is deleted).
   * `envelope_expired` marks it `expired` (then `resign`); any other error leaves it unchanged.
   */
  async deliver(requestId: string, transport: (env: ACEMessage) => Promise<void>): Promise<void> {
    if (typeof transport !== 'function') throw new ACEError('invalid_argument', 'transport must be a function');
    const found = await this.#require(requestId);
    if (found.pending.status === 'expired') throw new ACEError('envelope_expired', 'the pending send expired; resign it first');
    const message = found.pending.message;
    try {
      await transport(message);
    } catch (e) {
      if (e instanceof ACEError && e.code === 'envelope_expired') await this.#markExpired(requestId, message.messageId);
      throw e;
    }
    await this.#acknowledge(requestId, message.messageId);
  }

  /**
   * Re-sign an `expired` send with the same messageId and `timestamp = now`. The ciphertext is
   * reused (the plaintext is not persisted; the AEAD binds the conversationId, the new signature
   * binds the new timestamp). Economic: the head entry is rebuilt with the new timestamp.
   */
  async resign(requestId: string): Promise<PendingSend> {
    const found = await this.#require(requestId);
    if (found.pending.status !== 'expired') throw new ACEError('invalid_argument', 'only an expired send can be re-signed');
    if (found.kind === 'outbox') {
      const pending = await this.#resigned(found.pending);
      await this.#writeOutbox(pending);
      return pending;
    }
    return this.#threads.withLock(async () => {
      const rec = await this.#reload(found.record, requestId);
      const pending = await this.#resigned(rec.pending!);
      const h = rec.snapshot.history.slice();
      const head = h[h.length - 1];
      if (head?.messageId !== pending.message.messageId) throw new ACEError('storage_failed', 'pending send is not the thread head');
      h[h.length - 1] = { ...head, timestamp: pending.message.timestamp };
      await this.#threads.saveRecord({ snapshot: snapshotWithHistory(rec.snapshot, h)!, pending });
      return pending;
    });
  }

  /** Drop a pending send (unknown requestId: no-op). Economic: if it is the thread head, the head entry is removed. */
  async abandon(requestId: string): Promise<void> {
    if (!isRequestId(requestId)) throw new ACEError('invalid_argument', 'invalid requestId');
    const found = await this.#locate(requestId);
    if (found === null) return; // unknown requestId: no-op
    if (found.kind === 'outbox') {
      await this.#store.delete(outboxKey(requestId));
      return;
    }
    await this.#threads.withLock(async () => {
      const rec = await this.#reload(found.record, requestId);
      const h = rec.snapshot.history;
      const isHead = h[h.length - 1]?.messageId === rec.pending!.message.messageId;
      const snapshot = isHead ? snapshotWithHistory(rec.snapshot, h.slice(0, -1)) : rec.snapshot;
      if (snapshot === null) await this.#threads.deleteRecord(rec.snapshot);
      else await this.#threads.saveRecord({ snapshot, pending: null });
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
    if (outboxKey(p.requestId) !== key) throw new ACEError('storage_failed', `${key}: record does not match its key`);
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

  /** Re-read a thread record under the lock and require the same pending send. */
  async #reload(record: ThreadRecord, requestId: string): Promise<ThreadRecord> {
    const rec = await this.#threads.loadRecord(record.snapshot.conversationId, record.snapshot.threadId);
    if (rec?.pending?.requestId !== requestId) throw new ACEError('invalid_argument', 'no pending send with this requestId');
    return rec;
  }

  async #acknowledge(requestId: string, messageId: string): Promise<void> {
    const found = await this.#locate(requestId);
    if (found === null) return;
    if (found.kind === 'outbox') {
      if (found.pending.message.messageId === messageId) await this.#store.delete(outboxKey(requestId));
      return;
    }
    await this.#threads.withLock(async () => {
      const rec = await this.#threads.loadRecord(found.record.snapshot.conversationId, found.record.snapshot.threadId);
      if (rec?.pending?.message.messageId === messageId) await this.#threads.saveRecord({ snapshot: rec.snapshot, pending: null });
    });
  }

  async #markExpired(requestId: string, messageId: string): Promise<void> {
    const found = await this.#locate(requestId);
    if (found === null || found.pending.message.messageId !== messageId) return;
    if (found.kind === 'outbox') {
      await this.#writeOutbox({ ...found.pending, status: 'expired' });
      return;
    }
    await this.#threads.withLock(async () => {
      const rec = await this.#threads.loadRecord(found.record.snapshot.conversationId, found.record.snapshot.threadId);
      if (rec?.pending?.message.messageId === messageId) {
        await this.#threads.saveRecord({ snapshot: rec.snapshot, pending: { ...rec.pending, status: 'expired' } });
      }
    });
  }
}
