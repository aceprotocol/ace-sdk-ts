/** Persistent thread records shared by Inbox and Outbox (06-security § Appendix A). */

import { ACEError } from './errors.js';
import {
  canonicalStateBytes, codePointLength, CONTROL_CHAR_RE, isACEId, pairKey, parseStateBytes, sha256Hex, wireInt,
} from './encoding.js';
import { decodeEnvelope, envelopeKnownFields } from './envelope.js';
import { MAX_OPEN_THREADS_PER_PEER } from './limits.js';
import {
  isTerminalState, ThreadStateMachine, type ThreadHistoryEntry, type ThreadSnapshot, type ThreadState,
} from './state-machine.js';
import type { ACEStore } from './store.js';
import type { ACEMessage, MessageType } from './types.js';

/**
 * A staged outbound message awaiting acknowledgement. `requestTtl` is the body `ttl` of a principal `request` (the
 * body is encrypted to the recipient, so the Outbox keeps it to write the `requests/` record after delivery);
 * persisted as `requestTtl` only when present (06 Appendix A).
 */
export interface PendingSend {
  requestId: string;
  status: 'pending' | 'expired';
  stagedAt: number;
  message: ACEMessage;
  requestTtl?: number;
}

/** Internal: a thread record (`threads/<sha256(c ‖ 0 ‖ t)>.json`). */
export interface ThreadRecord {
  snapshot: ThreadSnapshot;
  pending: PendingSend | null;
}

export const THREAD_RETENTION_SECONDS = 2592000;
const PRUNE_INTERVAL_SECONDS = 3600;

export function threadKey(conversationId: string, threadId: string): string {
  return `threads/${pairKey(conversationId, threadId)}.json`;
}

const INDEX_PREFIX = 'threads/index/';

/** Internal: the per-peer open-thread index (`threads/index/<sha256(peerAceId)>.json`). */
export function threadIndexKey(peerAceId: string): string {
  return `${INDEX_PREFIX}${sha256Hex(peerAceId)}.json`;
}

/** A thread record key (`threads/<64 hex>.json`), not an index file. */
function isRecordKey(key: string): boolean {
  return !key.startsWith(INDEX_PREFIX);
}

/** Index entry: the record key without `.json`. */
function indexEntry(recordKey: string): string {
  return recordKey.slice(0, -'.json'.length);
}

export function isRequestId(v: unknown): v is string {
  if (typeof v !== 'string' || v.length === 0 || v.length > 512) return false;
  const n = codePointLength(v);
  return n >= 1 && n <= 256 && !CONTROL_CHAR_RE.test(v);
}

/** Internal: decode a persisted PendingSend (without `version`); `storage_failed` on any defect. */
export function decodePendingSend(v: unknown, what: string): PendingSend {
  const bad = () => new ACEError('storage_failed', `${what}: invalid pending send`);
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw bad();
  const p = v as Record<string, unknown>;
  const stagedAt = wireInt(p.stagedAt);
  if (!isRequestId(p.requestId) || (p.status !== 'pending' && p.status !== 'expired') || stagedAt === null) throw bad();
  const rawTtl = p.requestTtl;
  const requestTtl = rawTtl === undefined || rawTtl === null ? null : wireInt(rawTtl);
  if (rawTtl !== undefined && rawTtl !== null && requestTtl === null) throw bad();
  let message: ACEMessage;
  try {
    message = decodeEnvelope(p.message);
  } catch {
    throw bad();
  }
  if (requestTtl !== null && message.type !== 'request') throw bad(); // requestTtl belongs to a principal request only
  const out: PendingSend = { requestId: p.requestId, status: p.status, stagedAt, message };
  if (requestTtl !== null) out.requestTtl = requestTtl;
  return out;
}

export function encodePendingSend(p: PendingSend): Record<string, unknown> {
  const d: Record<string, unknown> = {
    message: envelopeKnownFields(p.message), requestId: p.requestId, stagedAt: p.stagedAt, status: p.status,
  };
  if (p.requestTtl !== undefined) d.requestTtl = p.requestTtl;
  return d;
}

/** Internal: derive the state reached by a history (no validation beyond the table). */
export function restoreMachine(localAceId: string, snapshot: ThreadSnapshot | null): ThreadStateMachine {
  return snapshot === null
    ? new ThreadStateMachine({ localAceId })
    : ThreadStateMachine.fromState([snapshot], { localAceId });
}

/** Internal: the snapshot whose history is `history` (state derived by replay), or null if empty. */
export function snapshotWithHistory(base: ThreadSnapshot, history: ThreadHistoryEntry[]): ThreadSnapshot | null {
  if (history.length === 0) return null;
  const sm = new ThreadStateMachine({ localAceId: base.localAceId });
  for (const h of history) {
    sm.apply(
      {
        conversationId: base.conversationId, threadId: base.threadId, type: h.type, messageId: h.messageId,
        timestamp: h.timestamp, from: h.from, to: h.from === base.localAceId ? base.peerAceId : base.localAceId,
      },
      referenceBody(h.type, sm.getSnapshot(base.conversationId, base.threadId)),
    );
  }
  return sm.getSnapshot(base.conversationId, base.threadId);
}

/** A body carrying exactly the reference the position rules require (history replay). */
function referenceBody(type: MessageType, snap: ThreadSnapshot | null): Record<string, string> {
  const h = snap?.history ?? [];
  const head = h[h.length - 1]?.messageId ?? '';
  const beforeHead = h[h.length - 2]?.messageId ?? '';
  switch (type) {
    case 'accept': return { offerId: head };
    case 'invoice': return { offerId: beforeHead };
    case 'receipt': return { referenceId: head };
    case 'confirm': return { deliverId: head };
    default: return {};
  }
}

function historyEqual(a: ThreadHistoryEntry, b: ThreadHistoryEntry): boolean {
  return a.type === b.type && a.messageId === b.messageId && a.timestamp === b.timestamp && a.from === b.from;
}

/** -1: a is a strict prefix of b; 0: equal; 1: b is a strict prefix of a; null: diverged. */
export function compareHistories(a: ThreadHistoryEntry[], b: ThreadHistoryEntry[]): -1 | 0 | 1 | null {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (!historyEqual(a[i], b[i])) return null;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/**
 * Persistent economic thread state. Each record is validated on load by replaying its
 * history (`ThreadStateMachine.fromState`); a record that fails is `storage_failed` and is
 * never reset. Writes prune threads without a pending send whose last entry is older than
 * 30 days and that are terminal, or non-terminal without any local entry (04 § Retention).
 * A per-peer index of non-terminal threads (`threads/index/`) bounds the open threads per
 * peer at `MAX_OPEN_THREADS_PER_PEER`. The index is written so that a crash can only leave
 * extra entries, which are reconciled when the bound is reached.
 */
export class ThreadStore {
  readonly #records: ThreadRecords;

  constructor(opts: { store: ACEStore; localAceId: string; clock?: () => number }) {
    this.#records = new ThreadRecords(opts);
  }

  async get(conversationId: string, threadId: string): Promise<ThreadSnapshot | null> {
    return this.#records.get(conversationId, threadId);
  }

  async list(): Promise<ThreadSnapshot[]> {
    return this.#records.list();
  }

  /** Delete a thread record; false when there was none. */
  async remove(conversationId: string, threadId: string): Promise<boolean> {
    return this.#records.remove(conversationId, threadId);
  }

  async allowedTypes(conversationId: string, threadId: string, senderAceId: string): Promise<MessageType[]> {
    return this.#records.allowedTypes(conversationId, threadId, senderAceId);
  }
}

/** Internal: the thread record store behind `ThreadStore`, used by Inbox and Outbox. */
export class ThreadRecords {
  readonly localAceId: string;
  readonly #store: ACEStore;
  readonly #clock?: () => number;
  #lastPrune: number | null = null;

  constructor(opts: { store: ACEStore; localAceId: string; clock?: () => number }) {
    if (typeof opts !== 'object' || opts === null || typeof opts.store !== 'object' || opts.store === null) {
      throw new ACEError('invalid_argument', 'store is required');
    }
    if (!isACEId(opts.localAceId)) throw new ACEError('invalid_argument', 'localAceId must be an ACE ID');
    this.#store = opts.store;
    this.localAceId = opts.localAceId;
    this.#clock = opts.clock;
  }

  #now(): number {
    return Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
  }

  async get(conversationId: string, threadId: string): Promise<ThreadSnapshot | null> {
    return (await this.loadRecord(conversationId, threadId))?.snapshot ?? null;
  }

  async list(): Promise<ThreadSnapshot[]> {
    return (await this.listRecords()).map((r) => r.snapshot);
  }

  async remove(conversationId: string, threadId: string): Promise<boolean> {
    return this.withLock(async () => {
      const key = threadKey(conversationId, threadId);
      const raw = await this.#store.read(key);
      if (raw === null) return false;
      let peer: string | null = null;
      try {
        peer = this.#decode(parseStateBytes(raw, key), key).snapshot.peerAceId;
      } catch {
        // a corrupt record leaves at most an extra index entry, reconciled at the bound
      }
      await this.#store.delete(key);
      if (peer !== null) await this.#setOpen(peer, key, false);
      return true;
    });
  }

  async allowedTypes(conversationId: string, threadId: string, senderAceId: string): Promise<MessageType[]> {
    const rec = await this.loadRecord(conversationId, threadId);
    return restoreMachine(this.localAceId, rec?.snapshot ?? null).allowedTypes(conversationId, threadId, senderAceId);
  }

  /** Run `fn` under the `threads` lock. */
  async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const release = await this.#store.lock('threads');
    try {
      return await fn();
    } finally {
      await release();
    }
  }

  async loadRecord(conversationId: string, threadId: string): Promise<ThreadRecord | null> {
    const key = threadKey(conversationId, threadId);
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const rec = this.#decode(parseStateBytes(raw, key), key);
    if (rec.snapshot.conversationId !== conversationId || rec.snapshot.threadId !== threadId) {
      throw new ACEError('storage_failed', `${key}: record does not match its key`);
    }
    return rec;
  }

  async listRecords(): Promise<ThreadRecord[]> {
    const out: ThreadRecord[] = [];
    for (const key of await this.#store.list('threads/')) {
      if (!isRecordKey(key)) continue;
      const raw = await this.#store.read(key);
      if (raw === null) continue;
      const rec = this.#decode(parseStateBytes(raw, key), key);
      if (threadKey(rec.snapshot.conversationId, rec.snapshot.threadId) !== key) {
        throw new ACEError('storage_failed', `${key}: record does not match its key`);
      }
      out.push(rec);
    }
    return out;
  }

  /** Write a record (caller holds the lock), then prune old terminal threads. */
  async saveRecord(rec: ThreadRecord): Promise<void> {
    const s = rec.snapshot;
    const doc = {
      conversationId: s.conversationId,
      history: s.history.map((h) => ({ from: h.from, messageId: h.messageId, timestamp: h.timestamp, type: h.type })),
      localAceId: s.localAceId,
      peerAceId: s.peerAceId,
      pending: rec.pending === null ? null : encodePendingSend(rec.pending),
      state: s.state,
      threadId: s.threadId,
      version: 1,
    };
    const key = threadKey(s.conversationId, s.threadId);
    const open = !isTerminalState(s.state);
    if (open) await this.#setOpen(s.peerAceId, key, true); // index first: a crash leaves only an extra entry
    await this.#store.write(key, canonicalStateBytes(doc));
    if (!open) await this.#setOpen(s.peerAceId, key, false);
    await this.#maybePrune();
  }

  async deleteRecord(snapshot: ThreadSnapshot): Promise<void> {
    const key = threadKey(snapshot.conversationId, snapshot.threadId);
    await this.#store.delete(key);
    await this.#setOpen(snapshot.peerAceId, key, false);
  }

  /**
   * The number of non-terminal threads held with `peerAceId` (caller holds the lock). At the
   * bound the index is reconciled against the records first, dropping stale entries.
   */
  async openThreadCount(peerAceId: string): Promise<number> {
    const open = await this.#readIndex(peerAceId);
    if (open.length < MAX_OPEN_THREADS_PER_PEER) return open.length;
    const live: string[] = [];
    for (const entry of open) {
      const key = `${entry}.json`;
      const raw = await this.#store.read(key);
      if (raw === null) continue;
      try {
        const rec = this.#decode(parseStateBytes(raw, key), key);
        if (rec.snapshot.peerAceId !== peerAceId || isTerminalState(rec.snapshot.state)) continue;
      } catch {
        // a corrupt record still counts: it is never reset or discarded
      }
      live.push(entry);
    }
    if (live.length !== open.length) await this.#writeIndex(peerAceId, live);
    return live.length;
  }

  /**
   * Throw `limit_exceeded` if a new thread with `peerAceId` would exceed
   * `MAX_OPEN_THREADS_PER_PEER` (caller holds the lock).
   */
  async checkCanOpen(peerAceId: string): Promise<void> {
    if ((await this.openThreadCount(peerAceId)) >= MAX_OPEN_THREADS_PER_PEER) {
      throw new ACEError('limit_exceeded', `open thread limit ${MAX_OPEN_THREADS_PER_PEER} reached for this peer`);
    }
  }

  async #readIndex(peerAceId: string): Promise<string[]> {
    const key = threadIndexKey(peerAceId);
    const raw = await this.#store.read(key);
    if (raw === null) return [];
    const doc = parseStateBytes(raw, key) as Record<string, unknown>;
    if (typeof doc !== 'object' || doc === null || doc.version !== 1 || !Array.isArray(doc.open)
      || !doc.open.every((e) => typeof e === 'string' && e.startsWith('threads/'))) {
      throw new ACEError('storage_failed', `${key}: invalid open-thread index`);
    }
    return doc.open as string[];
  }

  async #writeIndex(peerAceId: string, open: string[]): Promise<void> {
    const key = threadIndexKey(peerAceId);
    if (open.length === 0) await this.#store.delete(key);
    else await this.#store.write(key, canonicalStateBytes({ open: [...open].sort(), version: 1 }));
  }

  async #setOpen(peerAceId: string, recordKey: string, open: boolean): Promise<void> {
    const entry = indexEntry(recordKey);
    const cur = await this.#readIndex(peerAceId);
    const has = cur.includes(entry);
    if (open === has) return;
    await this.#writeIndex(peerAceId, open ? [...cur, entry] : cur.filter((e) => e !== entry));
  }

  async #maybePrune(): Promise<void> {
    const now = this.#now();
    if (this.#lastPrune !== null && now - this.#lastPrune < PRUNE_INTERVAL_SECONDS) return;
    this.#lastPrune = now;
    for (const key of await this.#store.list('threads/')) {
      if (!isRecordKey(key)) continue;
      const raw = await this.#store.read(key);
      if (raw === null) continue;
      let rec: ThreadRecord;
      try {
        rec = this.#decode(parseStateBytes(raw, key), key);
      } catch {
        continue; // never reset or delete a corrupt record
      }
      const s = rec.snapshot;
      const h = s.history;
      if (rec.pending !== null || h[h.length - 1].timestamp >= now - THREAD_RETENTION_SECONDS) continue;
      // terminal, or non-terminal with no local entry (no local obligation exists)
      if (isTerminalState(s.state) || !h.some((e) => e.from === this.localAceId)) await this.deleteRecord(s);
    }
  }

  #decode(doc: unknown, key: string): ThreadRecord {
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) throw new ACEError('storage_failed', `${key}: not an object`);
    const d = doc as Record<string, unknown>;
    if (d.version !== 1) throw new ACEError('storage_failed', `${key}: unknown version`);
    if (d.localAceId !== this.localAceId) throw new ACEError('storage_failed', `${key}: belongs to another identity`);
    if (!Array.isArray(d.history)) throw new ACEError('storage_failed', `${key}: invalid history`);
    const snapshot: ThreadSnapshot = {
      conversationId: d.conversationId as string,
      threadId: d.threadId as string,
      localAceId: d.localAceId as string,
      peerAceId: d.peerAceId as string,
      state: d.state as ThreadState,
      history: d.history.map((h) => {
        const e = (typeof h === 'object' && h !== null ? h : {}) as Record<string, unknown>;
        return { type: e.type as MessageType, messageId: e.messageId as string, timestamp: e.timestamp as number, from: e.from as string };
      }),
    };
    try {
      ThreadStateMachine.fromState([snapshot], { localAceId: this.localAceId });
    } catch (e) {
      throw new ACEError('storage_failed', `${key}: history does not replay (${e instanceof ACEError ? e.message : 'invalid'})`);
    }
    for (const h of snapshot.history) h.timestamp = wireInt(h.timestamp)!;
    const pending = d.pending === null || d.pending === undefined ? null : decodePendingSend(d.pending, key);
    return { snapshot, pending };
  }
}
