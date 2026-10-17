/** A delivered-message log over any ACEStore: the Inbox `onMessage`/`checkCapacity` pair, with unread cap and ack. */
import { ACEError } from './errors.js';
import { canonicalStateBytes, nowOf, pairKey, parseStateBytes } from './encoding.js';
import { withLock, type ACEStore } from './store.js';
import type { ParsedMessage } from './types.js';

export interface StoredMessage extends ParsedMessage { receivedAt: number; read: boolean }
export interface MessageFilter { from?: string; type?: string; threadId?: string }
export interface MessageRef { from: string; messageId: string }

const PREFIX = 'messages/';
/**
 * Index keys carry their sort order and message key in the name (`<receivedAt, 12 digits>-<message key hash>`), so
 * counting, listing and retention read only the messages they return. `unread/` holds every unread message, `read/`
 * every read one.
 */
const UNREAD = 'message-index/unread/';
const READ = 'message-index/read/';
const hashOf = (from: string, messageId: string) => pairKey(from, messageId);
const keyOf = (h: string) => `${PREFIX}${h}.json`;
const indexName = (receivedAt: number, h: string) => `${String(receivedAt).padStart(12, '0')}-${h}`;
const parseIndex = (k: string, prefix: string): { receivedAt: number; h: string } => {
  const m = /^(\d{12})-([0-9a-f]{64})$/.exec(k.slice(prefix.length));
  if (!m) throw new ACEError('storage_failed', `${k} is not a message index key`);
  return { receivedAt: Number(m[1]), h: m[2] };
};

const matchesFilter = (f: MessageFilter) => (m: Pick<ParsedMessage, 'from' | 'type' | 'threadId'>): boolean =>
  (!f.from || m.from === f.from) && (!f.type || m.type === f.type) && (!f.threadId || m.threadId === f.threadId);

export class MessageLog {
  readonly #store: ACEStore;
  readonly #maxUnread: number;
  readonly #retention: number;
  readonly #clock?: () => number;

  /** `maxUnread` (default 1000) unread messages; read messages are deleted after `retentionSeconds` (default 30 days). */
  constructor(store: ACEStore, o: { maxUnread?: number; retentionSeconds?: number; clock?: () => number } = {}) {
    this.#store = store;
    this.#maxUnread = o.maxUnread ?? 1000;
    this.#retention = o.retentionSeconds ?? 30 * 86400;
    this.#clock = o.clock;
  }

  async #read(h: string): Promise<StoredMessage | null> {
    const k = keyOf(h), raw = await this.#store.read(k);
    return raw === null ? null : parseStateBytes(raw, k) as StoredMessage;
  }

  /** Counts index entries; reads no message. */
  async unreadCount(): Promise<number> {
    return (await this.#store.list(UNREAD)).length;
  }

  /** Throws `receiver_capacity` when the unread cap is reached (a message already stored always fits). */
  async checkCapacity(m: ParsedMessage): Promise<void> {
    if (await this.#store.read(keyOf(hashOf(m.from, m.messageId))) !== null) return;
    if (await this.unreadCount() >= this.#maxUnread) throw new ACEError('receiver_capacity', 'consume and acknowledge unread messages to make room', { retryAfterSeconds: 30 });
  }

  /** Idempotent per (from, messageId). */
  async save(m: ParsedMessage): Promise<'saved' | 'duplicate'> {
    return withLock(this.#store, 'messages', async () => {
      const h = hashOf(m.from, m.messageId), old = await this.#read(h);
      if (old !== null) {
        // Repair an index entry a crash between the two writes left out (rewriting an empty marker is harmless).
        await this.#store.write((old.read ? READ : UNREAD) + indexName(old.receivedAt, h), new Uint8Array());
        return 'duplicate';
      }
      const receivedAt = nowOf(this.#clock);
      // Index after the record: an index entry always names a stored message.
      await this.#store.write(keyOf(h), canonicalStateBytes({ ...m, receivedAt, read: false }));
      await this.#store.write(UNREAD + indexName(receivedAt, h), new Uint8Array());
      return 'saved';
    });
  }

  /** Delete read messages past retention (oldest first; stops at the first one inside it). */
  async #purge(): Promise<void> {
    const cutoff = nowOf(this.#clock) - this.#retention;
    for (const k of await this.#store.list(READ)) {
      const { receivedAt, h } = parseIndex(k, READ);
      if (receivedAt >= cutoff) break;
      await this.#store.delete(keyOf(h));
      await this.#store.delete(k);
    }
  }

  /** Oldest first; `limit` applies after filtering. Read messages past retention are deleted first. */
  async list(o: MessageFilter & { unreadOnly?: boolean; limit?: number } = {}): Promise<StoredMessage[]> {
    await withLock(this.#store, 'messages', () => this.#purge());
    const keep = matchesFilter(o), limit = o.limit ?? 50, out: StoredMessage[] = [];
    const names = (await this.#store.list(UNREAD)).map((k) => parseIndex(k, UNREAD));
    if (o.unreadOnly === false) names.push(...(await this.#store.list(READ)).map((k) => parseIndex(k, READ)));
    names.sort((a, b) => a.receivedAt - b.receivedAt || (a.h < b.h ? -1 : 1));
    for (const { h } of names) {
      if (out.length >= limit) break;
      const m = await this.#read(h);
      if (m !== null && keep(m) && !(m.read && o.unreadOnly !== false)) out.push(m);
    }
    return out;
  }

  /** Mark messages read; returns how many changed. */
  async ack(refs: readonly MessageRef[]): Promise<number> {
    return withLock(this.#store, 'messages', async () => {
      let n = 0;
      for (const r of refs) {
        const h = hashOf(r.from, r.messageId), m = await this.#read(h);
        if (m === null) continue;
        if (!m.read) {
          await this.#store.write(keyOf(h), canonicalStateBytes({ ...m, read: true }));
          n++;
        }
        // Also repairs the index after a crash between these writes.
        await this.#store.write(READ + indexName(m.receivedAt, h), new Uint8Array());
        await this.#store.delete(UNREAD + indexName(m.receivedAt, h));
      }
      return n;
    });
  }
}
