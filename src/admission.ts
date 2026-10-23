/**
 * The local admission table: which peers may deliver to this identity, the permits exchanged with them, blocks, and
 * pending incoming contact requests. Only explicit local actions (connect, accept, block) change admission; a remote
 * packet never does, except the `accepted` answer to a request this identity sent and a packet presenting a permit this
 * identity issued (05 § Admission recovery). The table caches those decisions: the issued permits are the decision.
 */
import { canonicalStateBytes, isACEId, isObj, nowOf, parseStateBytes, sha256Hex, wireInt } from './encoding.js';
import { CONTACT_REQUEST_TTL_SECONDS, MAX_PENDING_CONTACT_REQUESTS, OFFLINE_WINDOW_SECONDS } from './limits.js';
import type { DeliveryPermit, PublishedAgent } from './descriptor.js';
import { ACEError } from './errors.js';
import { withLock, type ACEStore } from './store.js';

/** `pending`: we sent a contact request; `admitted`: contact accepted in either direction; `blocked`: refused. */
export type PeerStatus = 'pending' | 'admitted' | 'blocked';

export interface PeerRecord {
  aceId: string;
  status: PeerStatus;
  /** The profile the relationship was opened for; absent on a row restored by admission recovery (05). */
  profile?: string;
  /**
   * The newest permit we issued to the peer, recorded once the packet carrying it was sent (renewed through receipts);
   * an Outbox retry presents it again as its reply permit while it is valid (05 § Admission recovery).
   */
  issued?: DeliveryPermit;
  /**
   * While a local block is not yet registered at the relay: the revision allocated for it, sent unchanged by every
   * retry (`maintain`); absent once the relay confirmed or superseded it.
   */
  unsyncedRevision?: number;
  /** When the status last changed; a `pending` entry lapses OFFLINE_WINDOW_SECONDS (the relay's retention) after it. */
  updatedAt: number;
}

export interface ContactRequest {
  from: string;
  messageId: string;
  profile: string;
  note: string;
  source: PublishedAgent;
  permit: DeliveryPermit;
  receivedAt: number;
}

const peerKey = (id: string) => `admission/peers/${sha256Hex(id)}.json`;
const requestKey = (id: string) => `admission/requests/${sha256Hex(id)}.json`;
const heldKey = (id: string) => `admission/permits/${sha256Hex(id)}.json`;
const revisionKey = (id: string) => `admission/block-revisions/${sha256Hex(id)}.json`;
const STATUSES: ReadonlySet<unknown> = new Set(['pending', 'admitted', 'blocked']);

/** The present `[key, bytes]` under `prefix`, read in parallel, in listing order. */
async function readAll(store: ACEStore, prefix: string): Promise<Array<[string, Uint8Array]>> {
  const keys = await store.list(prefix);
  const raws = await Promise.all(keys.map((k) => store.read(k)));
  return keys.flatMap((k, i) => { const r = raws[i]; return r === null ? [] : [[k, r] as [string, Uint8Array]]; });
}

/** A stored admission record, validated: anything malformed is `storage_failed`, never treated as absent or admitted. */
function checkRecord(v: unknown, aceId: string): PeerRecord {
  const ok = isObj(v) && v.aceId === aceId && STATUSES.has(v.status) && wireInt(v.updatedAt) !== null
    && (v.profile === undefined || typeof v.profile === 'string')
    && (v.issued === undefined || (isObj(v.issued) && v.issued.subject === aceId && wireInt(v.issued.expiresAt) !== null
      && isObj(v.issued.signature) && wireInt(v.issued.signature.seq) !== null))
    && (v.unsyncedRevision === undefined || (v.status === 'blocked' && wireInt(v.unsyncedRevision) !== null));
  if (!ok) throw new ACEError('storage_failed', 'admission record is invalid');
  return v as unknown as PeerRecord;
}

export class AdmissionBook {
  readonly #store: ACEStore;
  readonly #clock?: () => number;
  readonly #maxRequests: number;
  /** `maxRequests`: held incoming contact requests (default MAX_PENDING_CONTACT_REQUESTS). */
  constructor(store: ACEStore, o: { clock?: () => number; maxRequests?: number } = {}) {
    this.#store = store;
    this.#clock = o.clock;
    this.#maxRequests = o.maxRequests ?? MAX_PENDING_CONTACT_REQUESTS;
  }

  /**
   * The peer's record; null for a stranger. A `pending` entry whose request was sent OFFLINE_WINDOW_SECONDS ago has
   * lapsed (05 § Flow step 4): it reads as absent, and the next `update` replaces it.
   */
  async get(aceId: string): Promise<PeerRecord | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const raw = await this.#store.read(peerKey(aceId));
    if (raw === null) return null;
    const r = checkRecord(parseStateBytes(raw, 'admission record'), aceId);
    return this.#lapsed(r) ? null : r;
  }

  #lapsed(r: PeerRecord): boolean {
    return r.status === 'pending' && nowOf(this.#clock) >= r.updatedAt + OFFLINE_WINDOW_SECONDS;
  }

  /** Read-modify-write under `admission`; an optional block revision rejects a decision overtaken by a block change. */
  async update(aceId: string, fn: (old: PeerRecord | null) => PeerRecord | null, o: { expectedBlockRevision?: number } = {}): Promise<PeerRecord | null> {
    return withLock(this.#store, 'admission', async () => {
      if (o.expectedBlockRevision !== undefined && await this.blockRevision(aceId) !== o.expectedBlockRevision) {
        throw new ACEError('not_permitted', 'the peer block changed during this admission');
      }
      const next = fn(await this.get(aceId));
      if (next === null) await this.#store.delete(peerKey(aceId));
      else await this.#store.write(peerKey(aceId), canonicalStateBytes(next));
      return next;
    });
  }

  async list(): Promise<PeerRecord[]> {
    const out: PeerRecord[] = [];
    for (const [key, raw] of await readAll(this.#store, 'admission/peers/')) {
      const d = parseStateBytes(raw, key);
      if (!isObj(d) || !isACEId(d.aceId) || peerKey(d.aceId) !== key) throw new ACEError('storage_failed', `${key} is invalid`);
      const r = checkRecord(d, d.aceId);
      if (!this.#lapsed(r)) out.push(r);
    }
    return out;
  }

  /**
   * Hold a verified permit `permit.issuer` issued to us: the one slot per issuer, written by every path (accept,
   * `accepted`, receipt renewal, invitation, import). Holding a permit only lets us reach the issuer and never touches
   * admission. Checked under the `admission` lock: `when` makes it conditional on the issuer's record, and `keep`
   * (default: the held one is newer by `issuedAt`) keeps the held permit instead.
   */
  async holdPermit(permit: DeliveryPermit, o: { when?: (record: PeerRecord | null) => boolean; keep?: (held: DeliveryPermit) => boolean } = {}): Promise<void> {
    const keep = o.keep ?? ((held: DeliveryPermit) => held.issuedAt > permit.issuedAt);
    await withLock(this.#store, 'admission', async () => {
      if (o.when !== undefined && !o.when(await this.get(permit.issuer))) return;
      const old = await this.heldPermit(permit.issuer);
      if (old === null || !keep(old)) await this.#store.write(heldKey(permit.issuer), canonicalStateBytes(permit));
    });
  }

  /** The permit held from `aceId` (see `holdPermit`), if any; unverified (verify it under the issuer's current pin). */
  async heldPermit(aceId: string): Promise<DeliveryPermit | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const raw = await this.#store.read(heldKey(aceId));
    if (raw === null) return null;
    const p = parseStateBytes(raw, 'held permit');
    if (!isObj(p) || p.issuer !== aceId || wireInt(p.issuedAt) === null || wireInt(p.expiresAt) === null) throw new ACEError('storage_failed', 'held permit is invalid');
    return p as unknown as DeliveryPermit;
  }

  /**
   * Hold an incoming contact request (05 § Flow): one per sender (a newer one replaces it), each expiring
   * CONTACT_REQUEST_TTL_SECONDS after `receivedAt`, and when the store is full the oldest held request is evicted.
   */
  async saveRequest(r: ContactRequest): Promise<void> {
    await withLock(this.#store, 'admission', async () => {
      // A block both changes admission and deletes the held request under this same lock.
      // Do not let a receive that started earlier recreate it after that deletion.
      if ((await this.get(r.from))?.status === 'blocked') return;
      const held = (await this.requests()).filter((x) => x.from !== r.from);
      while (held.length >= this.#maxRequests) await this.deleteRequest(held.shift()!.from);
      await this.#store.write(requestKey(r.from), canonicalStateBytes(r));
    });
  }

  #expired(r: ContactRequest): boolean {
    return nowOf(this.#clock) >= r.receivedAt + CONTACT_REQUEST_TTL_SECONDS;
  }

  /** The unexpired held request from `aceId`, if any. */
  async request(aceId: string): Promise<ContactRequest | null> {
    const raw = await this.#store.read(requestKey(aceId));
    if (raw === null) return null;
    const r = parseStateBytes(raw, 'contact request') as ContactRequest;
    return this.#expired(r) ? null : r;
  }

  /** Unexpired held requests, oldest first; expired ones are deleted. */
  async requests(): Promise<ContactRequest[]> {
    const out: ContactRequest[] = [];
    for (const [key, raw] of await readAll(this.#store, 'admission/requests/')) {
      const r = parseStateBytes(raw, key) as ContactRequest;
      if (this.#expired(r)) await this.#store.delete(key);
      else out.push(r);
    }
    return out.sort((a, b) => a.receivedAt - b.receivedAt || (a.from < b.from ? -1 : 1));
  }

  async deleteRequest(aceId: string): Promise<void> {
    await this.#store.delete(requestKey(aceId));
  }

  /**
   * The next relay block revision for `aceId` (05 § Blocks: strictly increasing per peer, `max(previous + 1, now)` so a
   * decision made after the records were lost still outranks the earlier ones), persisted before it is used and kept
   * after an unblock, as the relay keeps it: a retried or lost request never reuses a revision.
   */
  async nextBlockRevision(aceId: string, expectedRevision?: number): Promise<number> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    return withLock(this.#store, 'admission', async () => {
      if (expectedRevision !== undefined && await this.blockRevision(aceId) !== expectedRevision) {
        throw new ACEError('not_permitted', 'the peer block changed during this admission');
      }
      return this.#allocate(aceId);
    });
  }

  /** The durable block generation, including after the record was unblocked or its relay sync completed. */
  async blockRevision(aceId: string): Promise<number> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const raw = await this.#store.read(revisionKey(aceId));
    const revision = raw === null ? 0 : wireInt((parseStateBytes(raw, 'block revision') as { revision?: unknown }).revision);
    if (revision === null) throw new ACEError('storage_failed', 'block revision is invalid');
    return revision;
  }

  /**
   * Record a local block of `aceId`, discard its held request and allocate its relay revision in one step under the
   * `admission` lock (an accept admits under the same lock, so it can never land between them): the record
   * carries that revision as `unsyncedRevision` until the relay registers it. Any later revision (an unblock, an
   * explicit admission) is strictly higher, so a late retry of this block is refused by the relay (`stale_revision`).
   */
  async block(aceId: string, now: number): Promise<number> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    return withLock(this.#store, 'admission', async () => {
      const revision = await this.#allocate(aceId);
      const old = await this.get(aceId);
      const next: PeerRecord = { ...(old ?? {}), aceId, status: 'blocked', unsyncedRevision: revision, updatedAt: now };
      await this.#store.write(peerKey(aceId), canonicalStateBytes(next));
      await this.deleteRequest(aceId);
      return revision;
    });
  }

  /**
   * Delete `aceId`'s blocked record after an unblock registered with `revision`, unless a later revision was
   * allocated since (a concurrent block or admission owns the record then).
   */
  async clearBlock(aceId: string, revision: number): Promise<void> {
    await withLock(this.#store, 'admission', async () => {
      const raw = await this.#store.read(revisionKey(aceId));
      const current = raw === null ? 0 : wireInt((parseStateBytes(raw, 'block revision') as { revision?: unknown }).revision);
      if (current === revision && (await this.get(aceId))?.status === 'blocked') await this.#store.delete(peerKey(aceId));
    });
  }

  async #allocate(aceId: string): Promise<number> {
    const next = Math.max(await this.blockRevision(aceId) + 1, nowOf(this.#clock));
    await this.#store.write(revisionKey(aceId), canonicalStateBytes({ revision: next }));
    return next;
  }
}
