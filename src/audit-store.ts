/** Durable optional audit infrastructure. Storage must honor ACEStore's atomic, durable writes and exclusive locks. */
import { ACEError } from './errors.js';
import { canonicalStateBytes, nowOf, isConversationId, hasExactKeys, isMessageId, parseStateBytes, wireInt } from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import type { ACEIdentity } from './types.js';
import { withLock, type ACEStore } from './store.js';
import { auditCheckpointDigest, signAuditCheckpoint, verifyAuditCheckpoint, createAuditWitnessReceipt,
  verifyAuditWitnessReceipt, witnessReceiptValid, merkle, type AuditCheckpoint, type AuditWitnessReceipt } from './audit.js';

const invalid = (message: string) => new ACEError('invalid_argument', message);
const corrupt = () => new ACEError('storage_failed', 'audit state is missing, inconsistent or corrupt');
function decode(b: Uint8Array | null): any {
  if (!b || b.length > 65_536) throw corrupt();
  try { return parseStateBytes(b, ''); } catch { throw corrupt(); }
}
const { empty, leaf, node, split } = merkle;
const same = (a: AuditCheckpoint, b: AuditCheckpoint) => auditCheckpointDigest(a) === auditCheckpointDigest(b);
interface NodeWrite { level: number; index: number; hash: string }
interface Pending { previous: AuditCheckpoint; next: AuditCheckpoint; commitment: string }
export interface AuditLogConfig {
  logId: string; signer: ACEIdentity; operator: VerifiedPeer; clock?: () => number;
}

/**
 * Incremental complete-subtree storage: O(log n) writes per append, no size/count eviction.
 * A write-ahead record is recovered before every operation. Nodes, entry, index and checkpoint
 * are durable before the head advances, and the head is durable before an acknowledgement.
 * FileStore supports multiple local processes, not replicated disks or rollback protection.
 */
export class AuditLog {
  readonly #c: AuditLogConfig;
  readonly #store: ACEStore;
  readonly #prefix: string;
  constructor(config: AuditLogConfig, store: ACEStore) {
    if (!isMessageId(config.logId) || !isVerifiedPeer(config.operator)
      || config.signer.getACEId() !== config.operator.aceId || config.signer.getSigningScheme() !== config.operator.scheme) throw invalid('invalid log configuration');
    this.#c = { ...config }; this.#store = store; this.#prefix = `audit-log/${config.logId}/`;
  }
  #locked<T>(body: () => Promise<T>): Promise<T> { return withLock(this.#store, `audit-log-${this.#c.logId}`, body); }
  #now(): number { return nowOf(this.#c.clock); }
  #verify(c: AuditCheckpoint): void {
    try { verifyAuditCheckpoint(c, this.#c.operator); if (c.logId !== this.#c.logId) throw corrupt(); }
    catch { throw corrupt(); }
  }
  async #get(key: string): Promise<any> { return decode(await this.#store.read(this.#prefix + key)); }
  async #put(key: string, value: unknown): Promise<void> { await this.#store.write(this.#prefix + key, canonicalStateBytes(value)); }
  async #immutable(key: string, value: string | AuditCheckpoint): Promise<void> {
    const old = await this.#store.read(this.#prefix + key);
    if (old) {
      const v = decode(old);
      if (typeof value !== 'string') this.#verify(v);
      if (typeof value === 'string' ? v !== value : !same(v, value)) throw corrupt();
    } else { await this.#put(key, value); }
  }
  async #node(level: number, index: number): Promise<string> {
    const value = await this.#get(`nodes/${level}-${index}`);
    if (!isConversationId(value)) throw corrupt();
    return value;
  }
  async #root(start: number, count: number): Promise<string> {
    if (count === 0) return empty;
    const k = split(count);
    if (count === 1 || count === k * 2) return this.#node(Math.log2(count), start / count);
    const [left, right] = await Promise.all([this.#root(start, k), this.#root(start + k, count - k)]);
    return node(left, right);
  }
  async #head(): Promise<AuditCheckpoint> {
    const c = await this.#get('head'); this.#verify(c);
    if (await this.#root(0, c.size) !== c.root) throw corrupt();
    return c;
  }
  async #plan(count: number, commitment: string): Promise<{ root: string; nodes: NodeWrite[] }> {
    let level = 0, index = count, h = leaf(commitment);
    const nodes: NodeWrite[] = [{ level, index, hash: h }];
    while (index % 2 === 1) {
      h = node(await this.#node(level, index - 1), h); index = Math.floor(index / 2); level++;
      nodes.push({ level, index, hash: h });
    }
    let remaining = count + 1, start = 0;
    const reads: Array<Promise<string>> = [];
    while (remaining > 0) {
      let width = 1; while (width * 2 <= remaining) width *= 2;
      const l = Math.log2(width), i = start / width, own = nodes.find(n => n.level === l && n.index === i);
      reads.push(own ? Promise.resolve(own.hash) : this.#node(l, i));
      start += width; remaining -= width;
    }
    const peaks = await Promise.all(reads);
    let root = peaks.pop()!;
    while (peaks.length) root = node(peaks.pop()!, root);
    return { root, nodes };
  }
  /**
   * Apply a write-ahead record. A recovered record is untrusted and fully re-checked; `plan` is passed only by
   * `append`, whose head was just verified and whose `next` was just signed over that plan in the same lock.
   */
  async #commit(p: Pending, plan?: { root: string; nodes: NodeWrite[] }): Promise<void> {
    if (plan === undefined) {
      this.#verify(p.previous); this.#verify(p.next);
      if (!isConversationId(p.commitment) || p.next.size !== p.previous.size + 1 || p.next.timestamp < p.previous.timestamp) throw corrupt();
      const head = await this.#head();
      if (!same(head, p.previous) && !same(head, p.next)) throw corrupt();
      if (await this.#root(0, p.previous.size) !== p.previous.root) throw corrupt();
      plan = await this.#plan(p.previous.size, p.commitment);
      if (plan.root !== p.next.root) throw corrupt();
    }
    for (const n of plan.nodes) await this.#immutable(`nodes/${n.level}-${n.index}`, n.hash);
    await this.#immutable(`entries/${p.previous.size}`, p.commitment);
    await this.#immutable(`indices/${p.commitment}`, String(p.previous.size));
    await this.#immutable(`checkpoints/${p.next.size}`, p.next);
    await this.#put('head', p.next);
    await this.#store.delete(this.#prefix + 'pending');
  }
  async #recover(): Promise<AuditCheckpoint> {
    const pending = await this.#store.read(this.#prefix + 'pending');
    if (pending) {
      const p = decode(pending);
      if (!hasExactKeys(p, ['commitment', 'next', 'previous'])) throw corrupt();
      await this.#commit(p);
    }
    return this.#head();
  }
  /** Explicit local administration. Ordinary requests never provision or reset a missing log. */
  async provision(): Promise<AuditCheckpoint> {
    return this.#locked(async () => {
      if ((await this.#store.list(this.#prefix)).length) throw invalid('log storage must be empty at provisioning');
      const timestamp = this.#now();
      const c = await signAuditCheckpoint({ logId: this.#c.logId, signer: this.#c.operator.aceId, size: 0, root: empty, timestamp }, this.#c.signer);
      this.#verify(c);
      await this.#put('checkpoints/0', c); await this.#put('head', c);
      return c;
    });
  }
  async #checkpoint(size: number, head: AuditCheckpoint): Promise<AuditCheckpoint> {
    if (wireInt(size) === null || size > head.size) throw invalid('invalid checkpoint size');
    if (size === head.size) return head; // `#recover` verified the head and its root
    const c = await this.#get(`checkpoints/${size}`);
    this.#verify(c);
    if (c.size !== size || await this.#root(0, size) !== c.root) throw corrupt();
    return c;
  }
  async checkpoint(size?: number): Promise<AuditCheckpoint> {
    return this.#locked(async () => { const h = await this.#recover(); return this.#checkpoint(size ?? h.size, h); });
  }
  /** Explicit operator heartbeat: refresh the signed time without inventing a new event. */
  async refresh(): Promise<AuditCheckpoint> {
    return this.#locked(async () => {
      const head = await this.#recover(), timestamp = this.#now();
      if (wireInt(timestamp) === null || timestamp < head.timestamp) throw invalid('log clock moved backwards');
      if (timestamp === head.timestamp) return head;
      const c = await signAuditCheckpoint({ logId: head.logId, size: head.size, root: head.root, signer: head.signer, timestamp }, this.#c.signer);
      this.#verify(c); await this.#put('head', c); return c;
    });
  }
  /** Exactly the same commitment is idempotent. Fresh private statements require fresh private salts. */
  async append(commitment: string): Promise<{ index: number; checkpoint: AuditCheckpoint; proof: string[] }> {
    if (!isConversationId(commitment)) throw invalid('a commitment must be 32 bytes of lowercase hex');
    return this.#locked(async () => {
      let head = await this.#recover();
      const old = await this.#store.read(this.#prefix + `indices/${commitment}`);
      let index: number;
      if (old) {
        const raw = decode(old); index = Number(raw);
        if (typeof raw !== 'string' || String(index) !== raw || wireInt(index) === null || index >= head.size
          || await this.#get(`entries/${index}`) !== commitment || await this.#node(0, index) !== leaf(commitment)) throw corrupt();
      } else {
        if (head.size === Number.MAX_SAFE_INTEGER) throw invalid('audit log size limit reached');
        index = head.size;
        const plan = await this.#plan(index, commitment), timestamp = this.#now();
        if (wireInt(timestamp) === null || timestamp < head.timestamp) throw invalid('log clock moved backwards');
        const next = await signAuditCheckpoint({ logId: head.logId, signer: head.signer, size: index + 1, root: plan.root, timestamp }, this.#c.signer);
        this.#verify(next);
        const pending = { previous: head, next, commitment };
        await this.#put('pending', pending);
        await this.#commit(pending, plan); head = next;
      }
      return { index, checkpoint: head, proof: await this.#inclusion(index, 0, head.size) };
    });
  }
  async #inclusion(index: number, start: number, count: number): Promise<string[]> {
    if (count === 1) return [];
    const k = split(count);
    return index < k ? [...await this.#inclusion(index, start, k), await this.#root(start + k, count - k)]
      : [...await this.#inclusion(index - k, start + k, count - k), await this.#root(start, k)];
  }
  async inclusion(index: number, size?: number): Promise<{ commitment: string; index: number; checkpoint: AuditCheckpoint; proof: string[] }> {
    return this.#locked(async () => {
      const head = await this.#recover(), c = await this.#checkpoint(size ?? head.size, head);
      if (wireInt(index) === null || index >= c.size) throw invalid('invalid inclusion index');
      const commitment = await this.#get(`entries/${index}`);
      if (!isConversationId(commitment) || leaf(commitment) !== await this.#node(0, index)) throw corrupt();
      return { commitment, index, checkpoint: c, proof: await this.#inclusion(index, 0, c.size) };
    });
  }
  async consistency(first: number, second?: number): Promise<{ checkpoint: AuditCheckpoint; proof: string[] }> {
    return this.#locked(async () => {
      const head = await this.#recover(), c = await this.#checkpoint(second ?? head.size, head);
      if (wireInt(first) === null || first > c.size) throw invalid('invalid consistency range');
      const walk = async (m: number, start: number, n: number, complete: boolean): Promise<string[]> => {
        if (m === n) return complete ? [] : [await this.#root(start, n)];
        const k = split(n);
        return m <= k ? [...await walk(m, start, k, complete), await this.#root(start + k, n - k)]
          : [...await walk(m - k, start + k, n - k, false), await this.#root(start, k)];
      };
      return { checkpoint: c, proof: first === 0 || first === c.size ? [] : await walk(first, 0, c.size, true) };
    });
  }
}

export interface AuditWitnessConfig { logId: string; operator: VerifiedPeer; signer: ACEIdentity; witness: VerifiedPeer; clock?: () => number }
/** One durable checkpoint per trusted operator/log. Run independent witnesses with independent stores and keys. */
export class AuditWitness {
  readonly #c: AuditWitnessConfig; readonly #store: ACEStore; readonly #key: string;
  constructor(config: AuditWitnessConfig, store: ACEStore) {
    if (!isMessageId(config.logId) || !isVerifiedPeer(config.operator) || !isVerifiedPeer(config.witness)
      || config.operator.aceId === config.witness.aceId || config.signer.getACEId() !== config.witness.aceId
      || config.signer.getSigningScheme() !== config.witness.scheme) throw invalid('invalid witness configuration');
    this.#c = { ...config }; this.#store = store;
    this.#key = `audit-witness/${config.logId}/${config.witness.aceId.slice(11)}.json`;
  }
  #locked<T>(fn: () => Promise<T>): Promise<T> { return withLock(this.#store, `audit-witness-${this.#c.logId}`, fn); }
  #now(): number { return nowOf(this.#c.clock); }
  async #read(): Promise<{ checkpoint: AuditCheckpoint; receipt: AuditWitnessReceipt }> {
    try {
      const s = decode(await this.#store.read(this.#key));
      if (!hasExactKeys(s, ['checkpoint', 'receipt']) || s.checkpoint.logId !== this.#c.logId) throw corrupt();
      verifyAuditWitnessReceipt(s.receipt, s.checkpoint, this.#c.operator, this.#c.witness);
      return s;
    } catch { throw corrupt(); }
  }
  async #write(checkpoint: AuditCheckpoint, previousTime = 0): Promise<AuditWitnessReceipt> {
    if (checkpoint.logId !== this.#c.logId) throw invalid('wrong log');
    const timestamp = this.#now();
    if (wireInt(timestamp) === null || timestamp < previousTime) throw invalid('witness clock moved backwards');
    const receipt = await createAuditWitnessReceipt(checkpoint, this.#c.operator, this.#c.signer, timestamp);
    // createAuditWitnessReceipt verified the checkpoint; check only the fresh signature against the pinned witness key.
    if (!witnessReceiptValid(receipt, checkpoint, auditCheckpointDigest(checkpoint), this.#c.witness)) throw new ACEError('invalid_signature', 'invalid audit witness receipt');
    await this.#store.write(this.#key, canonicalStateBytes({ checkpoint, receipt }));
    return receipt;
  }
  /** Explicit trusted bootstrap, never an unauthenticated network operation or automatic reset. */
  async provision(anchor: AuditCheckpoint): Promise<AuditWitnessReceipt> {
    const c = structuredClone(anchor);
    return this.#locked(async () => {
      if (await this.#store.read(this.#key)) throw invalid('witness already provisioned');
      return this.#write(c);
    });
  }
  async checkpoint(): Promise<AuditCheckpoint> { return this.#locked(async () => (await this.#read()).checkpoint); }
  async observe(checkpoint: AuditCheckpoint, proof: readonly string[]): Promise<AuditWitnessReceipt> {
    if (!Array.isArray(proof) || proof.length > 54 || !proof.every(isConversationId)) throw invalid('invalid consistency proof');
    const c = structuredClone(checkpoint), p = [...proof];
    return this.#locked(async () => {
      const held = await this.#read();
      verifyAuditCheckpoint(c, this.#c.operator, held.checkpoint, p);
      if (same(c, held.checkpoint)) return held.receipt;
      return this.#write(c, held.receipt.timestamp);
    });
  }
}
