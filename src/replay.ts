/** Seen store with replay horizons and a per-sender quota (06-security). */

import { ACEError } from './errors.js';
import { compareUtf8, isMessageId, wireInt } from './encoding.js';
import { DEFAULT_REPLAY_CAPACITY, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import type { ReplayState } from './types.js';

class MinHeap<T> {
  items: T[];
  constructor(private readonly less: (a: T, b: T) => boolean, items: T[] = []) {
    this.items = items;
  }
  get size(): number {
    return this.items.length;
  }
  peek(): T | undefined {
    return this.items[0];
  }
  push(v: T): void {
    const a = this.items;
    a.push(v);
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (!this.less(a[i], a[p])) break;
      [a[i], a[p]] = [a[p], a[i]];
      i = p;
    }
  }
  pop(): T | undefined {
    const a = this.items;
    if (a.length === 0) return undefined;
    const top = a[0];
    const last = a.pop()!;
    if (a.length > 0) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let m = i;
        if (l < a.length && this.less(a[l], a[m])) m = l;
        if (r < a.length && this.less(a[r], a[m])) m = r;
        if (m === i) break;
        [a[i], a[m]] = [a[m], a[i]];
        i = m;
      }
    }
    return top;
  }
  clone(): MinHeap<T> {
    return new MinHeap(this.less, this.items.slice());
  }
}

type GlobalEntry = [number, string, string]; // ts, sender, id
type SenderEntry = [number, string]; // ts, id
type HorizonEntry = [number, string]; // h, sender

const globalLess = (a: GlobalEntry, b: GlobalEntry) =>
  a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? compareUtf8(a[1], b[1]) < 0 : compareUtf8(a[2], b[2]) < 0;
const pairLess = (a: [number, string], b: [number, string]) =>
  a[0] !== b[0] ? a[0] < b[0] : compareUtf8(a[1], b[1]) < 0;

function nowOf(clock?: () => number): number {
  return Math.floor(clock ? clock() : Date.now() / 1000);
}

function tsArg(v: unknown, what: string): number {
  const n = wireInt(v);
  if (n === null) throw new ACEError('invalid_argument', `${what} must be an integer in [0, 2^53-1]`);
  return n;
}

export interface ReplayDetectorOptions {
  capacity?: number;
  horizon?: number;
  clock?: () => number;
}

/**
 * Seen store. A message `(id, sender, ts)` is accepted iff `ts > H`, `ts > SH[sender]`
 * and the pair is unseen. Entries are removed only once a horizon covers them:
 *
 * 1. entries below the acceptance floor raise `H`;
 * 2. a sender holding more than `Q = max(1, floor(capacity / 16))` entries loses its
 *    smallest ones and raises only its own `SH[sender]`;
 * 3. over capacity, the global smallest is removed and raises its sender's `SH`;
 * 4. sender horizons covered by `H` are dropped; more than `capacity` of them fold the lowest into `H`.
 *
 * Persist with `exportState()` / `ReplayDetector.fromState()`.
 */
export class ReplayDetector {
  readonly capacity: number;
  readonly #quota: number;
  readonly #clock?: () => number;
  #horizon: number;
  #sh = new Map<string, number>();
  #shHeap = new MinHeap<HorizonEntry>(pairLess);
  #live = new Map<string, Map<string, number>>(); // sender -> id -> ts
  #size = 0;
  #global = new MinHeap<GlobalEntry>(globalLess);
  #perSender = new Map<string, MinHeap<SenderEntry>>();

  constructor(opts: ReplayDetectorOptions = {}) {
    const capacity = opts.capacity ?? DEFAULT_REPLAY_CAPACITY;
    if (typeof capacity !== 'number' || !Number.isSafeInteger(capacity) || capacity < 1) {
      throw new ACEError('invalid_argument', 'capacity must be an integer >= 1');
    }
    this.capacity = capacity;
    this.#quota = Math.max(1, Math.floor(capacity / 16));
    this.#clock = opts.clock;
    this.#horizon = opts.horizon === undefined
      ? Math.max(0, nowOf(opts.clock) - TIMESTAMP_WINDOW_SECONDS)
      : tsArg(opts.horizon, 'horizon');
  }

  get horizon(): number {
    return this.#horizon;
  }

  /** Internal: the sender horizon, if any. */
  senderHorizon(sender: string): number | undefined {
    return this.#sh.get(sender);
  }

  accepts(messageId: string, sender: string, timestamp: number): boolean {
    ReplayDetector.#checkArgs(messageId, sender, timestamp);
    return this.#accepts(messageId, sender, timestamp);
  }

  /** Record a verified message. False if it is a duplicate or covered by a horizon. */
  commit(messageId: string, sender: string, timestamp: number, floor?: number): boolean {
    ReplayDetector.#checkArgs(messageId, sender, timestamp);
    const f = floor === undefined ? Math.max(0, nowOf(this.#clock) - TIMESTAMP_WINDOW_SECONDS) : tsArg(floor, 'floor');
    if (!this.#accepts(messageId, sender, timestamp)) return false;
    this.#insert(timestamp, sender, messageId);
    // 1. floor eviction raises H
    for (let m = this.#peekGlobal(); m !== undefined && m[0] < f; m = this.#peekGlobal()) {
      this.#remove(m[1], m[2]);
      this.#horizon = Math.max(this.#horizon, m[0]);
    }
    this.#purgeGlobal();
    // 2. sender quota
    this.#enforceQuota(sender);
    // 3. capacity
    this.#enforceCapacity();
    // 4. sender-horizon compaction
    this.#compact();
    return true;
  }

  /** Deep copy (used for tentative commits). */
  clone(): ReplayDetector {
    const other = new ReplayDetector({ capacity: this.capacity, horizon: this.#horizon, clock: this.#clock });
    other.#sh = new Map(this.#sh);
    other.#shHeap = this.#shHeap.clone();
    other.#live = new Map([...this.#live].map(([s, m]) => [s, new Map(m)]));
    other.#size = this.#size;
    other.#global = this.#global.clone();
    other.#perSender = new Map([...this.#perSender].map(([s, h]) => [s, h.clone()]));
    return other;
  }

  /** Canonical state: entries sorted by (timestamp, sender, messageId), horizons sorted by sender. */
  exportState(): ReplayState {
    const entries: GlobalEntry[] = [];
    for (const [s, m] of this.#live) for (const [id, ts] of m) entries.push([ts, s, id]);
    entries.sort((a, b) => (globalLess(a, b) ? -1 : globalLess(b, a) ? 1 : 0));
    const senderHorizons: Record<string, number> = {};
    for (const s of [...this.#sh.keys()].sort(compareUtf8)) {
      const h = this.#sh.get(s)!;
      if (h > this.#horizon) senderHorizons[s] = h;
    }
    return { entries: entries.map(([ts, s, id]) => [id, s, ts]), horizon: this.#horizon, senderHorizons, version: 1 };
  }

  /** Validate (`invalid_argument`) and normalize a persisted state. */
  static fromState(state: ReplayState, opts: { capacity?: number; clock?: () => number } = {}): ReplayDetector {
    const bad = (msg: string) => new ACEError('invalid_argument', `fromState: ${msg}`);
    if (typeof state !== 'object' || state === null || Array.isArray(state)) throw bad('state must be an object');
    if ((state as { version: unknown }).version !== 1) throw bad('version must be 1');
    const horizon = wireInt(state.horizon);
    const sh = state.senderHorizons as unknown;
    const entries = state.entries as unknown;
    if (horizon === null || typeof sh !== 'object' || sh === null || Array.isArray(sh) || !Array.isArray(entries)) {
      throw bad('horizon, senderHorizons and entries are required');
    }
    const det = new ReplayDetector({ capacity: opts.capacity, horizon, clock: opts.clock });
    for (const [s, h] of Object.entries(sh as Record<string, unknown>)) {
      const hv = wireInt(h);
      if (s.length === 0 || hv === null) throw bad('invalid sender horizon');
      det.#setSh(s, hv);
    }
    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length !== 3) throw bad('entries must be [messageId, sender, timestamp]');
      const [mid, s, rawTs] = entry as unknown[];
      const ts = wireInt(rawTs);
      if (!isMessageId(mid) || typeof s !== 'string' || s.length === 0 || ts === null) throw bad('invalid entry');
      if (!det.#accepts(mid, s, ts)) throw bad('entry is covered by a horizon or duplicated');
      det.#insert(ts, s, mid);
    }
    for (const s of [...det.#live.keys()].sort(compareUtf8)) det.#enforceQuota(s);
    det.#enforceCapacity();
    det.#compact();
    return det;
  }

  // --- internals ---

  static #checkArgs(messageId: unknown, sender: unknown, timestamp: unknown): void {
    if (typeof messageId !== 'string' || messageId.length === 0 || typeof sender !== 'string' || sender.length === 0) {
      throw new ACEError('invalid_argument', 'messageId and sender must be non-empty strings');
    }
    tsArg(timestamp, 'timestamp');
  }

  #accepts(mid: string, s: string, ts: number): boolean {
    return ts > this.#horizon && ts > (this.#sh.get(s) ?? this.#horizon) && !(this.#live.get(s)?.has(mid) ?? false);
  }

  #insert(ts: number, s: string, mid: string): void {
    let m = this.#live.get(s);
    if (m === undefined) {
      m = new Map();
      this.#live.set(s, m);
    }
    m.set(mid, ts);
    this.#size++;
    this.#global.push([ts, s, mid]);
    let h = this.#perSender.get(s);
    if (h === undefined) {
      h = new MinHeap<SenderEntry>(pairLess);
      this.#perSender.set(s, h);
    }
    h.push([ts, mid]);
  }

  #remove(s: string, mid: string): void {
    const m = this.#live.get(s)!;
    m.delete(mid);
    this.#size--;
    if (m.size === 0) {
      this.#live.delete(s);
      this.#perSender.delete(s);
    }
  }

  #isLive(s: string, mid: string, ts: number): boolean {
    return this.#live.get(s)?.get(mid) === ts;
  }

  #peekGlobal(): GlobalEntry | undefined {
    const g = this.#global;
    for (let top = g.peek(); top !== undefined && !this.#isLive(top[1], top[2], top[0]); top = g.peek()) g.pop();
    return g.peek();
  }

  #peekSender(s: string): SenderEntry | undefined {
    const h = this.#perSender.get(s);
    if (h === undefined) return undefined;
    for (let top = h.peek(); top !== undefined && !this.#isLive(s, top[1], top[0]); top = h.peek()) h.pop();
    return h.peek();
  }

  #setSh(s: string, h: number): void {
    this.#sh.set(s, h);
    this.#shHeap.push([h, s]);
  }

  #raiseSh(s: string, ts: number): void {
    this.#setSh(s, Math.max(this.#sh.get(s) ?? this.#horizon, ts));
    const limit = this.#sh.get(s)!;
    for (let m = this.#peekSender(s); m !== undefined && m[0] <= limit; m = this.#peekSender(s)) this.#remove(s, m[1]);
  }

  #purgeGlobal(): void {
    for (let m = this.#peekGlobal(); m !== undefined && m[0] <= this.#horizon; m = this.#peekGlobal()) this.#remove(m[1], m[2]);
  }

  #enforceQuota(s: string): void {
    while ((this.#live.get(s)?.size ?? 0) > this.#quota) {
      const [ts, mid] = this.#peekSender(s)!;
      this.#remove(s, mid);
      this.#raiseSh(s, ts);
    }
  }

  #enforceCapacity(): void {
    while (this.#size > this.capacity) {
      const [ts, s, mid] = this.#peekGlobal()!;
      this.#remove(s, mid);
      this.#raiseSh(s, ts);
    }
  }

  #dropCoveredSh(): void {
    const heap = this.#shHeap;
    for (let top = heap.peek(); top !== undefined && top[0] <= this.#horizon; top = heap.peek()) {
      heap.pop();
      if (this.#sh.get(top[1]) === top[0]) this.#sh.delete(top[1]);
    }
  }

  #compact(): void {
    this.#dropCoveredSh();
    if (this.#sh.size <= this.capacity) return;
    const excess = this.#sh.size - Math.floor(this.capacity / 2);
    const sorted = [...this.#sh].sort((a, b) => a[1] - b[1] || compareUtf8(a[0], b[0])).slice(0, excess);
    for (const [s, h] of sorted) {
      this.#sh.delete(s);
      this.#horizon = Math.max(this.#horizon, h);
    }
    this.#purgeGlobal();
    this.#dropCoveredSh();
    this.#shHeap = new MinHeap<HorizonEntry>(pairLess);
    for (const [s, h] of this.#sh) this.#shHeap.push([h, s]);
  }
}
