const replayKey = (id: string, sender: string): string => JSON.stringify([sender, id]);

const MAX_DRIFT_SECONDS = 300; // 5 minutes
const MESSAGE_ID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

import { sanitizeForError } from './utils.js';

export function validateMessageId(messageId: string): void {
  if (!MESSAGE_ID_V4_PATTERN.test(messageId)) {
    throw new Error(`Invalid messageId: expected UUID v4, got '${sanitizeForError(messageId, 50)}'`);
  }
}

/**
 * Check that a timestamp is within the 5-minute freshness window.
 * Rejects messages with |now - timestamp| > 5 minutes.
 */
export function checkTimestampFreshness(timestamp: number, oldestTimestamp?: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new Error('Invalid timestamp: must be a non-negative safe integer');
  }
  const now = Math.floor(Date.now() / 1000);
  if (oldestTimestamp !== undefined && (!Number.isSafeInteger(oldestTimestamp) || oldestTimestamp < 0 || oldestTimestamp > now)) {
    throw new Error('Invalid offline timestamp floor');
  }
  const drift = Math.abs(now - timestamp);
  if (timestamp < (oldestTimestamp ?? now - MAX_DRIFT_SECONDS) || timestamp > now + MAX_DRIFT_SECONDS) {
    throw new Error(
      `Timestamp not fresh: drift ${drift}s exceeds max ${MAX_DRIFT_SECONDS}s`,
    );
  }
}

export interface ReplayDetectorExport {
  /** Messages with `timestamp <= horizon` are rejected. */
  horizon: number;
  /** Messages from `sender` with `timestamp <= senderHorizons[sender]` are rejected. */
  senderHorizons: Record<string, number>;
  /** `[messageId, sender ACE ID, signed envelope timestamp]` triples. */
  entries: [string, string, number][];
}

/**
 * Seen store with a replay horizon (06-security § Replay Protection).
 *
 * Holds `(messageId, sender, timestamp)` for every message whose signature
 * verified. Rejects any message with `timestamp <= horizon`, or `<=` its
 * sender's horizon, so an entry can be removed once a horizon covers it: only
 * the smallest-timestamp entry is removed. Below the acceptance floor it raises
 * the horizon; over `capacity` it raises only its sender's horizon, so a sender
 * flooding the store cannot block anyone else.
 *
 * SAFETY: This class is NOT thread-safe. Do not share instances across
 * Worker Threads or concurrent event loops.
 *
 * Callers MUST persist state via export()/fromExport() across restarts.
 */
export class ReplayDetector {
  private readonly ids = new Set<string>();
  // Min-heap of [timestamp, messageId, sender].
  private readonly heap: [number, string, string][] = [];
  private _horizon = Math.floor(Date.now() / 1000) - MAX_DRIFT_SECONDS;
  private senderHorizons = new Map<string, number>();

  constructor(private readonly capacity: number = 100_000) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) {
      throw new Error('ReplayDetector capacity must be a positive integer');
    }
  }

  get horizon(): number {
    return this._horizon;
  }

  /** Pipeline steps 2–3: true if `timestamp` is above both horizons and `messageId` is unseen. */
  accepts(messageId: string, sender: string, timestamp: number): boolean {
    return timestamp > this._horizon
      && timestamp > (this.senderHorizons.get(sender) ?? this._horizon)
      && !this.ids.has(replayKey(messageId, sender));
  }

  /**
   * Pipeline step 4: record a message whose signature has verified.
   * Returns false if it is a duplicate or at/below a horizon.
   * `floor` is the acceptance floor (default `now - 5 min`).
   */
  commit(messageId: string, sender: string, timestamp: number, floor: number = Math.floor(Date.now() / 1000) - MAX_DRIFT_SECONDS): boolean {
    if (!this.accepts(messageId, sender, timestamp)) return false;
    this.ids.add(replayKey(messageId, sender));
    this.push([timestamp, messageId, sender]);
    this.evict(floor);
    return true;
  }

  export(): ReplayDetectorExport {
    // Horizon-covered heap entries may remain until serialization. Remove them
    // here (already O(n)) so every exported entry is valid on restoration.
    const live = this.heap.filter(([ts, , sender]) => ts > this._horizon && ts > (this.senderHorizons.get(sender) ?? this._horizon));
    this.heap.length = 0;
    this.ids.clear();
    for (const entry of live) {
      this.push(entry);
      this.ids.add(replayKey(entry[1], entry[2]));
    }
    return {
      horizon: this._horizon,
      senderHorizons: Object.fromEntries(this.senderHorizons),
      entries: this.heap.map(([ts, id, sender]) => [id, sender, ts]),
    };
  }

  static fromExport(data: ReplayDetectorExport, capacity: number = 100_000): ReplayDetector {
    const detector = new ReplayDetector(capacity);
    const senderHorizons: unknown = data?.senderHorizons;
    if (!Number.isSafeInteger(data?.horizon) || data.horizon < 0 || !Array.isArray(data.entries)
      || typeof senderHorizons !== 'object' || senderHorizons === null || Array.isArray(senderHorizons)) {
      throw new Error('fromExport: invalid replay state');
    }
    detector._horizon = data.horizon;
    for (const [sender, h] of Object.entries(senderHorizons)) {
      if (sender === '' || !Number.isSafeInteger(h) || h < 0) {
        throw new Error('fromExport: invalid replay state');
      }
      detector.senderHorizons.set(sender, h);
    }
    for (const entry of data.entries) {
      const [id, sender, ts]: unknown[] = Array.isArray(entry) ? entry : [];
      if (typeof id !== 'string' || !MESSAGE_ID_V4_PATTERN.test(id)) {
        throw new Error(`fromExport: invalid messageId '${sanitizeForError(String(id), 50)}'`);
      }
      if (typeof sender !== 'string' || sender === '' || typeof ts !== 'number' || !Number.isSafeInteger(ts)
        || !detector.accepts(id, sender, ts)) {
        throw new Error('fromExport: invalid entry');
      }
      detector.ids.add(replayKey(id, sender));
      detector.push([ts, id, sender]);
    }
    detector.evict(0);
    return detector;
  }

  /**
   * Remove smallest-timestamp entries: below `floor` they raise the horizon,
   * over capacity they raise only their sender's horizon.
   */
  private evict(floor: number): void {
    while (this.heap.length > 0 && this.heap[0][0] < floor) {
      const [ts, id, sender] = this.pop();
      this.ids.delete(replayKey(id, sender));
      this._horizon = Math.max(this._horizon, ts);
    }
    while (this.heap.length > this.capacity) {
      const [ts, id, sender] = this.pop();
      this.ids.delete(replayKey(id, sender));
      this.senderHorizons.set(sender, Math.max(this.senderHorizons.get(sender) ?? ts, ts));
    }
    this.compactSenderHorizons();
  }

  /**
   * Keep at most `capacity` sender horizons: drop those the horizon already
   * covers, then fold the lowest half into the horizon (amortized O(log n)).
   */
  private compactSenderHorizons(): void {
    if (this.senderHorizons.size <= this.capacity) return;
    for (const [sender, h] of this.senderHorizons) {
      if (h <= this._horizon) this.senderHorizons.delete(sender);
    }
    const excess = this.senderHorizons.size - Math.floor(this.capacity / 2);
    if (excess <= 0) return;
    const lowest = [...this.senderHorizons].sort((a, b) => a[1] - b[1]).slice(0, excess);
    for (const [sender, h] of lowest) {
      this.senderHorizons.delete(sender);
      this._horizon = Math.max(this._horizon, h);
    }
  }

  private push(item: [number, string, string]): void {
    const h = this.heap;
    h.push(item);
    for (let i = h.length - 1; i > 0;) {
      const parent = (i - 1) >> 1;
      if (h[parent][0] <= h[i][0]) break;
      [h[parent], h[i]] = [h[i], h[parent]];
      i = parent;
    }
  }

  private pop(): [number, string, string] {
    const h = this.heap;
    const top = h[0];
    const last = h.pop()!;
    if (h.length > 0) {
      h[0] = last;
      for (let i = 0; ;) {
        const l = 2 * i + 1, r = l + 1;
        let min = i;
        if (l < h.length && h[l][0] < h[min][0]) min = l;
        if (r < h.length && h[r][0] < h[min][0]) min = r;
        if (min === i) break;
        [h[min], h[i]] = [h[i], h[min]];
        i = min;
      }
    }
    return top;
  }
}
