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
  /** `[messageId, signed envelope timestamp]` pairs. */
  entries: [string, number][];
}

/**
 * Seen store with a replay horizon (06-security § Replay Protection).
 *
 * Holds `(messageId, timestamp)` for every message whose signature verified.
 * Rejects any message with `timestamp <= horizon`, so an entry can be removed
 * once the horizon covers it: only the smallest-timestamp entry is removed,
 * and the horizon moves up to its timestamp. Removal happens when the entry
 * falls below the acceptance floor or the store exceeds `capacity`.
 *
 * SAFETY: This class is NOT thread-safe. Do not share instances across
 * Worker Threads or concurrent event loops.
 *
 * Callers MUST persist state via export()/fromExport() across restarts.
 */
export class ReplayDetector {
  private readonly ids = new Set<string>();
  // Min-heap of [timestamp, messageId].
  private readonly heap: [number, string][] = [];
  private _horizon = Math.floor(Date.now() / 1000) - MAX_DRIFT_SECONDS;

  constructor(private readonly capacity: number = 100_000) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) {
      throw new Error('ReplayDetector capacity must be a positive integer');
    }
  }

  get horizon(): number {
    return this._horizon;
  }

  /** Pipeline steps 2–3: true if `timestamp` is above the horizon and `messageId` is unseen. */
  accepts(messageId: string, timestamp: number): boolean {
    return timestamp > this._horizon && !this.ids.has(messageId);
  }

  /**
   * Pipeline step 4: record a message whose signature has verified.
   * Returns false if it is a duplicate or at/below the horizon.
   * `floor` is the acceptance floor (default `now - 5 min`).
   */
  commit(messageId: string, timestamp: number, floor: number = Math.floor(Date.now() / 1000) - MAX_DRIFT_SECONDS): boolean {
    if (!this.accepts(messageId, timestamp)) return false;
    this.ids.add(messageId);
    this.push([timestamp, messageId]);
    this.evict(floor);
    return true;
  }

  export(): ReplayDetectorExport {
    return { horizon: this._horizon, entries: this.heap.map(([ts, id]) => [id, ts]) };
  }

  static fromExport(data: ReplayDetectorExport, capacity: number = 100_000): ReplayDetector {
    const detector = new ReplayDetector(capacity);
    if (!Number.isSafeInteger(data?.horizon) || data.horizon < 0 || !Array.isArray(data.entries)) {
      throw new Error('fromExport: invalid replay state');
    }
    detector._horizon = data.horizon;
    for (const entry of data.entries) {
      const [id, ts]: unknown[] = Array.isArray(entry) ? entry : [];
      if (typeof id !== 'string' || !MESSAGE_ID_V4_PATTERN.test(id)) {
        throw new Error(`fromExport: invalid messageId '${sanitizeForError(String(id), 50)}'`);
      }
      if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts <= data.horizon || detector.ids.has(id)) {
        throw new Error('fromExport: invalid entry');
      }
      detector.ids.add(id);
      detector.push([ts, id]);
    }
    detector.evict(0);
    return detector;
  }

  /** Remove smallest-timestamp entries while below `floor` or over capacity. */
  private evict(floor: number): void {
    while (this.heap.length > 0 && (this.heap[0][0] < floor || this.heap.length > this.capacity)) {
      const [ts, id] = this.pop();
      this.ids.delete(id);
      this._horizon = ts;
    }
  }

  private push(item: [number, string]): void {
    const h = this.heap;
    h.push(item);
    for (let i = h.length - 1; i > 0;) {
      const parent = (i - 1) >> 1;
      if (h[parent][0] <= h[i][0]) break;
      [h[parent], h[i]] = [h[i], h[parent]];
      i = parent;
    }
  }

  private pop(): [number, string] {
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
