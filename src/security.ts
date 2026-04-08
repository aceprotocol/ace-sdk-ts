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
export function checkTimestampFreshness(timestamp: number): void {
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
    throw new Error('Invalid timestamp: must be a finite number');
  }
  const now = Math.floor(Date.now() / 1000);
  const drift = Math.abs(now - timestamp);
  if (drift > MAX_DRIFT_SECONDS) {
    throw new Error(
      `Timestamp not fresh: drift ${drift}s exceeds max ${MAX_DRIFT_SECONDS}s`,
    );
  }
}

/**
 * In-memory replay detector with TTL-based eviction.
 *
 * Messages are evicted after `ttlSeconds` (default: matches the freshness
 * window of 300 s). A hard `capacity` cap prevents unbounded memory growth
 * under burst traffic — when reached, the oldest entry is evicted regardless
 * of TTL.
 *
 * SAFETY: This class is NOT thread-safe. Do not share instances across
 * Worker Threads or concurrent event loops. In single-threaded Node.js/browser
 * environments, synchronous operations between awaits are safe.
 *
 * Callers SHOULD persist state via export()/fromExport() across restarts
 * to avoid a replay window during the freshness period after restart.
 */
export class ReplayDetector {
  // Map preserves insertion order — O(1) FIFO eviction.
  // Stores messageId -> insertion timestamp (Date.now() ms).
  private seen: Map<string, number>;
  private readonly capacity: number;
  private readonly ttlMs: number;

  constructor(capacity: number = 100_000, ttlSeconds: number = MAX_DRIFT_SECONDS) {
    this.capacity = capacity;
    this.ttlMs = ttlSeconds * 1000;
    this.seen = new Map();
  }

  /** Remove entries older than TTL. */
  private evictExpired(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [id, ts] of this.seen) {
      if (ts <= cutoff) {
        this.seen.delete(id);
      } else {
        break; // Map is insertion-ordered, so all remaining are newer
      }
    }
  }

  /**
   * Atomically check if a messageId has been seen and reserve it.
   * Returns true if the message is new (accepted), false if duplicate (rejected).
   */
  checkAndReserve(messageId: string): boolean {
    this.evictExpired();

    if (this.seen.has(messageId)) {
      return false;
    }

    // Hard capacity cap — evict oldest regardless of TTL
    if (this.seen.size >= this.capacity) {
      const oldest = this.seen.keys().next().value!;
      this.seen.delete(oldest);
    }

    this.seen.set(messageId, Date.now());
    return true;
  }

  /**
   * Check if a messageId has been seen (without reserving).
   */
  hasSeen(messageId: string): boolean {
    this.evictExpired();
    return this.seen.has(messageId);
  }

  /**
   * Release a previously reserved message ID after processing failure.
   */
  release(messageId: string): void {
    this.seen.delete(messageId);
  }

  /**
   * Export seen message IDs for persistence.
   */
  export(): string[] {
    this.evictExpired();
    return Array.from(this.seen.keys());
  }

  /**
   * Import previously persisted seen message IDs.
   */
  static fromExport(messageIds: string[], capacity: number = 100_000, ttlSeconds: number = MAX_DRIFT_SECONDS): ReplayDetector {
    const detector = new ReplayDetector(capacity, ttlSeconds);
    // Truncate to capacity — keep the most recent entries
    const trimmed = messageIds.length > capacity
      ? messageIds.slice(-capacity)
      : messageIds;
    const now = Date.now();
    for (const id of trimmed) {
      if (typeof id !== 'string' || !MESSAGE_ID_V4_PATTERN.test(id)) {
        throw new Error(`fromExport: invalid messageId '${sanitizeForError(String(id), 50)}'`);
      }
      detector.seen.set(id, now);
    }
    return detector;
  }
}
