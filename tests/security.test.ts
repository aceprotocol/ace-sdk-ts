import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ReplayDetector, checkTimestampFreshness, validateMessageId } from '../src/security.js';

describe('Security', () => {
  describe('checkTimestampFreshness', () => {
    it('accepts timestamp within 5-minute window', () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() => checkTimestampFreshness(now)).not.toThrow();
      expect(() => checkTimestampFreshness(now - 60)).not.toThrow();
      expect(() => checkTimestampFreshness(now + 60)).not.toThrow();
    });

    it('rejects timestamp older than 5 minutes', () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() => checkTimestampFreshness(now - 301)).toThrow(/fresh/i);
    });

    it('rejects timestamp more than 5 minutes in the future', () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() => checkTimestampFreshness(now + 301)).toThrow(/fresh/i);
    });

    it('rejects NaN timestamp', () => {
      expect(() => checkTimestampFreshness(NaN)).toThrow(/Invalid timestamp/);
    });

    it('rejects non-finite timestamp', () => {
      expect(() => checkTimestampFreshness(Infinity)).toThrow(/Invalid timestamp/);
      expect(() => checkTimestampFreshness(-Infinity)).toThrow(/Invalid timestamp/);
    });

    it('rejects non-number timestamp', () => {
      expect(() => checkTimestampFreshness('abc' as any)).toThrow(/Invalid timestamp/);
      expect(() => checkTimestampFreshness(undefined as any)).toThrow(/Invalid timestamp/);
    });
  });

  describe('ReplayDetector', () => {
    const T = 1_800_000_000;
    const id = (n: number) => `550e8400-e29b-41d4-a716-4466554400${String(n).padStart(2, '0')}`;
    const ALICE = 'ace:sha256:alice', MALLORY = 'ace:sha256:mallory';
    beforeEach(() => { vi.useFakeTimers({ now: T * 1000 }); });
    afterEach(() => { vi.useRealTimers(); });

    it('isolates duplicate IDs by authenticated sender, including after restart', () => {
      const d = new ReplayDetector();
      expect(d.commit(id(1), MALLORY, T)).toBe(true);
      expect(d.commit(id(1), ALICE, T)).toBe(true);
      const restored = ReplayDetector.fromExport(d.export());
      expect(restored.commit(id(1), ALICE, T)).toBe(false);
      expect(restored.commit(id(1), MALLORY, T)).toBe(false);
    });

    it('survives restart after same-second capacity eviction', () => {
      const d = new ReplayDetector(2);
      for (let n = 1; n <= 3; n++) expect(d.commit(id(n), ALICE, T)).toBe(true);
      const restored = ReplayDetector.fromExport(d.export(), 2);
      for (let n = 1; n <= 3; n++) expect(restored.accepts(id(n), ALICE, T)).toBe(false);
      expect(restored.commit(id(1), MALLORY, T)).toBe(true);
      expect(ReplayDetector.fromExport(restored.export(), 2).export()).toEqual(restored.export());
    });

    it('starts with horizon = now - 5 min', () => {
      expect(new ReplayDetector().horizon).toBe(T - 300);
    });

    it('rejects duplicates and timestamps at or below the horizon', () => {
      const d = new ReplayDetector();
      expect(d.commit(id(1), ALICE, T)).toBe(true);
      expect(d.accepts(id(1), ALICE, T)).toBe(false);
      expect(d.commit(id(1), ALICE, T)).toBe(false);
      expect(d.accepts(id(2), ALICE, T - 300)).toBe(false);
      expect(d.accepts(id(2), ALICE, T - 299)).toBe(true);
    });

    it('keeps an entry until it falls below the floor, then raises the horizon to it', () => {
      const d = new ReplayDetector();
      d.commit(id(1), ALICE, T + 300); // max future drift: acceptable until T + 600
      vi.advanceTimersByTime(450_000);
      d.commit(id(2), ALICE, T + 450);
      expect(d.accepts(id(1), ALICE, T + 300)).toBe(false);
      vi.advanceTimersByTime(200_000);
      d.commit(id(3), ALICE, T + 650); // floor T + 350 > T + 300: id(1) removed
      expect(d.horizon).toBe(T + 300);
      expect(d.accepts(id(1), ALICE, T + 300)).toBe(false);
    });

    it('a fixed earlier floor keeps entries; only capacity removes them', () => {
      // A store that has been running since before the receiver went offline.
      const d = ReplayDetector.fromExport({ horizon: T - 7200, senderHorizons: {}, entries: [] }, 2);
      d.commit(id(1), ALICE, T - 3000, T - 7200);
      d.commit(id(2), ALICE, T - 1000, T - 7200);
      expect(d.horizon).toBe(T - 7200); // nothing removed
      d.commit(id(3), ALICE, T - 2000, T - 7200);
      expect(d.horizon).toBe(T - 7200);
      expect(d.export().senderHorizons).toEqual({ [ALICE]: T - 3000 });
    });

    it("at capacity removes the smallest timestamp and raises only its sender's horizon", () => {
      const d = new ReplayDetector(2);
      d.commit(id(1), ALICE, T - 10);
      d.commit(id(2), ALICE, T - 50);
      d.commit(id(3), ALICE, T - 20);
      expect(d.horizon).toBe(T - 300);
      for (const [n, ts] of [[1, T - 10], [2, T - 50], [3, T - 20]]) {
        expect(d.accepts(id(n), ALICE, ts)).toBe(false);
      }
      expect(d.accepts(id(4), ALICE, T - 50)).toBe(false);
      expect(d.accepts(id(4), ALICE, T - 49)).toBe(true);
      expect(d.accepts(id(4), MALLORY, T - 50)).toBe(true);
    });

    it('one sender flooding the store cannot block other senders', () => {
      const d = new ReplayDetector(3);
      for (let n = 1; n <= 4; n++) d.commit(id(n), MALLORY, T + 300);
      expect(d.horizon).toBe(T - 300);
      expect(d.accepts(id(5), MALLORY, T + 300)).toBe(false);
      expect(d.commit(id(5), ALICE, T)).toBe(true);
    });

    it('sender horizons are bounded by capacity, folding the lowest into the horizon', () => {
      const d = new ReplayDetector(2);
      for (let n = 1; n <= 6; n++) d.commit(id(n), `ace:sha256:s${n}`, T + n);
      expect(Object.keys(d.export().senderHorizons ?? {}).length).toBeLessThanOrEqual(2);
      expect(d.horizon).toBeGreaterThan(T - 300);
      for (let n = 1; n <= 4; n++) {
        expect(d.accepts(id(n), `ace:sha256:s${n}`, T + n)).toBe(false);
      }
    });

    it('round-trips through export/fromExport', () => {
      const d = new ReplayDetector();
      d.commit(id(1), ALICE, T - 10);
      d.commit(id(2), ALICE, T - 20);
      const restored = ReplayDetector.fromExport(d.export());
      expect(restored.horizon).toBe(d.horizon);
      expect(restored.accepts(id(1), ALICE, T - 10)).toBe(false);
      expect(restored.accepts(id(2), ALICE, T - 20)).toBe(false);
      expect(restored.accepts(id(3), ALICE, T - 20)).toBe(true);
    });

    it('round-trips sender horizons through export/fromExport', () => {
      const d = new ReplayDetector(1);
      d.commit(id(1), MALLORY, T + 10);
      d.commit(id(2), ALICE, T + 20);
      const restored = ReplayDetector.fromExport(JSON.parse(JSON.stringify(d.export())), 1);
      expect(restored.export()).toEqual(d.export());
      expect(restored.accepts(id(3), MALLORY, T + 10)).toBe(false);
      expect(restored.accepts(id(3), ALICE, T + 10)).toBe(true);
    });

    it('fromExport over capacity removes the smallest timestamps and raises their sender horizon', () => {
      const entries: [string, string, number][] = [[id(1), ALICE, T - 30], [id(2), ALICE, T - 10], [id(3), ALICE, T - 20]];
      const restored = ReplayDetector.fromExport({ horizon: T - 300, senderHorizons: {}, entries }, 2);
      expect(restored.horizon).toBe(T - 300);
      expect(restored.export().senderHorizons).toEqual({ [ALICE]: T - 30 });
      expect(restored.export().entries).toHaveLength(2);
    });

    it('fromExport rejects malformed state', () => {
      expect(() => ReplayDetector.fromExport({ horizon: -1, senderHorizons: {}, entries: [] })).toThrow(/invalid replay state/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: { '': T }, entries: [] })).toThrow(/invalid replay state/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: { [ALICE]: 1.5 }, entries: [] })).toThrow(/invalid replay state/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: { [ALICE]: -1 }, entries: [] })).toThrow(/invalid replay state/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: [] as any, entries: [] })).toThrow(/invalid replay state/);
      // senderHorizons is required (D10): no default for a missing field.
      expect(() => ReplayDetector.fromExport({ horizon: T, entries: [] } as any)).toThrow(/invalid replay state/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: {}, entries: [['msg-1', ALICE, T + 1]] })).toThrow(/invalid messageId/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: {}, entries: [[id(1), '', T + 1]] })).toThrow(/invalid entry/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: {}, entries: [[id(1), T + 1] as any] })).toThrow(/invalid entry/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: {}, entries: [[id(1), ALICE, T]] })).toThrow(/invalid entry/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: { [ALICE]: T + 5 }, entries: [[id(1), ALICE, T + 5]] })).toThrow(/invalid entry/);
      expect(() => ReplayDetector.fromExport({ horizon: T, senderHorizons: {}, entries: [[id(1), ALICE, T + 1], [id(1), ALICE, T + 2]] })).toThrow(/invalid entry/);
    });

    it('rejects a non-positive capacity', () => {
      expect(() => new ReplayDetector(0)).toThrow(/capacity/);
    });
  });

  describe('validateMessageId', () => {
    it('accepts UUID v4', () => {
      expect(() => validateMessageId('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
    });

    it('rejects non-UUID values', () => {
      expect(() => validateMessageId('msg-001')).toThrow(/UUID v4/);
    });

    it('sanitizes control characters in error message', () => {
      const malicious = 'msg\x00\x01\x02\n\rinjection';
      try {
        validateMessageId(malicious);
        expect.unreachable('should have thrown');
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg).not.toContain('\x00');
        expect(msg).not.toContain('\n');
        expect(msg).not.toContain('\r');
        expect(msg).toContain('msg???');
      }
    });

    it('truncates long input in error message', () => {
      const long = 'a'.repeat(200);
      try {
        validateMessageId(long);
        expect.unreachable('should have thrown');
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg.length).toBeLessThan(200);
      }
    });
  });
});
