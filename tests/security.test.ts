import { describe, it, expect, beforeEach } from 'vitest';
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
    let detector: ReplayDetector;

    beforeEach(() => {
      detector = new ReplayDetector(100);
    });

    it('accepts new message IDs', () => {
      expect(detector.checkAndReserve('msg-001')).toBe(true);
      expect(detector.checkAndReserve('msg-002')).toBe(true);
    });

    it('rejects duplicate message IDs', () => {
      expect(detector.checkAndReserve('msg-001')).toBe(true);
      expect(detector.checkAndReserve('msg-001')).toBe(false);
    });

    it('evicts oldest entries when capacity reached', () => {
      const detector = new ReplayDetector(3);
      detector.checkAndReserve('a');
      detector.checkAndReserve('b');
      detector.checkAndReserve('c');
      detector.checkAndReserve('d');
      expect(detector.checkAndReserve('a')).toBe(true);
      expect(detector.checkAndReserve('b')).toBe(true);
    });

    it('exports and imports seen set', () => {
      const id1 = '550e8400-e29b-41d4-a716-446655440001';
      const id2 = '550e8400-e29b-41d4-a716-446655440002';
      const id3 = '550e8400-e29b-41d4-a716-446655440003';
      detector.checkAndReserve(id1);
      detector.checkAndReserve(id2);

      const exported = detector.export();
      expect(exported).toContain(id1);
      expect(exported).toContain(id2);

      const restored = ReplayDetector.fromExport(exported, 100);
      expect(restored.checkAndReserve(id1)).toBe(false);
      expect(restored.checkAndReserve(id3)).toBe(true);
    });

    it('fromExport truncates to capacity (keeps most recent)', () => {
      const ids = Array.from({ length: 10 }, (_, i) =>
        `550e8400-e29b-41d4-a716-44665544000${i}`,
      );
      const restored = ReplayDetector.fromExport(ids, 3);
      // Only the last 3 entries should be kept
      expect(restored.checkAndReserve(ids[7])).toBe(false);
      expect(restored.checkAndReserve(ids[8])).toBe(false);
      expect(restored.checkAndReserve(ids[9])).toBe(false);
      // Earlier entries should have been truncated
      expect(restored.checkAndReserve(ids[0])).toBe(true);
      expect(restored.checkAndReserve(ids[6])).toBe(true);
    });

    it('release removes a failed reservation', () => {
      detector.checkAndReserve('msg-001');
      detector.release('msg-001');
      expect(detector.checkAndReserve('msg-001')).toBe(true);
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
