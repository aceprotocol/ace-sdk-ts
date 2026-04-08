import { describe, it, expect } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import { buildSignData, encodePayload } from '../src/signing.js';

describe('Relay Signing', () => {
  const aceId = 'ace:sha256:abc123';
  const timestamp = 1741000000;

  describe('buildSignData for registration', () => {
    it('produces 32-byte deterministic hash', () => {
      const regPayload = encodePayload('enc-pub-key-base64', 'sig-pub-key-base64');
      const data = buildSignData('register', aceId, timestamp, regPayload);
      expect(data).toHaveLength(32);
    });

    it('same input produces same output', () => {
      const regPayload = encodePayload('enc-pub-key-base64', 'sig-pub-key-base64');
      const a = buildSignData('register', aceId, timestamp, regPayload);
      const b = buildSignData('register', aceId, timestamp, regPayload);
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });

    it('different input produces different output', () => {
      const p1 = encodePayload('enc-pub-key-base64', 'sig-pub-key-base64');
      const p2 = encodePayload('enc-pub-key-base64', 'sig-pub-key-base64');
      const a = buildSignData('register', aceId, timestamp, p1);
      const b = buildSignData('register', 'ace:sha256:different', timestamp, p2);
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });
  });

  describe('buildSignData for relay auth actions', () => {
    it('produces 32-byte deterministic hash', () => {
      const data = buildSignData('listen', aceId, timestamp, encodePayload('-'));
      expect(data).toHaveLength(32);
    });

    it('same input produces same output', () => {
      const a = buildSignData('listen', aceId, timestamp, encodePayload('-'));
      const b = buildSignData('listen', aceId, timestamp, encodePayload('-'));
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });
  });

  describe('cross-function', () => {
    it('listen and registration hashes differ for same aceId/timestamp', () => {
      const regPayload = encodePayload('enc-pub-key-base64', 'sig-pub-key-base64');
      const reg = buildSignData('register', aceId, timestamp, regPayload);
      const hs = buildSignData('listen', aceId, timestamp, encodePayload('-'));
      expect(bytesToHex(reg)).not.toBe(bytesToHex(hs));
    });
  });
});
