import { describe, it, expect } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import { SoftwareIdentity } from '../src/identity.js';
import { buildSignData, encodePayload, verifySignature, encodeSignature, decodeSignature } from '../src/signing.js';

describe('Signing', () => {
  describe('buildSignData', () => {
    it('produces deterministic 32-byte hash', () => {
      const payload = encodePayload('rfq', 'ace:sha256:bbb', 'ccc', '550e8400-e29b-41d4-a716-446655440000', 'thread-1', new Uint8Array([1, 2, 3]));
      const data = buildSignData('message', 'ace:sha256:aaa', 1741000000, payload);
      expect(data).toHaveLength(32);

      const data2 = buildSignData('message', 'ace:sha256:aaa', 1741000000, payload);
      expect(bytesToHex(data)).toBe(bytesToHex(data2));
    });

    it('changes output when type changes (prevents type-switching)', () => {
      const payload = new Uint8Array([1, 2, 3]);
      const p1 = encodePayload('offer', 'ace:sha256:bbb', 'ccc', 'id1', 'thread-1', payload);
      const p2 = encodePayload('text', 'ace:sha256:bbb', 'ccc', 'id1', '', payload);
      const d1 = buildSignData('message', 'ace:sha256:aaa', 1741000000, p1);
      const d2 = buildSignData('message', 'ace:sha256:aaa', 1741000000, p2);
      expect(bytesToHex(d1)).not.toBe(bytesToHex(d2));
    });

    it('rejects negative timestamps', () => {
      expect(() => buildSignData('message', 'a', -1)).toThrow(/Invalid timestamp/);
    });

    it('rejects NaN timestamps', () => {
      expect(() => buildSignData('message', 'a', NaN)).toThrow(/Invalid timestamp/);
    });
  });

  describe('encodeSignature / decodeSignature round-trip', () => {
    it('round-trips ed25519 signature', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const data = new Uint8Array([1, 2, 3]);
      const { signature } = await id.sign(data);
      const encoded = encodeSignature(signature, 'ed25519');
      const decoded = decodeSignature(encoded, 'ed25519');
      expect(bytesToHex(decoded)).toBe(bytesToHex(signature));
    });

    it('round-trips secp256k1 signature', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const data = new Uint8Array([1, 2, 3]);
      const { signature } = await id.sign(data);
      const encoded = encodeSignature(signature, 'secp256k1');
      expect(encoded.startsWith('0x')).toBe(true);
      const decoded = decodeSignature(encoded, 'secp256k1');
      expect(bytesToHex(decoded)).toBe(bytesToHex(signature));
    });
  });

  describe('sign + verify (ed25519)', () => {
    it('round-trips correctly', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const messagePayload = encodePayload('rfq', 'ace:sha256:recipient', 'conv123', 'msg-001', 'thread-1', new Uint8Array([10, 20, 30]));
      const signData = buildSignData('message', id.getACEId(), 1741000000, messagePayload);

      const { signature, scheme } = await id.sign(signData);
      const valid = verifySignature(
        signData,
        signature,
        scheme,
        id.getSigningPublicKey(),
      );
      expect(valid).toBe(true);
    });

    it('rejects tampered data', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const messagePayload = encodePayload('rfq', 'ace:sha256:recipient', 'conv123', 'msg-001', 'thread-1', new Uint8Array([10, 20, 30]));
      const signData = buildSignData('message', id.getACEId(), 1741000000, messagePayload);

      const { signature, scheme } = await id.sign(signData);

      const tampered = new Uint8Array(signData);
      tampered[0] ^= 0xff;

      const valid = verifySignature(
        tampered,
        signature,
        scheme,
        id.getSigningPublicKey(),
      );
      expect(valid).toBe(false);
    });
  });

  describe('sign + verify (secp256k1)', () => {
    it('round-trips correctly', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const messagePayload = encodePayload('offer', 'ace:sha256:recipient', 'conv456', 'msg-002', 'thread-1', new Uint8Array([99]));
      const signData = buildSignData('message', id.getACEId(), 1741000000, messagePayload);

      const { signature, scheme } = await id.sign(signData);
      const valid = verifySignature(
        signData,
        signature,
        scheme,
        id.getSigningPublicKey(),
      );
      expect(valid).toBe(true);
    });

    it('rejects tampered data', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const messagePayload = encodePayload('offer', 'ace:sha256:recipient', 'conv456', 'msg-002', 'thread-1', new Uint8Array([99]));
      const signData = buildSignData('message', id.getACEId(), 1741000000, messagePayload);

      const { signature, scheme } = await id.sign(signData);

      const tampered = new Uint8Array(signData);
      tampered[0] ^= 0xff;

      const valid = verifySignature(
        tampered,
        signature,
        scheme,
        id.getSigningPublicKey(),
      );
      expect(valid).toBe(false);
    });
  });
});
