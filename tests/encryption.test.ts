import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { SoftwareIdentity } from '../src/identity.js';
import {
  computeConversationId,
  encrypt,
  decrypt,
  getACEKemSalt,
  kemEncapsulate,
  kemDecapsulate,
  kemPublicKeyFromSeed,
  generateKemSeed,
  KEM_SEED_SIZE,
  KEM_PUBLIC_KEY_SIZE,
  KEM_CIPHERTEXT_SIZE,
  MAX_PAYLOAD_SIZE,
  MAX_PLAINTEXT_SIZE,
} from '../src/encryption.js';

// Draft test vectors (keygen → pk, decaps → ss) live in spec/test-vectors.json
// and are exercised by tests/interop-vectors.test.ts.

describe('Encryption', () => {
  describe('X-Wing KEM (draft-connolly-cfrg-xwing-kem-11)', () => {
    it('our constants match ml_kem768_x25519.lengths and secretKey is the seed', () => {
      expect(ml_kem768_x25519.lengths.seed).toBe(KEM_SEED_SIZE);
      expect(ml_kem768_x25519.lengths.publicKey).toBe(KEM_PUBLIC_KEY_SIZE);
      expect(ml_kem768_x25519.lengths.cipherText).toBe(KEM_CIPHERTEXT_SIZE);
      // The identity export stores the seed as the private key, so the code
      // relies on @noble's secretKey being exactly the 32-byte seed.
      const seed = generateKemSeed();
      expect(ml_kem768_x25519.lengths.secretKey).toBe(KEM_SEED_SIZE);
      expect(bytesToHex(ml_kem768_x25519.keygen(seed).secretKey)).toBe(bytesToHex(seed));
    });

    it('encapsulate/decapsulate round-trip', () => {
      const seed = generateKemSeed();
      const pk = kemPublicKeyFromSeed(seed);
      const { kemCiphertext, sharedSecret } = kemEncapsulate(pk);
      expect(kemCiphertext).toHaveLength(KEM_CIPHERTEXT_SIZE);
      expect(sharedSecret).toHaveLength(32);
      expect(bytesToHex(kemDecapsulate(kemCiphertext, seed))).toBe(bytesToHex(sharedSecret));
    });

    it('rejects off-by-one seeds, public keys and ciphertexts', () => {
      const seed = generateKemSeed();
      const pk = kemPublicKeyFromSeed(seed);
      const { kemCiphertext } = kemEncapsulate(pk);
      expect(() => kemPublicKeyFromSeed(new Uint8Array(31))).toThrow(/X-Wing seed must be exactly 32 bytes, got 31/);
      expect(() => kemDecapsulate(kemCiphertext, new Uint8Array(33))).toThrow(/X-Wing seed must be exactly 32 bytes, got 33/);
      expect(() => kemEncapsulate(pk.slice(0, 1215))).toThrow(/X-Wing public key must be exactly 1216 bytes, got 1215/);
      expect(() => kemEncapsulate(new Uint8Array(1217))).toThrow(/X-Wing public key must be exactly 1216 bytes, got 1217/);
      expect(() => kemDecapsulate(kemCiphertext.slice(0, 1119), seed)).toThrow(/X-Wing KEM ciphertext must be exactly 1120 bytes, got 1119/);
      expect(() => kemDecapsulate(new Uint8Array(1121), seed)).toThrow(/X-Wing KEM ciphertext must be exactly 1120 bytes, got 1121/);
    });
  });

  describe('getACEKemSalt', () => {
    it('is SHA-256 of "ace.protocol.kem.v1"', () => {
      const expected = sha256(new TextEncoder().encode('ace.protocol.kem.v1'));
      expect(bytesToHex(getACEKemSalt())).toBe(bytesToHex(expected));
      expect(bytesToHex(getACEKemSalt())).toBe(
        '4d47944503bb761780f5214d54a2565e89d0efb29a9641df4747bd66d5821611',
      );
    });

    it('getACEKemSalt returns a safe copy', () => {
      const copy1 = getACEKemSalt();
      const copy2 = getACEKemSalt();
      expect(bytesToHex(copy1)).toBe(bytesToHex(copy2));
      copy1.fill(0);
      // Second copy must be unaffected
      const copy3 = getACEKemSalt();
      expect(bytesToHex(copy3)).toBe(bytesToHex(copy2));
    });

    it('mutating a copy does not affect encrypt/decrypt', async () => {
      const originalHex = bytesToHex(getACEKemSalt());
      const copy = getACEKemSalt();
      copy.fill(0);
      expect(bytesToHex(getACEKemSalt())).toBe(originalHex);

      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );
      const plaintext = new TextEncoder().encode('Still works!');
      const { kemCiphertext, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );
      const decrypted = await receiver.decrypt(kemCiphertext, payload, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('Still works!');
    });
  });

  describe('conversationId', () => {
    it('is deterministic for same key pair', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const id1 = computeConversationId(a.getEncryptionPublicKey(), b.getEncryptionPublicKey());
      const id2 = computeConversationId(a.getEncryptionPublicKey(), b.getEncryptionPublicKey());
      expect(id1).toBe(id2);
    });

    it('is symmetric (A,B == B,A)', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const ab = computeConversationId(a.getEncryptionPublicKey(), b.getEncryptionPublicKey());
      const ba = computeConversationId(b.getEncryptionPublicKey(), a.getEncryptionPublicKey());
      expect(ab).toBe(ba);
    });

    it('handles identical public keys (self-conversation)', () => {
      const key = new Uint8Array(1216).fill(0xab);
      const id = computeConversationId(key, key);
      expect(id).toMatch(/^[a-f0-9]{64}$/);
      expect(computeConversationId(key, key)).toBe(id);
    });

    it('validates both public keys', () => {
      const normal = new Uint8Array(1216);
      expect(() => computeConversationId(new Uint8Array(1215), normal)).toThrow(/1216 bytes, got 1215/);
      expect(() => computeConversationId(normal, new Uint8Array(1217))).toThrow(/1216 bytes, got 1217/);
    });

    it('produces 64-char hex string', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const id = computeConversationId(a.getEncryptionPublicKey(), b.getEncryptionPublicKey());
      expect(id).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('encrypt/decrypt round-trip', () => {
    it('encrypts and decrypts a message (via identity.decrypt)', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const plaintext = new TextEncoder().encode('Hello ACE!');
      const { kemCiphertext, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      expect(kemCiphertext).toHaveLength(1120);
      expect(payload.length).toBeGreaterThan(plaintext.length);

      const decrypted = await receiver.decrypt(kemCiphertext, payload, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello ACE!');
    });

    it('decrypts via the low-level decrypt() with the raw seed', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const seed = receiver.exportPrivateKeyBytes().encryptionPrivateKey;
      expect(seed).toHaveLength(32);
      const convId = 'c'.repeat(64);
      const { kemCiphertext, payload } = await encrypt(
        new TextEncoder().encode('raw seed'), receiver.getEncryptionPublicKey(), convId,
      );
      const decrypted = await decrypt(kemCiphertext, payload, seed, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('raw seed');
    });

    it('encrypts and decrypts empty payload', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const plaintext = new Uint8Array(0);
      const { kemCiphertext, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      // nonce(12) + GCM-tag(16) = 28 minimum
      expect(payload.length).toBe(28);

      const decrypted = await receiver.decrypt(kemCiphertext, payload, convId);
      expect(decrypted).toHaveLength(0);
    });

    it('fails to decrypt with wrong identity', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const wrong = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const { kemCiphertext, payload } = await encrypt(
        new TextEncoder().encode('Secret'),
        receiver.getEncryptionPublicKey(),
        convId,
      );

      await expect(wrong.decrypt(kemCiphertext, payload, convId)).rejects.toThrow();
    });

    it('fails to decrypt with wrong conversationId', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const { kemCiphertext, payload } = await encrypt(
        new TextEncoder().encode('Secret'),
        receiver.getEncryptionPublicKey(),
        convId,
      );

      await expect(receiver.decrypt(kemCiphertext, payload, 'wrong-conv-id')).rejects.toThrow();
    });

    it('fails to decrypt with a tampered kemCiphertext (implicit rejection → AEAD failure)', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = 'a'.repeat(64);
      const { kemCiphertext, payload } = await encrypt(
        new TextEncoder().encode('Secret'), receiver.getEncryptionPublicKey(), convId,
      );
      const tampered = kemCiphertext.slice();
      tampered[0] ^= 0x01; // ML-KEM part
      await expect(receiver.decrypt(tampered, payload, convId)).rejects.toThrow();
      const tampered2 = kemCiphertext.slice();
      tampered2[1119] ^= 0x01; // X25519 part
      await expect(receiver.decrypt(tampered2, payload, convId)).rejects.toThrow();
    });

    it('rejects payload shorter than 28 bytes', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const shortPayload = new Uint8Array(20);
      const { kemCiphertext } = kemEncapsulate(receiver.getEncryptionPublicKey());
      await expect(
        receiver.decrypt(kemCiphertext, shortPayload, 'conv'),
      ).rejects.toThrow(/Payload too short/);
    });

    it('encrypts and decrypts the maximum allowed plaintext size', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );
      const plaintext = new Uint8Array(MAX_PLAINTEXT_SIZE);

      const { kemCiphertext, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      expect(payload.length).toBeLessThanOrEqual(MAX_PAYLOAD_SIZE);
      const decrypted = await receiver.decrypt(kemCiphertext, payload, convId);
      expect(decrypted.length).toBe(plaintext.length);
      expect(bytesToHex(sha256(decrypted))).toBe(bytesToHex(sha256(plaintext)));
    }, 20000);

    it('rejects plaintext larger than the maximum allowed size', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const plaintext = new Uint8Array(MAX_PLAINTEXT_SIZE + 1);
      await expect(
        encrypt(plaintext, receiver.getEncryptionPublicKey(), 'a'.repeat(64)),
      ).rejects.toThrow(/Plaintext too large/);
    });

    it('rejects payload larger than the maximum allowed size', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const payload = new Uint8Array(MAX_PAYLOAD_SIZE + 1);
      const { kemCiphertext } = kemEncapsulate(receiver.getEncryptionPublicKey());
      await expect(
        receiver.decrypt(kemCiphertext, payload, 'conv'),
      ).rejects.toThrow(/Payload too large/);
    });

    it('each encryption produces a different KEM ciphertext and payload', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = 'a'.repeat(64);
      const plaintext = new TextEncoder().encode('Same message');

      const enc1 = await encrypt(plaintext, receiver.getEncryptionPublicKey(), convId);
      const enc2 = await encrypt(plaintext, receiver.getEncryptionPublicKey(), convId);

      expect(bytesToHex(enc1.kemCiphertext)).not.toBe(bytesToHex(enc2.kemCiphertext));
      expect(bytesToHex(enc1.payload)).not.toBe(bytesToHex(enc2.payload));
    });
  });
});
