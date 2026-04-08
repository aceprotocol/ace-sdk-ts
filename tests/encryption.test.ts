import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { SoftwareIdentity } from '../src/identity.js';
import {
  computeConversationId,
  encrypt,
  decrypt,
  getACEDHSalt,
  MAX_PAYLOAD_SIZE,
  MAX_PLAINTEXT_SIZE,
} from '../src/encryption.js';

describe('Encryption', () => {
  describe('getACEDHSalt', () => {
    it('is SHA-256 of "ace.protocol.dh.v1"', () => {
      const expected = sha256(new TextEncoder().encode('ace.protocol.dh.v1'));
      expect(bytesToHex(getACEDHSalt())).toBe(bytesToHex(expected));
    });

    it('getACEDHSalt returns a safe copy', () => {
      const copy1 = getACEDHSalt();
      const copy2 = getACEDHSalt();
      expect(bytesToHex(copy1)).toBe(bytesToHex(copy2));
      copy1.fill(0);
      // Second copy must be unaffected
      const copy3 = getACEDHSalt();
      expect(bytesToHex(copy3)).toBe(bytesToHex(copy2));
    });

    it('mutating a copy does not affect encrypt/decrypt', async () => {
      // Save original value
      const originalHex = bytesToHex(getACEDHSalt());

      // Mutate a copy
      const copy = getACEDHSalt();
      copy.fill(0);

      // getACEDHSalt should still return the correct value
      expect(bytesToHex(getACEDHSalt())).toBe(originalHex);

      // Encrypt/decrypt should still work (uses internal _ACE_DH_SALT)
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );
      const plaintext = new TextEncoder().encode('Still works!');
      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );
      const decrypted = await receiver.decrypt(ephemeralPubKey, payload, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('Still works!');
    });
  });

  describe('conversationId', () => {
    it('is deterministic for same key pair', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const id1 = computeConversationId(
        a.getEncryptionPublicKey(),
        b.getEncryptionPublicKey(),
      );
      const id2 = computeConversationId(
        a.getEncryptionPublicKey(),
        b.getEncryptionPublicKey(),
      );
      expect(id1).toBe(id2);
    });

    it('is symmetric (A,B == B,A)', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const ab = computeConversationId(
        a.getEncryptionPublicKey(),
        b.getEncryptionPublicKey(),
      );
      const ba = computeConversationId(
        b.getEncryptionPublicKey(),
        a.getEncryptionPublicKey(),
      );
      expect(ab).toBe(ba);
    });

    it('handles identical public keys (self-conversation)', () => {
      const key = new Uint8Array(32).fill(0xab);
      const id = computeConversationId(key, key);
      expect(id).toMatch(/^[a-f0-9]{64}$/);
      expect(computeConversationId(key, key)).toBe(id);
    });

    it('rejects non-32-byte public keys', () => {
      const short = new Uint8Array(16);
      const normal = new Uint8Array(32);
      expect(() => computeConversationId(short, normal)).toThrow(/32 bytes/);
    });

    it('produces 64-char hex string', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      const id = computeConversationId(
        a.getEncryptionPublicKey(),
        b.getEncryptionPublicKey(),
      );
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
      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      expect(ephemeralPubKey).toHaveLength(32);
      expect(payload.length).toBeGreaterThan(plaintext.length);

      const decrypted = await receiver.decrypt(ephemeralPubKey, payload, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello ACE!');
    });

    it('encrypts and decrypts empty payload', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const plaintext = new Uint8Array(0);
      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      // nonce(12) + GCM-tag(16) = 28 minimum
      expect(payload.length).toBe(28);

      const decrypted = await receiver.decrypt(ephemeralPubKey, payload, convId);
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

      const plaintext = new TextEncoder().encode('Secret');
      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      await expect(
        wrong.decrypt(ephemeralPubKey, payload, convId),
      ).rejects.toThrow();
    });

    it('fails to decrypt with wrong conversationId', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = computeConversationId(
        sender.getEncryptionPublicKey(),
        receiver.getEncryptionPublicKey(),
      );

      const plaintext = new TextEncoder().encode('Secret');
      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      await expect(
        receiver.decrypt(ephemeralPubKey, payload, 'wrong-conv-id'),
      ).rejects.toThrow();
    });

    it('rejects payload shorter than 28 bytes', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const shortPayload = new Uint8Array(20);
      // Use a valid X25519 public key (not a low-order point)
      const dummySender = await SoftwareIdentity.generate('ed25519');
      const ephemeralPub = dummySender.getEncryptionPublicKey();
      await expect(
        receiver.decrypt(ephemeralPub, shortPayload, 'conv'),
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

      const { ephemeralPubKey, payload } = await encrypt(
        plaintext,
        receiver.getEncryptionPublicKey(),
        convId,
      );

      expect(payload.length).toBeLessThanOrEqual(MAX_PAYLOAD_SIZE);
      const decrypted = await receiver.decrypt(ephemeralPubKey, payload, convId);
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
      // Use a valid X25519 public key (not a low-order point)
      const dummySender = await SoftwareIdentity.generate('ed25519');
      const ephemeralPub = dummySender.getEncryptionPublicKey();
      await expect(
        receiver.decrypt(ephemeralPub, payload, 'conv'),
      ).rejects.toThrow(/Payload too large/);
    });

    it('each encryption produces different ciphertext (ephemeral keys)', async () => {
      const receiver = await SoftwareIdentity.generate('ed25519');
      const convId = 'a'.repeat(64);
      const plaintext = new TextEncoder().encode('Same message');

      const enc1 = await encrypt(plaintext, receiver.getEncryptionPublicKey(), convId);
      const enc2 = await encrypt(plaintext, receiver.getEncryptionPublicKey(), convId);

      expect(bytesToHex(enc1.ephemeralPubKey)).not.toBe(bytesToHex(enc2.ephemeralPubKey));
      expect(bytesToHex(enc1.payload)).not.toBe(bytesToHex(enc2.payload));
    });
  });
});
