import { describe, it, expect } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import { SoftwareIdentity, fromBase64, toBase64 } from '../src/identity.js';
import { buildSignData, encodePayload, verifySignature } from '../src/signing.js';
import { computeConversationId, encrypt } from '../src/encryption.js';

describe('SoftwareIdentity', () => {
  describe('ed25519', () => {
    it('generates a new identity', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      expect(id.getSigningScheme()).toBe('ed25519');
      expect(id.getTier()).toBe(0);
      expect(id.getSigningPublicKey()).toHaveLength(32);
      expect(id.getEncryptionPublicKey()).toHaveLength(1216);
    });

    it('derives deterministic ACE ID from signing key', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const aceId = id.getACEId();
      expect(aceId).toMatch(/^ace:sha256:[a-f0-9]{64}$/);
      expect(id.getACEId()).toBe(aceId);
    });

    it('derives Base58 address for ed25519', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const address = id.getAddress();
      expect(address.length).toBeGreaterThan(0);
      expect(address).not.toContain('0x');
    });

    it('two identities have different keys', async () => {
      const a = await SoftwareIdentity.generate('ed25519');
      const b = await SoftwareIdentity.generate('ed25519');
      expect(a.getACEId()).not.toBe(b.getACEId());
      expect(a.getAddress()).not.toBe(b.getAddress());
    });

    it('returns detached public key copies', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const signing = id.getSigningPublicKey();
      const encryption = id.getEncryptionPublicKey();

      signing[0] ^= 0xff;
      encryption[0] ^= 0xff;

      expect(bytesToHex(id.getSigningPublicKey())).not.toBe(bytesToHex(signing));
      expect(bytesToHex(id.getEncryptionPublicKey())).not.toBe(bytesToHex(encryption));
    });

    it('signs data and returns ed25519 scheme', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const data = new Uint8Array([1, 2, 3, 4]);
      const { signature, scheme } = await id.sign(data);
      expect(scheme).toBe('ed25519');
      expect(signature).toHaveLength(64);
    });

    it('exports and imports private keys', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const exported = id.exportPrivateKey();
      // encryptionPrivateKey is the 32-byte X-Wing seed
      expect(fromBase64(exported.encryptionPrivateKey)).toHaveLength(32);
      const restored = SoftwareIdentity.fromExport(exported);
      expect(restored.getACEId()).toBe(id.getACEId());
      expect(restored.getAddress()).toBe(id.getAddress());
      expect(restored.getSigningScheme()).toBe(id.getSigningScheme());
      expect(bytesToHex(restored.getEncryptionPublicKey())).toBe(bytesToHex(id.getEncryptionPublicKey()));
    });

    it('rejects an encryptionPrivateKey that is not a 32-byte seed', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const exported = id.exportPrivateKey();
      expect(() => SoftwareIdentity.fromExport({
        ...exported,
        encryptionPrivateKey: toBase64(new Uint8Array(31)),
      })).toThrow(/X-Wing seed must be exactly 32 bytes, got 31/);
    });

    it('registration file carries the 1216-byte X-Wing public key', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({ name: 'T', endpoint: 'https://t.example.com/ace' });
      expect(fromBase64(reg.signing.encryptionPublicKey)).toHaveLength(1216);
    });

    it('toJSON returns safe public info (no private keys)', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const json = id.toJSON();
      expect(json.aceId).toBe(id.getACEId());
      expect(json.scheme).toBe('ed25519');
      expect(json.address).toBe(id.getAddress());
      expect(json.tier).toBe(0);
      // Ensure no private key leakage
      const jsonStr = JSON.stringify(json);
      expect(jsonStr).not.toContain('PrivateKey');
      expect(jsonStr).not.toContain('privateKey');
    });

    it('JSON.stringify(identity) does not leak private keys', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const serialized = JSON.stringify(id);
      expect(serialized).not.toContain('signingPrivateKey');
      expect(serialized).not.toContain('encryptionPrivateKey');
      // Should contain safe fields
      const parsed = JSON.parse(serialized);
      expect(parsed.aceId).toBe(id.getACEId());
    });

    it('fromExport restores functional signing and decryption', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const restored = SoftwareIdentity.fromExport(id.exportPrivateKey());

      // Verify signing works
      const messagePayload = encodePayload('rfq', 'ace:sha256:other', 'conv', 'msg', 'thread-1', new Uint8Array([1, 2, 3]));
      const signData = buildSignData('message', restored.getACEId(), 1741000000, messagePayload);
      const { signature, scheme } = await restored.sign(signData);
      expect(verifySignature(signData, signature, scheme, restored.getSigningPublicKey())).toBe(true);

      // Verify decryption works
      const convId = computeConversationId(restored.getEncryptionPublicKey(), restored.getEncryptionPublicKey());
      const { kemCiphertext, payload } = await encrypt(
        new TextEncoder().encode('test'), restored.getEncryptionPublicKey(), convId,
      );
      const decrypted = await restored.decrypt(kemCiphertext, payload, convId);
      expect(new TextDecoder().decode(decrypted)).toBe('test');
    });

    it('generates registration file', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      expect(reg.ace).toBe('1.0');
      expect(reg.id).toBe(id.getACEId());
      expect(reg.name).toBe('TestAgent');
      expect(reg.tier).toBe(0);
      expect(reg.signing.scheme).toBe('ed25519');
      expect(reg.signing.encryptionPublicKey).toBeTruthy();
    });
  });

  describe('secp256k1', () => {
    it('generates a new identity', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      expect(id.getSigningScheme()).toBe('secp256k1');
      expect(id.getSigningPublicKey()).toHaveLength(33); // compressed
      expect(id.getEncryptionPublicKey()).toHaveLength(1216);
    });

    it('derives 0x-prefixed EIP-55 checksummed address', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const address = id.getAddress();
      expect(address).toMatch(/^0x[a-fA-F0-9]{40}$/);
    });

    it('signs data and returns secp256k1 scheme', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const data = new Uint8Array([1, 2, 3, 4]);
      const { signature, scheme } = await id.sign(data);
      expect(scheme).toBe('secp256k1');
      expect(signature).toHaveLength(65); // r(32) + s(32) + v(1)
    });

    it('exports and imports private keys', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const exported = id.exportPrivateKey();
      const restored = SoftwareIdentity.fromExport(exported);
      expect(restored.getACEId()).toBe(id.getACEId());
      expect(restored.getAddress()).toBe(id.getAddress());
    });
  });

  describe('exportPrivateKeyBytes', () => {
    it('round-trips via fromBinaryExport', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const exported = id.exportPrivateKeyBytes();
      const restored = SoftwareIdentity.fromBinaryExport(exported);
      expect(restored.getACEId()).toBe(id.getACEId());
      expect(restored.getAddress()).toBe(id.getAddress());
    });

    it('returns copies that can be zeroed without affecting original', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const exported = id.exportPrivateKeyBytes();
      exported.signingPrivateKey.fill(0);
      exported.encryptionPrivateKey.fill(0);
      // Original identity should still work
      const data = new Uint8Array([1, 2, 3]);
      const { signature, scheme } = await id.sign(data);
      expect(verifySignature(data, signature, scheme, id.getSigningPublicKey())).toBe(true);
    });

    it('fromBinaryExport copies input (caller can zero safely)', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const exported = id.exportPrivateKeyBytes();
      const restored = SoftwareIdentity.fromBinaryExport(exported);
      // Zero the export after creating identity
      exported.signingPrivateKey.fill(0);
      exported.encryptionPrivateKey.fill(0);
      // Restored identity should still work
      expect(restored.getACEId()).toBe(id.getACEId());
    });
  });

  describe('fromBase64 error handling', () => {
    it('throws Error (not DOMException) on invalid Base64', () => {
      expect(() => fromBase64('not-valid-base64!!!')).toThrow(Error);
      expect(() => fromBase64('not-valid-base64!!!')).toThrow('Invalid Base64 input');
    });

    it('decodes valid Base64', () => {
      const result = fromBase64('AQID');
      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });

    // atob alone accepts these; the Python and Swift SDKs reject them.
    it.each([['unpadded', 'AQI'], ['embedded whitespace', 'AQ ID'], ['newline', 'AQID\n']])(
      'rejects %s input', (_name, input) => {
        expect(() => fromBase64(input)).toThrow('Invalid Base64 input');
      },
    );
  });

  describe('scheme validation', () => {
    it('fromExport rejects an unknown signing scheme instead of treating it as secp256k1', async () => {
      const exported = (await SoftwareIdentity.generate('ed25519')).exportPrivateKey();
      expect(() => SoftwareIdentity.fromExport({ ...exported, scheme: 'Ed25519' as never }))
        .toThrow(/Unsupported signing scheme/);
    });
  });
});
