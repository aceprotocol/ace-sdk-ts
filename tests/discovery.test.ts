import { describe, it, expect } from 'vitest';
import {
  validateRegistrationFile,
  validateACEId,
  verifyRegistrationId,
  fetchRegistrationFile,
  getRegistrationSigningPublicKey,
  getRegistrationEncryptionPublicKey,
} from '../src/discovery.js';
import { SoftwareIdentity, toBase64 } from '../src/identity.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { RegistrationFile } from '../src/types.js';

describe('Discovery', () => {
  describe('validateACEId', () => {
    it('validates correct ACE ID format', () => {
      const validId = 'ace:sha256:' + 'a'.repeat(64);
      expect(validateACEId(validId)).toBe(true);
    });

    it('rejects invalid format', () => {
      expect(validateACEId('invalid')).toBe(false);
      expect(validateACEId('ace:sha256:short')).toBe(false);
      expect(validateACEId('ace:md5:' + 'a'.repeat(64))).toBe(false);
    });
  });

  describe('validateRegistrationFile', () => {
    const validReg: RegistrationFile = {
      ace: '1.0',
      id: 'ace:sha256:' + 'a'.repeat(64),
      name: 'TestAgent',
      endpoint: 'https://test.example.com/ace',
      tier: 0,
      signing: {
        scheme: 'ed25519',
        address: '5Ht7RkVSupHeNbGWiHfwJ3RYn4RZfpAv5tk2UrQKbkWR',
        encryptionPublicKey: toBase64(new Uint8Array(1216)),
      },
    };

    it('accepts valid registration file', () => {
      expect(() => validateRegistrationFile(validReg)).not.toThrow();
    });

    it('returns the decoded signing and X-Wing encryption keys', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const keys = validateRegistrationFile(id.toRegistrationFile({ name: 'A', endpoint: 'https://a.example.com' }));
      expect(keys.signingPublicKey).toEqual(id.getSigningPublicKey());
      expect(keys.encryptionPublicKey).toEqual(id.getEncryptionPublicKey());
    });

    it('rejects an unknown signing.scheme', () => {
      const bad = { ...validReg, signing: { ...validReg.signing, scheme: 'rsa' as never } };
      expect(() => validateRegistrationFile(bad)).toThrow(/Unsupported signing.scheme/);
    });

    it('rejects control characters in name but imposes no length limit', () => {
      expect(() => validateRegistrationFile({ ...validReg, name: 'Agent\u001b[2J' }))
        .toThrow(/name must not contain control characters/);
      expect(() => validateRegistrationFile({ ...validReg, name: 'a'.repeat(1000) })).not.toThrow();
    });

    it('rejects ed25519 address that does not decode to 32 bytes', () => {
      const bad: RegistrationFile = {
        ...validReg,
        signing: { ...validReg.signing, address: '1234' },
      };
      expect(() => validateRegistrationFile(bad)).toThrow(/decode to 32 bytes/);
    });

    it('rejects ed25519 signingPublicKey that does not match address', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const other = await SoftwareIdentity.generate('ed25519');
      const bad = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      bad.signing.signingPublicKey = toBase64(other.getSigningPublicKey());
      expect(() => validateRegistrationFile(bad)).toThrow(/does not match/);
    });

    it('rejects missing ace version', () => {
      const bad = { ...validReg, ace: undefined } as any;
      expect(() => validateRegistrationFile(bad)).toThrow(/ace/);
    });

    it('rejects missing endpoint', () => {
      const bad = { ...validReg, endpoint: undefined } as any;
      expect(() => validateRegistrationFile(bad)).toThrow(/endpoint/);
    });

    it('requires a non-empty name', () => {
      expect(() => validateRegistrationFile({ ...validReg, name: '' })).toThrow(/name/);
    });

    it('requires an absolute https endpoint with a host (scheme case-insensitive)', () => {
      expect(() => validateRegistrationFile({ ...validReg, endpoint: 'HTTPS://test.example.com/ace' })).not.toThrow();
      for (const endpoint of ['http://test.example.com', 'https://', '/ace', 'not a url']) {
        expect(() => validateRegistrationFile({ ...validReg, endpoint })).toThrow(/endpoint/);
      }
    });

    it.each([1215, 1217])('rejects encryptionPublicKey that decodes to %i bytes (not an X-Wing key)', (len) => {
      const bad: RegistrationFile = {
        ...validReg,
        signing: { ...validReg.signing, encryptionPublicKey: toBase64(new Uint8Array(len)) },
      };
      expect(() => validateRegistrationFile(bad)).toThrow(new RegExp(`X-Wing public key (must be exactly 1216 bytes, got|too large:) ${len}`));
    });

    it('rejects an oversized encryptionPublicKey by Base64 length before decoding', () => {
      const bad: RegistrationFile = {
        ...validReg,
        signing: { ...validReg.signing, encryptionPublicKey: 'A'.repeat(1628) },
      };
      expect(() => validateRegistrationFile(bad)).toThrow(/1628 Base64 chars exceeds max 1624/);
    });

    it('accepts a real SoftwareIdentity registration (1216-byte key)', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({ name: 'TestAgent', endpoint: 'https://test.example.com/ace' });
      expect(() => validateRegistrationFile(reg)).not.toThrow();
      expect(getRegistrationEncryptionPublicKey(reg)).toHaveLength(1216);
    });

    it('rejects missing encryptionPublicKey', () => {
      const bad = {
        ...validReg,
        signing: { ...validReg.signing, encryptionPublicKey: undefined },
      } as any;
      expect(() => validateRegistrationFile(bad)).toThrow(/encryptionPublicKey/);
    });

    it('rejects secp256k1 without signingPublicKey', () => {
      const bad: RegistrationFile = {
        ...validReg,
        signing: {
          scheme: 'secp256k1',
          address: '0x' + 'a'.repeat(40),
          encryptionPublicKey: toBase64(new Uint8Array(1216)),
        },
      };
      expect(() => validateRegistrationFile(bad)).toThrow(/signingPublicKey/);
    });

    it('accepts secp256k1 with signingPublicKey', () => {
      return SoftwareIdentity.generate('secp256k1').then((id) => {
        const good = id.toRegistrationFile({
          name: 'TestAgent',
          endpoint: 'https://test.example.com/ace',
        });
        expect(() => validateRegistrationFile(good)).not.toThrow();
      });
    });

    it('rejects secp256k1 address that does not match signingPublicKey', () => {
      return SoftwareIdentity.generate('secp256k1').then((id) => {
        const bad = id.toRegistrationFile({
          name: 'TestAgent',
          endpoint: 'https://test.example.com/ace',
        });
        bad.signing.address = '0x' + 'a'.repeat(40);
        expect(() => validateRegistrationFile(bad)).toThrow(/does not match/);
      });
    });
  });

  describe('verifyRegistrationId', () => {
    it('returns true for valid registration from SoftwareIdentity', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      expect(verifyRegistrationId(reg)).toBe(true);
    });

    it('returns false for tampered ACE ID', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      reg.id = 'ace:sha256:' + 'f'.repeat(64);
      expect(verifyRegistrationId(reg)).toBe(false);
    });

    it('works for secp256k1 identity', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      expect(verifyRegistrationId(reg)).toBe(true);
    });

    it('returns false when secp256k1 address is tampered', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      reg.signing.address = '0x' + 'f'.repeat(40);
      expect(verifyRegistrationId(reg)).toBe(false);
    });
  });

  describe('registration key extraction', () => {
    it('extracts ed25519 signing and encryption public keys', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });

      expect(bytesToHex(getRegistrationSigningPublicKey(reg))).toBe(bytesToHex(id.getSigningPublicKey()));
      expect(bytesToHex(getRegistrationEncryptionPublicKey(reg))).toBe(bytesToHex(id.getEncryptionPublicKey()));
    });

    it('extracts secp256k1 signing and encryption public keys', async () => {
      const id = await SoftwareIdentity.generate('secp256k1');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });

      expect(bytesToHex(getRegistrationSigningPublicKey(reg))).toBe(bytesToHex(id.getSigningPublicKey()));
      expect(bytesToHex(getRegistrationEncryptionPublicKey(reg))).toBe(bytesToHex(id.getEncryptionPublicKey()));
    });

    it('rejects mismatched ed25519 signingPublicKey during extraction', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const other = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      reg.signing.signingPublicKey = toBase64(other.getSigningPublicKey());

      expect(() => getRegistrationSigningPublicKey(reg)).toThrow(/does not match/);
    });
  });

  describe('fetchRegistrationFile', () => {
    it('rejects invalid domain with path traversal', async () => {
      await expect(fetchRegistrationFile('evil.com/../../admin'))
        .rejects.toThrow(/Invalid domain/);
    });

    it('rejects domain with port', async () => {
      await expect(fetchRegistrationFile('localhost:8080'))
        .rejects.toThrow(/Invalid domain/);
    });

    it('rejects single-label domain', async () => {
      await expect(fetchRegistrationFile('localhost'))
        .rejects.toThrow(/Invalid domain/);
    });

    it('rejects registration whose ACE ID does not match the signing key', async () => {
      const id = await SoftwareIdentity.generate('ed25519');
      const reg = id.toRegistrationFile({
        name: 'TestAgent',
        endpoint: 'https://test.example.com/ace',
      });
      reg.id = 'ace:sha256:' + 'f'.repeat(64);

      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () => new Response(JSON.stringify(reg), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });

      try {
        await expect(fetchRegistrationFile('example.com')).rejects.toThrow(/ACE ID does not match/);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('rejects oversized registration file from declared content-length', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () => new Response('{}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(1_048_577),
        },
      });

      try {
        await expect(fetchRegistrationFile('example.com')).rejects.toThrow(/too large/);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe('SSRF protection', () => {
    it('rejects localhost domain', async () => {
      await expect(fetchRegistrationFile('localhost')).rejects.toThrow(/Invalid domain|SSRF/);
    });

    it('rejects .local domains', async () => {
      await expect(fetchRegistrationFile('myhost.local')).rejects.toThrow(/SSRF protection/);
    });

    it('rejects .internal domains', async () => {
      await expect(fetchRegistrationFile('service.internal')).rejects.toThrow(/SSRF protection/);
    });

    it('rejects evil.localhost subdomain', async () => {
      await expect(fetchRegistrationFile('evil.localhost')).rejects.toThrow(/SSRF protection/);
    });

    it('allows bypass with allowPrivateIPs option', async () => {
      // This will fail at the fetch stage (no server), but should NOT fail at SSRF check
      await expect(
        fetchRegistrationFile('service.internal', { allowPrivateIPs: true }),
      ).rejects.toThrow(/fetch|ENOTFOUND|network/i);
    });
  });
});
