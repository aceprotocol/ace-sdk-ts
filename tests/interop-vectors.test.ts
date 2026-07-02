/**
 * Cross-language interoperability tests using shared V1 test vectors.
 *
 * These vectors are generated from deterministic seed keys (spec/generate-vectors.py)
 * and shared across all SDKs (TypeScript, Python, Swift) to guarantee wire-format
 * compatibility for identity derivation, conversationId, signData, and signatures.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { SoftwareIdentity, toBase64, fromBase64, computeACEId } from '../src/identity.js';
import { computeConversationId, getACEDHSalt } from '../src/encryption.js';
import { buildSignData, encodePayload, verifySignature, decodeSignature, encodeSignature } from '../src/signing.js';

interface Vectors {
  agents: Record<string, {
    scheme: string;
    signingPrivateKey: string;
    encryptionPrivateKey: string;
    signingPublicKey: string;
    encryptionPublicKey: string;
    address: string;
    aceId: string;
  }>;
  vectors: {
    aceDhSalt: string;
    conversationId: string;
    signData: {
      action: string;
      aceId: string;
      timestamp: number;
      messagePayload: {
        type: string;
        to: string;
        conversationId: string;
        messageId: string;
        threadId: string;
        ephemeralPubKey: string;
        ciphertext: string;
      };
      signDataHex: string;
    };
    signature: {
      scheme: string;
      signDataHex: string;
      signatureValue: string;
    };
  };
}

function loadVectors(): Vectors {
  const path = new URL('../../spec/test-vectors.json', import.meta.url);
  return JSON.parse(readFileSync(path, 'utf8'));
}

describe('Cross-Language Interop Vectors (V1)', () => {
  it('test-vectors.json exists and loads', () => {
    expect(() => loadVectors()).not.toThrow();
  });

  it('ACE DH salt matches cross-language vector', () => {
    const v = loadVectors();
    expect(bytesToHex(getACEDHSalt())).toBe(v.vectors.aceDhSalt);
  });

  it('Alice (ed25519) identity derivation', () => {
    const v = loadVectors();
    const a = v.agents.alice;
    const alice = SoftwareIdentity.fromExport({
      scheme: 'ed25519',
      signingPrivateKey: a.signingPrivateKey,
      encryptionPrivateKey: a.encryptionPrivateKey,
    });

    expect(alice.getACEId()).toBe(a.aceId);
    expect(alice.getAddress()).toBe(a.address);
    expect(toBase64(alice.getSigningPublicKey())).toBe(a.signingPublicKey);
    expect(toBase64(alice.getEncryptionPublicKey())).toBe(a.encryptionPublicKey);
  });

  it('Bob (secp256k1) identity derivation', () => {
    const v = loadVectors();
    const b = v.agents.bob;
    const bob = SoftwareIdentity.fromExport({
      scheme: 'secp256k1',
      signingPrivateKey: b.signingPrivateKey,
      encryptionPrivateKey: b.encryptionPrivateKey,
    });

    expect(bob.getACEId()).toBe(b.aceId);
    expect(bob.getAddress()).toBe(b.address);
    expect(toBase64(bob.getSigningPublicKey())).toBe(b.signingPublicKey);
    expect(toBase64(bob.getEncryptionPublicKey())).toBe(b.encryptionPublicKey);
  });

  it('conversationId matches cross-language vector', () => {
    const v = loadVectors();
    const aliceEnc = fromBase64(v.agents.alice.encryptionPublicKey);
    const bobEnc = fromBase64(v.agents.bob.encryptionPublicKey);

    expect(computeConversationId(aliceEnc, bobEnc)).toBe(v.vectors.conversationId);
    // Symmetric: B↔A == A↔B
    expect(computeConversationId(bobEnc, aliceEnc)).toBe(v.vectors.conversationId);
  });

  it('signData matches cross-language vector', () => {
    const v = loadVectors();
    const sd = v.vectors.signData;
    const mp = sd.messagePayload;

    const messagePayload = encodePayload(
      mp.type, mp.to, mp.conversationId, mp.messageId, mp.threadId,
      fromBase64(mp.ephemeralPubKey),
      fromBase64(mp.ciphertext),
    );
    const signData = buildSignData(sd.action, sd.aceId, sd.timestamp, messagePayload);

    expect(bytesToHex(signData)).toBe(sd.signDataHex);
  });

  it('ed25519 signature verification against cross-language vector', () => {
    const v = loadVectors();
    const sigV = v.vectors.signature;
    const alice = v.agents.alice;

    const signData = hexToBytes(sigV.signDataHex);
    const sigBytes = decodeSignature(sigV.signatureValue, 'ed25519');
    const pubKey = fromBase64(alice.signingPublicKey);

    expect(verifySignature(signData, sigBytes, 'ed25519', pubKey)).toBe(true);
  });

  it('Alice signs and TS-produced signature verifies', async () => {
    const v = loadVectors();
    const a = v.agents.alice;
    const alice = SoftwareIdentity.fromExport({
      scheme: 'ed25519',
      signingPrivateKey: a.signingPrivateKey,
      encryptionPrivateKey: a.encryptionPrivateKey,
    });

    const signData = hexToBytes(v.vectors.signData.signDataHex);
    const { signature, scheme } = await alice.sign(signData);
    expect(scheme).toBe('ed25519');

    // Verify TS-produced signature matches the Python-produced one
    // (ed25519 is deterministic in @noble/curves — no synthetic randomness)
    expect(encodeSignature(signature, 'ed25519')).toBe(v.vectors.signature.signatureValue);
  });
});
