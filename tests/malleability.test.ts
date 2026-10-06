import { describe, it, expect } from 'vitest';
import {
  SoftwareIdentity, buildSignData, encodePayload, verifySignature,
  createMessage, parseMessage, kemEncapsulate, toBase64,
  ThreadStateMachine, ReplayDetector, type SigningScheme,
} from '../src/index.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const MSG_ID = '550e8400-e29b-41d4-a716-446655440000';

function bytesToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (const y of b) x = (x << 8n) | BigInt(y);
  return x;
}
function bigTo32(x: bigint): Uint8Array {
  const o = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; }
  return o;
}

// (r, s, v) -> (r, n - s, v ^ 1): the canonical ECDSA malleability transform.
function malleate(sig: Uint8Array): Uint8Array {
  const out = new Uint8Array(65);
  out.set(sig.slice(0, 32), 0);
  out.set(bigTo32(ORDER - bytesToBig(sig.slice(32, 64))), 32);
  out[64] = sig[64] ^ 1;
  return out;
}

function signData(id: SoftwareIdentity): Uint8Array {
  return buildSignData('message', id.getACEId(), 1741000000,
    encodePayload('text', 'ace:sha256:x', 'conv', MSG_ID, '', new Uint8Array([1])));
}

describe('secp256k1 signature malleability', () => {
  it('signs low-S and verifies', async () => {
    const id = await SoftwareIdentity.generate('secp256k1');
    const sd = signData(id);
    const { signature, scheme } = await id.sign(sd);
    expect(verifySignature(sd, signature, scheme, id.getSigningPublicKey())).toBe(true);
    expect(bytesToBig(signature.slice(32, 64)) <= ORDER / 2n).toBe(true);
  });

  it('rejects the high-S malleated twin (same key, different bytes)', async () => {
    const id = await SoftwareIdentity.generate('secp256k1');
    const sd = signData(id);
    const { signature, scheme } = await id.sign(sd);
    const mal = malleate(signature);

    // The malleated signature IS a valid signature for this identity...
    const recovered = secp256k1.Signature.fromBytes(mal.slice(0, 64))
      .addRecoveryBit(mal[64]).recoverPublicKey(sd).toBytes(true);
    expect(recovered).toEqual(id.getSigningPublicKey());

    // ...but verification rejects it as non-canonical (high-S).
    expect(verifySignature(sd, mal, scheme, id.getSigningPublicKey())).toBe(false);
  });

  it('rejects an invalid recovery id', async () => {
    const id = await SoftwareIdentity.generate('secp256k1');
    const sd = buildSignData('message', id.getACEId(), 1741000000);
    const { signature, scheme } = await id.sign(sd);
    const bad = new Uint8Array(signature);
    bad[64] = 2;
    expect(verifySignature(sd, bad, scheme, id.getSigningPublicKey())).toBe(false);
  });
});

// The X-Wing KEM ciphertext is part of the signed commitment: a relay that swaps
// it must break SIGNATURE verification, not merely fail decryption later.
describe('kemCiphertext is signed (relay swap defense)', () => {
  const SCHEMES: SigningScheme[] = ['ed25519', 'secp256k1'];

  it.each(SCHEMES)('swapping kemCiphertext fails signature verification (%s)', async (scheme) => {
    const sender = await SoftwareIdentity.generate(scheme);
    const receiver = await SoftwareIdentity.generate('ed25519');

    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'text',
      body: { message: 'hi' },
      stateMachine: new ThreadStateMachine(),
    });

    // Swap in a different, perfectly valid X-Wing ciphertext for the same
    // recipient, as a malicious relay might.
    const { kemCiphertext } = kemEncapsulate(receiver.getEncryptionPublicKey());
    msg.encryption.kemCiphertext = toBase64(kemCiphertext);

    await expect(
      parseMessage(msg, receiver, sender.getSigningPublicKey(), {
        stateMachine: new ThreadStateMachine(),
        replayDetector: new ReplayDetector(),
      }),
    ).rejects.toThrow(/Signature verification failed/);
  });

  it('a single flipped bit in kemCiphertext fails signature verification', async () => {
    const sender = await SoftwareIdentity.generate('ed25519');
    const receiver = await SoftwareIdentity.generate('ed25519');
    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'text',
      body: { message: 'hi' },
      stateMachine: new ThreadStateMachine(),
    });
    const bytes = Uint8Array.from(atob(msg.encryption.kemCiphertext), (c) => c.charCodeAt(0));
    bytes[500] ^= 0x80;
    msg.encryption.kemCiphertext = toBase64(bytes);

    await expect(
      parseMessage(msg, receiver, sender.getSigningPublicKey(), {
        stateMachine: new ThreadStateMachine(),
      }),
    ).rejects.toThrow(/Signature verification failed/);
  });
});
