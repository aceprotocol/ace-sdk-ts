import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bindingSignData } from '../src/discovery.js';
import { encodeSignature } from '../src/encoding.js';
import { readFileSync } from 'node:fs';
import { expect } from 'vitest';
import { ACEError, SoftwareIdentity, verifyPeerRecord, toBase64, type VerifiedPeer } from '../src/index.js';

export const VECTORS = JSON.parse(readFileSync(new URL('./fixtures/test-vectors.json', import.meta.url), 'utf8'));
export const V = VECTORS.vectors;

export function agent(name: 'alice' | 'bob'): SoftwareIdentity {
  const a = VECTORS.agents[name];
  return SoftwareIdentity.fromExport({ scheme: a.scheme, signingPrivateKey: a.signingPrivateKey, encryptionPrivateKey: a.encryptionPrivateKey });
}

export function peerOf(identity: SoftwareIdentity, pinnedAt = 0): VerifiedPeer {
  const scheme = identity.getSigningScheme();
  const spk = toBase64(identity.getSigningPublicKey()), epk = toBase64(identity.getEncryptionPublicKey());
  const digest = bindingSignData(identity.getACEId(), pinnedAt, epk, spk);
  const secret = b64(identity.exportPrivateKey().signingPrivateKey);
  let sig: Uint8Array;
  if (scheme === 'ed25519') sig = ed25519.sign(digest, secret);
  else {
    const recovered = secp256k1.sign(digest, secret, { prehash: false, lowS: true, format: 'recovered' });
    sig = new Uint8Array([...recovered.subarray(1), recovered[0]]);
  }
  return verifyPeerRecord({ aceId: identity.getACEId(), scheme, signingPublicKey: spk, encryptionPublicKey: epk,
    registeredAt: pinnedAt, registrationSignature: encodeSignature(sig, scheme) });
}

/** The wire bytes of a JSON value (what `Inbox.receive` takes). */
export function wire(v: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(v));
}

export function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

export function unhex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'hex'));
}

export function b64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

export async function expectCode(p: Promise<unknown> | (() => unknown), code: string): Promise<ACEError> {
  try {
    if (typeof p === 'function') await p();
    else await p;
  } catch (e) {
    expect(e).toBeInstanceOf(ACEError);
    expect((e as ACEError).code, (e as ACEError).message).toBe(code);
    return e as ACEError;
  }
  throw new Error(`expected ACEError(${code})`);
}

export function codeOf(fn: () => unknown): string {
  try {
    fn();
    return 'ok';
  } catch (e) {
    if (e instanceof ACEError) return e.code;
    throw e;
  }
}
