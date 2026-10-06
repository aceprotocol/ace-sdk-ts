import { readFileSync } from 'node:fs';
import { expect } from 'vitest';
import { ACEError, SoftwareIdentity, verifyRegistrationFile, type VerifiedPeer } from '../src/index.js';

export const VECTORS = JSON.parse(readFileSync(new URL('./fixtures/test-vectors.json', import.meta.url), 'utf8'));
export const V = VECTORS.vectors;

export function agent(name: 'alice' | 'bob'): SoftwareIdentity {
  const a = VECTORS.agents[name];
  return SoftwareIdentity.fromExport({ scheme: a.scheme, signingPrivateKey: a.signingPrivateKey, encryptionPrivateKey: a.encryptionPrivateKey });
}

export function peerOf(identity: SoftwareIdentity, pinnedAt = 0): VerifiedPeer {
  return verifyRegistrationFile(identity.toRegistrationFile({ name: 'Peer', endpoint: 'https://peer.example/ace' }), { pinnedAt });
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
