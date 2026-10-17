/** The signed message `M` and ML-DSA-65 verification (02 § Signatures); the only signature-size table. */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { concat, decimal, decodeB64, utf8, wireInt } from './encoding.js';

const DOMAIN = 'ace.v1';
export const SCHEME = 'ml-dsa-65';
export const SEED_SIZE = 32;
export const PUBLIC_KEY_SIZE = 1952;
export const SIGNATURE_SIZE = 3309;

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/** `len(4 BE) || bytes` per field; strings are UTF-8. */
export function encodePayload(...fields: Array<string | Uint8Array>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const f of fields) { const b = typeof f === 'string' ? utf8(f) : f; parts.push(u32be(b.length), b); }
  return concat(parts);
}

/**
 * `M = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)`: `seq` is null for a KEL event
 * signature, else the `seq` of the signing delegation.
 */
export function signingMessage(aceId: string, timestamp: number, seq: number | null, payload: Uint8Array): Uint8Array {
  if (wireInt(timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be an integer in [0, 2^53-1]');
  if (seq !== null && wireInt(seq) === null) throw new ACEError('invalid_argument', 'seq must be an integer in [0, 2^53-1]');
  return encodePayload(DOMAIN, aceId, decimal(timestamp), seq === null ? '' : decimal(seq), payload);
}

export function isValidSigningPublicKey(scheme: unknown, key: Uint8Array): boolean {
  return scheme === SCHEME && key instanceof Uint8Array && key.length === PUBLIC_KEY_SIZE;
}

/** ML-DSA-65 verify of `message` with ctx = UTF-8(action). Malformed input is `false`, never a throw. */
export function verifySignature(message: Uint8Array, action: string, sig: Uint8Array, publicKey: Uint8Array): boolean {
  if (!(message instanceof Uint8Array) || typeof action !== 'string' || !(sig instanceof Uint8Array)) return false;
  if (!isValidSigningPublicKey(SCHEME, publicKey) || sig.length !== SIGNATURE_SIZE) return false;
  try {
    return ml_dsa65.verify(sig, message, publicKey, { context: utf8(action) });
  } catch {
    return false;
  }
}

/** Canonical Base64 of exactly 3309 bytes, or `ACEError(code)`. */
export function decodeSignature(text: unknown, code: ACEErrorCode): Uint8Array {
  const raw = decodeB64(text, code, 'ml-dsa-65 signature', SIGNATURE_SIZE);
  if (raw.length !== SIGNATURE_SIZE) throw new ACEError(code, `ml-dsa-65 signature must be ${SIGNATURE_SIZE} bytes`);
  return raw;
}
