/** Key providers: where a signing key lives and how it signs. Software provider only here. */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { concat, sha256Bytes, utf8 } from './encoding.js';
import { SEED_SIZE } from './signing.js';
import type { SigningScheme } from './types.js';

const MAX_CONTEXT_BYTES = 255; // FIPS 204 context limit

export interface KeyProvider {
  readonly scheme: SigningScheme;
  publicKey(): Uint8Array;
  /** ML-DSA-65 over the full message `M`, ctx = UTF-8(action). */
  sign(message: Uint8Array, action: string): Promise<Uint8Array>;
}

/** `SHA-256(scheme || 0x00 || publicKey)`: the pre-rotation commitment of a key. */
export function keyDigest(scheme: string, publicKey: Uint8Array): Uint8Array {
  return sha256Bytes(concat([utf8(scheme), new Uint8Array([0]), publicKey]));
}

/** Hex `keyDigest`: the form a KEL's `next` commitment takes. */
export function keyDigestHex(scheme: string, publicKey: Uint8Array): string {
  return bytesToHex(keyDigest(scheme, publicKey));
}

/** An ML-DSA-65 key from its 32-byte seed (FIPS 204 § 3.6.3). */
export class SoftwareKey implements KeyProvider {
  readonly scheme = 'ml-dsa-65' as const;
  readonly seed: Uint8Array;
  readonly #secretKey: Uint8Array;
  readonly #publicKey: Uint8Array;

  constructor(seed: Uint8Array) {
    if (!(seed instanceof Uint8Array) || seed.length !== SEED_SIZE) throw new ACEError('invalid_argument', `seed must be ${SEED_SIZE} bytes`);
    this.seed = Uint8Array.from(seed);
    const { secretKey, publicKey } = ml_dsa65.keygen(this.seed);
    this.#secretKey = secretKey;
    this.#publicKey = publicKey;
  }

  publicKey(): Uint8Array { return this.#publicKey.slice(); }

  async sign(message: Uint8Array, action: string): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) throw new ACEError('invalid_argument', 'message must be a Uint8Array');
    if (typeof action !== 'string') throw new ACEError('invalid_argument', 'action must be a string');
    const context = utf8(action);
    if (context.length > MAX_CONTEXT_BYTES) throw new ACEError('invalid_argument', `action must be at most ${MAX_CONTEXT_BYTES} UTF-8 bytes`);
    return ml_dsa65.sign(message, this.#secretKey, { context });
  }
}

export function generateSoftwareKey(): SoftwareKey {
  return new SoftwareKey(randomBytes(SEED_SIZE));
}
