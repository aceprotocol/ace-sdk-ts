/** SoftwareIdentity (Tier 0): keys held in process memory. */

import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ACEError } from './errors.js';
import { decodeB64, toBase64 } from './encoding.js';
import { decryptWithSeed, generateKemSeed, kemPublicKeyFromSeed } from './encryption.js';
import { KEM_SEED_SIZE } from './limits.js';
import { computeACEId, signingAddress } from './signing.js';
import type { ACEIdentity, SigningScheme } from './types.js';
import { isSigningScheme } from './types.js';

export interface SoftwareIdentityExport {
  scheme: SigningScheme;
  /** Base64 of the 32-byte signing private key. */
  signingPrivateKey: string;
  /** Base64 of the 32-byte X-Wing seed. */
  encryptionPrivateKey: string;
}

/**
 * Software ACE identity. JavaScript cannot reliably zeroize strings; use a hardware
 * identity (Secure Enclave, TPM, HSM) for high-value deployments.
 */
export class SoftwareIdentity implements ACEIdentity {
  readonly #scheme: SigningScheme;
  readonly #signingPrivateKey: Uint8Array;
  readonly #seed: Uint8Array;
  readonly #signingPublicKey: Uint8Array;
  readonly #encryptionPublicKey: Uint8Array;
  readonly #aceId: string;

  private constructor(scheme: SigningScheme, signingPrivateKey: Uint8Array, seed: Uint8Array) {
    if (!isSigningScheme(scheme)) throw new ACEError('invalid_argument', `unsupported signing scheme ${String(scheme).slice(0, 32)}`);
    if (!(signingPrivateKey instanceof Uint8Array) || signingPrivateKey.length !== 32) {
      throw new ACEError('invalid_key', 'signing private key must be 32 bytes');
    }
    if (!(seed instanceof Uint8Array) || seed.length !== KEM_SEED_SIZE) {
      throw new ACEError('invalid_key', `encryption seed must be ${KEM_SEED_SIZE} bytes`);
    }
    this.#scheme = scheme;
    this.#signingPrivateKey = Uint8Array.from(signingPrivateKey);
    this.#seed = Uint8Array.from(seed);
    try {
      this.#signingPublicKey = scheme === 'ed25519'
        ? ed25519.getPublicKey(this.#signingPrivateKey)
        : secp256k1.getPublicKey(this.#signingPrivateKey, true);
    } catch {
      throw new ACEError('invalid_key', `${scheme} private key out of range`);
    }
    this.#encryptionPublicKey = kemPublicKeyFromSeed(this.#seed);
    this.#aceId = computeACEId(this.#signingPublicKey);
  }

  static async generate(scheme: SigningScheme): Promise<SoftwareIdentity> {
    if (!isSigningScheme(scheme)) throw new ACEError('invalid_argument', `unsupported signing scheme ${String(scheme).slice(0, 32)}`);
    const signing = scheme === 'ed25519' ? ed25519.utils.randomSecretKey() : secp256k1.utils.randomSecretKey();
    return new SoftwareIdentity(scheme, signing, generateKemSeed());
  }

  static fromExport(data: unknown): SoftwareIdentity {
    if (typeof data !== 'object' || data === null) throw new ACEError('invalid_argument', 'export must be an object');
    const e = data as { [K in keyof SoftwareIdentityExport]?: unknown };
    return new SoftwareIdentity(
      e.scheme as SigningScheme, // checked by the constructor
      decodeB64(e.signingPrivateKey, 'invalid_key', 'signingPrivateKey'),
      decodeB64(e.encryptionPrivateKey, 'invalid_key', 'encryptionPrivateKey'),
    );
  }

  getACEId(): string {
    return this.#aceId;
  }

  getSigningScheme(): SigningScheme {
    return this.#scheme;
  }

  getSigningPublicKey(): Uint8Array {
    return this.#signingPublicKey.slice();
  }

  getEncryptionPublicKey(): Uint8Array {
    return this.#encryptionPublicKey.slice();
  }

  /** ed25519: Base58 of the signing key. secp256k1: EIP-55 address. */
  getAddress(): string {
    return signingAddress(this.#scheme, this.#signingPublicKey);
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array) || data.length !== 32) throw new ACEError('invalid_argument', 'signData must be 32 bytes');
    if (this.#scheme === 'ed25519') return ed25519.sign(data, this.#signingPrivateKey);
    // 'recovered' = recovery[1] || r[32] || s[32]; ACE wire order is r || s || v.
    const rec = secp256k1.sign(data, this.#signingPrivateKey, {
      prehash: false, lowS: true, extraEntropy: true, format: 'recovered',
    });
    const out = new Uint8Array(65);
    out.set(rec.subarray(1), 0);
    out[64] = rec[0];
    return out;
  }

  async decrypt(kemCiphertext: Uint8Array, payload: Uint8Array, conversationId: string): Promise<Uint8Array> {
    return decryptWithSeed(kemCiphertext, payload, this.#seed, conversationId);
  }

  /** Private key material as Base64. Never log or store it unencrypted. */
  exportPrivateKey(): SoftwareIdentityExport {
    return {
      scheme: this.#scheme,
      signingPrivateKey: toBase64(this.#signingPrivateKey),
      encryptionPrivateKey: toBase64(this.#seed),
    };
  }
}

export { computeACEId };
