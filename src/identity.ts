import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import bs58 from 'bs58';
import type {
  ACEIdentity, SigningScheme, IdentityTier, RegistrationFile,
} from './types.js';
import { decrypt as decryptPayload } from './encryption.js';

/**
 * Apply EIP-55 mixed-case checksum to an Ethereum address.
 */
const _encoder = new TextEncoder();

function eip55Checksum(address: string): string {
  const addr = address.toLowerCase().replace(/^0x/, '');
  const addrHash = bytesToHex(keccak_256(_encoder.encode(addr)));
  return '0x' + [...addr].map((c, i) =>
    parseInt(addrHash[i], 16) >= 8 ? c.toUpperCase() : c,
  ).join('');
}

/**
 * Derive Ethereum-style address from a secp256k1 public key (compressed or uncompressed).
 * keccak256(uncompressed[1:]) → last 20 bytes → 0x hex
 */
export function secp256k1Address(pubKeyBytes: Uint8Array): string {
  // If already uncompressed (65 bytes, 0x04 prefix), use directly
  const uncompressed = pubKeyBytes.length === 65 && pubKeyBytes[0] === 0x04
    ? pubKeyBytes
    : secp256k1.Point.fromHex(bytesToHex(pubKeyBytes)).toBytes(false);
  const hash = keccak_256(uncompressed.slice(1));
  return eip55Checksum('0x' + bytesToHex(hash.slice(-20)));
}

/** Portable Base64 encoding (no Buffer dependency). */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Portable Base64 decoding (no Buffer dependency). */
export function fromBase64(str: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(str);
  } catch {
    throw new Error('Invalid Base64 input');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function computeACEId(signingPublicKeyBytes: Uint8Array): string {
  const hash = sha256(signingPublicKeyBytes);
  return `ace:sha256:${bytesToHex(hash)}`;
}

import { constantTimeEqual } from './utils.js';

export interface SoftwareIdentityExport {
  scheme: SigningScheme;
  signingPrivateKey: string; // Base64
  encryptionPrivateKey: string; // Base64
}

/**
 * Zeroable binary export of private key material.
 * Caller MUST call .signingPrivateKey.fill(0) and .encryptionPrivateKey.fill(0) after use.
 */
export interface SoftwareIdentityBinaryExport {
  scheme: SigningScheme;
  signingPrivateKey: Uint8Array;
  encryptionPrivateKey: Uint8Array;
}

export class SoftwareIdentity implements ACEIdentity {
  private readonly scheme: SigningScheme;
  private readonly signingPrivateKey: Uint8Array;
  private readonly encryptionPrivateKey: Uint8Array;
  private readonly signingPublicKey: Uint8Array;
  private readonly encryptionPublicKey: Uint8Array;
  private readonly signingPubUncompressed: Uint8Array | null; // cached for secp256k1
  private readonly aceId: string;

  private constructor(
    scheme: SigningScheme,
    signingPrivateKey: Uint8Array,
    encryptionPrivateKey: Uint8Array,
  ) {
    this.scheme = scheme;
    this.signingPrivateKey = signingPrivateKey;
    this.encryptionPrivateKey = encryptionPrivateKey;

    // Derive public keys
    if (scheme === 'ed25519') {
      this.signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
      this.signingPubUncompressed = null;
    } else {
      this.signingPublicKey = secp256k1.getPublicKey(signingPrivateKey, true); // compressed
      this.signingPubUncompressed = secp256k1.getPublicKey(signingPrivateKey, false);
    }
    this.encryptionPublicKey = x25519.getPublicKey(encryptionPrivateKey);
    this.aceId = computeACEId(this.signingPublicKey);
  }

  static async generate(scheme: SigningScheme): Promise<SoftwareIdentity> {
    const signingPrivateKey = scheme === 'ed25519'
      ? ed25519.utils.randomSecretKey()
      : secp256k1.utils.randomSecretKey();
    const encryptionPrivateKey = x25519.utils.randomSecretKey();
    return new SoftwareIdentity(scheme, signingPrivateKey, encryptionPrivateKey);
  }

  getEncryptionPublicKey(): Uint8Array {
    return this.encryptionPublicKey.slice();
  }

  getSigningPublicKey(): Uint8Array {
    return this.signingPublicKey.slice();
  }

  async decrypt(
    ephemeralPub: Uint8Array,
    payload: Uint8Array,
    conversationId: string,
  ): Promise<Uint8Array> {
    return decryptPayload(ephemeralPub, payload, this.encryptionPrivateKey, conversationId);
  }

  async sign(data: Uint8Array): Promise<{ signature: Uint8Array; scheme: SigningScheme }> {
    if (this.scheme === 'ed25519') {
      const sig = ed25519.sign(data, this.signingPrivateKey);
      return { signature: sig, scheme: 'ed25519' };
    } else {
      // @noble/curves v2: sign() returns 64-byte Uint8Array (r||s)
      // extraEntropy: RFC 6979 §3.6 — randomizes nonce to harden against fault-injection attacks
      const compact = secp256k1.sign(data, this.signingPrivateKey, { prehash: false, lowS: true, extraEntropy: true });
      const sigObj = secp256k1.Signature.fromBytes(compact);

      // Determine recovery bit by trying both values
      let recovery = 0;
      let found = false;
      for (const v of [0, 1]) {
        try {
          const recovered = sigObj.addRecoveryBit(v).recoverPublicKey(data);
          const recoveredBytes = recovered.toBytes(false);
          if (constantTimeEqual(recoveredBytes, this.signingPubUncompressed!)) {
            recovery = v;
            found = true;
            break;
          }
        } catch { /* try next v */ }
      }
      if (!found) {
        throw new Error('secp256k1: failed to determine recovery bit');
      }

      const sigBytes = new Uint8Array(65);
      sigBytes.set(compact, 0); // r[32] || s[32]
      sigBytes[64] = recovery;
      return { signature: sigBytes, scheme: 'secp256k1' };
    }
  }

  getAddress(): string {
    if (this.scheme === 'ed25519') {
      return bs58.encode(this.signingPublicKey);
    } else {
      return secp256k1Address(this.signingPubUncompressed!);
    }
  }

  getSigningScheme(): SigningScheme {
    return this.scheme;
  }

  getTier(): IdentityTier {
    return 0; // SoftwareIdentity is always Tier 0
  }

  getACEId(): string {
    return this.aceId;
  }

  /**
   * Safe serialization — returns public info only. Private keys are never included.
   * Use exportPrivateKey() for full key export.
   */
  toJSON(): { aceId: string; scheme: SigningScheme; address: string; tier: IdentityTier } {
    return {
      aceId: this.aceId,
      scheme: this.scheme,
      address: this.getAddress(),
      tier: this.getTier(),
    };
  }

  /**
   * Export private key material as Base64 strings. Handle with extreme care.
   * @security Never log, transmit over insecure channels, or store without encryption.
   * WARNING: JavaScript strings are immutable and cannot be zeroed from memory.
   * The returned Base64 values will persist in the JS heap until garbage-collected.
   * Prefer exportPrivateKeyBytes() when you need to zero keys after use.
   */
  exportPrivateKey(): SoftwareIdentityExport {
    return {
      scheme: this.scheme,
      signingPrivateKey: toBase64(this.signingPrivateKey),
      encryptionPrivateKey: toBase64(this.encryptionPrivateKey),
    };
  }

  /**
   * Export private key material as Uint8Array copies that CAN be zeroed.
   * @security Caller MUST call .signingPrivateKey.fill(0) and
   * .encryptionPrivateKey.fill(0) after use to prevent key material
   * from lingering in memory.
   */
  exportPrivateKeyBytes(): SoftwareIdentityBinaryExport {
    return {
      scheme: this.scheme,
      signingPrivateKey: this.signingPrivateKey.slice(),
      encryptionPrivateKey: this.encryptionPrivateKey.slice(),
    };
  }

  static fromExport(data: SoftwareIdentityExport): SoftwareIdentity {
    return new SoftwareIdentity(
      data.scheme,
      fromBase64(data.signingPrivateKey),
      fromBase64(data.encryptionPrivateKey),
    );
  }

  static fromBinaryExport(data: SoftwareIdentityBinaryExport): SoftwareIdentity {
    return new SoftwareIdentity(
      data.scheme,
      data.signingPrivateKey.slice(),
      data.encryptionPrivateKey.slice(),
    );
  }

  toRegistrationFile(opts: {
    name: string;
    endpoint: string;
    description?: string;
    hardwareBacking?: RegistrationFile['hardwareBacking'];
    capabilities?: RegistrationFile['capabilities'];
    settlement?: string[];
    chains?: RegistrationFile['chains'];
  }): RegistrationFile {
    const reg: RegistrationFile = {
      ace: '1.0',
      id: this.getACEId(),
      name: opts.name,
      endpoint: opts.endpoint,
      tier: this.getTier(),
      signing: {
        scheme: this.scheme,
        address: this.getAddress(),
        encryptionPublicKey: toBase64(this.encryptionPublicKey),
      },
    };

    if (opts.description !== undefined) reg.description = opts.description;
    if (opts.hardwareBacking !== undefined) reg.hardwareBacking = opts.hardwareBacking;
    if (opts.capabilities !== undefined) reg.capabilities = opts.capabilities;
    if (opts.settlement !== undefined) reg.settlement = opts.settlement;
    if (opts.chains !== undefined) reg.chains = opts.chains;

    // secp256k1 requires signingPublicKey (address is a hash)
    if (this.scheme === 'secp256k1') {
      reg.signing.signingPublicKey = toBase64(this.signingPublicKey);
    }

    return reg;
  }
}
