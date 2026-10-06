import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { SigningScheme } from './types.js';
import { toBase64, fromBase64 } from './identity.js';

const _encoder = new TextEncoder();

// Unified domain prefix — action field provides domain separation
const _DOMAIN_PREFIX = _encoder.encode('ace.v1');

// secp256k1 curve order N and N/2 — used to enforce canonical low-S signatures.
const _SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const _SECP256K1_HALF_ORDER = _SECP256K1_ORDER >> 1n;

function _bytesToBigIntBE(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

/** Encode a string as length-prefixed bytes: [len(4 BE)] || UTF-8(str) */
function encodeLengthPrefixed(field: string): Uint8Array[] {
  const bytes = _encoder.encode(field);
  const len = new DataView(new ArrayBuffer(4));
  len.setUint32(0, bytes.length, false);
  return [new Uint8Array(len.buffer), bytes];
}

/** Validate and encode a timestamp as 8-byte big-endian */
function encodeTimestamp(ts: number): Uint8Array {
  if (ts < 0 || ts > Number.MAX_SAFE_INTEGER || !Number.isSafeInteger(ts)) {
    throw new Error(
      `Invalid timestamp: must be a finite number in [0, ${Number.MAX_SAFE_INTEGER}], got ${ts}`,
    );
  }
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(ts / 0x100000000), false);
  view.setUint32(4, ts >>> 0, false);
  return new Uint8Array(buf);
}

/** Concatenate parts and return SHA-256 digest */
function concatAndHash(parts: Uint8Array[]): Uint8Array {
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const buffer = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }
  return sha256(buffer);
}

/** Encode a binary blob as length-prefixed: [len(4 BE)] || bytes */
function encodeLengthPrefixedBytes(data: Uint8Array): Uint8Array[] {
  const len = new DataView(new ArrayBuffer(4));
  len.setUint32(0, data.length, false);
  return [new Uint8Array(len.buffer), data];
}

import { constantTimeEqual } from './utils.js';

/**
 * Encode multiple fields (string or binary) into a single payload blob.
 * Each field is length-prefixed: [len(4 BE)] || data.
 */
export function encodePayload(...fields: Array<string | Uint8Array>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const field of fields) {
    if (typeof field === 'string') {
      parts.push(...encodeLengthPrefixed(field));
    } else {
      parts.push(...encodeLengthPrefixedBytes(field));
    }
  }
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

const _EMPTY_PAYLOAD = new Uint8Array(0);

/**
 * Unified signData construction with domain separation via action field:
 *
 * SHA-256(
 *   "ace.v1" ||
 *   len(action)[4 BE] || UTF-8(action) ||
 *   len(aceId)[4 BE] || UTF-8(aceId) ||
 *   timestamp[8 big-endian] ||
 *   len(payload)[4 BE] || payload
 * )
 *
 * Actions: "message", "register", "listen", "inbox", "unregister", "intent"
 * Payload: action-specific data built via encodePayload()
 */
export function buildSignData(
  action: string,
  aceId: string,
  timestamp: number,
  payload: Uint8Array = _EMPTY_PAYLOAD,
): Uint8Array {
  const parts: Uint8Array[] = [_DOMAIN_PREFIX];
  parts.push(...encodeLengthPrefixed(action));
  parts.push(...encodeLengthPrefixed(aceId));
  parts.push(encodeTimestamp(timestamp));
  parts.push(...encodeLengthPrefixedBytes(payload));
  return concatAndHash(parts);
}

/**
 * Verify a signature against signData.
 * For ed25519: direct verification with public key.
 * For secp256k1: recover public key from signature and compare against expected key.
 */
export function verifySignature(
  signData: Uint8Array,
  signature: Uint8Array,
  scheme: SigningScheme,
  signingPublicKey: Uint8Array,
): boolean {
  if (scheme === 'ed25519') {
    return ed25519.verify(signature, signData, signingPublicKey);
  } else if (scheme === 'secp256k1') {
    // Extract compact(r||s) and recovery bit v from 65-byte signature
    if (signature.length !== 65) {
      return false;
    }
    const compact = signature.slice(0, 64);
    const v = signature[64];
    if (v !== 0 && v !== 1) {
      return false; // Only recovery bits 0 and 1 are valid for secp256k1
    }

    // Reject out-of-range and non-canonical (high-S) signatures. ECDSA is
    // malleable: (r, s) and (r, n - s) recover the same key, so accepting high-S
    // lets an observer re-mint a valid signature with different bytes and slip
    // past signature-keyed replay protection. Low-S makes the bytes canonical
    // (matches how all ACE SDKs sign).
    const r = _bytesToBigIntBE(signature.slice(0, 32));
    const s = _bytesToBigIntBE(signature.slice(32, 64));
    if (r < 1n || r >= _SECP256K1_ORDER) {
      return false;
    }
    if (s < 1n || s > _SECP256K1_HALF_ORDER) {
      return false;
    }

    // Recover public key (signData is already SHA-256 digest from buildSignData)
    const sigObj = secp256k1.Signature.fromBytes(compact).addRecoveryBit(v);
    const recovered = sigObj.recoverPublicKey(signData);
    const recoveredCompressed = recovered.toBytes(true);

    // Compare compressed public key bytes directly (constant-time)
    return constantTimeEqual(recoveredCompressed, signingPublicKey);
  }
  return false;
}

/**
 * Encode a signature to its wire format.
 * ed25519: Base64
 * secp256k1: 0x + hex(r || s || v)
 */
export function encodeSignature(signature: Uint8Array, scheme: SigningScheme): string {
  if (scheme === 'ed25519') {
    return toBase64(signature);
  } else {
    return '0x' + bytesToHex(signature);
  }
}

/**
 * Decode a signature from its wire format.
 */
export function decodeSignature(encoded: string, scheme: SigningScheme): Uint8Array {
  if (scheme === 'ed25519') {
    return fromBase64(encoded);
  } else {
    return hexToBytes(encoded.startsWith('0x') ? encoded.slice(2) : encoded);
  }
}
