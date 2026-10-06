/** signData construction and strict ed25519 / secp256k1 verification. Internal. */

import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import bs58 from 'bs58';
import { ACEError } from './errors.js';
import { bytesEqual, MAX_SAFE_INTEGER, utf8 } from './encoding.js';

const DOMAIN_PREFIX = utf8('ace.v1');
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

const SMALL_ORDER = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/** `len(4 BE) || bytes` per field; strings are UTF-8. */
export function encodePayload(...fields: Array<string | Uint8Array>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    const b = typeof f === 'string' ? utf8(f) : f;
    parts.push(u32be(b.length), b);
  }
  return concat(parts);
}

/** SHA-256("ace.v1" || lp(action) || lp(aceId) || ts[8 BE] || lp(payload)). */
export function buildSignData(action: string, aceId: string, timestamp: number, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (typeof timestamp !== 'number' || !Number.isInteger(timestamp) || timestamp < 0 || timestamp > MAX_SAFE_INTEGER) {
    throw new ACEError('invalid_argument', 'timestamp must be an integer in [0, 2^53-1]');
  }
  const ts = new Uint8Array(8);
  const view = new DataView(ts.buffer);
  view.setUint32(0, Math.floor(timestamp / 0x100000000), false);
  view.setUint32(4, timestamp >>> 0, false);
  const a = utf8(action);
  const id = utf8(aceId);
  return sha256(concat([DOMAIN_PREFIX, u32be(a.length), a, u32be(id.length), id, ts, u32be(payload.length), payload]));
}

/** ed25519: 32 bytes. secp256k1: a 33-byte compressed point on the curve. */
export function isValidSigningPublicKey(scheme: unknown, key: Uint8Array): boolean {
  if (!(key instanceof Uint8Array)) return false;
  if (scheme === 'ed25519') return key.length === 32;
  if (scheme === 'secp256k1') {
    if (key.length !== 33 || (key[0] !== 2 && key[0] !== 3)) return false;
    try {
      secp256k1.Point.fromBytes(key).assertValidity();
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function leToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function beToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}

function ed25519PointOk(enc: Uint8Array): boolean {
  const b = Uint8Array.from(enc);
  b[31] &= 0x7f;
  if (b[31] === 0x7f && b[0] >= 0xed) {
    let all = true;
    for (let i = 1; i < 31; i++) if (b[i] !== 0xff) { all = false; break; }
    if (all) return false; // non-canonical y >= p
  }
  return !SMALL_ORDER.includes(bytesToHex(b));
}

/** Strict ed25519 (signing-schemes/ed25519.md "Verification (strict)"). */
export function verifyEd25519(signData: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean {
  if (sig.length !== 64 || publicKey.length !== 32) return false;
  if (leToBigInt(sig.subarray(32)) >= ED25519_L) return false;
  if (!ed25519PointOk(publicKey) || !ed25519PointOk(sig.subarray(0, 32))) return false;
  try {
    return ed25519.verify(sig, signData, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** Strict secp256k1: r in [1, n-1], s in [1, n/2], v in {0, 1}; recovered key compared in constant time. */
export function verifySecp256k1(signData: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean {
  if (sig.length !== 65 || signData.length !== 32 || !isValidSigningPublicKey('secp256k1', publicKey)) return false;
  const r = beToBigInt(sig.subarray(0, 32));
  const s = beToBigInt(sig.subarray(32, 64));
  const v = sig[64];
  if ((v !== 0 && v !== 1) || r < 1n || r >= SECP256K1_N || s < 1n || s > SECP256K1_HALF_N) return false;
  try {
    const recovered = secp256k1.Signature.fromBytes(sig.slice(0, 64), 'compact')
      .addRecoveryBit(v)
      .recoverPublicKey(signData)
      .toBytes(true);
    return bytesEqual(recovered, publicKey);
  } catch {
    return false;
  }
}

export function verifySignature(signData: Uint8Array, sig: Uint8Array, scheme: unknown, publicKey: Uint8Array): boolean {
  if (scheme === 'ed25519') return verifyEd25519(signData, sig, publicKey);
  if (scheme === 'secp256k1') return verifySecp256k1(signData, sig, publicKey);
  return false;
}

function eip55(hex40: string): string {
  const addr = hex40.toLowerCase();
  const h = bytesToHex(keccak_256(utf8(addr)));
  let out = '0x';
  for (let i = 0; i < addr.length; i++) out += parseInt(h[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
  return out;
}

/** ed25519: Base58 of the key. secp256k1: EIP-55 address of the compressed key. */
export function signingAddress(scheme: string, signingPublicKey: Uint8Array): string {
  if (scheme === 'ed25519') return bs58.encode(signingPublicKey);
  const uncompressed = secp256k1.Point.fromBytes(signingPublicKey).toBytes(false);
  return eip55(bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(-20)));
}

/** `ace:sha256:hex(SHA-256(signingPublicKey))`. */
export function computeACEId(signingPublicKey: Uint8Array): string {
  return `ace:sha256:${bytesToHex(sha256(signingPublicKey))}`;
}
