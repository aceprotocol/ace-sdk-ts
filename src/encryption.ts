/**
 * ACE E2E encryption: X-Wing hybrid KEM + HKDF-SHA256 + AES-256-GCM.
 *
 *   (ss, kemCiphertext) = XWing.Encapsulate(recipientPublicKey)
 *   aesKey  = HKDF-SHA256(ikm = ss, salt = SHA-256("ace.protocol.kem.v1"), info = conversationId, L = 32)
 *   payload = nonce[12] || AES-256-GCM(aesKey, nonce, plaintext, aad = conversationId)
 *
 * `@noble/post-quantum`'s `ml_kem768_x25519` is X-Wing (draft-connolly-cfrg-xwing-kem-11).
 * This module is the single owner of the X-Wing byte-length checks.
 */

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { compareBytes, isConversationId, utf8 } from './encoding.js';
import {
  KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_SEED_SIZE, MAX_PAYLOAD_BYTES, MAX_PLAINTEXT_BYTES,
} from './limits.js';

export const ACE_KEM_SALT = sha256(utf8('ace.protocol.kem.v1'));
const NONCE_LEN = 12;
export const MIN_PAYLOAD_BYTES = 28;

function isBytes(v: unknown, n: number): v is Uint8Array {
  return v instanceof Uint8Array && v.length === n;
}

export function isKemPublicKey(v: unknown): v is Uint8Array {
  return isBytes(v, KEM_PUBLIC_KEY_SIZE);
}

export function isKemCiphertext(v: unknown): v is Uint8Array {
  return isBytes(v, KEM_CIPHERTEXT_SIZE);
}

/** hex(SHA-256(min(pubA, pubB) || max(pubA, pubB))) over two 1216-byte X-Wing public keys. */
export function computeConversationId(pubA: Uint8Array, pubB: Uint8Array): string {
  if (!isKemPublicKey(pubA) || !isKemPublicKey(pubB)) {
    throw new ACEError('invalid_key', `X-Wing public keys must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  }
  const [a, b] = compareBytes(pubA, pubB) <= 0 ? [pubA, pubB] : [pubB, pubA];
  const buf = new Uint8Array(a.length + b.length);
  buf.set(a, 0);
  buf.set(b, a.length);
  return bytesToHex(sha256(buf));
}

/** A fresh 32-byte X-Wing private seed. */
export function generateKemSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEM_SEED_SIZE));
}

/** The 1216-byte X-Wing public key of a 32-byte seed. */
export function kemPublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (!isBytes(seed, KEM_SEED_SIZE)) throw new ACEError('invalid_key', `X-Wing seed must be ${KEM_SEED_SIZE} bytes`);
  return ml_kem768_x25519.getPublicKey(seed);
}

/** Internal: raw X-Wing decapsulation (used by the KAT tests). */
export function xwingDecapsulate(ciphertext: Uint8Array, seed: Uint8Array): Uint8Array {
  if (!isKemCiphertext(ciphertext)) throw new ACEError('decryption_failed', `X-Wing ciphertext must be ${KEM_CIPHERTEXT_SIZE} bytes`);
  try {
    return ml_kem768_x25519.decapsulate(ciphertext, seed);
  } catch {
    throw new ACEError('decryption_failed', 'X-Wing decapsulation failed');
  }
}

async function aesKey(sharedSecret: Uint8Array, conversationId: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const raw = hkdf(sha256, sharedSecret, ACE_KEM_SALT, utf8(conversationId), 32);
  const copy = Uint8Array.from(raw);
  try {
    return await crypto.subtle.importKey('raw', copy, 'AES-GCM', false, [usage]);
  } finally {
    raw.fill(0);
    copy.fill(0);
  }
}

/** Internal: returns `{kemCiphertext, payload}`. */
export async function encrypt(
  plaintext: Uint8Array, recipientPublicKey: Uint8Array, conversationId: string,
): Promise<{ kemCiphertext: Uint8Array; payload: Uint8Array }> {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new ACEError('limit_exceeded', `plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  if (!isKemPublicKey(recipientPublicKey)) throw new ACEError('invalid_key', 'recipient X-Wing public key must be 1216 bytes');
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(recipientPublicKey);
  try {
    const key = await aesKey(sharedSecret, conversationId, 'encrypt');
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: Uint8Array.from(utf8(conversationId)) }, key, Uint8Array.from(plaintext),
    ));
    const payload = new Uint8Array(NONCE_LEN + ct.length);
    payload.set(nonce, 0);
    payload.set(ct, NONCE_LEN);
    return { kemCiphertext: cipherText, payload };
  } finally {
    sharedSecret.fill(0);
  }
}

/**
 * Decrypt with a borrowed 32-byte X-Wing seed (for custom identities, e.g. a Secure Enclave
 * wrapper that keeps the seed in a keychain).
 *
 * Crypto failures (decapsulation, AEAD, wrong ciphertext / payload length) are
 * `ACEError(decryption_failed)`; a malformed seed is `invalid_key`; a malformed
 * conversationId is `invalid_argument`.
 */
export async function decryptWithSeed(
  kemCiphertext: Uint8Array, payload: Uint8Array, seed: Uint8Array, conversationId: string,
): Promise<Uint8Array> {
  if (!isBytes(seed, KEM_SEED_SIZE)) throw new ACEError('invalid_key', `X-Wing seed must be ${KEM_SEED_SIZE} bytes`);
  if (!isConversationId(conversationId)) throw new ACEError('invalid_argument', 'conversationId must be 64 lowercase hex characters');
  if (!(payload instanceof Uint8Array) || payload.length < MIN_PAYLOAD_BYTES || payload.length > MAX_PAYLOAD_BYTES) {
    throw new ACEError('decryption_failed', 'payload length out of range');
  }
  const sharedSecret = xwingDecapsulate(kemCiphertext, seed);
  try {
    const key = await aesKey(sharedSecret, conversationId, 'decrypt');
    try {
      return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: Uint8Array.from(payload.subarray(0, NONCE_LEN)), additionalData: Uint8Array.from(utf8(conversationId)) },
        key, Uint8Array.from(payload.subarray(NONCE_LEN)),
      ));
    } catch {
      throw new ACEError('decryption_failed', 'AEAD authentication failed');
    }
  } finally {
    sharedSecret.fill(0);
  }
}
