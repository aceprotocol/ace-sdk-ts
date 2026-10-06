import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { fromBase64 } from './utils.js';

// ACE message encryption: X-Wing hybrid KEM → HKDF-SHA256 → AES-256-GCM.
//
// X-Wing (draft-connolly-cfrg-xwing-kem-11) combines ML-KEM-768 with X25519 as
// its classical component. `@noble/post-quantum`'s `ml_kem768_x25519` IS X-Wing:
// label `\.//^\`, SHA3-256 combiner, SHAKE256 seed expansion. The combiner binds
// the recipient public key and the KEM ciphertext, so no small-order-point or
// all-zero shared-secret checks are needed (or performed) here.

const _encoder = new TextEncoder();

/** X-Wing private key = 32-byte seed (expanded with SHAKE256 at use time). */
export const KEM_SEED_SIZE = 32;
/** X-Wing public key: pk_M[1184] || pk_X[32]. */
export const KEM_PUBLIC_KEY_SIZE = 1216;
/** X-Wing ciphertext: ct_M[1088] || ct_X[32]. */
export const KEM_CIPHERTEXT_SIZE = 1120;

// Pre-computed: SHA-256("ace.protocol.kem.v1") — internal, never exposed directly
const _ACE_KEM_SALT = sha256(_encoder.encode('ace.protocol.kem.v1'));

/** Returns a copy of the ACE KEM salt (SHA-256 of "ace.protocol.kem.v1"). */
export function getACEKemSalt(): Uint8Array {
  return _ACE_KEM_SALT.slice();
}

// === Byte-length validation (single owner for the X-Wing sizes) ===

function assertExactLength(bytes: Uint8Array, expected: number, what: string): void {
  if (bytes.length !== expected) {
    throw new Error(`${what} must be exactly ${expected} bytes, got ${bytes.length}`);
  }
}

/** Assert that `pk` is a 1216-byte X-Wing public key. */
export function validatePublicKey(pk: Uint8Array): void {
  assertExactLength(pk, KEM_PUBLIC_KEY_SIZE, 'X-Wing public key');
}

/** Assert that `ct` is a 1120-byte X-Wing KEM ciphertext. */
export function validateKemCiphertext(ct: Uint8Array): void {
  assertExactLength(ct, KEM_CIPHERTEXT_SIZE, 'X-Wing KEM ciphertext');
}

/** Assert that `seed` is a 32-byte X-Wing seed (the private key). */
export function validateSeed(seed: Uint8Array): void {
  assertExactLength(seed, KEM_SEED_SIZE, 'X-Wing seed');
}

// === Base64 wire decoding ===

/** Padded Base64 length of `byteLength` bytes. */
function base64LengthFor(byteLength: number): number {
  return Math.ceil(byteLength / 3) * 4;
}

/**
 * Decode a fixed-size X-Wing object from its Base64 wire form.
 * The string-length pre-check rejects oversized input before any decoding
 * (DoS guard); the byte-length check then enforces the exact size.
 */
function decodeFixedSize(b64: string, expected: number, what: string): Uint8Array {
  if (typeof b64 !== 'string') {
    throw new Error(`${what} must be a Base64 string`);
  }
  const maxB64Length = base64LengthFor(expected);
  if (b64.length > maxB64Length) {
    throw new Error(
      `${what} must be exactly ${expected} bytes; Base64 length ${b64.length} exceeds ${maxB64Length}`,
    );
  }
  const bytes = fromBase64(b64);
  assertExactLength(bytes, expected, what);
  return bytes;
}

/** Decode a Base64 X-Wing public key, enforcing the exact 1216-byte length. */
export function decodeKemPublicKey(b64: string): Uint8Array {
  return decodeFixedSize(b64, KEM_PUBLIC_KEY_SIZE, 'X-Wing public key');
}

/** Decode a Base64 X-Wing KEM ciphertext, enforcing the exact 1120-byte length. */
export function decodeKemCiphertext(b64: string): Uint8Array {
  return decodeFixedSize(b64, KEM_CIPHERTEXT_SIZE, 'X-Wing KEM ciphertext');
}

/**
 * Lexicographic byte comparison. Returns negative if a < b, positive if a > b, 0 if equal.
 *
 * SAFETY: This is variable-time, which is acceptable here because it operates
 * exclusively on public keys (not secret material). Do NOT reuse for secrets.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Compute deterministic conversation ID from two X-Wing encryption public keys.
 * conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
 */
export function computeConversationId(
  pubA: Uint8Array,
  pubB: Uint8Array,
): string {
  validatePublicKey(pubA);
  validatePublicKey(pubB);
  const [first, second] = compareBytes(pubA, pubB) <= 0 ? [pubA, pubB] : [pubB, pubA];
  const combined = new Uint8Array(first.length + second.length);
  combined.set(first, 0);
  combined.set(second, first.length);
  return bytesToHex(sha256(combined));
}

// Minimum payload size: nonce[12] + GCM tag[16] = 28 bytes (0-byte plaintext)
const MIN_PAYLOAD_LENGTH = 28;
export const MAX_PAYLOAD_SIZE = 10 * 1024 * 1024;
export const MAX_PLAINTEXT_SIZE = MAX_PAYLOAD_SIZE - MIN_PAYLOAD_LENGTH;

// === X-Wing KEM primitives ===

/**
 * Derive the X-Wing public key (1216 bytes) from a 32-byte seed.
 */
export function kemPublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  validateSeed(seed);
  return ml_kem768_x25519.getPublicKey(seed);
}

/**
 * Generate a fresh random X-Wing seed (the private key).
 */
export function generateKemSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEM_SEED_SIZE));
}

/**
 * X-Wing encapsulation against a recipient public key.
 * Returns the 1120-byte KEM ciphertext and the 32-byte shared secret.
 */
export function kemEncapsulate(
  recipientPubKey: Uint8Array,
): { kemCiphertext: Uint8Array; sharedSecret: Uint8Array } {
  validatePublicKey(recipientPubKey);
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(recipientPubKey);
  return { kemCiphertext: cipherText, sharedSecret };
}

/**
 * X-Wing decapsulation with a 32-byte seed. Implicit rejection: an invalid
 * ciphertext yields a pseudorandom secret rather than an error; the AEAD tag
 * check downstream is what actually fails.
 */
export function kemDecapsulate(kemCiphertext: Uint8Array, seed: Uint8Array): Uint8Array {
  validateSeed(seed);
  validateKemCiphertext(kemCiphertext);
  return ml_kem768_x25519.decapsulate(kemCiphertext, seed);
}

// === ACE message encryption ===

/**
 * Encrypt plaintext for a recipient.
 * Returns the X-Wing KEM ciphertext + encrypted payload (nonce || ciphertext || tag).
 * The recipient public key is validated by {@link kemEncapsulate}.
 */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array,
  conversationId: string,
): Promise<{ kemCiphertext: Uint8Array; payload: Uint8Array }> {
  // 0. Validate plaintext size
  if (plaintext.length > MAX_PLAINTEXT_SIZE) {
    throw new Error(
      `Plaintext too large: maximum is ${MAX_PLAINTEXT_SIZE} bytes, got ${plaintext.length}`,
    );
  }

  // 1. X-Wing encapsulation → (ct, ss)
  const { kemCiphertext, sharedSecret } = kemEncapsulate(recipientPubKey);

  // 2. HKDF key derivation
  const convIdBytes = _encoder.encode(conversationId);
  const aesKey = hkdf(sha256, sharedSecret, _ACE_KEM_SALT, convIdBytes, 32);

  try {
    // 3. AES-256-GCM encryption via Web Crypto
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await crypto.subtle.importKey(
      'raw', Uint8Array.from(aesKey), 'AES-GCM', false, ['encrypt'],
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: convIdBytes },
      cryptoKey,
      Uint8Array.from(plaintext),
    );
    // Web Crypto returns ciphertext || tag (tag is last 16 bytes)
    const encryptedBytes = new Uint8Array(encrypted);

    // 4. Payload = nonce[12] || ciphertext || tag[16]
    const payload = new Uint8Array(12 + encryptedBytes.length);
    payload.set(nonce, 0);
    payload.set(encryptedBytes, 12);
    if (payload.length > MAX_PAYLOAD_SIZE) {
      throw new Error(
        `Encrypted payload too large: maximum is ${MAX_PAYLOAD_SIZE} bytes, got ${payload.length}`,
      );
    }

    return { kemCiphertext, payload };
  } finally {
    // Zero all key material
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}

/**
 * Decrypt a message using own X-Wing seed (private key).
 * The seed and KEM ciphertext are validated by {@link kemDecapsulate}.
 */
export async function decrypt(
  kemCiphertext: Uint8Array,
  payload: Uint8Array,
  recipientSeed: Uint8Array,
  conversationId: string,
): Promise<Uint8Array> {
  // 0. Validate payload length (before any decapsulation)
  if (payload.length < MIN_PAYLOAD_LENGTH) {
    throw new Error(
      `Payload too short: expected at least ${MIN_PAYLOAD_LENGTH} bytes, got ${payload.length}`,
    );
  }
  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new Error(
      `Payload too large: maximum is ${MAX_PAYLOAD_SIZE} bytes, got ${payload.length}`,
    );
  }

  // 1. X-Wing decapsulation → ss
  const sharedSecret = kemDecapsulate(kemCiphertext, recipientSeed);

  // 2. HKDF key derivation
  const convIdBytes = _encoder.encode(conversationId);
  const aesKey = hkdf(sha256, sharedSecret, _ACE_KEM_SALT, convIdBytes, 32);

  try {
    // 3. Parse payload: nonce[12] || ciphertext+tag
    const nonce = payload.slice(0, 12);
    const ciphertextAndTag = payload.slice(12);

    // 4. AES-256-GCM decryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw', Uint8Array.from(aesKey), 'AES-GCM', false, ['decrypt'],
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: convIdBytes },
      cryptoKey,
      ciphertextAndTag,
    );

    return new Uint8Array(decrypted);
  } finally {
    // Zero all key material
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}
