import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { constantTimeEqual } from './utils.js';

const _encoder = new TextEncoder();

// Pre-computed: SHA-256("ace.protocol.dh.v1") — internal, never exposed directly
const _ACE_DH_SALT = sha256(_encoder.encode('ace.protocol.dh.v1'));

/** Returns a copy of the ACE DH salt (SHA-256 of "ace.protocol.dh.v1"). */
export function getACEDHSalt(): Uint8Array {
  return _ACE_DH_SALT.slice();
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
 * Compute deterministic conversation ID from two X25519 public keys.
 * conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
 */
export function computeConversationId(
  pubA: Uint8Array,
  pubB: Uint8Array,
): string {
  if (pubA.length !== 32 || pubB.length !== 32) {
    throw new Error(`X25519 public keys must be 32 bytes, got ${pubA.length} and ${pubB.length}`);
  }
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

/**
 * All 7 known Curve25519 low-order points (order dividing cofactor 8).
 * These yield predictable ECDH outputs. @noble/curves also rejects them,
 * but we check first for clearer error messages.
 * Ref: https://cr.yp.to/ecdh.html, libsodium _crypto_scalarmult_curve25519_ref10
 */
const _LOW_ORDER_POINTS: ReadonlyArray<Uint8Array> = [
  '0000000000000000000000000000000000000000000000000000000000000000', // order 1
  '0100000000000000000000000000000000000000000000000000000000000000', // order 2
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', // order 4
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', // order 4
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // order 8
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p (= order 1 mod p)
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p+1 (= order 2 mod p)
].map(hexToBytes);

/** Validate X25519 public key: must be 32 bytes, not a known low-order point. */
function validatePublicKey(pubKey: Uint8Array): void {
  if (pubKey.length !== 32) {
    throw new Error(`X25519 public key must be exactly 32 bytes, got ${pubKey.length}`);
  }
  if (_LOW_ORDER_POINTS.some(p => constantTimeEqual(p, pubKey))) {
    throw new Error('Refusing to use low-order X25519 public key (small-subgroup attack)');
  }
}

/**
 * Encrypt plaintext for a recipient.
 * Returns ephemeral public key + encrypted payload (nonce || ciphertext || tag).
 */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array,
  conversationId: string,
): Promise<{ ephemeralPubKey: Uint8Array; payload: Uint8Array }> {
  // 0. Validate recipient public key
  validatePublicKey(recipientPubKey);
  if (plaintext.length > MAX_PLAINTEXT_SIZE) {
    throw new Error(
      `Plaintext too large: maximum is ${MAX_PLAINTEXT_SIZE} bytes, got ${plaintext.length}`,
    );
  }

  // 1. Generate ephemeral X25519 key pair
  const ephemeralPriv = x25519.utils.randomSecretKey();
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv);

  // 2. ECDH shared secret
  const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientPubKey);

  // 3. HKDF key derivation
  const convIdBytes = _encoder.encode(conversationId);
  const aesKey = hkdf(sha256, sharedSecret, _ACE_DH_SALT, convIdBytes, 32);

  try {
    // 4. AES-256-GCM encryption via Web Crypto
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

    // 5. Payload = nonce[12] || ciphertext || tag[16]
    const payload = new Uint8Array(12 + encryptedBytes.length);
    payload.set(nonce, 0);
    payload.set(encryptedBytes, 12);
    if (payload.length > MAX_PAYLOAD_SIZE) {
      throw new Error(
        `Encrypted payload too large: maximum is ${MAX_PAYLOAD_SIZE} bytes, got ${payload.length}`,
      );
    }

    return { ephemeralPubKey: ephemeralPub, payload };
  } finally {
    // Zero all key material
    ephemeralPriv.fill(0);
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}

/**
 * Decrypt a message using own private key.
 */
export async function decrypt(
  ephemeralPubKey: Uint8Array,
  payload: Uint8Array,
  recipientPrivKey: Uint8Array,
  conversationId: string,
): Promise<Uint8Array> {
  // 0. Validate inputs
  if (recipientPrivKey.length !== 32) {
    throw new Error(`X25519 private key must be exactly 32 bytes, got ${recipientPrivKey.length}`);
  }
  validatePublicKey(ephemeralPubKey);
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

  // 1. ECDH shared secret
  const sharedSecret = x25519.getSharedSecret(recipientPrivKey, ephemeralPubKey);

  // 2. HKDF key derivation
  const convIdBytes = _encoder.encode(conversationId);
  const aesKey = hkdf(sha256, sharedSecret, _ACE_DH_SALT, convIdBytes, 32);

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
