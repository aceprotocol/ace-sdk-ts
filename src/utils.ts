/** Constant-time byte array comparison (prevents timing side-channels). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Sanitize external string for safe inclusion in error messages. */
export function sanitizeForError(s: string, maxLen: number = 32): string {
  return s.slice(0, maxLen).replace(/[^\x20-\x7E]/g, '?');
}

/** Length in Unicode code points (not UTF-16 code units). */
export function codePointLength(s: string): number {
  return [...s].length;
}

/** Pattern matching control characters (U+0000–U+001F and U+007F). */
export const CONTROL_CHAR_PATTERN = /[\x00-\x1f\x7f]/;

/** Portable Base64 encoding (no Buffer dependency). */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Padded standard Base64, the only form any ACE SDK emits or accepts. A flat
// character class (no repeated group) so V8 matches multi-MB payloads without
// exhausting its backtracking stack; the length check completes the grammar.
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Strict, portable Base64 decoding (no Buffer dependency).
 *
 * Requires padded standard Base64 (atob alone would also accept unpadded input
 * and embedded whitespace, which the Python and Swift SDKs reject). With
 * `maxLen`, input longer than the padded encoding of `maxLen` bytes is refused
 * before decoding (DoS guard).
 */
export function fromBase64(str: string, maxLen?: number, what: string = 'Base64 value'): Uint8Array {
  if (typeof str !== 'string') {
    throw new Error(`${what} must be a Base64 string`);
  }
  if (maxLen !== undefined) {
    const maxEncoded = Math.ceil(maxLen / 3) * 4;
    if (str.length > maxEncoded) {
      throw new Error(`${what} too large: ${str.length} Base64 chars exceeds max ${maxEncoded}`);
    }
  }
  if (str.length % 4 !== 0 || !BASE64_PATTERN.test(str)) {
    throw new Error('Invalid Base64 input');
  }
  const binary = atob(str);
  if (maxLen !== undefined && binary.length > maxLen) {
    throw new Error(`${what} too large: ${binary.length} bytes exceeds max ${maxLen}`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
