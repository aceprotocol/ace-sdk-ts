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

/** Pattern matching control characters (U+0000–U+001F and U+007F). */
export const CONTROL_CHAR_PATTERN = /[\x00-\x1f\x7f]/;
