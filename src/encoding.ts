/** Strict wire encodings, canonical JSON and hashing shared by every module. */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH } from './limits.js';

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/** The ACE ID grammar; `isACEId` is the check (exported so schemas can show the same pattern). */
export const ACE_ID_RE = /^ace:sha256:[0-9a-f]{64}$/;
const STREAM_ID_RE = /^[0-9]{1,20}-[0-9]{1,20}$/;
const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
/** CAIP-10 account id (`namespace:reference:address`); `isCaip10` is the check (exported so schemas can show the same pattern). */
export const CAIP10_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
export const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
/** A relay-scoped public handle (the only copy of this grammar). */
export const HANDLE_RE = /^[a-z][a-z0-9_-]{2,31}$/;
const B64_CHARS_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const B64_VALUE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const HTTPS_URL_RE = new RegExp(
  `^https://(${LABEL}(?:\\.${LABEL})*)(?::([0-9]{1,5}))?(?:[/?#][A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?$`,
);

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const encoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

/** The one SHA-256 helper: raw digest of bytes or UTF-8 text. */
export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  return sha256(typeof data === 'string' ? utf8(data) : data);
}

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256Bytes(data));
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** hex SHA-256(UTF-8(a) ‖ 0x00 ‖ UTF-8(b)): store keys. */
export function pairKey(a: string, b: string): string {
  return sha256Hex(concat([utf8(a), new Uint8Array([0]), utf8(b)]));
}

/**
 * The local conversation key of two identities (no longer on the wire):
 * hex(SHA-256(min(a, b) ‖ 0x00 ‖ max(a, b))) over the UTF-8 bytes of the two ACE IDs.
 */
export function conversationKey(a: string, b: string): string {
  return compareUtf8(a, b) <= 0 ? pairKey(a, b) : pairKey(b, a);
}

// --- predicates --------------------------------------------------------------

/** Relay stream ID `<ms>-<seq>`, each a u64 in decimal (02 § Identifiers). */
export function isStreamId(value: unknown): value is string {
  return typeof value === 'string' && STREAM_ID_RE.test(value);
}

/** `ace:sha256:<64 lowercase hex>`. */
export function isACEId(value: unknown): value is string {
  return typeof value === 'string' && ACE_ID_RE.test(value);
}

/** A CAIP-10 account identifier (`namespace:reference:address`). */
export function isCaip10(value: unknown): value is string {
  return typeof value === 'string' && CAIP10_RE.test(value);
}

export function isHandle(value: unknown): value is string {
  return typeof value === 'string' && HANDLE_RE.test(value);
}

/** How a handle is written (04 § Handles): `@name@host`, `host` being the host (with its port, if any) of `home`. */
export function handleAddress(handle: string, home: string): string {
  return `@${handle}@${new URL(home).host}`;
}

/** Lowercase UUIDv4. */
export function isMessageId(value: unknown): value is string {
  return typeof value === 'string' && MESSAGE_ID_RE.test(value);
}

/** 64 lowercase hex characters (SHA-256 digests, prekey IDs, conversation keys). */
export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64_RE.test(value);
}

/** Length in Unicode code points. */
export function codePointLength(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

/** 1..256 code points with no U+0000–U+001F or U+007F. */
export function isThreadId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_THREAD_ID_LENGTH * 2) return false;
  const n = codePointLength(value);
  return n >= 1 && n <= MAX_THREAD_ID_LENGTH && !CONTROL_CHAR_RE.test(value);
}

/** The ACE HTTPS URL grammar: regex plus length/host/port checks. Never a platform URL parser. */
export function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false;
  const m = HTTPS_URL_RE.exec(value);
  if (m === null || m[0] !== value || m[1].length > 253) return false;
  if (m[2] !== undefined) {
    const port = Number(m[2]);
    if (port < 1 || port > 65535) return false;
  }
  return true;
}

// --- integers ----------------------------------------------------------------

/** The wire-integer rule: an integral number in [0, 2^53-1]; booleans and non-finite rejected. */
export function wireInt(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_SAFE_INTEGER) return null;
  return value === 0 ? 0 : value; // normalizes -0
}

export function decimal(n: number): string {
  return String(n);
}

// --- base64 / hex --------------------------------------------------------------

/** Padded standard Base64. */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return btoa(binary);
}

/** Canonical padded standard Base64, or `ACEError(code)`; at most `maxBytes` decoded bytes. */
export function decodeB64(text: unknown, code: ACEErrorCode, what: string, maxBytes?: number): Uint8Array {
  if (typeof text !== 'string') throw new ACEError(code, `${what} must be a Base64 string`);
  if (maxBytes !== undefined && text.length > 4 * Math.floor((maxBytes + 2) / 3)) {
    throw new ACEError(code, `${what} is too large`);
  }
  if (text.length % 4 !== 0 || !B64_CHARS_RE.test(text)) {
    throw new ACEError(code, `${what} is not padded standard Base64`);
  }
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new ACEError(code, `${what} is not valid Base64`);
  }
  // Alphabet, length and padding are checked, so the text is canonical exactly when the bits the padding leaves
  // unused in the last symbol are zero.
  const pad = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  if (pad > 0 && (B64_VALUE.indexOf(text[text.length - pad - 1]) & (pad === 2 ? 0x0f : 0x03)) !== 0) {
    throw new ACEError(code, `${what} is not canonical Base64`);
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  // The text pre-check above admits up to 2 extra bytes; maxBytes bounds the decoded bytes.
  if (maxBytes !== undefined && out.length > maxBytes) throw new ACEError(code, `${what} is too large`);
  return out;
}

/** Decode canonical padded standard Base64; `invalid_argument` otherwise. */
export function fromBase64(text: string): Uint8Array {
  return decodeB64(text, 'invalid_argument', 'value');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Order strings by their UTF-8 bytes (06: "strings compare by their UTF-8 bytes"). */
export function compareUtf8(a: string, b: string): number {
  if (a === b) return 0;
  // Code-point order equals UTF-8 byte order; UTF-16 order differs only for astral vs U+E000..U+FFFF.
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx - cy;
  }
}

// --- JSON values -------------------------------------------------------------------

/** Internal: a non-null, non-array object (a parsed JSON object). */
export function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Internal: the injected clock or the wall clock, in whole Unix seconds. An injected clock must return a finite number in
 * [0, 2^53-1] (fractions are floored); anything else is `invalid_argument`.
 */
export function nowOf(clock?: () => number): number {
  if (!clock) return Math.floor(Date.now() / 1000);
  const t: unknown = clock();
  if (typeof t !== 'number' || !Number.isFinite(t) || t < 0 || t > MAX_SAFE_INTEGER) {
    throw new ACEError('invalid_argument', 'clock must return integer Unix seconds');
  }
  return Math.floor(t) + 0; // normalizes -0
}

/** A closed JSON object: every `required` key present, nothing outside `required` ∪ `optional`. */
export function closedKeys(v: unknown, required: readonly string[], optional: readonly string[] = []): v is Record<string, unknown> {
  if (!isObj(v)) return false;
  if (!required.every((k) => Object.hasOwn(v, k))) return false;
  return Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
}

/** Internal: an object whose prototype is `Object.prototype` or `null`. */
export function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Sender-side JSON-value rules: plain JSON types, finite numbers, depth <= `maxDepth` (32; the root is depth 0). */
export function checkJsonValue(value: unknown, code: ACEErrorCode = 'invalid_body', maxDepth: number = MAX_JSON_DEPTH): void {
  const stack: Array<[unknown, number]> = [[value, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!;
    if (v === null || typeof v === 'boolean') continue;
    if (typeof v === 'string') {
      if (LONE_SURROGATE.test(v)) throw new ACEError(code, 'unpaired surrogate');
      continue;
    }
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new ACEError(code, 'non-finite number');
      continue;
    }
    if (typeof v === 'object') {
      if (depth > maxDepth) throw new ACEError(code, `JSON nesting exceeds depth ${maxDepth}`);
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (!(i in v)) throw new ACEError(code, 'sparse arrays are not JSON');
          stack.push([v[i], depth + 1]);
        }
        continue;
      }
      if (!isPlainObject(v)) throw new ACEError(code, 'not a plain JSON object');
      if (Object.getOwnPropertySymbols(v).length > 0) throw new ACEError(code, 'symbol keys are not JSON');
      for (const k of Object.keys(v)) {
        if (LONE_SURROGATE.test(k)) throw new ACEError(code, 'unpaired surrogate');
        stack.push([(v as Record<string, unknown>)[k], depth + 1]);
      }
      continue;
    }
    throw new ACEError(code, `not a JSON value: ${typeof v}`);
  }
}

// --- canonical JSON --------------------------------------------------------------

/**
 * The one canonical JSON: object keys sorted by code point (= UTF-8 byte order), compact, UTF-8, non-ASCII and '/'
 * unescaped. Used for signatures, digests and persisted state alike.
 */
export function canonicalStateBytes(value: unknown): Uint8Array {
  return utf8(stringifySorted(value));
}

function jsonString(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new ACEError('invalid_argument', 'string contains an unpaired surrogate');
  return JSON.stringify(s); // escapes exactly " \\ \b \t \n \f \r and other < U+0020 as lowercase \u00xx
}

export function stringifySorted(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return jsonString(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new ACEError('invalid_argument', 'non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map((v) => stringifySorted(v === undefined ? null : v)).join(',') + ']';
  if (value instanceof Uint8Array) throw new ACEError('invalid_argument', 'bytes must be encoded before serializing');
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareUtf8);
    return '{' + keys.map((k) => jsonString(k) + ':' + stringifySorted(obj[k])).join(',') + '}';
  }
  throw new ACEError('invalid_argument', `cannot serialize ${typeof value}`);
}

const stateDecoder = new TextDecoder('utf-8', { fatal: true });

function parseUtf8JSON(raw: Uint8Array, code: ACEErrorCode, what: string): unknown {
  try {
    return JSON.parse(stateDecoder.decode(raw));
  } catch (cause) {
    throw new ACEError(code, `${what} is not UTF-8 JSON`, { cause });
  }
}

/** Parse received UTF-8 JSON bytes under 02 § JSON values (within `maxDepth`, by default MAX_JSON_DEPTH); any failure is `code`. */
export function parseJSONBytes(raw: Uint8Array, code: ACEErrorCode, what: string, maxDepth: number = MAX_JSON_DEPTH): unknown {
  const value = parseUtf8JSON(raw, code, what);
  checkJsonValue(value, code, maxDepth);
  return value;
}

/** Parse a persisted JSON document (written by this SDK, so not depth-limited); any failure is `storage_failed`. */
export function parseStateBytes(raw: Uint8Array, what: string): unknown {
  return parseUtf8JSON(raw, 'storage_failed', what);
}
