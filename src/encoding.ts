/** Strict wire encodings shared by every module (design §0). Internal except the re-exported predicates. */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH } from './limits.js';
import type { JSONObject } from './types.js';

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

const ACE_ID_RE = /^ace:sha256:[0-9a-f]{64}$/;
const STREAM_ID_RE = /^[0-9]{1,20}-[0-9]{1,20}$/;
const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONVERSATION_ID_RE = /^[0-9a-f]{64}$/;
export const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const B64_CHARS_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const HEX_SIG_RE = /^0x[0-9a-f]{130}$/;
const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const HTTPS_URL_RE = new RegExp(
  `^https://(${LABEL}(?:\\.${LABEL})*)(?::([0-9]{1,5}))?(?:[/?#][A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?$`,
);

const encoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256(typeof data === 'string' ? utf8(data) : data));
}

/** hex SHA-256(UTF-8(a) ‖ 0x00 ‖ UTF-8(b)) — the store key derivation of Appendix A. */
export function pairKey(a: string, b: string): string {
  const ab = utf8(a);
  const bb = utf8(b);
  const buf = new Uint8Array(ab.length + 1 + bb.length);
  buf.set(ab, 0);
  buf.set(bb, ab.length + 1);
  return bytesToHex(sha256(buf));
}

// --- predicates --------------------------------------------------------------

/** Relay stream ID `<ms>-<seq>`, each a u64 in decimal (08-relay). */
export function isStreamId(value: unknown): value is string {
  return typeof value === 'string' && STREAM_ID_RE.test(value);
}

/** `ace:sha256:<64 lowercase hex>`. */
export function isACEId(value: unknown): value is string {
  return typeof value === 'string' && ACE_ID_RE.test(value);
}

/** Lowercase UUIDv4. */
export function isMessageId(value: unknown): value is string {
  return typeof value === 'string' && MESSAGE_ID_RE.test(value);
}

/** 64 lowercase hex characters. */
export function isConversationId(value: unknown): value is string {
  return typeof value === 'string' && CONVERSATION_ID_RE.test(value);
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
  if (m === null || m[1].length > 253) return false;
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

export function isWireInt(value: unknown): value is number {
  return wireInt(value) !== null;
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
    binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)));
  }
  return btoa(binary);
}

/** Canonical padded standard Base64, or `ACEError(code)`. */
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
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (toBase64(out) !== text) throw new ACEError(code, `${what} is not canonical Base64`);
  return out;
}

/** Decode canonical padded standard Base64; `invalid_argument` otherwise. */
export function fromBase64(text: string): Uint8Array {
  return decodeB64(text, 'invalid_argument', 'value');
}

export function encodeHexSignature(sig: Uint8Array): string {
  return '0x' + bytesToHex(sig);
}

export function decodeHexSignature(text: unknown, code: ACEErrorCode): Uint8Array {
  if (typeof text !== 'string' || !HEX_SIG_RE.test(text)) {
    throw new ACEError(code, 'secp256k1 signature must match ^0x[0-9a-f]{130}$');
  }
  const out = new Uint8Array(65);
  for (let i = 0; i < 65; i++) out[i] = parseInt(text.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

export function encodeSignature(sig: Uint8Array, scheme: string): string {
  return scheme === 'ed25519' ? toBase64(sig) : encodeHexSignature(sig);
}

export function decodeSignature(text: unknown, scheme: unknown, code: ACEErrorCode): Uint8Array {
  if (scheme === 'ed25519') {
    const raw = decodeB64(text, code, 'ed25519 signature', 64);
    if (raw.length !== 64) throw new ACEError(code, 'ed25519 signature must be 64 bytes');
    return raw;
  }
  if (scheme === 'secp256k1') return decodeHexSignature(text, code);
  throw new ACEError(code, 'unsupported signature scheme');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
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

function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Sender-side JSON-value rules: plain JSON types, finite numbers, depth <= 32. */
export function checkJsonValue(value: unknown, code: ACEErrorCode = 'invalid_body'): void {
  const stack: Array<[unknown, number]> = [[value, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!;
    if (v === null || typeof v === 'boolean' || typeof v === 'string') continue;
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new ACEError(code, 'non-finite number');
      continue;
    }
    if (typeof v === 'object') {
      if (depth > MAX_JSON_DEPTH) throw new ACEError(code, `JSON nesting exceeds depth ${MAX_JSON_DEPTH}`);
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (!(i in v)) throw new ACEError(code, 'sparse arrays are not JSON');
          stack.push([v[i], depth + 1]);
        }
        continue;
      }
      if (!isPlainObject(v)) throw new ACEError(code, 'not a plain JSON object');
      if (Object.getOwnPropertySymbols(v).length > 0) throw new ACEError(code, 'symbol keys are not JSON');
      for (const k of Object.keys(v)) stack.push([(v as Record<string, unknown>)[k], depth + 1]);
      continue;
    }
    throw new ACEError(code, `not a JSON value: ${typeof v}`);
  }
}

/** Compact UTF-8 JSON of a validated body. */
export function dumpsBody(body: JSONObject): Uint8Array {
  return utf8(JSON.stringify(body));
}

const bodyDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Decode a decrypted body: fatal UTF-8, no non-finite numbers, depth, object. `invalid_body`. */
export function loadsBody(raw: Uint8Array): JSONObject {
  let text: string;
  try {
    text = bodyDecoder.decode(raw);
  } catch {
    throw new ACEError('invalid_body', 'body is not valid UTF-8');
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch (e) {
    throw new ACEError('invalid_body', `body is not JSON: ${e instanceof Error ? e.message.slice(0, 100) : ''}`);
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new ACEError('invalid_body', 'body must be a JSON object');
  }
  checkJsonValue(body);
  return body as JSONObject;
}

// --- canonical JSON --------------------------------------------------------------

/** Minimal RFC 8785 serializer for objects of strings / safe integers / objects. */
export function canonicalJson(value: unknown): string {
  if (typeof value === 'string') return jcsString(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareUtf16);
    return '{' + keys.map((k) => jcsString(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
  }
  throw new TypeError('canonicalJson supports objects, strings and integers only');
}

/** RFC 8785 sorts keys by UTF-16 code units. */
function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

const JCS_ESCAPES: Record<string, string> = {
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t',
};

function jcsString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const esc = JCS_ESCAPES[ch];
    if (esc !== undefined) out += esc;
    else if (ch.charCodeAt(0) < 0x20) out += '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

/** Persisted-JSON writer: keys sorted ascending, compact, UTF-8, non-ASCII and '/' unescaped. */
export function canonicalStateBytes(value: unknown): Uint8Array {
  return utf8(stringifySorted(value));
}

export function stringifySorted(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map((v) => stringifySorted(v === undefined ? null : v)).join(',') + ']';
  if (value instanceof Uint8Array) throw new TypeError('bytes must be encoded before persisting');
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareUtf8);
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + stringifySorted(obj[k])).join(',') + '}';
  }
  throw new TypeError(`cannot persist ${typeof value}`);
}

const stateDecoder = new TextDecoder('utf-8', { fatal: true });

/** Parse a persisted JSON document; any failure is `storage_failed`. */
export function parseStateBytes(raw: Uint8Array, what: string): unknown {
  try {
    return JSON.parse(stateDecoder.decode(raw));
  } catch {
    throw new ACEError('storage_failed', `${what} is not valid JSON`);
  }
}
