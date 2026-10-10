/** Namespaced extensions (02-discovery § Profile Fields) and the bundled commerce extension (04-messages § Commerce extension). */

import { canonicalStateBytes, checkJsonValue, codePointLength, CONTROL_CHAR_RE, isObj, utf8 } from './encoding.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { MAX_EXT_BYTES, MAX_EXT_DEPTH, MAX_EXT_KEYS, MAX_EXT_KEY_BYTES } from './limits.js';
import {
  NAMESPACED_ID_RE, type AgentProfile, type CommerceIntentExt, type CommerceProfileExt, type ExtMap, type Intent, type RegistrationFile,
} from './types.js';

/** The bundled commerce extension namespace. */
export const COMMERCE_EXT = 'urn:ace:commerce:1';

/** What carries the `ext`: a profile or registration file (`invalid_profile`) or an intent (`invalid_argument`). */
export type ExtCarrier = 'profile' | 'intent';

const CAIP2_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const AMOUNT_RE = /^[0-9]+(\.[0-9]+)?$/;
const decoder = new TextDecoder();

function codeFor(carrier: ExtCarrier): ACEErrorCode {
  return carrier === 'intent' ? 'invalid_argument' : 'invalid_profile';
}

/** Canonical JSON text of `ext` (06 Appendix A form, the registration / intent payload field), or `''` when absent or empty. */
export function extCanonical(ext: ExtMap | null | undefined): string {
  if (ext === null || ext === undefined || Object.keys(ext).length === 0) return '';
  return decoder.decode(canonicalStateBytes(ext));
}

/**
 * Validate an `ext` object (02 § Profile Fields): keys are namespaced identifiers of at most 256 bytes, values are JSON
 * objects, at most 8 keys, canonical JSON at most 4096 bytes, nesting depth at most 8; `urn:ace:commerce:1`, when
 * present, must satisfy 04 § Commerce extension for the carrier. Other namespaces are opaque. Returns the
 * re-canonicalised plain object, or `undefined` when `ext` is absent, `null` or empty.
 */
export function validateExt(value: unknown, carrier: ExtCarrier): ExtMap | undefined {
  const code = codeFor(carrier);
  if (value === null || value === undefined) return undefined;
  if (!isObj(value)) throw new ACEError(code, 'ext must be a JSON object');
  const keys = Object.keys(value);
  if (keys.length === 0) return undefined;
  if (keys.length > MAX_EXT_KEYS) throw new ACEError(code, `ext has more than ${MAX_EXT_KEYS} namespaces`);
  for (const k of keys) {
    if (utf8(k).length > MAX_EXT_KEY_BYTES || NAMESPACED_ID_RE.exec(k)?.[0] !== k) {
      throw new ACEError(code, `ext key ${JSON.stringify(k.slice(0, 64))} is not a namespaced identifier of at most ${MAX_EXT_KEY_BYTES} bytes`);
    }
    if (!isObj(value[k])) throw new ACEError(code, `ext[${JSON.stringify(k)}] must be a JSON object`);
  }
  checkJsonValue(value, code, MAX_EXT_DEPTH);
  const canonical = canonicalStateBytes(value);
  if (canonical.length > MAX_EXT_BYTES) throw new ACEError(code, `ext exceeds ${MAX_EXT_BYTES} bytes of canonical JSON`);
  const out = JSON.parse(decoder.decode(canonical)) as ExtMap;
  if (out[COMMERCE_EXT] !== undefined) validateCommerceExt(out[COMMERCE_EXT], carrier);
  return out;
}

const bad = (code: ACEErrorCode, member: string, rule: string) => new ACEError(code, `ext["${COMMERCE_EXT}"].${member} ${rule}`);

function strList(code: ACEErrorCode, v: unknown, member: string, max: number): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) throw bad(code, member, 'must be an array of strings');
  if (v.length > max) throw bad(code, member, `has more than ${max} items`);
  return [...(v as string[])];
}

function text(code: ACEErrorCode, v: unknown, member: string, lo: number, hi: number, noControl: boolean): string {
  if (typeof v !== 'string') throw bad(code, member, 'must be a string');
  const n = codePointLength(v);
  if (n < lo || n > hi || (noControl && CONTROL_CHAR_RE.test(v))) {
    throw bad(code, member, `must be ${lo}-${hi} characters${noControl ? ' without control characters' : ''}`);
  }
  return v;
}

function onlyMembers(code: ACEErrorCode, o: Record<string, unknown>, allowed: readonly string[], where: string): void {
  const extra = Object.keys(o).filter((k) => !allowed.includes(k));
  if (extra.length > 0) throw new ACEError(code, `ext["${COMMERCE_EXT}"]${where} has unknown members: ${extra.slice(0, 3).join(',')}`);
}

/**
 * Validate the `urn:ace:commerce:1` object of a profile / registration file (`chains`, `pricing`, `settlement`,
 * `accounts`; `invalid_profile`) or of an intent (`maxPrice` + `currency`, both or neither; `invalid_argument`).
 * Unknown members are invalid. Returns the typed object.
 */
export function validateCommerceExt(value: unknown, carrier: 'profile'): CommerceProfileExt;
export function validateCommerceExt(value: unknown, carrier: 'intent'): CommerceIntentExt;
export function validateCommerceExt(value: unknown, carrier: ExtCarrier): CommerceProfileExt | CommerceIntentExt;
export function validateCommerceExt(value: unknown, carrier: ExtCarrier): CommerceProfileExt | CommerceIntentExt {
  const code = codeFor(carrier);
  if (!isObj(value)) throw new ACEError(code, `ext["${COMMERCE_EXT}"] must be a JSON object`);
  if (carrier === 'intent') {
    onlyMembers(code, value, ['maxPrice', 'currency'], '');
    const out: CommerceIntentExt = {};
    if ((value.maxPrice === undefined) !== (value.currency === undefined)) {
      throw new ACEError(code, `ext["${COMMERCE_EXT}"] needs both maxPrice and currency or neither`);
    }
    if (value.maxPrice !== undefined) {
      out.maxPrice = text(code, value.maxPrice, 'maxPrice', 1, 64, false);
      out.currency = text(code, value.currency, 'currency', 1, 16, false);
    }
    return out;
  }
  onlyMembers(code, value, ['chains', 'pricing', 'settlement', 'accounts'], '');
  const out: CommerceProfileExt = {};
  if (value.chains !== undefined) {
    out.chains = strList(code, value.chains, 'chains', 10);
    if (!out.chains.every((c) => CAIP2_RE.test(c))) throw bad(code, 'chains', 'items must be CAIP-2 identifiers');
  }
  if (value.pricing !== undefined) {
    const p = value.pricing;
    if (!isObj(p)) throw bad(code, 'pricing', 'must be a JSON object');
    onlyMembers(code, p, ['currency', 'maxAmount'], '.pricing');
    out.pricing = { currency: text(code, p.currency, 'pricing.currency', 1, 16, true) };
    if (p.maxAmount !== undefined) {
      const m = text(code, p.maxAmount, 'pricing.maxAmount', 1, 32, false);
      if (!AMOUNT_RE.test(m)) throw bad(code, 'pricing.maxAmount', 'must match ^[0-9]+(\\.[0-9]+)?$');
      out.pricing.maxAmount = m;
    }
  }
  if (value.settlement !== undefined) out.settlement = strList(code, value.settlement, 'settlement', 10);
  if (value.accounts !== undefined) {
    const a = value.accounts;
    if (!Array.isArray(a)) throw bad(code, 'accounts', 'must be an array');
    if (a.length > 10) throw bad(code, 'accounts', 'has more than 10 items');
    out.accounts = a.map((entry, i) => {
      if (!isObj(entry)) throw bad(code, `accounts[${i}]`, 'must be a JSON object');
      onlyMembers(code, entry, ['network', 'address'], `.accounts[${i}]`);
      if (typeof entry.network !== 'string' || !CAIP2_RE.test(entry.network)) throw bad(code, `accounts[${i}].network`, 'must be a CAIP-2 identifier');
      if (typeof entry.address !== 'string') throw bad(code, `accounts[${i}].address`, 'must be a string');
      return { network: entry.network, address: entry.address };
    });
  }
  return out;
}

/** The typed `urn:ace:commerce:1` member of a validated profile or registration file, or `undefined`. */
export function commerceExt(carrier: Pick<AgentProfile, 'ext'> | Pick<RegistrationFile, 'ext'> | null | undefined): CommerceProfileExt | undefined {
  return carrier?.ext?.[COMMERCE_EXT] as CommerceProfileExt | undefined;
}

/** The typed `urn:ace:commerce:1` member of an intent returned by `RelayClient.listIntents`, or `undefined`. */
export function intentCommerceExt(intent: Pick<Intent, 'ext'> | null | undefined): CommerceIntentExt | undefined {
  return intent?.ext?.[COMMERCE_EXT] as CommerceIntentExt | undefined;
}
