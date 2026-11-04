/**
 * Profile manifests: the one schema-digest rule and the installed-profile set.
 *
 *   profile digest = SHA-256(canonical(manifest))
 *   message digest = SHA-256(canonical({type, schema}))
 *
 * The official manifests (`ace:core:1`, `ace:text:1`, `ace:commerce:1`, `ace:delegation:1`) are bundled; `ace:core:1`
 * is always installed and never listed in a descriptor. Third-party manifests may not use the reserved `ace:` prefix.
 * Installing a profile is local policy: it never grants authority.
 */
import { ACEError } from './errors.js';
import { canonicalStateBytes, closedKeys, codePointLength, isHex64, isObj, sha256Hex, stringifySorted } from './encoding.js';
import { MAX_MANIFEST_BYTES } from './limits.js';
import { COMMERCE_MANIFEST, CORE_MANIFEST, DELEGATION_MANIFEST, TEXT_MANIFEST } from './profiles.generated.js';
import { isMessageType, type JSONObject } from './types.js';

export interface ProfileManifest { id: string; messages: Array<{ type: string; schema: Record<string, unknown> }> }
/** A descriptor `profiles` entry: a profile ID and its profile digest. */
export interface NetworkProfile { id: string; digest: string }

export const CORE_PROFILE_ID = 'ace:core:1';
export const RECEIPT_TYPE = 'ace:receipt:1';
export const CONTACT_TYPE = 'ace:contact:1';
export const TEXT_TYPE = 'ace:text:1';

export const BUNDLED_MANIFESTS: Readonly<Record<'core' | 'text' | 'commerce' | 'delegation', ProfileManifest>> = Object.freeze({
  core: CORE_MANIFEST, text: TEXT_MANIFEST, commerce: COMMERCE_MANIFEST, delegation: DELEGATION_MANIFEST,
});

const fail = (message: string): never => { throw new ACEError('invalid_argument', message); };
const reserved = (s: string) => s.startsWith('ace:');
const KEYWORDS: Record<string, readonly string[]> = {
  object: ['properties', 'required', 'additionalProperties'], array: ['items', 'maxItems'], string: ['maxLength'],
  integer: ['minimum', 'maximum'], boolean: [], null: [],
};

function checkSchema(s: unknown, depth = 0): void {
  if (!isObj(s) || depth > 8 || typeof s.type !== 'string' || !Object.hasOwn(KEYWORDS, s.type)) fail('unsupported profile schema');
  const v = s as Record<string, unknown>;
  const allowed = new Set(['type', 'enum', ...KEYWORDS[v.type as string]]);
  if (Object.keys(v).some((k) => !allowed.has(k))) fail('schema keyword does not apply to its type');
  if (v.type === 'object') {
    const p = v.properties, r = v.required;
    if (!isObj(p) || Object.keys(p).length > 64 || !Array.isArray(r) || new Set(r).size !== r.length
      || !r.every((k) => typeof k === 'string' && Object.hasOwn(p, k)) || typeof v.additionalProperties !== 'boolean') fail('object schema needs properties, required and additionalProperties');
    Object.values(p as object).forEach((c) => checkSchema(c, depth + 1));
  }
  if (v.type === 'array') checkSchema(v.items, depth + 1);
  for (const k of ['maxItems', 'maxLength', 'minimum', 'maximum']) {
    if (v[k] !== undefined && (!Number.isSafeInteger(v[k]) || ((k === 'maxItems' || k === 'maxLength') && (v[k] as number) < 0))) fail('invalid schema bound');
  }
  if (typeof v.minimum === 'number' && typeof v.maximum === 'number' && v.minimum > v.maximum) fail('inverted schema bounds');
  if (v.enum !== undefined && (!Array.isArray(v.enum) || v.enum.length < 1 || v.enum.length > 64 || v.enum.some((x) => !matches({ ...v, enum: undefined }, x)))) fail('invalid schema enum');
}

/** Whether `value` satisfies the schema subset (`maxLength` counts code points). */
export function matches(s: Record<string, unknown>, value: unknown): boolean {
  if (s.enum !== undefined) {
    const v = stringifySorted(value);   // canonical JSON equality
    if (!(s.enum as unknown[]).some((x) => stringifySorted(x) === v)) return false;
  }
  switch (s.type) {
    case 'object': {
      if (!isObj(value)) return false;
      const p = s.properties as Record<string, Record<string, unknown>>;
      return (s.required as string[]).every((k) => Object.hasOwn(value, k))
        && Object.entries(value).every(([k, v]) => (Object.hasOwn(p, k) ? matches(p[k], v) : s.additionalProperties === true));
    }
    case 'array': return Array.isArray(value) && (s.maxItems === undefined || value.length <= (s.maxItems as number)) && value.every((v) => matches(s.items as Record<string, unknown>, v));
    case 'string': return typeof value === 'string' && (s.maxLength === undefined || codePointLength(value) <= (s.maxLength as number));
    case 'integer': return Number.isSafeInteger(value) && (s.minimum === undefined || (value as number) >= (s.minimum as number)) && (s.maximum === undefined || (value as number) <= (s.maximum as number));
    case 'boolean': return typeof value === 'boolean';
    case 'null': return value === null;
    default: return false;
  }
}

/**
 * Validate a manifest (`invalid_argument`). A bundled official manifest is accepted as is; any other manifest is
 * third-party and may not use reserved `ace:` ids or message types.
 */
export function validateProfileManifest(value: unknown): ProfileManifest {
  if (!closedKeys(value, ['id', 'messages']) || !isMessageType(value.id)
    || !Array.isArray(value.messages) || value.messages.length < 1 || value.messages.length > 32) fail('invalid profile manifest');
  const m = value as unknown as ProfileManifest;
  if (canonicalStateBytes(m).length > MAX_MANIFEST_BYTES || new Set(m.messages.map((x) => x?.type)).size !== m.messages.length) fail('oversized manifest or duplicate message types');
  for (const x of m.messages) {
    if (!closedKeys(x, ['type', 'schema']) || !isMessageType(x.type)) fail('manifest messages must be {type, schema}');
    checkSchema(x.schema);
    if (x.schema.type !== 'object') fail('message schema must describe an object');
  }
  if (!BUNDLED_DIGESTS.has(profileDigest(m)) && (reserved(m.id) || m.messages.some((x) => reserved(x.type)))) fail('third-party profiles cannot use reserved ace: identifiers');
  return structuredClone(m);
}

export function profileDigest(m: ProfileManifest): string {
  return sha256Hex(canonicalStateBytes(m));
}

const BUNDLED_DIGESTS: ReadonlySet<string> = new Set(Object.values(BUNDLED_MANIFESTS).map(profileDigest));

export function messageDigest(type: string, schema: Record<string, unknown>): string {
  return sha256Hex(canonicalStateBytes({ type, schema }));
}

interface Installed { profile: string; type: string; digest: string; schema: Record<string, unknown> }

/**
 * The locally installed profiles. `ace:core:1` is always included. Lookup is by `(type, schemaDigest)`: a message
 * whose pair is not installed is `unsupported_schema`, never "custom data".
 */
export class ProfileSet {
  /** Installed manifests by id, with their profile digest. */
  readonly #manifests = new Map<string, { manifest: ProfileManifest; digest: string }>();
  readonly #byDigest = new Map<string, Installed>();
  readonly #byType = new Map<string, Installed>();

  /** `profiles`: bundled names (`'text'`, `'commerce'`, `'delegation'`) or manifests. */
  constructor(profiles: ReadonlyArray<'text' | 'commerce' | 'delegation' | ProfileManifest> = []) {
    for (const p of [BUNDLED_MANIFESTS.core, ...profiles]) {
      const m = validateProfileManifest(typeof p === 'string' ? BUNDLED_MANIFESTS[p] : p);
      const digest = profileDigest(m);
      const prior = this.#manifests.get(m.id);
      if (prior !== undefined) {
        if (prior.digest === digest) continue;
        fail(`conflicting manifests for ${m.id}`);
      }
      for (const x of m.messages) if (this.#byType.has(x.type)) fail(`message type ${x.type} is installed twice`);
      this.#manifests.set(m.id, { manifest: m, digest });
      for (const x of m.messages) {
        const entry = { profile: m.id, type: x.type, digest: messageDigest(x.type, x.schema), schema: x.schema };
        this.#byDigest.set(entry.digest, entry);
        this.#byType.set(x.type, entry);
      }
    }
  }

  /** Descriptor `profiles` (core excluded), in installation order. */
  descriptors(): NetworkProfile[] {
    return [...this.#manifests.values()].filter(({ manifest }) => manifest.id !== CORE_PROFILE_ID).map(({ manifest, digest }) => ({ id: manifest.id, digest }));
  }

  manifests(): ProfileManifest[] { return [...this.#manifests.values()].map(({ manifest }) => structuredClone(manifest)); }
  has(profileId: string): boolean { return this.#manifests.has(profileId); }
  /** True when `profile` is installed here with the same digest. */
  shares(profile: NetworkProfile): boolean {
    return this.#manifests.get(profile.id)?.digest === profile.digest;
  }
  /** The installed message digest of `type`, or undefined. */
  digestOf(type: string): string | undefined { return this.#byType.get(type)?.digest; }
  /** The profile that installed `type`, or undefined. */
  profileOf(type: string): string | undefined { return this.#byType.get(type)?.profile; }

  /**
   * Check a message: `(type, schemaDigest)` must be installed (`unsupported_schema`) and the body must satisfy the
   * schema (`invalid_body`).
   */
  validate(type: string, schemaDigest: string, body: JSONObject): void {
    const e = isHex64(schemaDigest) ? this.#byDigest.get(schemaDigest) : undefined;
    if (e === undefined || e.type !== type) throw new ACEError('unsupported_schema', `(${type.slice(0, 64)}, schemaDigest) is not installed`);
    if (!matches(e.schema, body)) throw new ACEError('invalid_body', `${type} body does not match the installed schema`);
  }
}
