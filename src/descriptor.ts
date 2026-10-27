/**
 * Signed, self-declared documents: the agent descriptor and delivery permits. Each is `{...claims, signature}` signed
 * with action `<action>` over `M(signer, issuedAt, seq, canonicalStateBytes(claims))`. Neither grants execution or
 * payment rights.
 */
import { OFFICIAL_EXT } from './commerce.js';
import { ACEError } from './errors.js';
import {
  canonicalStateBytes, checkJsonValue, closedKeys, codePointLength, CONTROL_CHAR_RE, isACEId, isHex64, isHttpsUrl, isObj, nowOf, sha256Hex, wireInt,
} from './encoding.js';
import { checkLifetime, claimsOf, docWindow, signClaims, type ACEIdentity } from './identity.js';
import {
  atLogTail, checkSignatureShape, isUsable, lastEventHash, reconcileKel, verifyKel, verifyOperationalSignature, type KelEvent, type KelState, type OperationalSignature,
} from './kel.js';
import {
  DEFAULT_DESCRIPTOR_LIFETIME, MAX_DESCRIPTOR_LIFETIME, MAX_DESCRIPTOR_PROFILES, MAX_DESCRIPTOR_RELAYS, MAX_EXT_BYTES, MAX_PERMIT_LIFETIME,
  MAX_PUBLISHED_AGENT_BYTES, MAX_STRANGER_KEL_EVENTS, TIMESTAMP_WINDOW_SECONDS,
} from './limits.js';
import { CORE_PROFILE_ID, type NetworkProfile } from './manifest.js';
import { decodePrekey, type Prekey } from './prekey.js';
import { isCanonicalRelayUrl } from './relay-url.js';
import { isMessageType, type JSONObject } from './types.js';

// --- shared ------------------------------------------------------------------------------------

/** A stable digest of a document's claims (signature excluded): revision comparison only. */
export function documentDigest(doc: { signature?: unknown }): string {
  return sha256Hex(canonicalStateBytes(claimsOf(doc)));
}

// --- relays, card ------------------------------------------------------------------------------

export interface VerifyOptions {
  /** Development only: accept `http://` loopback relays (production verifiers reject them). */
  allowLoopbackRelays?: boolean;
  /**
   * The verifier's pin for this identity. The carried KEL is reconciled with it under the fork rules and the signature
   * must verify under the resulting newest state: a descriptor carrying an older prefix of the pinned log, signed by a
   * delegation the pin has superseded, is `stale_peer_binding`; a fork is `kel_conflict`.
   */
  pinned?: KelState | null;
}

/** A descriptor route: a canonical HTTPS relay URL; loopback HTTP only for local development. */
export function validateNetworkRelay(value: unknown, o: VerifyOptions = {}): string {
  if (!isCanonicalRelayUrl(value, { allowLoopback: o.allowLoopbackRelays === true })) {
    throw new ACEError('invalid_authorization', 'relay route must be a canonical HTTPS relay URL');
  }
  return value;
}

/**
 * Self-asserted discovery metadata (a card record's `card`). The tag `hosted` means a hosting provider holds the keys. No
 * name: a display name is application data; the handle is the human-readable identifier (04 § Card).
 */
export interface AgentCard { description?: string; image?: string; tags?: string[] }

/** A card tag (also the directory's `tag` filter). */
export const TAG_RE = /^[a-z0-9-]{1,32}$/;

/** Validate a card (`invalid_authorization`); returns a copy. */
export function validateCard(value: unknown): AgentCard {
  if (!closedKeys(value, [], ['description', 'image', 'tags'])) throw new ACEError('invalid_authorization', 'card permits only description, image and tags');
  const text = (v: unknown, name: string, lo: number, hi: number) => {
    if (v === undefined) return;
    if (typeof v !== 'string' || codePointLength(v) < lo || codePointLength(v) > hi || CONTROL_CHAR_RE.test(v)) {
      throw new ACEError('invalid_authorization', `card.${name} must be ${lo}-${hi} characters without control characters`);
    }
  };
  text(value.description, 'description', 0, 256);
  if (value.image !== undefined && !isHttpsUrl(value.image)) {
    throw new ACEError('invalid_authorization', 'card.image must be an ACE HTTPS URL');
  }
  if (value.tags !== undefined && (!Array.isArray(value.tags) || value.tags.length > 10 || new Set(value.tags).size !== value.tags.length
    || !value.tags.every((t) => typeof t === 'string' && TAG_RE.test(t)))) {
    throw new ACEError('invalid_authorization', 'card.tags must be at most 10 distinct tags matching ^[a-z0-9-]{1,32}$');
  }
  return structuredClone(value) as AgentCard;
}

// --- permits -----------------------------------------------------------------------------------

/** The receiver (`issuer`) lets `subject` deliver to it. Communication only. */
export interface DeliveryPermit { issuer: string; subject: string; issuedAt: number; expiresAt: number; signature: OperationalSignature }

export async function createPermit(issuer: ACEIdentity, subject: string, o: { now?: number; ttl?: number } = {}): Promise<DeliveryPermit> {
  if (!isACEId(subject) || subject === issuer.getACEId()) throw new ACEError('invalid_argument', 'permit subject must be another ACE ID');
  return signClaims(issuer, 'delivery-permit', { issuer: issuer.getACEId(), subject, ...docWindow(issuer.getKel(), o, MAX_PERMIT_LIFETIME) });
}

/**
 * Verify a permit issued by `issuer` (its verified KEL state) to `subject` (when given): `invalid_authorization`, or
 * `stale_peer_binding` when not signed by the issuer's current, live delegation (01 § Operational signatures).
 */
export function verifyPermit(value: unknown, issuer: KelState, subject?: string, now: number = nowOf()): DeliveryPermit {
  if (!closedKeys(value, ['issuer', 'subject', 'issuedAt', 'expiresAt', 'signature'])) throw new ACEError('invalid_authorization', 'invalid permit');
  if (value.issuer !== issuer.aceId || !isACEId(value.subject) || value.subject === value.issuer
    || (subject !== undefined && value.subject !== subject)) {
    throw new ACEError('invalid_authorization', 'invalid permit binding');
  }
  checkLifetime(value, now, MAX_PERMIT_LIFETIME, 'permit');
  verifyOperationalSignature(issuer, 'delivery-permit', value.issuedAt as number, canonicalStateBytes(claimsOf(value)), value.signature, now, 'invalid_authorization');
  return structuredClone(value) as unknown as DeliveryPermit;
}

// --- descriptor --------------------------------------------------------------------------------

export interface AgentDescriptor {
  aceId: string;
  issuedAt: number;
  expiresAt: number;
  relays: string[];
  prekey: Prekey;
  profiles: NetworkProfile[];
  /** Keyed by profile id (each key listed in `profiles`); values are defined by that profile. */
  ext?: Record<string, JSONObject>;
  signature: OperationalSignature;
}

/** The publication unit: `{kel, descriptor}`. */
export interface PublishedAgent { kel: KelEvent[]; descriptor: AgentDescriptor }

export interface VerifiedAgent {
  /** The complete signed document (never merged with unsigned metadata). */
  agent: PublishedAgent;
  /** The verified KEL state of `agent.descriptor.aceId`. */
  state: KelState;
}

export interface DescriptorOptions extends VerifyOptions {
  relays: string[];
  prekey: Prekey;
  profiles: NetworkProfile[];
  ext?: Record<string, JSONObject>;
  now?: number;
  /** Lifetime in seconds: 86400 by default, at most MAX_DESCRIPTOR_LIFETIME. */
  ttl?: number;
}

/**
 * Create and sign this identity's PublishedAgent (verified before it is returned). `issuedAt` is never before the log's
 * last event, so a clock behind it still signs a valid descriptor.
 */
export async function createDescriptor(identity: ACEIdentity, o: DescriptorOptions): Promise<PublishedAgent> {
  const { issuedAt, expiresAt } = docWindow(identity.getKel(), o, MAX_DESCRIPTOR_LIFETIME, DEFAULT_DESCRIPTOR_LIFETIME);
  const claims = {
    aceId: identity.getACEId(), issuedAt, expiresAt, relays: [...o.relays],
    prekey: { id: o.prekey.id, publicKey: o.prekey.publicKey }, profiles: o.profiles.map((p) => ({ id: p.id, digest: p.digest })),
    ...(o.ext !== undefined && Object.keys(o.ext).length > 0 ? { ext: structuredClone(o.ext) } : {}),
  };
  const agent: PublishedAgent = { kel: identity.getKel(), descriptor: await signClaims(identity, 'agent-descriptor', claims) as AgentDescriptor };
  verifyPublishedAgent(agent, issuedAt, o);
  return agent;
}

const D_REQUIRED = ['aceId', 'issuedAt', 'expiresAt', 'relays', 'prekey', 'profiles', 'signature'];
const D_OPTIONAL = ['ext'];

/**
 * Verify a PublishedAgent at `now`, in order: shape including `ext` and the signature's (its value of the scheme's length)
 * (`invalid_authorization`); KEL usable at `now` (`invalid_kel` / `invalid_signature`) naming `aceId`
 * (`invalid_authorization`); the signature as an operational signature of the KEL reconciled with `o.pinned`
 * (`stale_peer_binding` / `invalid_authorization`).
 */
export function verifyPublishedAgent(value: unknown, now: number = nowOf(), o: VerifyOptions = {}): VerifiedAgent {
  const bad = (m: string) => new ACEError('invalid_authorization', m);
  if (!closedKeys(value, ['kel', 'descriptor'])) throw bad('published agent must be {kel, descriptor}');
  checkJsonValue(value, 'invalid_authorization'); // bounds the depth before anything recurses
  if (canonicalStateBytes(value).length > MAX_PUBLISHED_AGENT_BYTES) throw bad(`published agent exceeds ${MAX_PUBLISHED_AGENT_BYTES} bytes`);
  const d = value.descriptor;
  if (!closedKeys(d, D_REQUIRED, D_OPTIONAL) || !isACEId(d.aceId)) throw bad('invalid descriptor shape');
  checkSignatureShape(d.signature, 'invalid_authorization');
  checkLifetime(d, now, MAX_DESCRIPTOR_LIFETIME, 'descriptor');
  if (!Array.isArray(d.relays) || d.relays.length < 1 || d.relays.length > MAX_DESCRIPTOR_RELAYS || new Set(d.relays).size !== d.relays.length) throw bad('relays must be 1-4 distinct URLs');
  d.relays.forEach((r) => validateNetworkRelay(r, o));
  decodePrekey(d.prekey);
  if (!Array.isArray(d.profiles) || d.profiles.length > MAX_DESCRIPTOR_PROFILES
    || !d.profiles.every((p) => closedKeys(p, ['id', 'digest']) && isMessageType(p.id) && p.id !== CORE_PROFILE_ID && isHex64(p.digest))
    || new Set(d.profiles.map((p) => (p as NetworkProfile).id)).size !== d.profiles.length) throw bad('profiles must be at most 32 distinct {id, digest}, core excluded');
  if (d.ext !== undefined) validateExt(d.ext, d.profiles as NetworkProfile[], d.aceId, now);
  let state = verifyKel(value.kel, now);
  if (!isUsable(state, now)) throw new ACEError('invalid_kel', 'identity has no live signing delegation');
  if (state.aceId !== d.aceId) throw bad('kel does not derive aceId');
  if (o.pinned) state = reconcileKel(o.pinned, state).state;
  verifyOperationalSignature(state, 'agent-descriptor', d.issuedAt as number, canonicalStateBytes(claimsOf(d)), d.signature, now, 'invalid_authorization');
  return { agent: structuredClone(value) as unknown as PublishedAgent, state };
}

/** A cached PublishedAgent's `kel` ends at `pinned`, the subject's current pin (it was not signed under a superseded state). */
export function isBoundTo(agent: PublishedAgent, pinned: KelState | null): pinned is KelState {
  return pinned !== null && pinned.aceId === agent.descriptor.aceId && lastEventHash(agent.kel) === pinned.lastHash;
}

/**
 * 04 § Caching: a verified, cached PublishedAgent is usable at `now` (to encrypt to, or to report) only while it is
 * unexpired, bound to the subject's current pin (`isBoundTo`) and that pin is usable (01 § Verifier rules 5: never
 * send to an unusable identity). Otherwise it is stale and must be refreshed.
 */
export function isCachedUsable(agent: PublishedAgent, now: number, pinned: KelState | null): boolean {
  return agent.descriptor.expiresAt > now && isBoundTo(agent, pinned) && isUsable(pinned, now);
}

/**
 * The bound on a stranger's contact `source` (05 § Receiver admission), checked before any signature: its `kel` holds
 * at most MAX_STRANGER_KEL_EVENTS events. `not_permitted` otherwise (the request is dropped).
 */
export function checkStrangerSource(value: unknown): void {
  const kel = isObj(value) ? value.kel : undefined;
  if (!Array.isArray(kel) || kel.length > MAX_STRANGER_KEL_EVENTS) throw new ACEError('not_permitted', 'stranger source exceeds the KEL bound');
}

// --- ext ---------------------------------------------------------------------------------------

/**
 * Descriptor `ext` of the descriptor of `aceId`, verified at `now`: keys are listed profiles, values objects, canonical
 * size at most MAX_EXT_BYTES; an official profile's value is checked by its validator (04 § Extensions).
 */
export function validateExt(ext: unknown, profiles: readonly NetworkProfile[], aceId: string, now: number): void {
  const bad = (m: string) => new ACEError('invalid_authorization', m);
  const ids = new Set(profiles.map((p) => p.id));
  if (!isObj(ext) || Object.keys(ext).length === 0) throw bad('ext must be a non-empty object');
  checkJsonValue(ext, 'invalid_authorization');
  if (canonicalStateBytes(ext).length > MAX_EXT_BYTES) throw bad(`ext exceeds ${MAX_EXT_BYTES} bytes`);
  for (const [k, v] of Object.entries(ext)) {
    if (!ids.has(k)) throw bad(`ext key ${k.slice(0, 64)} is not a listed profile`);
    if (!isObj(v)) throw bad('ext values must be objects');
    if (k.startsWith('ace:')) {
      const check = OFFICIAL_EXT[k];
      if (check === undefined) throw bad(`official profile ${k} defines no ext`);
      check(v, aceId, now);
    }
  }
}
