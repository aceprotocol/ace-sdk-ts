/**
 * Signed, self-declared documents: the agent descriptor (with its optional Delegation and ERC-8004 bindings), delivery
 * permits and delegation credentials. Each is `{...claims, signature}` signed with action `<action>` over
 * `M(signer, issuedAt, seq, canonicalStateBytes(claims))`. None of them grants execution or payment rights.
 */
import { OFFICIAL_EXT } from './commerce.js';
import { ACEError } from './errors.js';
import {
  canonicalStateBytes, checkJsonValue, closedKeys, codePointLength, CONTROL_CHAR_RE, isACEId, isCaip10, isHex64,
  isHttpsUrl, isObj, nowOf, parseJSONBytes, sha256Hex, utf8, wireInt,
} from './encoding.js';
import { signClaims, type ACEIdentity } from './identity.js';
import {
  atLogTail, checkSignedAfterDelegation, checkSignatureShape, isUsable, lastEventHash, reconcileKel, verifyKel, verifyOperationalSignature, type KelEvent, type KelState, type OperationalSignature,
} from './kel.js';
import {
  DEFAULT_DESCRIPTOR_LIFETIME, MAX_DELEGATION_LIFETIME, MAX_DESCRIPTOR_DELEGATIONS, MAX_DESCRIPTOR_ERC8004, MAX_DESCRIPTOR_LIFETIME, MAX_DESCRIPTOR_PROFILES,
  MAX_DESCRIPTOR_RELAYS, MAX_EXT_BYTES, MAX_PERMIT_LIFETIME, MAX_PUBLISHED_AGENT_BYTES, MAX_STRANGER_DELEGATIONS, MAX_STRANGER_KEL_EVENTS,
  TIMESTAMP_WINDOW_SECONDS,
} from './limits.js';
import { CORE_PROFILE_ID, type NetworkProfile } from './manifest.js';
import { decodePrekey, type Prekey } from './prekey.js';
import { isCanonicalRelayUrl } from './relay-url.js';
import { isMessageType, type JSONObject } from './types.js';

// --- shared ------------------------------------------------------------------------------------

/** `doc` without its `signature`: the bytes a signature and a digest cover. */
export function claimsOf<T extends { signature?: unknown }>(doc: T): Omit<T, 'signature'> {
  const { signature: _s, ...claims } = doc;
  return claims;
}

/** Lifetime bounds of a signed document (`invalid_authorization`); an expired one passes only when `allowExpired`. */
function lifetime(d: Record<string, unknown>, now: number, max: number, what: string, allowExpired = false): void {
  const i = wireInt(d.issuedAt), e = wireInt(d.expiresAt);
  if (i === null || e === null || i > now + TIMESTAMP_WINDOW_SECONDS || i >= e || (!allowExpired && e <= now) || e - i > max) {
    throw new ACEError('invalid_authorization', `invalid ${what} lifetime`);
  }
}

/** `issuedAt` (`o.now` or the clock) and `expiresAt = issuedAt + ttl` (`o.ttl` or `fallback`, default `max`), ttl in 1..max. */
function docWindow(o: { now?: number; ttl?: number }, max: number, fallback = max): { issuedAt: number; expiresAt: number } {
  const issuedAt = o.now ?? nowOf();
  const ttl = o.ttl ?? fallback;
  if (wireInt(ttl) === null || ttl < 1 || ttl > max) throw new ACEError('invalid_argument', `ttl must be 1..${max}`);
  return { issuedAt, expiresAt: issuedAt + ttl };
}

/** The issuer a delegation entry names (unverified). */
function issuerOf(entry: unknown): unknown {
  return isObj(entry) && isObj(entry.credential) ? entry.credential.issuer : undefined;
}

/** A stable digest of a document's claims (signature excluded): revision comparison only. */
export function documentDigest(doc: { signature?: unknown }): string {
  return sha256Hex(canonicalStateBytes(claimsOf(doc)));
}

// --- relays, card, ERC-8004 -------------------------------------------------------------------

export interface VerifyOptions {
  /** Development only: accept `http://` loopback relays (production verifiers reject them). */
  allowLoopbackRelays?: boolean;
  /**
   * The verifier's pin for this identity. The carried KEL is reconciled with it under the fork rules and the signature
   * must verify under the resulting newest state: a descriptor carrying an older prefix of the pinned log, signed by a
   * delegation the pin has superseded, is `stale_peer_binding`; a fork is `kel_conflict`.
   */
  pinned?: KelState | null;
  /**
   * The verifier's pins for delegation issuers, by ACE ID. Each entry's issuer KEL is reconciled with its pin the same
   * way (01 § Pinning, 04 § Delegations): a fork, or an older prefix whose credential is signed by a superseded
   * delegation, is `invalid_authorization`.
   */
  delegationPins?: ReadonlyMap<string, KelState>;
}

/** A descriptor route: a canonical HTTPS relay URL; loopback HTTP only for local development. */
export function validateNetworkRelay(value: unknown, o: VerifyOptions = {}): string {
  if (!isCanonicalRelayUrl(value, { allowLoopback: o.allowLoopbackRelays === true })) {
    throw new ACEError('invalid_authorization', 'relay route must be a canonical HTTPS relay URL');
  }
  return value;
}

/** Self-asserted presentation metadata (a card record's `card`). The tag `hosted` means a hosting provider holds the keys. */
export interface AgentCard { name?: string; description?: string; image?: string; tags?: string[] }

const TAG_RE = /^[a-z0-9-]{1,32}$/;

/** Validate a card (`invalid_authorization`); returns a copy. */
export function validateCard(value: unknown): AgentCard {
  if (!closedKeys(value, [], ['name', 'description', 'image', 'tags'])) throw new ACEError('invalid_authorization', 'card permits only name, description, image and tags');
  const text = (v: unknown, name: string, lo: number, hi: number) => {
    if (v === undefined) return;
    if (typeof v !== 'string' || codePointLength(v) < lo || codePointLength(v) > hi || CONTROL_CHAR_RE.test(v)) {
      throw new ACEError('invalid_authorization', `card.${name} must be ${lo}-${hi} characters without control characters`);
    }
  };
  text(value.name, 'name', 1, 64);
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

/**
 * `{agentRegistry: <CAIP-10 registry address>, agentId}`: for an `eip155` registry a decimal of at most 78 digits; for
 * any other CAIP-2 namespace 1-128 characters of `[A-Za-z0-9]` (a chain-native identifier, e.g. a Solana address).
 */
export interface Erc8004Binding { agentRegistry: string; agentId: string }

export function validateErc8004Binding(value: unknown): Erc8004Binding {
  if (!closedKeys(value, ['agentRegistry', 'agentId']) || !isCaip10(value.agentRegistry) || typeof value.agentId !== 'string') {
    throw new ACEError('invalid_authorization', 'erc8004 entries must be {agentRegistry: CAIP-10, agentId}');
  }
  const eip155 = value.agentRegistry.split(':', 1)[0] === 'eip155';
  if (!(eip155 ? /^(0|[1-9][0-9]{0,77})$/ : /^[A-Za-z0-9]{1,128}$/).test(value.agentId)) {
    throw new ACEError('invalid_authorization', 'erc8004 agentId must be decimal (eip155) or 1-128 [A-Za-z0-9]');
  }
  return { agentRegistry: value.agentRegistry, agentId: value.agentId };
}

/**
 * The reverse direction of an ERC-8004 binding: true iff the agent's registration file (its tokenURI document; an
 * object or JSON text) is a JSON object whose `services` array lists `{"name": "ACE", "endpoint": <aceId>}`.
 * Reading the chain and the tokenURI is the host's job.
 */
export function verifyErc8004Registration(registrationJson: unknown, aceId: string): boolean {
  let doc = registrationJson;
  if (typeof doc === 'string') {
    try { doc = parseJSONBytes(utf8(doc), 'invalid_argument', 'registration'); } catch { return false; }
  }
  if (!isObj(doc) || !isACEId(aceId)) return false;
  return Array.isArray(doc.services) && doc.services.some((s) => isObj(s) && s.name === 'ACE' && s.endpoint === aceId);
}

// --- delegation credentials ---------------------------------------------------------------------

/** `issuer` declares that `subject` acts on its behalf. Grants no execution, payment or delivery right. */
export interface DelegationCredential { issuer: string; subject: string; issuedAt: number; expiresAt: number; signature: OperationalSignature }
/** A descriptor `delegations` entry: the credential plus the issuer's full KEL. */
export interface DescriptorDelegation { kel: KelEvent[]; credential: DelegationCredential }

export async function createDelegationCredential(issuer: ACEIdentity, subject: string, o: { now?: number; ttl?: number } = {}): Promise<DelegationCredential> {
  if (!isACEId(subject) || subject === issuer.getACEId()) throw new ACEError('invalid_argument', 'subject must be another ACE ID');
  return signClaims(issuer, 'delegation', { issuer: issuer.getACEId(), subject, ...docWindow(o, MAX_DELEGATION_LIFETIME) });
}

/**
 * Verify a descriptor delegation entry for `subject`, in order: shape and lifetime bounds (`invalid_authorization`),
 * the issuer KEL, the credential signature as an operational signature of that state (its issuer usable at `now`),
 * then expiry. Returns null when the entry fails only because it has expired (it is dropped). `o.pinned`: the verifier's pin
 * for the issuer, when it holds one; the carried KEL is reconciled with it (01 § Pinning) and the credential must
 * verify under the newest state (a fork or a superseded delegation is `invalid_authorization`).
 */
export function verifyDelegation(entry: unknown, subject: string, now: number = nowOf(), o: { pinned?: KelState | null } = {}): { issuer: string; credential: DelegationCredential } | null {
  const bad = (m: string) => new ACEError('invalid_authorization', m);
  if (!closedKeys(entry, ['kel', 'credential'])) throw bad('delegation must be {kel, credential}');
  const c = entry.credential;
  if (!closedKeys(c, ['issuer', 'subject', 'issuedAt', 'expiresAt', 'signature'])
    || !isACEId(c.issuer) || !isACEId(c.subject) || c.issuer === c.subject || c.subject !== subject) throw bad('invalid delegation credential');
  lifetime(c, now, MAX_DELEGATION_LIFETIME, 'delegation', true);
  const i = c.issuedAt as number, e = c.expiresAt as number;
  try {
    let state = verifyKel(entry.kel, now);
    if (state.aceId !== c.issuer) throw bad('kel is not the issuer\'s');
    if (o.pinned && o.pinned.aceId === state.aceId) state = reconcileKel(o.pinned, state).state;
    verifyOperationalSignature(state, 'delegation', i, canonicalStateBytes(claimsOf(c)), c.signature, now, 'invalid_authorization');
  } catch (e) {
    // 04 § Verification: any failure of an entry other than expiry is invalid_authorization.
    if (e instanceof ACEError && e.code !== 'invalid_authorization') throw bad(`delegation: ${e.message}`);
    throw e;
  }
  if (e <= now) return null;
  return { issuer: c.issuer, credential: structuredClone(c) as unknown as DelegationCredential };
}

// --- permits -----------------------------------------------------------------------------------

/** The receiver (`issuer`) lets `subject` deliver to it. Communication only. */
export interface DeliveryPermit { issuer: string; subject: string; issuedAt: number; expiresAt: number; signature: OperationalSignature }

export async function createPermit(issuer: ACEIdentity, subject: string, o: { now?: number; ttl?: number } = {}): Promise<DeliveryPermit> {
  if (!isACEId(subject) || subject === issuer.getACEId()) throw new ACEError('invalid_argument', 'permit subject must be another ACE ID');
  return signClaims(issuer, 'delivery-permit', { issuer: issuer.getACEId(), subject, ...docWindow(o, MAX_PERMIT_LIFETIME) });
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
  lifetime(value, now, MAX_PERMIT_LIFETIME, 'permit');
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
  delegations?: DescriptorDelegation[];
  erc8004?: Erc8004Binding[];
  signature: OperationalSignature;
}

/** The publication unit: `{kel, descriptor}`. */
export interface PublishedAgent { kel: KelEvent[]; descriptor: AgentDescriptor }

export interface VerifiedAgent {
  /** The complete signed document (never merged with unsigned metadata). */
  agent: PublishedAgent;
  /** The verified KEL state of `agent.descriptor.aceId`. */
  state: KelState;
  /** The unexpired, verified delegations (expired entries are dropped from this view only). */
  delegations: Array<{ issuer: string; credential: DelegationCredential }>;
}

export interface DescriptorOptions extends VerifyOptions {
  relays: string[];
  prekey: Prekey;
  profiles: NetworkProfile[];
  ext?: Record<string, JSONObject>;
  delegations?: DescriptorDelegation[];
  erc8004?: Erc8004Binding[];
  now?: number;
  /** Lifetime in seconds: 86400 by default, at most MAX_DESCRIPTOR_LIFETIME. */
  ttl?: number;
}

/**
 * Create and sign this identity's PublishedAgent (verified before it is returned). `issuedAt` is never before the log's
 * last event, so a clock behind it still signs a valid descriptor.
 */
export async function createDescriptor(identity: ACEIdentity, o: DescriptorOptions): Promise<PublishedAgent> {
  const { issuedAt, expiresAt } = docWindow({ ...o, now: atLogTail(identity.getKel(), o.now ?? nowOf()) }, MAX_DESCRIPTOR_LIFETIME, DEFAULT_DESCRIPTOR_LIFETIME);
  const claims = {
    aceId: identity.getACEId(), issuedAt, expiresAt, relays: [...o.relays],
    prekey: { id: o.prekey.id, publicKey: o.prekey.publicKey }, profiles: o.profiles.map((p) => ({ id: p.id, digest: p.digest })),
    ...(o.ext !== undefined && Object.keys(o.ext).length > 0 ? { ext: structuredClone(o.ext) } : {}),
    ...(o.delegations !== undefined && o.delegations.length > 0 ? { delegations: structuredClone(o.delegations) } : {}),
    ...(o.erc8004 !== undefined && o.erc8004.length > 0 ? { erc8004: structuredClone(o.erc8004) } : {}),
  };
  const agent: PublishedAgent = { kel: identity.getKel(), descriptor: await signClaims(identity, 'agent-descriptor', claims) as AgentDescriptor };
  verifyPublishedAgent(agent, issuedAt, o);
  return agent;
}

const D_REQUIRED = ['aceId', 'issuedAt', 'expiresAt', 'relays', 'prekey', 'profiles', 'signature'];
const D_OPTIONAL = ['ext', 'delegations', 'erc8004'];

/**
 * A delegation entry's closed shape, part of the descriptor's (04 § Verification step 1): `{kel, credential: {issuer:
 * ACE ID, subject: string, issuedAt, expiresAt: wire integers, signature: operational signature shape}}`. `kel` is
 * step 2's (`invalid_kel`); the entry's rules (04 § Delegations) are step 4's.
 */
function isDelegationShape(e: unknown): boolean {
  if (!closedKeys(e, ['kel', 'credential'])) return false;
  const c = e.credential;
  if (!closedKeys(c, ['issuer', 'subject', 'issuedAt', 'expiresAt', 'signature']) || !isACEId(c.issuer) || typeof c.subject !== 'string'
    || wireInt(c.issuedAt) === null || wireInt(c.expiresAt) === null) return false;
  try { checkSignatureShape(c.signature, 'invalid_authorization'); } catch { return false; }
  return true;
}

/**
 * Verify a PublishedAgent at `now`, in order: shape including `ext`, `delegations` (`{kel, credential}` entries, the credential's shape and its signature's) and
 * `erc8004` and the signature's (its value of the scheme's length) (`invalid_authorization`); KEL usable at `now` (`invalid_kel` / `invalid_signature`) naming `aceId`
 * (`invalid_authorization`); the signature as an operational signature of the KEL reconciled with `o.pinned`, signed
 * no earlier than its delegation's `dlg` (`stale_peer_binding` / `invalid_authorization`); each delegation (an entry that only expired is dropped from
 * `delegations`).
 */
export function verifyPublishedAgent(value: unknown, now: number = nowOf(), o: VerifyOptions = {}): VerifiedAgent {
  const bad = (m: string) => new ACEError('invalid_authorization', m);
  if (!closedKeys(value, ['kel', 'descriptor'])) throw bad('published agent must be {kel, descriptor}');
  checkJsonValue(value, 'invalid_authorization'); // bounds the depth before anything recurses
  if (canonicalStateBytes(value).length > MAX_PUBLISHED_AGENT_BYTES) throw bad(`published agent exceeds ${MAX_PUBLISHED_AGENT_BYTES} bytes`);
  const d = value.descriptor;
  if (!closedKeys(d, D_REQUIRED, D_OPTIONAL) || !isACEId(d.aceId)) throw bad('invalid descriptor shape');
  checkSignatureShape(d.signature, 'invalid_authorization');
  lifetime(d, now, MAX_DESCRIPTOR_LIFETIME, 'descriptor');
  if (!Array.isArray(d.relays) || d.relays.length < 1 || d.relays.length > MAX_DESCRIPTOR_RELAYS || new Set(d.relays).size !== d.relays.length) throw bad('relays must be 1-4 distinct URLs');
  d.relays.forEach((r) => validateNetworkRelay(r, o));
  decodePrekey(d.prekey);
  if (!Array.isArray(d.profiles) || d.profiles.length > MAX_DESCRIPTOR_PROFILES
    || !d.profiles.every((p) => closedKeys(p, ['id', 'digest']) && isMessageType(p.id) && p.id !== CORE_PROFILE_ID && isHex64(p.digest))
    || new Set(d.profiles.map((p) => (p as NetworkProfile).id)).size !== d.profiles.length) throw bad('profiles must be at most 32 distinct {id, digest}, core excluded');
  if (d.ext !== undefined) validateExt(d.ext, d.profiles as NetworkProfile[]);
  if (d.erc8004 !== undefined) {
    if (!Array.isArray(d.erc8004) || d.erc8004.length < 1 || d.erc8004.length > MAX_DESCRIPTOR_ERC8004) throw bad('erc8004 must hold 1-4 entries');
    const seen = new Set(d.erc8004.map((b) => { const v = validateErc8004Binding(b); return `${v.agentRegistry}#${v.agentId}`; }));
    if (seen.size !== d.erc8004.length) throw bad('erc8004 entries must be distinct');
  }
  if (d.delegations !== undefined) {
    if (!Array.isArray(d.delegations) || d.delegations.length < 1 || d.delegations.length > MAX_DESCRIPTOR_DELEGATIONS) throw bad('delegations must hold 1-4 entries');
    if (!d.delegations.every(isDelegationShape)) throw bad('delegations must be {kel, credential} with a well-formed credential');
    const issuers = d.delegations.map(issuerOf);
    if (new Set(issuers).size !== issuers.length) throw bad('delegation issuers must be distinct');
  }
  let state = verifyKel(value.kel, now);
  if (!isUsable(state, now)) throw new ACEError('invalid_kel', 'identity has no live signing delegation');
  if (state.aceId !== d.aceId) throw bad('kel does not derive aceId');
  if (o.pinned) state = reconcileKel(o.pinned, state).state;
  checkSignedAfterDelegation(state, d.issuedAt as number);
  verifyOperationalSignature(state, 'agent-descriptor', d.issuedAt as number, canonicalStateBytes(claimsOf(d)), d.signature, now, 'invalid_authorization');
  const delegations: VerifiedAgent['delegations'] = [];
  for (const entry of (d.delegations as unknown[] | undefined) ?? []) {
    const who = issuerOf(entry);
    const pin = typeof who === 'string' ? o.delegationPins?.get(who) : undefined;
    const v = verifyDelegation(entry, d.aceId, now, { pinned: pin ?? null });
    if (v !== null) delegations.push(v);
  }
  return { agent: structuredClone(value) as unknown as PublishedAgent, state, delegations };
}

/** A cached PublishedAgent's `kel` ends at `pinned`, the subject's current pin (it was not signed under a superseded state). */
export function isBoundTo(agent: PublishedAgent, pinned: KelState | null): pinned is KelState {
  return pinned !== null && pinned.aceId === agent.descriptor.aceId && lastEventHash(agent.kel) === pinned.lastHash;
}

/**
 * Bound to the verifier's current pins: the subject's (`isBoundTo`), and every delegation entry whose issuer is pinned
 * still verifies under that pin, as of the descriptor's `issuedAt` (expiry aside). A bound descriptor's relays are the
 * subject's current choice; an unbound one's may be a superseded key's.
 */
export function isBoundToPins(agent: PublishedAgent, pins: { pinned: KelState | null; delegationPins: ReadonlyMap<string, KelState> }): boolean {
  if (!isBoundTo(agent, pins.pinned)) return false;
  const d = agent.descriptor;
  try {
    for (const e of d.delegations ?? []) {
      const pin = pins.delegationPins.get(e.credential.issuer);
      if (pin) verifyDelegation(e, d.aceId, d.issuedAt, { pinned: pin });
    }
  } catch {
    return false;
  }
  return true;
}

/**
 * 04 § Caching: a verified, cached PublishedAgent is usable at `now` (to encrypt to, or to report) only while it is
 * unexpired, bound to the subject's current pin (`isBoundTo`), that pin is usable (01 § Verifier rules 5: never send
 * to an unusable identity), and every delegation entry is unexpired and, when its issuer is pinned, still verifies
 * under that pin. Otherwise it is stale and must be refreshed.
 */
export function isCachedUsable(agent: PublishedAgent, now: number, pins: { pinned: KelState | null; delegationPins: ReadonlyMap<string, KelState> }): boolean {
  const d = agent.descriptor;
  if (d.expiresAt <= now || !isBoundTo(agent, pins.pinned) || !isUsable(pins.pinned, now)) return false;
  try {
    for (const e of d.delegations ?? []) {
      // an entry that has expired since is dropped (§ Delegations): the signed entry cannot be filtered, so refresh it
      if (e.credential.expiresAt <= now) return false;
      const pin = pins.delegationPins.get(e.credential.issuer);
      if (pin && verifyDelegation(e, d.aceId, now, { pinned: pin }) === null) return false;
    }
  } catch {
    return false;
  }
  return true;
}

/** The delegation issuers a PublishedAgent names (unverified; for looking up the verifier's pins). */
export function delegationIssuers(value: unknown): string[] {
  const d = isObj(value) ? value.descriptor : undefined;
  const entries = isObj(d) && Array.isArray(d.delegations) ? d.delegations : [];
  const out: string[] = [];
  for (const e of entries) {
    const who = issuerOf(e);
    if (isACEId(who) && !out.includes(who)) out.push(who);
  }
  return out;
}

/**
 * The bounds on a stranger's contact `source` (05 § Receiver admission), checked before any signature: its KEL and
 * each delegation entry's KEL hold at most MAX_STRANGER_KEL_EVENTS events, and it carries at most
 * MAX_STRANGER_DELEGATIONS delegation entries. `not_permitted` otherwise (the request is dropped).
 */
export function checkStrangerSource(value: unknown): void {
  const short = (kel: unknown) => Array.isArray(kel) && kel.length <= MAX_STRANGER_KEL_EVENTS;
  const d = isObj(value) ? value.descriptor : undefined;
  if (!isObj(value) || !isObj(d) || !short(value.kel)) throw new ACEError('not_permitted', 'stranger source exceeds the KEL bound');
  const dl = d.delegations ?? [];
  if (!Array.isArray(dl) || dl.length > MAX_STRANGER_DELEGATIONS) throw new ACEError('not_permitted', 'stranger source carries too many delegations');
  if (!dl.every((e) => isObj(e) && short(e.kel))) throw new ACEError('not_permitted', 'stranger delegation exceeds the KEL bound');
}

// --- ext ---------------------------------------------------------------------------------------

/** Descriptor `ext`: keys are listed profiles, values objects, canonical size at most 4096; official schemas enforced. */
export function validateExt(ext: unknown, profiles: readonly NetworkProfile[]): void {
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
      check(v);
    }
  }
}
