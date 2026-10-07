/** Peers: relay peer records, registration files, well-known fetch, profiles, rollback barrier. */

import bs58 from 'bs58';
import { ACEError, type ACEErrorCode } from './errors.js';
import {
  bytesEqual, codePointLength, CONTROL_CHAR_RE, decodeB64, decodeSignature, isACEId, isHttpsUrl, isObj, wireInt,
} from './encoding.js';
import { KEM_PUBLIC_KEY_SIZE, MAX_REGISTRATION_FILE_BYTES, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import {
  buildSignData, computeACEId, encodePayload, isValidSigningPublicKey, signingAddress, verifySignature,
} from './signing.js';
import { loadHttps, loadLookup, pinnedRequest, type LookupFn } from './pinned-https.js';
import type {
  AgentProfile, Capability, ChainInfo, PeerRecord, ProfilePricing, RegistrationFile, SigningScheme,
} from './types.js';
import { isSigningScheme } from './types.js';

// --- VerifiedPeer ------------------------------------------------------------------------

const MINT = Symbol('VerifiedPeer.mint');

interface PeerFields {
  aceId: string;
  scheme: SigningScheme;
  signingPublicKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
  registeredAt: number;
  registrationSignature: string | null;
  source: 'relay' | 'registration';
  profile: AgentProfile | null;
}

let isPeerImpl: (x: unknown) => boolean;

/**
 * A peer whose keys were verified. Obtain only from `verifyPeerRecord`,
 * `verifyRegistrationFile`, `verifyRegistrationRequest`, `PeerStore` or `RelayClient`.
 * Instances are immutable; key getters return copies.
 */
export class VerifiedPeer {
  readonly #brand = true;
  readonly aceId: string;
  readonly scheme: SigningScheme;
  readonly #signingPublicKey: Uint8Array;
  readonly #encryptionPublicKey: Uint8Array;
  readonly registeredAt: number;
  /** The relay binding signature (`register` action); `null` for a registration-file source. */
  readonly registrationSignature: string | null;
  readonly source: 'relay' | 'registration';
  /**
   * Unverified relay metadata: self-asserted by the peer and NOT covered by the binding
   * signature, so a relay can alter it. Never base trust decisions on it.
   */
  readonly profile: AgentProfile | null;

  private constructor(token: symbol, f: PeerFields) {
    if (token !== MINT) throw new ACEError('invalid_argument', 'VerifiedPeer is created only by the verify functions');
    this.aceId = f.aceId;
    this.scheme = f.scheme;
    this.#signingPublicKey = Uint8Array.from(f.signingPublicKey);
    this.#encryptionPublicKey = Uint8Array.from(f.encryptionPublicKey);
    this.registeredAt = f.registeredAt;
    this.registrationSignature = f.registrationSignature;
    this.source = f.source;
    this.profile = f.profile === null ? null : deepFreeze(structuredClone(f.profile));
    Object.freeze(this);
  }

  static {
    isPeerImpl = (x: unknown) => typeof x === 'object' && x !== null && #brand in x;
  }

  get signingPublicKey(): Uint8Array {
    return this.#signingPublicKey.slice();
  }

  get encryptionPublicKey(): Uint8Array {
    return this.#encryptionPublicKey.slice();
  }

  /** ed25519: Base58 of the signing key; secp256k1: EIP-55 address. */
  get address(): string {
    return signingAddress(this.scheme, this.#signingPublicKey);
  }

  toJSON(): Record<string, unknown> {
    return {
      aceId: this.aceId, scheme: this.scheme, registeredAt: this.registeredAt, source: this.source,
      registrationSignature: this.registrationSignature, profile: this.profile,
    };
  }
}

function deepFreeze<T>(v: T): T {
  if (typeof v === 'object' && v !== null) {
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k]);
    Object.freeze(v);
  }
  return v;
}

/** Internal: construct a VerifiedPeer from already-verified fields. */
export function mintPeer(f: PeerFields): VerifiedPeer {
  return new (VerifiedPeer as unknown as new (t: symbol, f: PeerFields) => VerifiedPeer)(MINT, f);
}

/** Internal: true for genuine VerifiedPeer instances (not structural look-alikes). */
export function isVerifiedPeer(x: unknown): x is VerifiedPeer {
  return isPeerImpl(x);
}

// --- strict readers ---------------------------------------------------------------------

type Kind = 'string' | 'object' | 'array';

function opt(d: Record<string, unknown>, key: string, kind: Kind, code: ACEErrorCode, what: string): any {
  const v = d[key];
  if (v === null || v === undefined) return undefined;
  const ok = kind === 'string' ? typeof v === 'string' : kind === 'array' ? Array.isArray(v) : isObj(v);
  if (!ok) throw new ACEError(code, `${what}.${key} must be a${kind === 'array' ? 'n array' : ` ${kind}`}`);
  return v;
}

function req(d: Record<string, unknown>, key: string, kind: Kind, code: ACEErrorCode, what: string): any {
  const v = opt(d, key, kind, code, what);
  if (v === undefined) throw new ACEError(code, `${what}.${key} is required`);
  return v;
}

function optStrList(d: Record<string, unknown>, key: string, code: ACEErrorCode, what: string): string[] | undefined {
  const v = opt(d, key, 'array', code, what) as unknown[] | undefined;
  if (v !== undefined && !v.every((x) => typeof x === 'string')) throw new ACEError(code, `${what}.${key} must be an array of strings`);
  return v === undefined ? undefined : [...(v as string[])];
}

// --- profile ----------------------------------------------------------------------------

const TAG_RE = /^[a-z0-9][a-z0-9-]*$/;
const CAIP2_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const AMOUNT_RE = /^[0-9]+(\.[0-9]+)?$/;

/** Parse the profile wire shape; unknown top-level fields are dropped; pricing is strict. */
function parseProfile(d: unknown): AgentProfile {
  const code: ACEErrorCode = 'invalid_profile';
  if (!isObj(d)) throw new ACEError(code, 'profile must be a JSON object');
  const out: AgentProfile = {};
  for (const k of ['name', 'description', 'image', 'endpoint'] as const) {
    const v = opt(d, k, 'string', code, 'profile');
    if (v !== undefined) out[k] = v;
  }
  for (const k of ['tags', 'capabilities', 'chains'] as const) {
    const v = optStrList(d, k, code, 'profile');
    if (v !== undefined) out[k] = v;
  }
  const p = opt(d, 'pricing', 'object', code, 'profile') as Record<string, unknown> | undefined;
  if (p !== undefined) {
    const extra = Object.keys(p).filter((k) => k !== 'currency' && k !== 'maxAmount');
    if (extra.length > 0) throw new ACEError(code, `profile.pricing has unknown fields: ${extra.slice(0, 3).join(',')}`);
    const pricing: ProfilePricing = { currency: req(p, 'currency', 'string', code, 'profile.pricing') };
    const max = opt(p, 'maxAmount', 'string', code, 'profile.pricing');
    if (max !== undefined) pricing.maxAmount = max;
    out.pricing = pricing;
  }
  return out;
}

function tagList(items: string[], name: string, max: number): void {
  if (items.length > max) throw new ACEError('invalid_profile', `profile.${name} has more than ${max} items`);
  for (const item of items) {
    if (item.length > 32 || !TAG_RE.test(item)) throw new ACEError('invalid_profile', `profile.${name} items must be 1-32 of [a-z0-9-]`);
  }
}

/** Validate a discovery profile (`invalid_profile`); returns the normalized profile. */
export function validateProfile(profile: AgentProfile): AgentProfile {
  const p = parseProfile(profile);
  const text = (v: string | undefined, name: string, lo: number, hi: number) => {
    if (v === undefined) return;
    const n = codePointLength(v);
    if (n < lo || n > hi || CONTROL_CHAR_RE.test(v)) {
      throw new ACEError('invalid_profile', `profile.${name} must be ${lo}-${hi} characters without control characters`);
    }
  };
  text(p.name, 'name', 1, 64);
  text(p.description, 'description', 0, 256);
  if (p.image !== undefined && (codePointLength(p.image) > 512 || !isHttpsUrl(p.image))) {
    throw new ACEError('invalid_profile', 'profile.image must be an HTTPS URL of at most 512 characters');
  }
  if (p.tags !== undefined) tagList(p.tags, 'tags', 10);
  if (p.capabilities !== undefined) tagList(p.capabilities, 'capabilities', 20);
  if (p.chains !== undefined && (p.chains.length > 10 || !p.chains.every((c) => CAIP2_RE.test(c)))) {
    throw new ACEError('invalid_profile', 'profile.chains must be at most 10 CAIP-2 identifiers');
  }
  if (p.endpoint !== undefined && !isHttpsUrl(p.endpoint)) throw new ACEError('invalid_profile', 'profile.endpoint must be an HTTPS URL');
  if (p.pricing !== undefined) {
    text(p.pricing.currency, 'pricing.currency', 1, 16);
    const m = p.pricing.maxAmount;
    if (m !== undefined && (m.length > 32 || !AMOUNT_RE.test(m))) {
      throw new ACEError('invalid_profile', 'profile.pricing.maxAmount must match ^[0-9]+(\\.[0-9]+)?$ (1-32 chars)');
    }
  }
  return p;
}

// --- keys / binding ----------------------------------------------------------------------

export function decodeSigningKey(scheme: unknown, text: unknown, code: ACEErrorCode): Uint8Array {
  const raw = decodeB64(text, code, 'signingPublicKey', 64);
  if (!isSigningScheme(scheme) || !isValidSigningPublicKey(scheme, raw)) {
    throw new ACEError(code, 'signingPublicKey is not a valid key for the scheme');
  }
  return raw;
}

export function decodeEncryptionKey(text: unknown, code: ACEErrorCode): Uint8Array {
  const raw = decodeB64(text, code, 'encryptionPublicKey', KEM_PUBLIC_KEY_SIZE + 3);
  if (raw.length !== KEM_PUBLIC_KEY_SIZE) throw new ACEError(code, `encryptionPublicKey must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  return raw;
}

export function bindingSignData(aceId: string, timestamp: number, encB64: string, sigB64: string): Uint8Array {
  return buildSignData('register', aceId, timestamp, encodePayload(encB64, sigB64));
}

/** Verify a relay `PeerRecord`; every failure is `invalid_peer`. */
export function verifyPeerRecord(record: unknown): VerifiedPeer {
  const code: ACEErrorCode = 'invalid_peer';
  if (!isObj(record)) throw new ACEError(code, 'peer record must be an object');
  const { aceId, scheme, encryptionPublicKey: encB64, signingPublicKey: sigB64 } = record;
  if (!isACEId(aceId)) throw new ACEError(code, 'aceId is not an ACE ID');
  if (!isSigningScheme(scheme)) throw new ACEError(code, 'unsupported scheme');
  const signingKey = decodeSigningKey(scheme, sigB64, code);
  if (computeACEId(signingKey) !== aceId) throw new ACEError(code, 'aceId does not match the signing key');
  const encKey = decodeEncryptionKey(encB64, code);
  const registeredAt = wireInt(record.registeredAt);
  if (registeredAt === null) throw new ACEError(code, 'registeredAt must be an integer');
  const signature = record.registrationSignature;
  const sig = decodeSignature(signature, scheme, code);
  if (!verifySignature(bindingSignData(aceId, registeredAt, encB64 as string, sigB64 as string), sig, scheme, signingKey)) {
    throw new ACEError(code, 'registrationSignature does not verify');
  }
  let profile: AgentProfile | null = null;
  if (record.profile !== null && record.profile !== undefined) {
    try {
      profile = validateProfile(record.profile as AgentProfile);
    } catch (e) {
      throw new ACEError(code, e instanceof ACEError ? e.message : 'invalid profile');
    }
  }
  return mintPeer({
    aceId, scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey, registeredAt,
    registrationSignature: signature as string, source: 'relay', profile,
  });
}

// --- registration files ---------------------------------------------------------------------

/** Parse the registration-file wire shape (`invalid_registration`). Unknown fields dropped; null optional = absent. */
export function parseRegistrationFile(d: unknown): RegistrationFile {
  const code: ACEErrorCode = 'invalid_registration';
  if (!isObj(d)) throw new ACEError(code, 'registration file must be a JSON object');
  const signing = req(d, 'signing', 'object', code, 'registration') as Record<string, unknown>;
  const tier = d.tier;
  if (tier !== 0 && tier !== 1) throw new ACEError(code, 'registration.tier must be 0 or 1');
  const reg: RegistrationFile = {
    ace: req(d, 'ace', 'string', code, 'registration'),
    id: req(d, 'id', 'string', code, 'registration'),
    name: req(d, 'name', 'string', code, 'registration'),
    endpoint: req(d, 'endpoint', 'string', code, 'registration'),
    tier,
    signing: {
      scheme: req(signing, 'scheme', 'string', code, 'signing'),
      address: req(signing, 'address', 'string', code, 'signing'),
      encryptionPublicKey: req(signing, 'encryptionPublicKey', 'string', code, 'signing'),
    },
  };
  const spk = opt(signing, 'signingPublicKey', 'string', code, 'signing');
  if (spk !== undefined) reg.signing.signingPublicKey = spk;
  const hb = opt(d, 'hardwareBacking', 'string', code, 'registration');
  if (hb !== undefined) reg.hardwareBacking = hb;
  const desc = opt(d, 'description', 'string', code, 'registration');
  if (desc !== undefined) reg.description = desc;
  const caps = opt(d, 'capabilities', 'array', code, 'registration') as unknown[] | undefined;
  if (caps !== undefined) {
    reg.capabilities = caps.map((c): Capability => {
      if (!isObj(c)) throw new ACEError(code, 'registration.capabilities entries must be objects');
      const cap: Capability = {
        id: req(c, 'id', 'string', code, 'capability'),
        description: req(c, 'description', 'string', code, 'capability'),
      };
      const input = opt(c, 'input', 'string', code, 'capability');
      if (input !== undefined) cap.input = input;
      const output = opt(c, 'output', 'string', code, 'capability');
      if (output !== undefined) cap.output = output;
      const p = opt(c, 'pricing', 'object', code, 'capability') as Record<string, unknown> | undefined;
      if (p !== undefined) {
        cap.pricing = {
          model: req(p, 'model', 'string', code, 'capability.pricing'),
          amount: req(p, 'amount', 'string', code, 'capability.pricing'),
          currency: req(p, 'currency', 'string', code, 'capability.pricing'),
        };
      }
      return cap;
    });
  }
  const settlement = optStrList(d, 'settlement', code, 'registration');
  if (settlement !== undefined) reg.settlement = settlement;
  const chains = opt(d, 'chains', 'array', code, 'registration') as unknown[] | undefined;
  if (chains !== undefined) {
    reg.chains = chains.map((c): ChainInfo => {
      if (!isObj(c)) throw new ACEError(code, 'registration.chains entries must be objects');
      return { network: req(c, 'network', 'string', code, 'chain'), address: req(c, 'address', 'string', code, 'chain') };
    });
  }
  return reg;
}

/**
 * Run all 01 rules (including the ID hash); failures are `invalid_registration`.
 * The peer's `registeredAt` is `pinnedAt` or now (a file has no signed timestamp).
 */
export function verifyRegistrationFile(
  reg: RegistrationFile, opts: { pinnedAt?: number; clock?: () => number } = {},
): VerifiedPeer {
  const code: ACEErrorCode = 'invalid_registration';
  if (opts.pinnedAt !== undefined && wireInt(opts.pinnedAt) === null) {
    throw new ACEError('invalid_argument', 'pinnedAt must be an integer in [0, 2^53-1]');
  }
  const r = parseRegistrationFile(reg);
  if (r.ace !== '1.0') throw new ACEError(code, "ace must be '1.0'");
  if (!isACEId(r.id)) throw new ACEError(code, 'id is not an ACE ID');
  if (r.name.length === 0 || CONTROL_CHAR_RE.test(r.name)) throw new ACEError(code, 'name must be non-empty without control characters');
  if (!isHttpsUrl(r.endpoint)) throw new ACEError(code, 'endpoint must match the ACE HTTPS URL grammar');
  const s = r.signing;
  if (!isSigningScheme(s.scheme)) throw new ACEError(code, 'unsupported signing.scheme');
  let signingKey: Uint8Array;
  if (s.scheme === 'ed25519') {
    try {
      signingKey = bs58.decode(s.address);
    } catch {
      throw new ACEError(code, 'signing.address is not Base58');
    }
    if (signingKey.length !== 32 || bs58.encode(signingKey) !== s.address) {
      throw new ACEError(code, 'signing.address must be the Base58 of a 32-byte key');
    }
    if (s.signingPublicKey !== undefined && !bytesEqual(decodeB64(s.signingPublicKey, code, 'signing.signingPublicKey'), signingKey)) {
      throw new ACEError(code, 'signing.signingPublicKey must equal Base58Decode(signing.address)');
    }
  } else {
    if (s.signingPublicKey === undefined) throw new ACEError(code, 'secp256k1 requires signing.signingPublicKey');
    signingKey = decodeSigningKey('secp256k1', s.signingPublicKey, code);
    if (s.address.toLowerCase() !== signingAddress('secp256k1', signingKey).toLowerCase()) {
      throw new ACEError(code, 'signing.address does not match signing.signingPublicKey');
    }
  }
  if (computeACEId(signingKey) !== r.id) throw new ACEError(code, 'id does not match the signing key');
  const encKey = decodeEncryptionKey(s.encryptionPublicKey, code);
  const now = Math.floor(opts.clock ? opts.clock() : Date.now() / 1000);
  return mintPeer({
    aceId: r.id, scheme: s.scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey,
    registeredAt: opts.pinnedAt ?? now, registrationSignature: null, source: 'registration', profile: null,
  });
}

// --- rollback barrier (02) ---------------------------------------------------------------------

export type AdoptOutcome = 'adopted' | 'unchanged' | 'rotated';

/**
 * Internal pure rule used by `PeerStore.adopt`: the binding to store and the outcome.
 *
 * Rotation to a different encryption key requires a signed (relay) binding with a strictly
 * newer `registeredAt`; an unsigned registration-file candidate is adopted only without a
 * pin, or as `unchanged` when its key equals the pin (the pin is then kept exactly).
 */
export function adoptDecision(pin: VerifiedPeer | null, candidate: VerifiedPeer, now: number): { peer: VerifiedPeer; outcome: AdoptOutcome } {
  if (candidate.registeredAt > now + TIMESTAMP_WINDOW_SECONDS) throw new ACEError('invalid_peer', 'registeredAt is in the future');
  if (pin === null) return { peer: candidate, outcome: 'adopted' };
  if (pin.aceId !== candidate.aceId || !bytesEqual(pin.signingPublicKey, candidate.signingPublicKey) || pin.scheme !== candidate.scheme) {
    throw new ACEError('invalid_peer', 'signing key or scheme differs from the pinned binding');
  }
  const unsigned = candidate.registrationSignature === null;
  if (bytesEqual(pin.encryptionPublicKey, candidate.encryptionPublicKey)) {
    if (unsigned) return { peer: pin, outcome: 'unchanged' };
    const newer = candidate.registeredAt > pin.registeredAt ? candidate : pin;
    return {
      peer: mintPeer({
        aceId: pin.aceId, scheme: pin.scheme, signingPublicKey: pin.signingPublicKey,
        encryptionPublicKey: pin.encryptionPublicKey, registeredAt: newer.registeredAt,
        registrationSignature: newer.registrationSignature, source: newer.source,
        profile: candidate.source === 'relay' ? candidate.profile : pin.profile,
      }),
      outcome: 'unchanged',
    };
  }
  if (unsigned) throw new ACEError('stale_peer_binding', 'an unsigned source cannot rotate a pinned encryption key');
  if (candidate.registeredAt > pin.registeredAt) return { peer: candidate, outcome: 'rotated' };
  throw new ACEError('stale_peer_binding', 'a different encryption key requires a newer registeredAt');
}

// --- well-known fetch ------------------------------------------------------------------------

const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

const V4_BLOCKED: Array<[number, number]> = ([
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as Array<[string, number]>).map(([a, p]) => [parseV4(a)!, p]);

const V6_BLOCKED: Array<[Uint8Array, number]> = ([
  // Transition ranges that embed an IPv4 address are blocked whole (fail closed): IPv4-compatible
  // ::/96 (includes :: and ::1), SIIT ::ffff:0:0:0/96, local-use NAT64 64:ff9b:1::/48, Teredo 2001::/32, 6to4 2002::/16.
  ['::', 96], ['::ffff:0:0:0', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 32], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
] as Array<[string, number]>).map(([a, p]) => [parseV6(a)!, p]);

function parseV4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^[0-9]{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function parseV6(ip: string): Uint8Array | null {
  if (!ip.includes(':')) return null;
  let s = ip.split('%')[0].toLowerCase(); // a %zone is ignored
  let tail: number[] = [];
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    const v4 = parseV4(s.slice(i + 1));
    if (i < 0 || v4 === null) return null;
    tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    s = s.slice(0, i + 1);
    if (!s.endsWith('::')) s = s.slice(0, -1);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h: string) => (h === '' ? [] : h.split(':').map((x) => (/^[0-9a-f]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
  const head = parse(halves[0]);
  const back = halves.length === 2 ? parse(halves[1]) : [];
  const groups = halves.length === 2
    ? [...head, ...new Array(8 - head.length - back.length - tail.length).fill(0), ...back, ...tail]
    : [...head, ...tail];
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[2 * i] = g >> 8; out[2 * i + 1] = g & 0xff; });
  return out;
}

function inV6(addr: Uint8Array, net: Uint8Array, prefix: number): boolean {
  for (let bit = 0; bit < prefix; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if ((addr[byte] & mask) !== (net[byte] & mask)) return false;
  }
  return true;
}

function v4Blocked(n: number): boolean {
  return V4_BLOCKED.some(([net, p]) => Math.floor(n / 2 ** (32 - p)) === Math.floor(net / 2 ** (32 - p)));
}

/**
 * SSRF blocklist (08-relay § Client Rules, Blocked Addresses): true for any blocked address, or an input that is not an IP literal.
 * IPv4-mapped and 64:ff9b::/96 are judged by the embedded IPv4; other IPv4-embedding transition
 * ranges (::/96, ::ffff:0:0:0/96, 64:ff9b:1::/48, 2001::/32, 2002::/16) are blocked whole. Exported so callers that open
 * their own connections (e.g. direct delivery) apply the same policy.
 */
export function isBlockedAddress(ip: string): boolean {
  const v4 = parseV4(ip);
  if (v4 !== null) return v4Blocked(v4);
  const v6 = parseV6(ip);
  if (v6 === null) return true;
  const mapped = parseV6('::ffff:0:0')!;
  const nat64 = parseV6('64:ff9b::')!;
  if (inV6(v6, mapped, 96) || inV6(v6, nat64, 96)) {
    return v4Blocked(((v6[12] << 24) >>> 0) + (v6[13] << 16) + (v6[14] << 8) + v6[15]);
  }
  return V6_BLOCKED.some(([net, p]) => inV6(v6, net, p));
}

/** Internal: injectable network dependencies (tests). */
export interface FetchDeps {
  /** DNS resolution (default `node:dns` lookup; `null` = non-Node runtime, no DNS check). */
  lookup?: LookupFn | null;
  /** TCP port (default 443). */
  port?: number;
}

export interface FetchRegistrationFileOptions {
  timeoutMs?: number;
  maxBytes?: number;
  allowPrivateAddresses?: boolean;
}

/**
 * GET `https://<domain>/.well-known/ace.json` with SSRF protection, then verify it.
 *
 * Under Node the name is resolved once; if ANY address is private / reserved the fetch fails
 * with `blocked_address`, otherwise the request connects only to the validated address
 * (`node:https` with a pinned lookup; SNI and certificate validation use the domain), which
 * closes the DNS-rebinding window. Redirects are never followed; `application/json` is
 * required; at most `maxBytes + 1` bytes are read. Network errors, timeouts, 5xx and 429 are
 * `fetch_failed`; everything else `invalid_registration`.
 *
 * Non-Node runtimes (browser, edge) have no DNS access: the request goes through `fetch` and
 * only the domain grammar applies. Use an egress proxy there if SSRF matters.
 */
export async function fetchRegistrationFile(domain: string, opts: FetchRegistrationFileOptions = {}): Promise<RegistrationFile> {
  return fetchRegistrationFileWith(domain, opts, {});
}

/** Internal: `fetchRegistrationFile` with injectable dependencies. */
export async function fetchRegistrationFileWith(
  domain: string, opts: FetchRegistrationFileOptions, deps: FetchDeps,
): Promise<RegistrationFile> {
  if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) throw new ACEError('invalid_argument', 'invalid domain');
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxBytes = opts.maxBytes ?? MAX_REGISTRATION_FILE_BYTES;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ACEError('invalid_argument', 'timeoutMs must be positive');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new ACEError('invalid_argument', 'maxBytes must be a positive integer');
  const lookup = deps.lookup === undefined ? await loadLookup() : deps.lookup;
  const https = lookup === null ? null : await loadHttps();
  let res: { status: number; contentType: string; body: () => Promise<Uint8Array> };
  if (lookup !== null && https !== null) {
    let addrs: Array<{ address: string; family: number }>;
    try {
      addrs = await lookup(domain, { all: true, verbatim: true });
    } catch (e) {
      throw new ACEError('fetch_failed', `DNS resolution failed: ${e instanceof Error ? e.message : ''}`);
    }
    if (addrs.length === 0) throw new ACEError('fetch_failed', 'no addresses resolved');
    if (opts.allowPrivateAddresses !== true && addrs.some((a) => isBlockedAddress(a.address))) {
      throw new ACEError('blocked_address', `${domain.slice(0, 100)} resolves to a blocked address`);
    }
    res = await pinnedRequest(https, {
      host: domain, addr: addrs[0], port: deps.port ?? 443, path: '/.well-known/ace.json', method: 'GET',
      headers: { Accept: 'application/json' }, timeoutMs, limit: maxBytes + 1, readBody: (status) => status === 200,
      fail: (message) => new ACEError('fetch_failed', message),
    });
  } else {
    res = await fetchGet(domain, timeoutMs, maxBytes + 1);
  }
  if (res.status >= 500 || res.status === 429) throw new ACEError('fetch_failed', `HTTP ${res.status}`, { status: res.status });
  if (res.status !== 200) {
    throw new ACEError('invalid_registration', `HTTP ${res.status} (redirects are not followed)`, { status: res.status });
  }
  if (res.contentType.split(';')[0].trim().toLowerCase() !== 'application/json') {
    throw new ACEError('invalid_registration', 'content-type must be application/json');
  }
  const body = await res.body();
  if (body.length > maxBytes) throw new ACEError('invalid_registration', `registration file exceeds ${maxBytes} bytes`);
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw new ACEError('invalid_registration', 'registration file is not JSON');
  }
  const reg = parseRegistrationFile(data);
  verifyRegistrationFile(reg);
  return reg;
}

/** Non-Node runtimes: plain fetch (no DNS check possible). */
async function fetchGet(domain: string, timeoutMs: number, limit: number): Promise<{ status: number; contentType: string; body: () => Promise<Uint8Array> }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let r: Response;
  try {
    r = await fetch(`https://${domain}/.well-known/ace.json`, {
      headers: { Accept: 'application/json' }, signal: controller.signal, redirect: 'manual',
    });
  } catch (e) {
    clearTimeout(timer);
    throw new ACEError('fetch_failed', `fetch failed: ${e instanceof Error ? e.message : ''}`);
  }
  return {
    status: r.status,
    contentType: r.headers.get('content-type') ?? '',
    body: async () => {
      try {
        return await readLimited(r, limit);
      } catch (e) {
        throw new ACEError('fetch_failed', `read failed: ${e instanceof Error ? e.message : ''}`);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/** Internal: read at most `limit` bytes of a response body, cancelling the rest. */
export async function readLimited(res: Response, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = value.subarray(0, Math.max(0, limit - total));
      chunks.push(take);
      total += take.length;
      if (total >= limit) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export type { PeerRecord };
