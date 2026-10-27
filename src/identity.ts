/** Identities: the `ACEIdentity` contract and `SoftwareIdentity` (root, next root and signing seeds in memory, plus the KEL). */
import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { bytesEqual, canonicalStateBytes, decodeB64, isObj, nowOf, toBase64, wireInt } from './encoding.js';
import { type KelEvent, type KelState, type OperationalSignature, atLogTail, createDelegation, createInception, createRotation, isUsable, verifyKel } from './kel.js';
import { SoftwareKey, generateSoftwareKey, keyDigest, keyDigestHex } from './keys.js';
import { TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { signingMessage } from './signing.js';

/**
 * What the SDK needs from an identity (software, Secure Enclave, HSM, ...). Identities only sign: decryption keys
 * are prekeys held by a `PrekeyVault`.
 */
export interface ACEIdentity {
  getACEId(): string;
  getSigningPublicKey(): Uint8Array;
  /** The `seq` of the `dlg` event that delegated the signing key. */
  getSigningSeq(): number;
  getKel(): KelEvent[];
  /** Sign the full message `M` (02 § Signatures) with the signing key, ML-DSA context UTF-8(action). */
  sign(message: Uint8Array, action: string): Promise<Uint8Array>;
}

/** Identity export: root, next root and signing seeds plus the KEL (no encryption seed). */
export interface SoftwareIdentityExport { rootSeed: string; nextRootSeed?: string; signingSeed: string; kel: KelEvent[] }

/** `now` (wire-integer Unix seconds) or, when not given (`undefined` / `null`), the system clock; anything else: invalid_argument. */
function nowArg(now: unknown): number {
  if (now === undefined || now === null) return nowOf();
  const n = wireInt(now);
  if (n === null) throw new ACEError('invalid_argument', 'now must be an integer in [0, 2^53-1]');
  return n;
}

function checkNextDigest(nextRootDigest: Uint8Array | null | undefined): Uint8Array | undefined {
  const digest = nextRootDigest ?? undefined;
  if (digest !== undefined && !(digest instanceof Uint8Array && digest.length === 32)) throw new ACEError('invalid_argument', 'nextRootDigest must be 32 bytes');
  return digest;
}

/**
 * The next root to commit (generated, or none held when `nextRootDigest` is given) and its digest. `current` is the
 * root after the event and `events` the (verified) log before it: committing any current or past root or delegated
 * signing key, each possibly exposed, would let that key rotate (01 § Rotation and recovery: a signer-side refusal).
 */
function newNextRoot(nextRootDigest: Uint8Array | undefined, current: SoftwareKey, events: readonly KelEvent[]): { key: SoftwareKey | null; digest: Uint8Array } {
  const key = nextRootDigest === undefined ? generateSoftwareKey() : null;
  const digest = key === null ? Uint8Array.from(nextRootDigest!) : keyDigest(key.scheme, key.publicKey());
  const roots = new Set([keyDigestHex(current.scheme, current.publicKey())]);
  for (const ev of events) {   // icp and every rot reveal a root, every dlg a signing key
    const k = ev.t === 'dlg' ? ev.key : ev.root;
    if (isObj(k)) roots.add(keyDigestHex(String(k.scheme), decodeB64(k.publicKey, 'invalid_kel', 'publicKey')));
  }
  if (roots.has(bytesToHex(digest))) throw new ACEError('invalid_argument', 'the next root must differ from every key the log has revealed');
  return { key, digest };
}

function checkCommitted(key: SoftwareKey, state: KelState): void {
  if (keyDigestHex(key.scheme, key.publicKey()) !== state.next) throw new ACEError('invalid_argument', 'nextRoot does not match the committed next root');
}

/**
 * The identity's verified log state, or `identity_unavailable` when it must not sign now. Construct-time guard for
 * every signing site: the log is verified at `t = max(now, ts of its last event)`, both operational keys must be live
 * at `t`, and the identity's signing scheme, key and `seq` must be the ones the log delegates. Any failure, a provider
 * exception included, is the local error `identity_unavailable`.
 */
export function checkUsable(identity: ACEIdentity, now: number): KelState {
  if (wireInt(now) === null) throw new ACEError('invalid_argument', 'now must be an integer in [0, 2^53-1]');
  let state: KelState, t = now, pk: Uint8Array, seq: number;
  try {
    const kel: unknown = identity.getKel();
    t = atLogTail(kel, now);
    state = verifyKel(kel, t);
    pk = identity.getSigningPublicKey(); seq = identity.getSigningSeq();
  } catch (e) {
    const detail = e instanceof ACEError ? `identity kel does not verify: ${e.message}` : `identity unavailable: ${e instanceof Error ? e.name : typeof e}`;
    throw new ACEError('identity_unavailable', detail, { cause: e });
  }
  if (!isUsable(state, t)) throw new ACEError('identity_unavailable', 'signing delegation missing or expired');
  const s = state.signing;
  if (s === null || !(pk instanceof Uint8Array) || !bytesEqual(s.publicKey, pk) || s.seq !== seq) {
    throw new ACEError('identity_unavailable', 'identity signing key or seq does not match its kel');
  }
  return state;
}

/** `{scheme, seq, value}` over `M(aceId, signedAt, seq, payload)`, after `checkUsable` at `signedAt`. */
export async function signOperational(identity: ACEIdentity, signedAt: number, payload: Uint8Array, action: string): Promise<OperationalSignature> {
  const seq = checkUsable(identity, signedAt).signing!.seq;
  const value = toBase64(await identity.sign(signingMessage(identity.getACEId(), signedAt, seq, payload), action));
  return { scheme: 'ml-dsa-65', seq, value };
}

/** `claims` plus `signature` over `canonicalStateBytes(claims)` at `issuedAt`. */
export async function signClaims<T extends { issuedAt: number }>(identity: ACEIdentity, action: string, claims: T): Promise<T & { signature: OperationalSignature }> {
  return { ...claims, signature: await signOperational(identity, claims.issuedAt, canonicalStateBytes(claims), action) };
}

/** `doc` without its `signature`: the bytes a signature and a digest cover. */
export function claimsOf<T extends { signature?: unknown }>(doc: T): Omit<T, 'signature'> {
  const { signature: _s, ...claims } = doc;
  return claims;
}

/**
 * Lifetime bounds of a signed document (`invalid_authorization`): `issuedAt <= now + 300`,
 * `issuedAt < expiresAt <= issuedAt + max` and, unless `o.requireLive` is false, `now < expiresAt`.
 */
export function checkLifetime(d: Record<string, unknown>, now: number, max: number, what: string, o: { requireLive?: boolean } = {}): void {
  const i = wireInt(d.issuedAt), e = wireInt(d.expiresAt);
  if (i === null || e === null || i > now + TIMESTAMP_WINDOW_SECONDS || i >= e || (o.requireLive !== false && e <= now) || e - i > max) {
    throw new ACEError('invalid_authorization', `invalid ${what} lifetime`);
  }
}

/**
 * `issuedAt` (the signer's `t`: `o.now` or the clock, moved up to the ts of the last event of `kel`, 01 § Operational
 * signatures) and `expiresAt = issuedAt + ttl` (`o.ttl` or `fallback`, default `max`), ttl in 1..max.
 */
export function docWindow(kel: unknown, o: { now?: number; ttl?: number }, max: number, fallback = max): { issuedAt: number; expiresAt: number } {
  const issuedAt = atLogTail(kel, o.now ?? nowOf());
  const ttl = o.ttl ?? fallback;
  if (wireInt(ttl) === null || ttl < 1 || ttl > max) throw new ACEError('invalid_argument', `ttl must be 1..${max}`);
  return { issuedAt, expiresAt: issuedAt + ttl };
}

const clone = (k: readonly KelEvent[]): KelEvent[] => JSON.parse(JSON.stringify(k)) as KelEvent[];

export class SoftwareIdentity implements ACEIdentity {
  #root: SoftwareKey; #nextRoot: SoftwareKey | null; #signing: SoftwareKey;
  #kel: KelEvent[]; #state: KelState;

  private constructor(root: SoftwareKey, nextRoot: SoftwareKey | null, signing: SoftwareKey, kel: KelEvent[], now: number) {
    const state = verifyKel(kel, now);
    if (state.signing === null) throw new ACEError('invalid_kel', 'kel has no signing delegation');
    if (!bytesEqual(state.rootPublicKey, root.publicKey())) throw new ACEError('invalid_argument', 'root seed does not match the kel');
    if (nextRoot !== null && keyDigestHex(nextRoot.scheme, nextRoot.publicKey()) !== state.next) throw new ACEError('invalid_argument', 'next root seed does not match the commitment');
    if (!bytesEqual(state.signing.publicKey, signing.publicKey())) throw new ACEError('invalid_argument', 'signing seed does not match the kel');
    this.#root = root; this.#nextRoot = nextRoot; this.#signing = signing;
    this.#kel = clone(kel); this.#state = state;
  }

  static async generate(opts: { nextRootDigest?: Uint8Array | null; now?: number | null } = {}): Promise<SoftwareIdentity> {
    if (!isObj(opts)) throw new ACEError('invalid_argument', 'options must be an object');
    const next = checkNextDigest(opts.nextRootDigest);
    const ts = nowArg(opts.now);
    const root = generateSoftwareKey(), signing = generateSoftwareKey();
    const { key: nextRoot, digest } = newNextRoot(next, root, []);
    const icp = await createInception(root, digest, ts);
    const d1 = await createDelegation(verifyKel([icp], ts), root, signing.publicKey(), ts);
    return new SoftwareIdentity(root, nextRoot, signing, [icp, d1], ts);
  }

  static fromExport(data: unknown, now?: number | null): SoftwareIdentity {
    if (!isObj(data)) throw new ACEError('invalid_argument', 'export must be an object');
    if (!Array.isArray(data.kel) || data.kel.length === 0) throw new ACEError('invalid_kel', 'export.kel must be a non-empty array');
    const ts = nowArg(now);
    const seed = (k: string) => new SoftwareKey(decodeB64(data[k], 'invalid_argument', k));
    const root = seed('rootSeed'), nextRoot = Object.hasOwn(data, 'nextRootSeed') ? seed('nextRootSeed') : null, signing = seed('signingSeed');
    return new SoftwareIdentity(root, nextRoot, signing, data.kel as KelEvent[], ts);
  }

  /**
   * Recover an identity whose keys are lost or stolen from its log and the committed next root held outside the lost
   * device. Forks the log at the start of the current root epoch (later events are dropped) and appends `rot` (signed
   * by `nextRoot` alone) and a `dlg` with a fresh signing key, dated `max(now, ts of the epoch start)`.
   */
  static async recover(kel: unknown, nextRoot: SoftwareKey, opts: { now?: number | null; nextRootDigest?: Uint8Array | null } = {}): Promise<SoftwareIdentity> {
    if (!isObj(opts)) throw new ACEError('invalid_argument', 'options must be an object');
    if (!(nextRoot instanceof SoftwareKey)) throw new ACEError('invalid_argument', 'nextRoot must be a SoftwareKey');
    const next = checkNextDigest(opts.nextRootDigest);
    const nowTs = nowArg(opts.now);
    const full = verifyKel(kel, nowTs);
    let start = full.events.length - 1;
    while (full.events[start].t !== 'icp' && full.events[start].t !== 'rot') start--;
    const events = clone(full.events.slice(0, start + 1));
    const ts = Math.max(nowTs, events[start].ts as number);
    const state = verifyKel(events, ts);
    checkCommitted(nextRoot, state);
    const { key: newNext, digest } = newNextRoot(next, nextRoot, full.events);
    const signing = generateSoftwareKey();
    events.push(await createRotation(state, nextRoot, digest, ts));
    events.push(await createDelegation(verifyKel(events, ts), nextRoot, signing.publicKey(), ts));
    return new SoftwareIdentity(nextRoot, newNext, signing, events, ts);
  }

  exportPrivateKey(): SoftwareIdentityExport {
    const out: SoftwareIdentityExport = { rootSeed: toBase64(this.#root.seed), signingSeed: toBase64(this.#signing.seed), kel: clone(this.#kel) };
    if (this.#nextRoot !== null) out.nextRootSeed = toBase64(this.#nextRoot.seed);
    return out;
  }

  getACEId(): string { return this.#state.aceId; }
  getSigningPublicKey(): Uint8Array { return this.#signing.publicKey(); }
  getSigningSeq(): number { return this.#state.signing!.seq; }
  getKel(): KelEvent[] { return clone(this.#kel); }
  sign(message: Uint8Array, action: string): Promise<Uint8Array> { return this.#signing.sign(message, action); }

  #commit(evs: KelEvent[], now: number): void {
    const state = verifyKel([...this.#kel, ...evs], now);
    this.#kel.push(...evs);
    this.#state = state;
  }

  /**
   * Reveal the committed next root (held, or `nextRoot` when it is held outside this identity) and commit a new one
   * (generated, or `nextRootDigest`); re-delegates the signing key.
   */
  async rotate(opts: { now?: number | null; nextRootDigest?: Uint8Array | null; nextRoot?: SoftwareKey | null } = {}): Promise<void> {
    if (!isObj(opts)) throw new ACEError('invalid_argument', 'options must be an object');
    let revealed: SoftwareKey;
    if (opts.nextRoot !== undefined && opts.nextRoot !== null) {
      if (this.#nextRoot !== null) throw new ACEError('invalid_argument', 'the next root key is held by this identity');
      if (!(opts.nextRoot instanceof SoftwareKey)) throw new ACEError('invalid_argument', 'nextRoot must be a SoftwareKey');
      checkCommitted(opts.nextRoot, this.#state);
      revealed = opts.nextRoot;
    } else if (this.#nextRoot === null) {
      throw new ACEError('invalid_argument', 'the next root key is not held by this identity');
    } else {
      revealed = this.#nextRoot;
    }
    const next = checkNextDigest(opts.nextRootDigest);
    const ts = nowArg(opts.now);
    const { key: newNext, digest } = newNextRoot(next, revealed, this.#state.events);
    const rot = await createRotation(this.#state, revealed, digest, ts);
    const d1 = await createDelegation(verifyKel([...this.#kel, rot], ts), revealed, this.#signing.publicKey(), ts);
    this.#commit([rot, d1], ts);
    this.#root = revealed; this.#nextRoot = newNext;
  }

  /** Delegate a fresh signing key (optionally with `notAfter`). */
  async delegate(opts: { now?: number | null; notAfter?: number } = {}): Promise<void> {
    if (!isObj(opts)) throw new ACEError('invalid_argument', 'options must be an object');
    const ts = nowArg(opts.now);
    const key = generateSoftwareKey();
    this.#commit([await createDelegation(this.#state, this.#root, key.publicKey(), ts, opts.notAfter)], ts);
    this.#signing = key;
  }
}
