/** Key event log: inception, rotation, delegation. ACE ID = SHA-256 of the inception bytes. */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { bytesEqual, canonicalStateBytes, closedKeys, concat, decimal, decodeB64, isHex64, isObj, sha256Hex, toBase64, utf8, wireInt } from './encoding.js';
import { MAX_KEL_EVENTS, MAX_SIGNING_KEY_LIFETIME, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { type KeyProvider, keyDigestHex } from './keys.js';
import { decodeSignature, encodePayload, isValidSigningPublicKey, signingMessage, verifySignature } from './signing.js';
import type { JSONObject, SigningScheme } from './types.js';

export type KelEvent = JSONObject;
export type ExtendOutcome = 'adopted' | 'unchanged' | 'extended' | 'recovered';

export interface DelegatedKey { scheme: SigningScheme; publicKey: Uint8Array; seq: number; notAfter: number | null }
export interface KelState {
  aceId: string; seq: number; lastHash: string; rootScheme: SigningScheme; rootPublicKey: Uint8Array; next: string;
  signing: DelegatedKey | null; events: readonly KelEvent[];
}

const KEYS: Record<string, readonly string[]> = {
  icp: ['t', 'seq', 'ts', 'root', 'next'],
  rot: ['t', 'seq', 'ts', 'prev', 'root', 'next'],
  dlg: ['t', 'seq', 'ts', 'prev', 'key'],
};
const bad = (m: string) => new ACEError('invalid_kel', m);

function keyOf(obj: unknown, what: string): { scheme: string; pk: Uint8Array } {
  if (!closedKeys(obj, ['scheme', 'publicKey']) || typeof obj.scheme !== 'string') throw bad(`${what} must be {scheme, publicKey}`);
  return { scheme: obj.scheme, pk: decodeB64(obj.publicKey, 'invalid_kel', `${what}.publicKey`) };
}

function hex64(v: unknown, what: string): string {
  if (!isHex64(v)) throw bad(`${what} must be 64 lowercase hex`);
  return v;
}

/** Canonical bytes (signatures excluded). Throws invalid_kel on shape errors. */
export function eventBytes(event: unknown): Uint8Array {
  if (!isObj(event) || typeof event.t !== 'string' || !Object.hasOwn(KEYS, event.t)) throw bad('event must be icp, rot or dlg');
  const t = event.t;
  const required = KEYS[t];
  const allowed = new Set([...required, 'sig', ...(t === 'dlg' ? ['notAfter'] : [])]);
  const present = Object.keys(event);
  if (!required.every((k) => Object.hasOwn(event, k)) || !present.every((k) => allowed.has(k))) throw bad(`${t} has unknown or missing members`);
  const seq = wireInt(event.seq), ts = wireInt(event.ts);
  if (seq === null || ts === null) throw bad('seq and ts must be wire integers');
  if (t === 'icp') {
    const { scheme, pk } = keyOf(event.root, 'root');
    return encodePayload('icp', decimal(seq), decimal(ts), scheme, pk, hexToBytes(hex64(event.next, 'next')));
  }
  const prev = hex64(event.prev, 'prev');
  if (t === 'rot') {
    const { scheme, pk } = keyOf(event.root, 'root');
    return encodePayload('rot', decimal(seq), decimal(ts), prev, scheme, pk, hexToBytes(hex64(event.next, 'next')));
  }
  const { scheme, pk } = keyOf(event.key, 'key');
  let na = '';
  if (Object.hasOwn(event, 'notAfter')) { const n = wireInt(event.notAfter); if (n === null) throw bad('notAfter must be a wire integer'); na = decimal(n); }
  return encodePayload('dlg', decimal(seq), decimal(ts), prev, scheme, pk, na);
}

/** The hash of a log's last event: `KelState.lastHash` of that log, without verifying it. */
export function lastEventHash(events: readonly KelEvent[]): string {
  return sha256Hex(eventBytes(events[events.length - 1]));
}

export function computeACEId(inceptionBytes: Uint8Array): string {
  return `ace:sha256:${sha256Hex(inceptionBytes)}`;
}

async function sig(provider: KeyProvider, aceId: string, ts: number, eb: Uint8Array): Promise<JSONObject> {
  return { scheme: provider.scheme, value: toBase64(await provider.sign(signingMessage(aceId, ts, null, eb), 'kel')) };
}

function checkSig(s: unknown, aceId: string, ts: number, eb: Uint8Array, scheme: string, pk: Uint8Array, who: string): void {
  if (!closedKeys(s, ['scheme', 'value']) || s.scheme !== scheme) throw bad(`${who} signature must be {scheme, value} for ${scheme}`);
  const raw = decodeB64(s.value, 'invalid_signature', `${who} signature`);
  if (!verifySignature(signingMessage(aceId, ts, null, eb), 'kel', raw, pk)) throw new ACEError('invalid_signature', `${who} signature does not verify`);
}

export async function createInception(root: KeyProvider, nextDigest: Uint8Array, ts: number): Promise<KelEvent> {
  const ev: KelEvent = { t: 'icp', seq: 0, ts, root: { scheme: root.scheme, publicKey: toBase64(root.publicKey()) }, next: bytesToHex(nextDigest) };
  const eb = eventBytes(ev);
  ev.sig = await sig(root, computeACEId(eb), ts, eb);
  return ev;
}

/** `rot` revealing the committed `newRoot`, signed by it alone (pre-rotation). */
export async function createRotation(state: KelState, newRoot: KeyProvider, nextDigest: Uint8Array, ts: number): Promise<KelEvent> {
  if (keyDigestHex(newRoot.scheme, newRoot.publicKey()) !== state.next) throw bad('new root does not match the committed next digest');
  const ev: KelEvent = { t: 'rot', seq: state.seq + 1, ts, prev: state.lastHash, root: { scheme: newRoot.scheme, publicKey: toBase64(newRoot.publicKey()) }, next: bytesToHex(nextDigest) };
  const eb = eventBytes(ev);
  ev.sig = await sig(newRoot, state.aceId, ts, eb);
  return ev;
}

/**
 * `dlg` delegating an `ml-dsa-65` signing key (the only delegated role). The signer refuses a key equal to the current
 * root or committed as the next root (01 § Rotation and recovery): a verifier cannot detect that reuse.
 */
export async function createDelegation(state: KelState, root: KeyProvider, keyPublic: Uint8Array, ts: number, notAfter?: number): Promise<KelEvent> {
  if (notAfter !== undefined && !(ts < notAfter && notAfter <= ts + MAX_SIGNING_KEY_LIFETIME)) throw bad('notAfter must be in (ts, ts + 31622400]');
  if (bytesEqual(keyPublic, state.rootPublicKey) || keyDigestHex('ml-dsa-65', keyPublic) === state.next) {
    throw new ACEError('invalid_argument', 'the signing key must differ from the current and the next root');
  }
  const ev: KelEvent = { t: 'dlg', seq: state.seq + 1, ts, prev: state.lastHash, key: { scheme: 'ml-dsa-65', publicKey: toBase64(keyPublic) } };
  if (notAfter !== undefined) ev.notAfter = notAfter;
  const eb = eventBytes(ev);
  ev.sig = await sig(root, state.aceId, ts, eb);
  return ev;
}

const VERIFIED_CACHE_SIZE = 256;
/** The cache's budget in canonical log bytes: 256 maximal logs would hold far more than a process should keep. */
const VERIFIED_CACHE_BYTES = 16 * 1024 * 1024;
const verified = new Map<string, { state: KelState; lastTs: number; bytes: number }>();
let verifiedBytes = 0;

/** Internal (tests): the cache's entry count and canonical log bytes. */
export function verifiedCacheUsage(): { entries: number; bytes: number } {
  return { entries: verified.size, bytes: verifiedBytes };
}

/**
 * Chained content keys: `key[i]` is the SHA-256 over `key[i-1]` and the canonical JSON of event `i` (its `sig`
 * included), so it identifies the exact prefix `events[0..i]`; `bytes` is the log's canonical size. Null for a value
 * that is not a bounded JSON array.
 */
function prefixKeys(events: unknown): { keys: string[]; bytes: number } | null {
  if (!Array.isArray(events) || events.length === 0 || events.length > MAX_KEL_EVENTS) return null;
  const keys: string[] = [];
  let bytes = 0;
  try {
    for (const ev of events) {
      const b = canonicalStateBytes(ev);
      bytes += b.length;
      keys.push(sha256Hex(concat([utf8(keys.at(-1) ?? ''), b])));
    }
  } catch {
    return null;
  }
  return { keys, bytes };
}

/** Cache a verified log usable at `now` (an unusable one is never a pin), evicting the oldest past either bound. */
function remember(key: string, state: KelState, bytes: number, now: number): void {
  if (!isUsable(state, now) || bytes > VERIFIED_CACHE_BYTES || verified.has(key)) return;
  verified.set(key, { state: structuredClone(state), lastTs: wireInt(state.events[state.events.length - 1].ts) ?? 0, bytes });
  verifiedBytes += bytes;
  for (const [k, v] of verified) {
    if (verified.size <= VERIFIED_CACHE_SIZE && verifiedBytes <= VERIFIED_CACHE_BYTES) break;
    verified.delete(k);
    verifiedBytes -= v.bytes;
  }
}

/**
 * Verify a KEL at `now` (01 § Verifier rules). Verified states are cached by their prefix key (05 § Receiver
 * admission): verification is a pure function of the log and `now`, and only the future bound
 * `ts <= now + TIMESTAMP_WINDOW_SECONDS` depends on `now`, so a hit re-checks that bound alone. A log extending a cached
 * one (e.g. a pin plus new events) re-checks the whole structure but verifies only the new events' signatures. Only a
 * log usable at `now` is cached, within VERIFIED_CACHE_SIZE entries and VERIFIED_CACHE_BYTES (a stranger's junk logs
 * cannot crowd out the pins or hold unbounded memory).
 */
export function verifyKel(events: unknown, now: number): KelState {
  const prefix = prefixKeys(events);
  let resume: KelState | undefined;
  if (prefix !== null) {
    const { keys } = prefix;
    const hit = verified.get(keys[keys.length - 1]);
    if (hit !== undefined && hit.lastTs <= now + TIMESTAMP_WINDOW_SECONDS) return structuredClone(hit.state);
    for (let i = keys.length - 2; i >= 0 && resume === undefined; i--) resume = verified.get(keys[i])?.state;
  }
  const state = verifyKelUncached(events, now, resume);
  if (prefix !== null) remember(prefix.keys[prefix.keys.length - 1], state, prefix.bytes, now);
  return state;
}

/** `resume`: a verified state of a prefix of `events` (same content, signatures included); its signatures are not re-checked. */
function verifyKelUncached(events: unknown, now: number, resume?: KelState): KelState {
  if (!Array.isArray(events) || events.length === 0) throw bad('kel must be a non-empty array');
  if (events.length > MAX_KEL_EVENTS) throw bad(`kel exceeds ${MAX_KEL_EVENTS} events`);
  if (!isObj(events[0]) || events[0].t !== 'icp') throw bad('kel must start with icp');
  const eb0 = eventBytes(events[0]);
  const aceId = computeACEId(eb0);
  const r0 = keyOf(events[0].root, 'root');
  // Rule 1: the whole log's structure before any signature.
  const bytes: Uint8Array[] = [];
  let prevTs = -1, prevHash = '';
  for (let i = 0; i < events.length; i++) {
    const ev = events[i] as KelEvent;
    const eb = i === 0 ? eb0 : eventBytes(ev);
    if (!Object.hasOwn(ev, 'sig')) throw bad(`event ${i}: missing signature`);
    const sg = ev.sig;
    if (!closedKeys(sg, ['scheme', 'value']) || typeof sg.scheme !== 'string') throw bad(`event ${i}: sig must be {scheme, value}`);
    decodeB64(sg.value, 'invalid_kel', `event ${i} sig.value`);
    const seq = wireInt(ev.seq)!, ts = wireInt(ev.ts)!;
    if (seq !== i || ts < prevTs || ts > now + TIMESTAMP_WINDOW_SECONDS) throw bad(`event ${i}: bad seq or ts`);
    if (i > 0 && ev.t === 'icp') throw bad(`event ${i}: icp only at seq 0`);
    if (i > 0 && ev.prev !== prevHash) throw bad(`event ${i}: prev does not match`);
    prevTs = ts; prevHash = sha256Hex(eb);
    bytes.push(eb);
  }
  if (!isValidSigningPublicKey(r0.scheme, r0.pk)) throw bad('root key must be an ml-dsa-65 key');
  let state: KelState = resume !== undefined
    ? structuredClone(resume)
    : { aceId, seq: 0, lastHash: sha256Hex(eb0), rootScheme: 'ml-dsa-65', rootPublicKey: r0.pk, next: events[0].next as string, signing: null, events: [] };
  const owned = state.events as KelEvent[];   // the state owns its events (a fresh copy when resumed)
  for (let i = owned.length; i < events.length; i++) {
    const ev = events[i] as KelEvent;
    const eb = bytes[i];
    const ts = wireInt(ev.ts)!;
    let { signing, rootScheme, rootPublicKey, next } = state;
    if (ev.t === 'icp') {
      checkSig(ev.sig, aceId, ts, eb, rootScheme, rootPublicKey, 'icp');
    } else if (ev.t === 'rot') {
      const r = keyOf(ev.root, 'root');
      if (!isValidSigningPublicKey(r.scheme, r.pk)) throw bad(`event ${i}: root key must be an ml-dsa-65 key`);
      if (keyDigestHex(r.scheme, r.pk) !== state.next) throw bad(`event ${i}: revealed root does not match commitment`);
      checkSig(ev.sig, aceId, ts, eb, r.scheme, r.pk, 'rot');   // the revealed root alone
      rootPublicKey = r.pk; next = ev.next as string; signing = null;
    } else {
      checkSig(ev.sig, aceId, ts, eb, state.rootScheme, state.rootPublicKey, 'dlg');
      const k = keyOf(ev.key, 'key');
      const na = Object.hasOwn(ev, 'notAfter') ? wireInt(ev.notAfter)! : null;
      if (na !== null && !(ts < na && na <= ts + MAX_SIGNING_KEY_LIFETIME)) throw bad(`event ${i}: notAfter out of range`);
      if (k.scheme !== 'ml-dsa-65' || !isValidSigningPublicKey(k.scheme, k.pk)) throw bad(`event ${i}: signing key must be ml-dsa-65`);
      signing = { scheme: 'ml-dsa-65', publicKey: k.pk, seq: i, notAfter: na };
    }
    owned.push(structuredClone(ev));
    state = { aceId, seq: i, lastHash: sha256Hex(eb), rootScheme, rootPublicKey, next, signing, events: owned };
  }
  return state;
}

/** Usable: a signing key is delegated and `now < notAfter` (when set). */
export function isUsable(state: KelState, now: number): boolean {
  const k = state.signing;
  return k !== null && (k.notAfter === null || now < k.notAfter);
}

/** An operational signature on the wire: `{scheme: "ml-dsa-65", seq, value}`. */
export interface OperationalSignature { scheme: 'ml-dsa-65'; seq: number; value: string }

/** Shape of an operational signature (`code` on failure). */
export function checkSignatureShape(sig: unknown, code: ACEErrorCode): OperationalSignature {
  if (!closedKeys(sig, ['scheme', 'seq', 'value']) || sig.scheme !== 'ml-dsa-65' || wireInt(sig.seq) === null) {
    throw new ACEError(code, 'signature must be {scheme: "ml-dsa-65", seq, value}');
  }
  decodeSignature(sig.value, code);
  return { scheme: 'ml-dsa-65', seq: sig.seq as number, value: sig.value as string };
}

/**
 * 01 § Operational signatures, in order, for a `{scheme, seq, value}` signature over `M(state.aceId, signedAt, seq,
 * payload)`: 1. the scheme is `ml-dsa-65` (shape failures are `code`); 2. `seq` names the current signing delegation;
 * 3. signed while live (the delegating `dlg`'s `ts` <= `signedAt` < `notAfter`); 4. the signature verifies (`code`);
 * 5. the signer is usable at `now`. Failures of 2, 3 and 5 are `stale_peer_binding`. The one check for packets, descriptors, permits, credentials and
 * relay authentication.
 */
export function verifyOperationalSignature(
  state: KelState, action: string, signedAt: number, payload: Uint8Array, sig: unknown, now: number, code: ACEErrorCode = 'invalid_signature',
): void {
  const s = checkSignatureShape(sig, code);
  const k = state.signing;
  if (k === null || s.seq !== k.seq) throw new ACEError('stale_peer_binding', 'signature.seq is not the current signing delegation');
  if (signedAt < (state.events[k.seq].ts as number)) throw new ACEError('stale_peer_binding', 'signed before the delegating dlg\'s ts');
  if (k.notAfter !== null && signedAt >= k.notAfter) throw new ACEError('stale_peer_binding', 'signed at or after the delegation notAfter');
  if (!verifySignature(signingMessage(state.aceId, signedAt, k.seq, payload), action, decodeSignature(s.value, code), k.publicKey)) {
    throw new ACEError(code, `${action} signature does not verify`);
  }
  if (!isUsable(state, now)) throw new ACEError('stale_peer_binding', 'the signer is not usable now');
}

/**
 * Max(`now`, ts of the log's last event): a stored log is verified at its own last timestamp, so it never fails the
 * future-ts bound against a clock that is behind it.
 */
export function atLogTail(kel: unknown, now: number): number {
  const tail = Array.isArray(kel) && kel.length > 0 ? kel[kel.length - 1] : undefined;
  const last = isObj(tail) ? wireInt(tail.ts) : null;
  return last === null ? now : Math.max(now, last);
}

/** Event hashes of a verified state: each event's hash is the next one's `prev`, the last is `lastHash`. */
export function eventHashes(state: KelState): string[] {
  return [...state.events.slice(1).map((e) => e.prev as string), state.lastHash];
}

export function extendKel(pinned: KelState | null, events: unknown, now: number): { state: KelState; outcome: ExtendOutcome } {
  return reconcileKel(pinned, verifyKel(events, now));
}

/** `extendKel` over a candidate state that `verifyKel` produced. */
export function reconcileKel(pinned: KelState | null, cand: KelState): { state: KelState; outcome: ExtendOutcome } {
  if (pinned === null) return { state: cand, outcome: 'adopted' };
  if (cand.aceId !== pinned.aceId) throw new ACEError('kel_conflict', 'candidate names a different identity');
  // the pin may be a host-supplied state (VerifyOptions.pinned), so its events are hashed, not read off its chain
  const ph = pinned.events.map((e) => sha256Hex(eventBytes(e)));
  const ch = eventHashes(cand);
  for (let k = 0; k < Math.min(ph.length, ch.length); k++) {
    if (ph[k] !== ch[k]) {
      // a rot supersedes the pinned events from the fork point only when none of them is a rot:
      // otherwise a holder of a revealed root could re-reveal it (01 rule 6)
      if (cand.events[k].t === 'rot' && pinned.events.slice(k).every((e) => e.t !== 'rot')) return { state: cand, outcome: 'recovered' };
      throw new ACEError('kel_conflict', `conflicting event at seq ${k}`);
    }
  }
  return ch.length > ph.length ? { state: cand, outcome: 'extended' } : { state: pinned, outcome: 'unchanged' };
}
