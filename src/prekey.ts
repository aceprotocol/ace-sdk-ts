/**
 * X-Wing prekeys: the only decryption keys. A descriptor publishes the current prekey; a superseded prekey's seed is
 * kept for OFFLINE_WINDOW_SECONDS after it was superseded (at most MAX_RETAINED_PREKEYS), then deleted.
 *
 * Peer prekeys (04 § Peer prekeys): per peer, the vault keeps at most an *offered* seed (the key every packet to that
 * peer offers it) and an *in-use* seed (the offered key the peer has encrypted to), each deleted OFFLINE_WINDOW_SECONDS
 * after it was last offered, and one *held* public key the peer offered us, bound to the pin it was authenticated under.
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { canonicalStateBytes, closedKeys, decodeB64, isACEId, isHex64, isObj, nowOf, parseStateBytes, sha256Hex, toBase64, wireInt } from './encoding.js';
import { KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_SEED_SIZE, MAX_RETAINED_PREKEYS, OFFLINE_WINDOW_SECONDS } from './limits.js';
import { MemoryStore, withLock, type ACEStore } from './store.js';

/** The descriptor form of a prekey: `id` = lowercase hex SHA-256 of the 1216-byte public key. */
export interface Prekey { id: string; publicKey: string }
export interface PrekeyInfo extends Prekey { createdAt: number }

/** An opened prekey: decapsulation only; the seed never leaves the vault. */
export interface PrekeySecret {
  readonly id: string;
  decapsulate(kemCiphertext: Uint8Array): Uint8Array;
}

/** Where prekey seeds live. Seeds are secrets with the same protection level as identity seeds. */
export interface PrekeyVault {
  /** The current prekey, or null before the first `rotate`. */
  current(): Promise<PrekeyInfo | null>;
  /** Make a fresh prekey current; the previous one is retained (superseded at `now`). */
  rotate(now: number): Promise<PrekeyInfo>;
  /**
   * The current or a retained prekey, else the peer prekey offered to `sender` or in use by it while
   * `now < offeredAt + OFFLINE_WINDOW_SECONDS`; null when unknown, deleted, or past its window (a retained prekey is
   * refused OFFLINE_WINDOW_SECONDS after its supersession even before `prune` deletes it, 04 § Prekey).
   */
  open(prekeyId: string, sender: string): Promise<PrekeySecret | null>;
  /**
   * Delete retained prekeys superseded at or before `now - OFFLINE_WINDOW_SECONDS` (returns how many), and peer seeds
   * and held keys whose window ended; a peer left with nothing is removed.
   */
  prune(now: number): Promise<number>;
  /**
   * The prekey offered to `peer` in a packet built at `now`: the offered key while its window lasts (the window restarts
   * at `now`), else a fresh one.
   */
  offer(peer: string, now: number): Promise<Prekey>;
  /**
   * A packet from `peer` opened under `prekeyId`: when that is the offered key it becomes the in-use key (replacing the
   * previous one) and the next `offer` is fresh. Any other ID changes nothing.
   */
  used(peer: string, prekeyId: string, now: number): Promise<void>;
  /**
   * Record the prekey `peer` offered in a packet dated `timestamp`, authenticated under pin `pin` (the last pinned KEL
   * event digest), unless the held key came from a packet at least as new.
   */
  hold(peer: string, prekey: Prekey, timestamp: number, pin: string): Promise<void>;
  /** The key held for `peer` while `pin` matches and `now < timestamp + OFFLINE_WINDOW_SECONDS`; otherwise it is deleted (null). */
  held(peer: string, pin: string, now: number): Promise<Prekey | null>;
  /** Delete the key held for `peer`. */
  dropHeld(peer: string): Promise<void>;
}

/** Optional at-rest protection for the vault document (e.g. a keychain-held key). */
export interface SecretProtector {
  seal(plain: Uint8Array): Promise<Uint8Array>;
  open(sealed: Uint8Array): Promise<Uint8Array>;
}

export function prekeyId(publicKey: Uint8Array): string {
  return sha256Hex(publicKey);
}

export function prekeyPublicKey(seed: Uint8Array): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== KEM_SEED_SIZE) throw new ACEError('invalid_argument', `X-Wing seed must be ${KEM_SEED_SIZE} bytes`);
  return ml_kem768_x25519.getPublicKey(seed);
}

/** Decode and check a descriptor prekey (`code` on failure); returns the raw public key. */
export function decodePrekey(value: unknown, code: 'invalid_authorization' | 'invalid_argument' = 'invalid_authorization'): Uint8Array {
  if (!closedKeys(value, ['id', 'publicKey']) || !isHex64(value.id)) throw new ACEError(code, 'prekey must be {id, publicKey}');
  const pk = decodeB64(value.publicKey, code, 'prekey.publicKey', KEM_PUBLIC_KEY_SIZE);
  if (pk.length !== KEM_PUBLIC_KEY_SIZE) throw new ACEError(code, `prekey.publicKey must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  if (prekeyId(pk) !== value.id) throw new ACEError(code, 'prekey.id is not SHA-256(publicKey)');
  return pk;
}

const MLKEM_PUBLIC_KEY_SIZE = 1184;

/**
 * Throw `code` unless `publicKey` is an X-Wing public key: 1216 bytes whose ML-KEM-768 half passes the FIPS 203 modulus
 * check (any 32 bytes are an X25519 public key). noble parses lazily (the check runs inside `encapsulate`), so this is a
 * trial encapsulation of the ML-KEM half; its result is discarded.
 */
export function checkXWingPublicKey(publicKey: Uint8Array, code: ACEErrorCode = 'invalid_argument'): void {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== KEM_PUBLIC_KEY_SIZE) throw new ACEError(code, `X-Wing public key must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  try {
    ml_kem768.encapsulate(publicKey.subarray(0, MLKEM_PUBLIC_KEY_SIZE));
  } catch {
    throw new ACEError(code, 'X-Wing public key is not a valid ML-KEM-768 key');
  }
}

/**
 * A content `prekey` member (04 § Peer prekeys): canonical Base64 of an X-Wing public key, else `code`. Checked here, at
 * decode, so a key that cannot be encapsulated to is never held (03 § Private content).
 */
export function decodePrekeyPublicKey(b64: unknown, code: ACEErrorCode): Uint8Array {
  const pk = decodeB64(b64, code, 'prekey', KEM_PUBLIC_KEY_SIZE);
  if (pk.length !== KEM_PUBLIC_KEY_SIZE) throw new ACEError(code, `prekey must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  checkXWingPublicKey(pk, code);
  return pk;
}

interface Entry { id: string; seed: Uint8Array; createdAt: number; supersededAt?: number }
/** A peer seed (offered or in use) and when it was last offered. */
interface PeerSeed { id: string; seed: Uint8Array; offeredAt: number }
interface Held { id: string; publicKey: Uint8Array; timestamp: number; pin: string }
interface PeerState { offered: PeerSeed | null; inUse: PeerSeed | null; held: Held | null }
interface VaultState { current: Entry | null; retained: Entry[]; peers: Record<string, PeerState> }

const VERSION = 2;

/** A superseded entry is retained (openable) until OFFLINE_WINDOW_SECONDS after its supersession. */
const retained = (r: Entry, now: number): boolean => r.supersededAt! + OFFLINE_WINDOW_SECONDS > now;
const keepRetained = (list: Entry[], now: number): Entry[] => list.filter((r) => retained(r, now)).slice(-MAX_RETAINED_PREKEYS);
const seedLive = (e: PeerSeed | null, now: number): e is PeerSeed => e !== null && now < e.offeredAt + OFFLINE_WINDOW_SECONDS;
const heldLive = (h: Held | null, now: number): h is Held => h !== null && now < h.timestamp + OFFLINE_WINDOW_SECONDS;
/** `p` without the seeds and held key whose window ended at `now`, or null when nothing is left. */
function prunedPeer(p: PeerState, now: number): PeerState | null {
  const q = { offered: seedLive(p.offered, now) ? p.offered : null, inUse: seedLive(p.inUse, now) ? p.inUse : null, held: heldLive(p.held, now) ? p.held : null };
  return q.offered === null && q.inUse === null && q.held === null ? null : q;
}
/** `s` with `peer`'s state set to `p` (removed when empty). */
function withPeer(s: VaultState, peer: string, p: PeerState): VaultState {
  const peers = { ...s.peers };
  if (p.offered === null && p.inUse === null && p.held === null) delete peers[peer];
  else peers[peer] = p;
  return { ...s, peers };
}
const NO_PEER: PeerState = { offered: null, inUse: null, held: null };

const checkPeer = (peer: unknown): void => {
  if (!isACEId(peer)) throw new ACEError('invalid_argument', 'peer must be an ACE ID');
};
const checkInt = (v: unknown, name: string): void => {
  if (wireInt(v) === null) throw new ACEError('invalid_argument', `${name} must be a wire integer`);
};

function secretOf(e: { id: string; seed: Uint8Array }): PrekeySecret {
  const seed = e.seed.slice();
  return {
    id: e.id,
    decapsulate(ct: Uint8Array): Uint8Array {
      if (!(ct instanceof Uint8Array) || ct.length !== KEM_CIPHERTEXT_SIZE) throw new ACEError('decryption_failed', `X-Wing ciphertext must be ${KEM_CIPHERTEXT_SIZE} bytes`);
      try {
        return ml_kem768_x25519.decapsulate(ct, seed);
      } catch {
        throw new ACEError('decryption_failed', 'X-Wing decapsulation failed');
      }
    },
  };
}

/**
 * A `PrekeyVault` persisted in an `ACEStore` under one key (default `prekeys.json`, the `version: 2` document of 04 §
 * Peer prekeys), every change under the lock `prekeys`. Secret protection: with `FileStore` the document is a 0600 file
 * in a 0700 directory, the same protection as a software identity keystore; pass `protect` to additionally seal the
 * whole document at rest (e.g. with a keychain-held key). Never point it at a store that other parties can read.
 */
export class StorePrekeyVault implements PrekeyVault {
  readonly #store: ACEStore;
  readonly #key: string;
  readonly #protect?: SecretProtector;
  readonly #clock?: () => number;
  /** Public keys of the seeds last loaded, by SHA-256 of the seed: X-Wing key generation runs once per seed. */
  #publicKeys = new Map<string, Uint8Array>();

  /** `clock`: Unix seconds for `open`'s window checks (default the system clock). */
  constructor(store: ACEStore, opts: { key?: string; protect?: SecretProtector; clock?: () => number } = {}) {
    this.#store = store;
    this.#key = opts.key ?? 'prekeys.json';
    this.#protect = opts.protect;
    this.#clock = opts.clock;
  }

  async #load(): Promise<VaultState> {
    let raw = await this.#store.read(this.#key);
    if (raw === null) return { current: null, retained: [], peers: {} };
    if (this.#protect) raw = await this.#protect.open(raw);
    const d = parseStateBytes(raw, this.#key);
    const bad = () => new ACEError('storage_failed', `${this.#key} is invalid`);
    const publicKeys = new Map<string, Uint8Array>();
    const derive = (seedText: unknown): { id: string; seed: Uint8Array; pk: Uint8Array } => {
      const seed = decodeB64(seedText, 'storage_failed', 'prekey seed', KEM_SEED_SIZE);
      if (seed.length !== KEM_SEED_SIZE) throw bad();
      const memo = sha256Hex(seed);
      const pk = publicKeys.get(memo) ?? this.#publicKeys.get(memo) ?? prekeyPublicKey(seed);
      publicKeys.set(memo, pk);
      return { id: prekeyId(pk), seed, pk };
    };
    const entry = (v: unknown, superseded: boolean): Entry => {
      if (!isObj(v) || !isHex64(v.id) || wireInt(v.createdAt) === null || (superseded && wireInt(v.supersededAt) === null)) throw bad();
      const { id, seed } = derive(v.seed);
      if (id !== v.id) throw bad();
      return { id: v.id, seed, createdAt: v.createdAt as number, ...(superseded ? { supersededAt: v.supersededAt as number } : {}) };
    };
    const peerSeed = (v: unknown): PeerSeed | null => {
      if (v === null) return null;
      if (!closedKeys(v, ['seed', 'offeredAt']) || wireInt(v.offeredAt) === null) throw bad();
      const { id, seed } = derive(v.seed);
      return { id, seed, offeredAt: v.offeredAt as number };
    };
    const held = (v: unknown): Held | null => {
      if (v === null) return null;
      if (!closedKeys(v, ['publicKey', 'timestamp', 'pin']) || wireInt(v.timestamp) === null || !isHex64(v.pin)) throw bad();
      const publicKey = decodePrekeyPublicKey(v.publicKey, 'storage_failed');
      return { id: prekeyId(publicKey), publicKey, timestamp: v.timestamp as number, pin: v.pin };
    };
    if (!closedKeys(d, ['version', 'current', 'retained', 'peers']) || d.version !== VERSION || !Array.isArray(d.retained) || !isObj(d.peers)) throw bad();
    const peers: Record<string, PeerState> = {};
    for (const [aceId, v] of Object.entries(d.peers)) {
      if (!isACEId(aceId) || !closedKeys(v, ['offered', 'inUse', 'held'])) throw bad();
      peers[aceId] = { offered: peerSeed(v.offered), inUse: peerSeed(v.inUse), held: held(v.held) };
    }
    const out = { current: d.current === null ? null : entry(d.current, false), retained: d.retained.map((r) => entry(r, true)), peers };
    this.#publicKeys = publicKeys;
    return out;
  }

  async #save(s: VaultState): Promise<void> {
    const enc = (e: Entry) => ({ id: e.id, seed: toBase64(e.seed), createdAt: e.createdAt, ...(e.supersededAt !== undefined ? { supersededAt: e.supersededAt } : {}) });
    const encSeed = (e: PeerSeed | null) => (e === null ? null : { seed: toBase64(e.seed), offeredAt: e.offeredAt });
    const peers = Object.fromEntries(Object.entries(s.peers).map(([aceId, p]) => [aceId, {
      offered: encSeed(p.offered), inUse: encSeed(p.inUse),
      held: p.held === null ? null : { publicKey: toBase64(p.held.publicKey), timestamp: p.held.timestamp, pin: p.held.pin },
    }]));
    let raw = canonicalStateBytes({ version: VERSION, current: s.current === null ? null : enc(s.current), retained: s.retained.map(enc), peers });
    if (this.#protect) raw = await this.#protect.seal(raw);
    await this.#store.write(this.#key, raw);
  }

  #publicKey(seed: Uint8Array): Uint8Array {
    return this.#publicKeys.get(sha256Hex(seed)) ?? prekeyPublicKey(seed);
  }

  /** Load, apply `change` and save its result when it returns a new state, all under the lock `prekeys`. */
  async #update<T>(change: (s: VaultState) => { state?: VaultState; result: T }): Promise<T> {
    return withLock(this.#store, 'prekeys', async () => {
      const { state, result } = change(await this.#load());
      if (state !== undefined) await this.#save(state);
      return result;
    });
  }

  async current(): Promise<PrekeyInfo | null> {
    const { current } = await this.#load();
    return current === null ? null : { id: current.id, publicKey: toBase64(this.#publicKey(current.seed)), createdAt: current.createdAt };
  }

  async rotate(now: number): Promise<PrekeyInfo> {
    checkInt(now, 'now');
    const seed = crypto.getRandomValues(new Uint8Array(KEM_SEED_SIZE));
    const pk = prekeyPublicKey(seed);
    const fresh: Entry = { id: prekeyId(pk), seed, createdAt: now };
    return this.#update((s) => {
      const superseded = s.current === null ? s.retained : [...s.retained, { ...s.current, supersededAt: now }];
      return { state: { ...s, current: fresh, retained: keepRetained(superseded, now) }, result: { id: fresh.id, publicKey: toBase64(pk), createdAt: now } };
    });
  }

  async open(id: string, sender: string): Promise<PrekeySecret | null> {
    if (!isHex64(id)) return null;
    const now = nowOf(this.#clock);
    const s = await this.#load();
    if (s.retained.some((r) => !retained(r, now))) await this.prune(now).catch(() => 0); // opportunistic
    const e = s.current?.id === id ? s.current : s.retained.find((r) => r.id === id && retained(r, now));
    if (e !== undefined) return secretOf(e);
    const p = Object.hasOwn(s.peers, sender) ? s.peers[sender] : undefined;
    const peer = [p?.offered ?? null, p?.inUse ?? null].find((x) => x?.id === id) ?? null;
    if (peer === null) return null;
    if (seedLive(peer, now)) return secretOf(peer);
    await this.prune(now).catch(() => 0); // its window ended: delete it (best effort, refused either way)
    return null;
  }

  async prune(now: number): Promise<number> {
    checkInt(now, 'now');
    return this.#update((s) => {
      const keep = keepRetained(s.retained, now);
      const peers: Record<string, PeerState> = {};
      let changed = keep.length !== s.retained.length;
      for (const [aceId, p] of Object.entries(s.peers)) {
        const q = prunedPeer(p, now);
        if (q !== null) peers[aceId] = q;
        if (q === null || q.offered !== p.offered || q.inUse !== p.inUse || q.held !== p.held) changed = true;
      }
      return { ...(changed ? { state: { current: s.current, retained: keep, peers } } : {}), result: s.retained.length - keep.length };
    });
  }

  async offer(peer: string, now: number): Promise<Prekey> {
    checkPeer(peer);
    checkInt(now, 'now');
    return this.#update((s) => {
      const p = s.peers[peer] ?? NO_PEER;
      let offered: PeerSeed;
      if (seedLive(p.offered, now)) {
        offered = { ...p.offered, offeredAt: now };
      } else {
        const seed = crypto.getRandomValues(new Uint8Array(KEM_SEED_SIZE));
        const pk = prekeyPublicKey(seed);
        this.#publicKeys.set(sha256Hex(seed), pk);
        offered = { id: prekeyId(pk), seed, offeredAt: now };
      }
      const result = { id: offered.id, publicKey: toBase64(this.#publicKey(offered.seed)) };
      const changed = p.offered === null || p.offered.id !== offered.id || p.offered.offeredAt !== now;
      return { ...(changed ? { state: withPeer(s, peer, { ...p, offered }) } : {}), result };
    });
  }

  async used(peer: string, prekeyId: string, now: number): Promise<void> {
    checkPeer(peer);
    checkInt(now, 'now');
    // `now` is intentionally unused (beyond its check): the in-use key keeps the offeredAt of its last offer (04 § Peer
    // prekeys: a seed's window runs from the last packet that carried it as the offered key).
    return this.#update((s) => {
      const p = s.peers[peer];
      if (p?.offered?.id !== prekeyId) return { result: undefined };
      return { state: withPeer(s, peer, { ...p, offered: null, inUse: p.offered }), result: undefined };
    });
  }

  async hold(peer: string, prekey: Prekey, timestamp: number, pin: string): Promise<void> {
    checkPeer(peer);
    checkInt(timestamp, 'timestamp');
    if (!isHex64(pin)) throw new ACEError('invalid_argument', 'pin must be 64 lowercase hex');
    const publicKey = decodePrekey(prekey, 'invalid_argument');
    return this.#update((s) => {
      const p = s.peers[peer] ?? NO_PEER;
      if (p.held !== null && timestamp <= p.held.timestamp) return { result: undefined };
      return { state: withPeer(s, peer, { ...p, held: { id: prekey.id, publicKey, timestamp, pin } }), result: undefined };
    });
  }

  async held(peer: string, pin: string, now: number): Promise<Prekey | null> {
    checkPeer(peer);
    checkInt(now, 'now');
    return this.#update((s) => {
      const p = s.peers[peer];
      if (p === undefined || p.held === null) return { result: null };
      if (p.held.pin === pin && heldLive(p.held, now)) return { result: { id: p.held.id, publicKey: toBase64(p.held.publicKey) } };
      return { state: withPeer(s, peer, { ...p, held: null }), result: null };
    });
  }

  async dropHeld(peer: string): Promise<void> {
    checkPeer(peer);
    return this.#update((s) => {
      const p = s.peers[peer];
      return p === undefined || p.held === null ? { result: undefined } : { state: withPeer(s, peer, { ...p, held: null }), result: undefined };
    });
  }
}
