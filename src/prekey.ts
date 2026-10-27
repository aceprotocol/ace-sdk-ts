/**
 * X-Wing prekeys: the only decryption keys. A descriptor publishes the current prekey; a superseded prekey's seed is
 * kept for OFFLINE_WINDOW_SECONDS after it was superseded (at most MAX_RETAINED_PREKEYS), then deleted.
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import { canonicalStateBytes, closedKeys, decodeB64, isHex64, isObj, nowOf, parseStateBytes, sha256Hex, toBase64, wireInt } from './encoding.js';
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
   * The current or a retained prekey; null when unknown, deleted, or retained past OFFLINE_WINDOW_SECONDS after its
   * supersession (refused even before `prune` deletes it, 04 § Prekey).
   */
  open(prekeyId: string): Promise<PrekeySecret | null>;
  /** Delete retained prekeys superseded at or before `now - OFFLINE_WINDOW_SECONDS`; returns how many were deleted. */
  prune(now: number): Promise<number>;
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

/** A content `prekey` member (04 § Peer prekeys): canonical Base64 of a 1216-byte X-Wing public key, else `code`. */
export function decodePrekeyPublicKey(b64: unknown, code: ACEErrorCode): Uint8Array {
  const pk = decodeB64(b64, code, 'prekey', KEM_PUBLIC_KEY_SIZE);
  if (pk.length !== KEM_PUBLIC_KEY_SIZE) throw new ACEError(code, `prekey must be ${KEM_PUBLIC_KEY_SIZE} bytes`);
  return pk;
}

interface Entry { id: string; seed: Uint8Array; createdAt: number; supersededAt?: number }

/** A superseded entry is retained (openable) until OFFLINE_WINDOW_SECONDS after its supersession. */
const retained = (r: Entry, now: number): boolean => r.supersededAt! + OFFLINE_WINDOW_SECONDS > now;
const keepRetained = (list: Entry[], now: number): Entry[] => list.filter((r) => retained(r, now)).slice(-MAX_RETAINED_PREKEYS);

function secretOf(e: Entry): PrekeySecret {
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
 * A `PrekeyVault` persisted in an `ACEStore` under one key (default `prekeys.json`), all operations under the lock
 * `prekeys`. Secret protection: with `FileStore` the document is a 0600 file in a 0700 directory, the same protection
 * as a software identity keystore; pass `protect` to additionally seal it at rest (e.g. with a keychain-held key).
 * Never point it at a store that other parties can read.
 */
export class StorePrekeyVault implements PrekeyVault {
  readonly #store: ACEStore;
  readonly #key: string;
  readonly #protect?: SecretProtector;
  readonly #clock?: () => number;
  /** Public keys of the seeds last loaded, by SHA-256 of the seed: X-Wing key generation runs once per seed. */
  #publicKeys = new Map<string, Uint8Array>();

  /** `clock`: Unix seconds for `open`'s retention check (default the system clock). */
  constructor(store: ACEStore, opts: { key?: string; protect?: SecretProtector; clock?: () => number } = {}) {
    this.#store = store;
    this.#key = opts.key ?? 'prekeys.json';
    this.#protect = opts.protect;
    this.#clock = opts.clock;
  }

  async #load(): Promise<{ current: Entry | null; retained: Entry[] }> {
    let raw = await this.#store.read(this.#key);
    if (raw === null) return { current: null, retained: [] };
    if (this.#protect) raw = await this.#protect.open(raw);
    const d = parseStateBytes(raw, this.#key);
    const bad = () => new ACEError('storage_failed', `${this.#key} is invalid`);
    const publicKeys = new Map<string, Uint8Array>();
    const entry = (v: unknown, superseded: boolean): Entry => {
      if (!isObj(v) || !isHex64(v.id) || wireInt(v.createdAt) === null || (superseded && wireInt(v.supersededAt) === null)) throw bad();
      const seed = decodeB64(v.seed, 'storage_failed', 'prekey seed', KEM_SEED_SIZE);
      if (seed.length !== KEM_SEED_SIZE) throw bad();
      const memo = sha256Hex(seed);
      const pk = this.#publicKeys.get(memo) ?? prekeyPublicKey(seed);
      publicKeys.set(memo, pk);
      if (prekeyId(pk) !== v.id) throw bad();
      return { id: v.id, seed, createdAt: v.createdAt as number, ...(superseded ? { supersededAt: v.supersededAt as number } : {}) };
    };
    if (!isObj(d) || d.version !== 1 || !Array.isArray(d.retained)) throw bad();
    const out = { current: d.current === null ? null : entry(d.current, false), retained: d.retained.map((r) => entry(r, true)) };
    this.#publicKeys = publicKeys;
    return out;
  }

  async #save(s: { current: Entry | null; retained: Entry[] }): Promise<void> {
    const enc = (e: Entry) => ({ id: e.id, seed: toBase64(e.seed), createdAt: e.createdAt, ...(e.supersededAt !== undefined ? { supersededAt: e.supersededAt } : {}) });
    let raw = canonicalStateBytes({ version: 1, current: s.current === null ? null : enc(s.current), retained: s.retained.map(enc) });
    if (this.#protect) raw = await this.#protect.seal(raw);
    await this.#store.write(this.#key, raw);
  }

  async current(): Promise<PrekeyInfo | null> {
    const { current } = await this.#load();
    return current === null ? null : { id: current.id, publicKey: toBase64(this.#publicKeys.get(sha256Hex(current.seed)) ?? prekeyPublicKey(current.seed)), createdAt: current.createdAt };
  }

  async rotate(now: number): Promise<PrekeyInfo> {
    if (wireInt(now) === null) throw new ACEError('invalid_argument', 'now must be a wire integer');
    return withLock(this.#store, 'prekeys', async () => {
      const s = await this.#load();
      const seed = crypto.getRandomValues(new Uint8Array(KEM_SEED_SIZE));
      const pk = prekeyPublicKey(seed);
      const fresh: Entry = { id: prekeyId(pk), seed, createdAt: now };
      const superseded = s.current === null ? s.retained : [...s.retained, { ...s.current, supersededAt: now }];
      await this.#save({ current: fresh, retained: keepRetained(superseded, now) });
      return { id: fresh.id, publicKey: toBase64(pk), createdAt: now };
    });
  }

  async open(id: string): Promise<PrekeySecret | null> {
    if (!isHex64(id)) return null;
    const now = nowOf(this.#clock);
    const s = await this.#load();
    if (s.retained.some((r) => !retained(r, now))) await this.prune(now).catch(() => 0); // opportunistic
    const e = s.current?.id === id ? s.current : s.retained.find((r) => r.id === id && retained(r, now));
    return e === undefined ? null : secretOf(e);
  }

  async prune(now: number): Promise<number> {
    return withLock(this.#store, 'prekeys', async () => {
      const s = await this.#load();
      const keep = keepRetained(s.retained, now);
      if (keep.length !== s.retained.length) await this.#save({ current: s.current, retained: keep });
      return s.retained.length - keep.length;
    });
  }
}
