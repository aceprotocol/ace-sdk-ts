/** Pinned peer bindings with the rollback barrier (02-discovery § Rollback Barrier). */

import { ACEError } from './errors.js';
import { canonicalStateBytes, isACEId, parseStateBytes, sha256Hex, toBase64, wireInt } from './encoding.js';
import {
  adoptDecision, isVerifiedPeer, mintPeer,
  verifyPeerRecord, verifyRegistrationFile, type AdoptOutcome, type VerifiedPeer,
} from './discovery.js';
import { parsePrincipalRecord, samePrincipalClaims, validatePrincipalRecord } from './principal.js';
import type { RelayClient } from './relay.js';
import type { ACEStore } from './store.js';
import type { RegistrationFile } from './types.js';

export const DEFAULT_PEER_TTL_SECONDS = 86400;

function peerKey(aceId: string): string {
  return `peers/${sha256Hex(aceId)}.json`;
}

/** Distinct verified pins remembered per PeerStore instance. */
const VERIFIED_PINS = 256;

interface PinRecord {
  peer: VerifiedPeer;
  fetchedAt: number;
}

let refreshImpl: (peers: PeerStore, aceId: string) => Promise<VerifiedPeer | null>;

/**
 * Internal (Inbox, 09 R-P20): look `aceId` up on the relay now and adopt it under the rollback barrier, regardless of
 * the pin's age; null without a relay. Errors propagate.
 */
export function refreshPeer(peers: PeerStore, aceId: string): Promise<VerifiedPeer | null> {
  return refreshImpl(peers, aceId);
}

export class PeerStore {
  static {
    refreshImpl = (peers, aceId) => peers.#refresh(aceId);
  }

  readonly #store: ACEStore;
  readonly #verified = new Map<string, PinRecord>();
  readonly #relay: RelayClient | null;
  readonly #ttl: number;
  readonly #clock?: () => number;

  constructor(opts: { store: ACEStore; relay?: RelayClient; ttlSeconds?: number; clock?: () => number }) {
    if (typeof opts !== 'object' || opts === null || typeof opts.store !== 'object' || opts.store === null) {
      throw new ACEError('invalid_argument', 'store is required');
    }
    const ttl = opts.ttlSeconds ?? DEFAULT_PEER_TTL_SECONDS;
    if (wireInt(ttl) === null) throw new ACEError('invalid_argument', 'ttlSeconds must be a non-negative integer');
    this.#store = opts.store;
    this.#relay = opts.relay ?? null;
    this.#ttl = ttl;
    this.#clock = opts.clock;
  }

  #now(): number {
    return Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
  }

  /** The pinned binding regardless of TTL, or null. A corrupt record is `storage_failed` (never overwritten). */
  async get(aceId: string): Promise<VerifiedPeer | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    return (await this.#load(aceId))?.peer ?? null;
  }

  /**
   * A fresh binding: the pin if fetched within `maxAgeSeconds` (default: the TTL), else a relay
   * lookup adopted under the rollback barrier. Falls back to the pin on transient errors,
   * `unknown_peer` or `stale_peer_binding` when `maxAgeSeconds > 0`.
   */
  async resolve(aceId: string, opts: { maxAgeSeconds?: number } = {}): Promise<VerifiedPeer> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const maxAge = opts.maxAgeSeconds ?? this.#ttl;
    if (wireInt(maxAge) === null) throw new ACEError('invalid_argument', 'maxAgeSeconds must be a non-negative integer');
    const pin = await this.#load(aceId);
    if (pin !== null && this.#now() - pin.fetchedAt <= maxAge) return pin.peer;
    if (this.#relay === null) {
      if (pin !== null) return pin.peer;
      throw new ACEError('unknown_peer', 'no pinned binding and no relay');
    }
    let candidate: VerifiedPeer;
    try {
      candidate = await this.#relay.lookupPeer(aceId);
    } catch (e) {
      const err = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'peer lookup failed', { cause: e });
      if ((err.isTransient || err.code === 'unknown_peer') && pin !== null && maxAge > 0) return pin.peer;
      throw err;
    }
    try {
      return (await this.adopt(candidate)).peer;
    } catch (e) {
      if (e instanceof ACEError && e.code === 'stale_peer_binding' && maxAge > 0 && pin !== null) return pin.peer;
      throw e;
    }
  }

  async #refresh(aceId: string): Promise<VerifiedPeer | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    if (this.#relay === null) return null;
    return (await this.adopt(await this.#relay.lookupPeer(aceId))).peer;
  }

  /** Adopt a verified binding under the rollback barrier (lock `peers`). */
  async adopt(peer: VerifiedPeer): Promise<{ peer: VerifiedPeer; outcome: AdoptOutcome }> {
    if (!isVerifiedPeer(peer)) throw new ACEError('invalid_argument', 'peer must be a VerifiedPeer');
    const release = await this.#store.lock('peers');
    try {
      const pin = await this.#load(peer.aceId, false);
      // Backfill the horizon of a pin cached before horizons existed, so a later strip cannot erase it.
      if (pin?.peer.principal !== undefined) await this.#checkPrincipalHorizon(pin.peer);
      const now = this.#now();
      const decision = adoptDecision(pin?.peer ?? null, peer, now);
      await this.#checkPrincipalHorizon(decision.peer);
      // Every adopted or kept candidate replaces the cached record, profile and fetchedAt included (02).
      await this.#write(decision.peer, now);
      return decision;
    } finally {
      await release();
    }
  }

  /** Verify a registration file and adopt it (signed binding time). */
  async pinRegistrationFile(reg: RegistrationFile): Promise<VerifiedPeer> {
    const peer = verifyRegistrationFile(reg, { clock: this.#clock });
    return (await this.adopt(peer)).peer;
  }

  async remove(aceId: string): Promise<void> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const release = await this.#store.lock('peers');
    try {
      await this.#store.delete(peerKey(aceId));
    } finally {
      await release();
    }
  }

  // A cache eviction, unsigned profile omission or key rotation must never erase the
  // newest signed principal already observed for this stable signing identity.
  async #checkPrincipalHorizon(peer: VerifiedPeer, persist = true): Promise<void> {
    const next = peer.principal;
    if (next === undefined) return;
    const key = `principal-horizons/${sha256Hex([peer.aceId, next.account, next.signer.scheme, next.signer.publicKey].join('\0'))}.json`;
    const raw = await this.#store.read(key);
    let high = null;
    if (raw !== null) {
      try {
        const d = parseStateBytes(raw, key) as Record<string, unknown>;
        if (d.version !== 1 || d.aceId !== peer.aceId) throw new Error('wrong record');
        high = parsePrincipalRecord(d.principal);
        if (high.account !== next.account || high.signer.scheme !== next.signer.scheme || high.signer.publicKey !== next.signer.publicKey) throw new Error('wrong authority');
        validatePrincipalRecord(high, peer.signingPublicKey, high.issuedAt);
      } catch { throw new ACEError('storage_failed', `${key}: invalid principal horizon`); }
    }
    if (high !== null && (next.issuedAt < high.issuedAt ||
      (next.issuedAt === high.issuedAt && !samePrincipalClaims(next, high)))) {
      throw new ACEError('invalid_principal', 'principal rolls back or conflicts with the durable horizon');
    }
    if (persist && (high === null || next.issuedAt > high.issuedAt)) {
      // Write the barrier first: a crash may deny access, never restore older authority.
      await this.#store.write(key, canonicalStateBytes({ aceId: peer.aceId, principal: next, version: 1 }));
    }
  }

  async #write(peer: VerifiedPeer, fetchedAt: number): Promise<void> {
    const doc = {
      aceId: peer.aceId,
      encryptionPublicKey: toBase64(peer.encryptionPublicKey),
      fetchedAt,
      profile: peer.profile,
      registeredAt: peer.registeredAt,
      registrationSignature: peer.registrationSignature,
      scheme: peer.scheme,
      signingPublicKey: toBase64(peer.signingPublicKey),
      source: peer.source,
      version: 1,
    };
    await this.#store.write(peerKey(peer.aceId), canonicalStateBytes(doc));
  }

  async #load(aceId: string, enforceHorizon = true): Promise<PinRecord | null> {
    const key = peerKey(aceId);
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const bad = (why: string) => new ACEError('storage_failed', `${key}: ${why}`);
    // Re-verification is a pure function of the stored bytes: verify each distinct pin once per instance.
    const memo = `${aceId}:${sha256Hex(raw)}`;
    let pin = this.#verified.get(memo);
    if (pin === undefined) {
      pin = verifyPin(key, aceId, raw, bad);
      if (this.#verified.size >= VERIFIED_PINS) this.#verified.delete(this.#verified.keys().next().value!);
      this.#verified.set(memo, pin);
    }
    if (enforceHorizon) {
      try {
        await this.#checkPrincipalHorizon(pin.peer, false);
      } catch (e) {
        if (e instanceof ACEError && e.code === 'storage_failed') throw e;
        throw bad(`re-verification failed (${e instanceof ACEError ? e.code : 'error'})`);
      }
    }
    return pin;
  }

}

/** Parse and re-verify a stored pin (`#load`); any defect is `storage_failed`. */
function verifyPin(key: string, aceId: string, raw: Uint8Array, bad: (why: string) => ACEError): PinRecord {
  const doc = parseStateBytes(raw, key);
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) throw bad('not an object');
  const d = doc as Record<string, unknown>;
  if (d.version !== 1) throw bad('unknown version');
  if (d.aceId !== aceId) throw bad('record belongs to another ACE ID');
  const fetchedAt = wireInt(d.fetchedAt);
  if (fetchedAt === null) throw bad('invalid fetchedAt');
  if (d.profile !== null && (typeof d.profile !== 'object' || Array.isArray(d.profile))) throw bad('invalid profile');
  try {
    if (d.source !== 'relay' && d.source !== 'registration') throw bad('unknown source');
    const verified = verifyPeerRecord({
      aceId: d.aceId, scheme: d.scheme, encryptionPublicKey: d.encryptionPublicKey, signingPublicKey: d.signingPublicKey,
      registrationSignature: d.registrationSignature, registeredAt: d.registeredAt, profile: d.profile,
    }, { clock: () => fetchedAt });
    const peer = mintPeer({ ...verified, signingPublicKey: verified.signingPublicKey, encryptionPublicKey: verified.encryptionPublicKey, source: d.source });
    return { peer, fetchedAt };
  } catch (e) {
    if (e instanceof ACEError && e.code === 'storage_failed') throw e;
    throw bad(`re-verification failed (${e instanceof ACEError ? e.code : 'error'})`);
  }
}
