/** Pinned peer bindings with the rollback barrier (02-discovery § Rollback Barrier). */

import { ACEError } from './errors.js';
import { canonicalStateBytes, isACEId, parseStateBytes, sha256Hex, toBase64, wireInt } from './encoding.js';
import {
  adoptDecision, decodeEncryptionKey, decodeSigningKey, isVerifiedPeer, mintPeer, validateProfile,
  verifyPeerRecord, verifyRegistrationFile, type AdoptOutcome, type VerifiedPeer,
} from './discovery.js';
import type { RelayClient } from './relay.js';
import { computeACEId } from './signing.js';
import type { ACEStore } from './store.js';
import type { AgentProfile, RegistrationFile } from './types.js';
import { isSigningScheme } from './types.js';

export const DEFAULT_PEER_TTL_SECONDS = 86400;

function peerKey(aceId: string): string {
  return `peers/${sha256Hex(aceId)}.json`;
}

interface PinRecord {
  peer: VerifiedPeer;
  fetchedAt: number;
}

export class PeerStore {
  readonly #store: ACEStore;
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

  /** Adopt a verified binding under the rollback barrier (lock `peers`). */
  async adopt(peer: VerifiedPeer): Promise<{ peer: VerifiedPeer; outcome: AdoptOutcome }> {
    if (!isVerifiedPeer(peer)) throw new ACEError('invalid_argument', 'peer must be a VerifiedPeer');
    const release = await this.#store.lock('peers');
    try {
      const pin = await this.#load(peer.aceId);
      const now = this.#now();
      const decision = adoptDecision(pin?.peer ?? null, peer, now);
      // An unsigned (registration-file) candidate with the pinned key keeps the pin exactly.
      const keepExactly = decision.outcome === 'unchanged' && peer.registrationSignature === null;
      if (!keepExactly) await this.#write(decision.peer, now);
      return decision;
    } finally {
      await release();
    }
  }

  /** Verify a registration file and adopt it (`registeredAt = pinnedAt ?? now`). */
  async pinRegistrationFile(reg: RegistrationFile, opts: { pinnedAt?: number } = {}): Promise<VerifiedPeer> {
    const peer = verifyRegistrationFile(reg, { pinnedAt: opts.pinnedAt ?? this.#now() });
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

  async #load(aceId: string): Promise<PinRecord | null> {
    const key = peerKey(aceId);
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const doc = parseStateBytes(raw, key);
    const bad = (why: string) => new ACEError('storage_failed', `${key}: ${why}`);
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) throw bad('not an object');
    const d = doc as Record<string, unknown>;
    if (d.version !== 1) throw bad('unknown version');
    if (d.aceId !== aceId) throw bad('record belongs to another ACE ID');
    const fetchedAt = wireInt(d.fetchedAt);
    if (fetchedAt === null) throw bad('invalid fetchedAt');
    if (d.profile !== null && (typeof d.profile !== 'object' || Array.isArray(d.profile))) throw bad('invalid profile');
    let peer: VerifiedPeer;
    try {
      if (d.source === 'relay') {
        peer = verifyPeerRecord({
          aceId: d.aceId, scheme: d.scheme, encryptionPublicKey: d.encryptionPublicKey, signingPublicKey: d.signingPublicKey,
          registrationSignature: d.registrationSignature, registeredAt: d.registeredAt, profile: d.profile,
        });
      } else if (d.source === 'registration') {
        if (d.registrationSignature !== null || !isSigningScheme(d.scheme)) throw bad('invalid registration pin');
        const signingKey = decodeSigningKey(d.scheme, d.signingPublicKey, 'storage_failed');
        if (computeACEId(signingKey) !== aceId) throw bad('aceId does not match the signing key');
        const registeredAt = wireInt(d.registeredAt);
        if (registeredAt === null) throw bad('invalid registeredAt');
        peer = mintPeer({
          aceId, scheme: d.scheme, signingPublicKey: signingKey,
          encryptionPublicKey: decodeEncryptionKey(d.encryptionPublicKey, 'storage_failed'),
          registeredAt, registrationSignature: null, source: 'registration',
          profile: d.profile === null ? null : validateProfile(d.profile as AgentProfile),
        });
      } else {
        throw bad('unknown source');
      }
    } catch (e) {
      if (e instanceof ACEError && e.code === 'storage_failed') throw e;
      throw bad(`re-verification failed (${e instanceof ACEError ? e.code : 'error'})`);
    }
    return { peer, fetchedAt };
  }
}
