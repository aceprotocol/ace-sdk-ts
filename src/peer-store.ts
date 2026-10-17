/** Persistent peer pins: the verified KEL per ACE ID, extended only under the fork rules (lock `peers`). */
import { ACEError } from './errors.js';
import { canonicalStateBytes, isACEId, isObj, nowOf, parseStateBytes, sha256Hex } from './encoding.js';
import { atLogTail, reconcileKel, verifyKel, type ExtendOutcome, type KelEvent, type KelState } from './kel.js';
import { withLock, type ACEStore } from './store.js';

const CACHE_SIZE = 256;

export interface Adopted { state: KelState; outcome: ExtendOutcome }

export function peerKey(aceId: string): string {
  return `peers/${sha256Hex(aceId)}.json`;
}

/**
 * Pinned peer KELs. `adopt` verifies a candidate log and extends the pin (a fork is `kel_conflict` unless a `rot`
 * recovers it); `get` returns the pinned state. Pins are written only by explicit adoption (import, accepted
 * contact, refresh of an admitted peer), never by an unsolicited packet.
 */
export class PeerStore {
  readonly #store: ACEStore;
  readonly #clock?: () => number;
  readonly #verified = new Map<string, KelState>();

  constructor(opts: { store: ACEStore; clock?: () => number }) {
    this.#store = opts.store;
    this.#clock = opts.clock;
  }

  async get(aceId: string): Promise<KelState | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const key = peerKey(aceId);
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const memo = `${key}:${sha256Hex(raw)}`;
    const hit = this.#verified.get(memo);
    if (hit !== undefined) return structuredClone(hit);
    let state: KelState;
    try {
      const d = parseStateBytes(raw, key);
      if (!isObj(d) || d.version !== 1 || d.aceId !== aceId) throw new Error('invalid pin');
      const kel = d.kel as KelEvent[];
      state = verifyKel(kel, atLogTail(kel, nowOf(this.#clock)));
      if (state.aceId !== aceId) throw new Error('pin names another identity');
    } catch (e) {
      throw new ACEError('storage_failed', `${key}: ${e instanceof Error ? e.message : 'invalid pin'}`);
    }
    if (this.#verified.size >= CACHE_SIZE) this.#verified.clear();
    this.#verified.set(memo, state);
    return structuredClone(state);
  }

  /** The pinned states of those of `ids` that are pinned (e.g. delegation issuers, 01 § Pinning). */
  async pins(ids: readonly string[]): Promise<Map<string, KelState>> {
    const unique = [...new Set(ids.filter(isACEId))];
    const states = await Promise.all(unique.map((id) => this.get(id)));
    const out = new Map<string, KelState>();
    unique.forEach((id, i) => { if (states[i] !== null) out.set(id, states[i]); });
    return out;
  }

  /**
   * Verify `kel` and adopt it under the fork rules. `then` runs with the resulting pin still under the `peers` lock, so
   * state derived from the pin (e.g. a cached descriptor) is written atomically with it: no other adoption intervenes.
   */
  adopt(kel: unknown): Promise<Adopted>;
  adopt<T>(kel: unknown, then: (r: Adopted) => Promise<T>): Promise<T>;
  async adopt<T>(kel: unknown, then?: (r: Adopted) => Promise<T>): Promise<Adopted | T> {
    return withLock(this.#store, 'peers', async () => {
      const now = nowOf(this.#clock);
      const candidate = verifyKel(kel, now);
      const pinned = await this.get(candidate.aceId);
      const result = reconcileKel(pinned, candidate);
      if (result.outcome !== 'unchanged') {
        await this.#store.write(peerKey(candidate.aceId), canonicalStateBytes({ version: 1, aceId: candidate.aceId, kel: result.state.events }));
      }
      return then === undefined ? result : then(result);
    });
  }

  async remove(aceId: string): Promise<void> {
    await withLock(this.#store, 'peers', () => this.#store.delete(peerKey(aceId)));
  }
}
