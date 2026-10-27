/** Persistent peer pins: the verified KEL per ACE ID, extended only under the fork rules (lock `peers`). */
import { ACEError } from './errors.js';
import { canonicalStateBytes, isACEId, isObj, nowOf, parseStateBytes, sha256Hex } from './encoding.js';
import { atLogTail, reconcileKel, verifyKel, type ExtendOutcome, type KelEvent, type KelState } from './kel.js';
import { withLock, type ACEStore } from './store.js';

const CACHE_SIZE = 256;

export interface Adopted { state: KelState; outcome: ExtendOutcome }

/**
 * `live`: a live descriptor served by a relay vouches for the KEL. A pin moved by anything else (an imported or contact
 * source, which a holder of a superseded key can sign) is not live until a relay's descriptor confirms it (04 § Card
 * record).
 */
export interface AdoptOptions<T> { live?: boolean; then?: (r: Adopted) => Promise<T> }

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
  readonly #verified = new Map<string, { state: KelState; kelLive: boolean }>();

  constructor(opts: { store: ACEStore; clock?: () => number }) {
    this.#store = opts.store;
    this.#clock = opts.clock;
  }

  /** The store's clock reading. */
  now(): number {
    return nowOf(this.#clock);
  }

  async get(aceId: string): Promise<KelState | null> {
    const pin = await this.#pin(aceId);
    return pin === null ? null : structuredClone(pin.state);
  }

  /** Whether a live descriptor vouched for the pinned KEL (see `AdoptOptions.live`); false without a pin. */
  async kelLive(aceId: string): Promise<boolean> {
    return (await this.#pin(aceId))?.kelLive ?? false;
  }

  /** The pin record; one written before `kelLive` existed counts as live (it was pinned through a descriptor). */
  async #pin(aceId: string): Promise<{ state: KelState; kelLive: boolean } | null> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const key = peerKey(aceId);
    const raw = await this.#store.read(key);
    if (raw === null) return null;
    const memo = `${key}:${sha256Hex(raw)}`;
    const hit = this.#verified.get(memo);
    if (hit !== undefined) return hit;
    let pin: { state: KelState; kelLive: boolean };
    try {
      const d = parseStateBytes(raw, key);
      if (!isObj(d) || d.version !== 1 || d.aceId !== aceId) throw new Error('invalid pin');
      if (d.kelLive !== undefined && typeof d.kelLive !== 'boolean') throw new Error('invalid pin');
      const kel = d.kel as KelEvent[];
      const state = verifyKel(kel, atLogTail(kel, nowOf(this.#clock)));
      if (state.aceId !== aceId) throw new Error('pin names another identity');
      pin = { state, kelLive: d.kelLive !== false };
    } catch (e) {
      throw new ACEError('storage_failed', `${key}: ${e instanceof Error ? e.message : 'invalid pin'}`);
    }
    if (this.#verified.size >= CACHE_SIZE) this.#verified.clear();
    this.#verified.set(memo, pin);
    return pin;
  }

  /**
   * Verify `kel` and adopt it under the fork rules, recording whether a live descriptor vouches for the pin (`live`).
   * `then` runs with the resulting pin still under the `peers` lock,
   * so state derived from the pin (e.g. a cached descriptor) is written atomically with it: no other adoption
   * intervenes.
   */
  adopt(kel: unknown, o?: { live?: boolean }): Promise<Adopted>;
  adopt<T>(kel: unknown, o: AdoptOptions<T> & { then: (r: Adopted) => Promise<T> }): Promise<T>;
  async adopt<T>(kel: unknown, o: AdoptOptions<T> = {}): Promise<Adopted | T> {
    return withLock(this.#store, 'peers', async () => {
      const now = nowOf(this.#clock);
      const candidate = verifyKel(kel, now);
      const pinned = await this.#pin(candidate.aceId);
      const result = reconcileKel(pinned === null ? null : structuredClone(pinned.state), candidate);
      // A relay's descriptor vouches only for its own KEL: not for a pin that has moved past it. A moved pin is live only
      // when a live descriptor moved it; an unchanged one becomes live, never unlive.
      const live = o.live === true && result.state.lastHash === candidate.lastHash;
      if (result.outcome !== 'unchanged' || (live && pinned?.kelLive === false)) {
        await this.#store.write(peerKey(candidate.aceId), canonicalStateBytes({ version: 1, aceId: candidate.aceId, kel: result.state.events, kelLive: live }));
      }
      return o.then === undefined ? result : o.then(result);
    });
  }

  async remove(aceId: string): Promise<void> {
    await withLock(this.#store, 'peers', () => this.#store.delete(peerKey(aceId)));
  }
}
