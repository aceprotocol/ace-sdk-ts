/** Pairwise MLS primitives. Enrollment inputs MUST be authenticated by the ACE host.
 * No automatic enrollment, transport, secret persistence, or static-encryption fallback.
 */
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { bytesEqual, canonicalStateBytes, decodeB64, isACEId, isObj, toBase64 } from './encoding.js';
import { MLS_MAX_ENGINE_IO_BYTES, MLS_MAX_KEY_PACKAGE_CHARS, MLS_MAX_MESSAGE_CHARS } from './limits.js';
import { SerialQueue, type CoordinatedStore, type StoreData } from './store.js';

/** The common Rust engine, normally the generated WASM SessionEngine. Trusted local code. */
export interface MLSEngine { execute(command: Uint8Array): Uint8Array }
export class MLSError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'MLSError'; }
}
export interface MLSState {
  handle: number; generation: number; local: string; peer: string;
  keyPackage: string; signatureKey: string; groupId: string | null; epoch: number | null; ready: boolean;
}
export interface MLSEvent { kind: 'welcome' | 'joined' | 'application' | 'commit'; message?: string; plaintext?: string }
interface CoreResponse { ok: boolean; result: unknown; error: string | null }
interface Gate { version: 1; context: string; local: string; peer: string; signatureKey: string; generation: number; closed: boolean }
const encoder = new TextEncoder(), text = new TextDecoder('utf-8', { fatal: true });

/**
 * Every transition consumes a durable generation BEFORE touching the ratchet. A failed or
 * uncertain store operation closes this handle. Secret state has no export/resume API.
 * Use a trusted monotonic store (e.g. pinned etcd) for protection from host snapshot rollback;
 * MemoryStore/FileStore cannot provide that guarantee against rollback of the whole host.
 * Returned ciphertext still needs the application's durable delivery journal.
 */
export class PairwiseMLS {
  readonly #queue = new SerialQueue();
  #closed = false;
  #state: MLSState;
  #gate: Gate;
  readonly #key: string;
  readonly #lock: string;
  private constructor(readonly engine: MLSEngine, readonly store: CoordinatedStore, state: MLSState, context: string) {
    this.#state = state;
    this.#gate = { version: 1, context, local: state.local, peer: state.peer, signatureKey: state.signatureKey, generation: 0, closed: false };
    this.#key = `mls/gates/${context}.json`;
    this.#lock = `mls-${context.slice(0, 48)}`;
  }
  /** Fresh context only. local/peer are authenticated ACE identities, not claimed MLS labels. */
  static async open(engine: MLSEngine, store: CoordinatedStore, local: string, peer: string): Promise<PairwiseMLS> {
    if (!isACEId(local) || !isACEId(peer) || local === peer || typeof engine?.execute !== 'function'
      || typeof store?.coordinate !== 'function') throw new ACEError('invalid_argument', 'MLS engine, coordinated store and distinct ACE identities required');
    const state = PairwiseMLS.#result(PairwiseMLS.#call(engine, { op: 'new', local, peer })) as MLSState;
    const context = bytesToHex(randomBytes(32));
    const session = new PairwiseMLS(engine, store, state, context);
    try {
      session.#checkState(state, 0);
      if (state.local !== local || state.peer !== peer || state.ready) throw new MLSError('invalid_engine_state');
      await store.coordinate(session.#lock, async data => {
        if (await data.read(session.#key) !== null) throw new MLSError('session_context_conflict');
        await data.write(session.#key, canonicalStateBytes(session.#gate));
      });
      return session;
    } catch (error) { session.#destroy(); throw error; }
  }
  get state(): Readonly<MLSState> { return { ...this.#state }; }
  /** The peer key package must come from a fresh, authenticated ACE handshake. */
  create(keyPackage: string): Promise<MLSEvent> { return this.#wireStep('create', 'key_package', keyPackage, MLS_MAX_KEY_PACKAGE_CHARS); }
  /** The Welcome must come from the pinned peer in the same authenticated handshake. */
  join(welcome: string): Promise<MLSEvent> { return this.#wireStep('join', 'welcome', welcome, MLS_MAX_MESSAGE_CHARS); }
  send(plaintext: Uint8Array): Promise<MLSEvent> {
    if (!(plaintext instanceof Uint8Array) || plaintext.length > 40_000) return Promise.reject(new MLSError('session_limit'));
    return this.#step({ op: 'send', plaintext: toBase64(plaintext) });
  }
  receive(message: string): Promise<MLSEvent> { return this.#wireStep('receive', 'message', message, MLS_MAX_MESSAGE_CHARS); }
  /** Coordinate epoch changes with delivery: past epochs are erased immediately. */
  update(): Promise<MLSEvent> { return this.#step({ op: 'update' }); }
  static plaintext(event: MLSEvent): Uint8Array {
    if (event.kind !== 'application' || typeof event.plaintext !== 'string') throw new MLSError('invalid_session_event');
    return decodeB64(event.plaintext, 'invalid_body', 'MLS plaintext', 40_000);
  }
  close(): Promise<void> {
    return this.#queue.run(async () => {
      if (this.#closed) return;
      try {
        await this.store.coordinate(this.#lock, async data => {
          await this.#checkGate(data);
          await data.delete(this.#key);
        });
      } finally { this.#destroy(); }
    });
  }
  #wireStep(op: string, field: string, value: string, limit: number): Promise<MLSEvent> {
    if (typeof value !== 'string' || value.length > limit) return Promise.reject(new MLSError('session_limit'));
    return this.#step({ op, [field]: value });
  }
  #step(command: Record<string, unknown>): Promise<MLSEvent> {
    return this.#queue.run(async () => {
      if (this.#closed) throw new MLSError('session_closed');
      let response: CoreResponse;
      try {
        response = await this.store.coordinate(this.#lock, async data => {
          await this.#checkGate(data);
          const before = PairwiseMLS.#result(PairwiseMLS.#call(this.engine, { op: 'info', handle: this.#state.handle })) as MLSState;
          this.#checkState(before, this.#gate.generation);
          const generation = this.#gate.generation;
          if (generation >= Number.MAX_SAFE_INTEGER) throw new MLSError('session_limit');
          const next = { ...this.#gate, generation: generation + 1 };
          await data.write(this.#key, canonicalStateBytes(next));
          this.#gate = next;
          const result = PairwiseMLS.#call(this.engine, { ...command, handle: this.#state.handle, generation });
          if (!result.ok && ['session_failed', 'session_closed', 'session_generation_mismatch'].includes(result.error ?? '')) {
            throw new MLSError(result.error!);
          }
          if (result.ok && (!isObj(result.result) || !isObj(result.result.event)
            || !['welcome', 'joined', 'application', 'commit'].includes(result.result.event.kind as string))) {
            throw new MLSError('invalid_engine_response');
          }
          const after = PairwiseMLS.#result(PairwiseMLS.#call(this.engine, { op: 'info', handle: this.#state.handle })) as MLSState;
          this.#checkState(after, generation + 1);
          this.#state = after;
          return result;
        });
      } catch (error) { this.#destroy(); throw error; }
      // Rejected ciphertext consumes the generation, but not the active ratchet. Throw only
      // AFTER coordinate returns so a lost unlock/fence acknowledgement cannot escape notice.
      const result = PairwiseMLS.#result(response) as { event: MLSEvent };
      return result.event;
    });
  }
  async #checkGate(data: StoreData): Promise<void> {
    const raw = await data.read(this.#key);
    if (!raw || !bytesEqual(raw, canonicalStateBytes(this.#gate))) throw new MLSError('session_generation_mismatch');
  }
  #checkState(state: MLSState, generation: number): void {
    if (!isObj(state) || !Number.isSafeInteger(state.handle) || state.handle < 1 || state.handle !== this.#state.handle
      || state.local !== this.#gate.local || state.peer !== this.#gate.peer || state.signatureKey !== this.#gate.signatureKey
      || state.generation !== generation) throw new MLSError('invalid_engine_state');
  }
  #destroy(): void {
    this.#closed = true;
    try { PairwiseMLS.#call(this.engine, { op: 'close', handle: this.#state.handle }); } catch { /* No further use. */ }
  }
  static #call(engine: MLSEngine, command: Record<string, unknown>): CoreResponse {
    const raw = engine.execute(encoder.encode(JSON.stringify(command)));
    if (!(raw instanceof Uint8Array) || raw.length > MLS_MAX_ENGINE_IO_BYTES) throw new MLSError('invalid_engine_response');
    const value: unknown = JSON.parse(text.decode(raw));
    if (!isObj(value) || typeof value.ok !== 'boolean' || !('result' in value)
      || !(value.error === null || typeof value.error === 'string')) throw new MLSError('invalid_engine_response');
    return value as unknown as CoreResponse;
  }
  static #result(response: CoreResponse): unknown {
    if (!response.ok) throw new MLSError(response.error ?? 'session_failed');
    return response.result;
  }
}
