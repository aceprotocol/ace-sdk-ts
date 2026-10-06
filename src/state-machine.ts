/** Thread state machine with parties, roles and fixed reference positions (04). */

import { ACEError } from './errors.js';
import { compareUtf8, isACEId, isConversationId, isMessageId, isThreadId, wireInt } from './encoding.js';
import type { MessageType } from './types.js';
import { isEconomicType, isMessageType } from './types.js';

export type ThreadState =
  | 'idle' | 'rfq' | 'offered' | 'accepted' | 'rejected' | 'invoiced' | 'paid' | 'delivered' | 'confirmed';

type Role = 'buyer' | 'seller';

/** (fromState, type) -> [toState, required sender role], in table order. */
const TRANSITIONS: ReadonlyArray<[ThreadState, MessageType, ThreadState, Role]> = [
  ['idle', 'rfq', 'rfq', 'buyer'],
  ['rfq', 'offer', 'offered', 'seller'],
  ['rfq', 'reject', 'rejected', 'seller'],
  ['offered', 'offer', 'offered', 'seller'],
  ['offered', 'accept', 'accepted', 'buyer'],
  ['offered', 'reject', 'rejected', 'buyer'],
  ['accepted', 'invoice', 'invoiced', 'seller'],
  ['accepted', 'receipt', 'paid', 'buyer'],
  ['accepted', 'deliver', 'delivered', 'seller'],
  ['invoiced', 'receipt', 'paid', 'buyer'],
  ['paid', 'deliver', 'delivered', 'seller'],
  ['delivered', 'confirm', 'confirmed', 'buyer'],
];
const TERMINAL: ReadonlySet<ThreadState> = new Set(['rejected', 'confirmed']);
const THREAD_STATES: ReadonlySet<string> = new Set(['idle', 'rfq', 'offered', 'accepted', 'rejected', 'invoiced', 'paid', 'delivered', 'confirmed']);
const REFERENCE_FIELDS: Partial<Record<MessageType, string>> = {
  accept: 'offerId', invoice: 'offerId', receipt: 'referenceId', confirm: 'deliverId',
};

export function isTerminalState(s: string): boolean {
  return TERMINAL.has(s as ThreadState);
}

export function isThreadState(s: unknown): s is ThreadState {
  return typeof s === 'string' && THREAD_STATES.has(s);
}

export interface ThreadEvent {
  conversationId: string;
  threadId?: string;
  type: MessageType;
  messageId: string;
  timestamp: number;
  from: string;
  to: string;
}

export interface ThreadHistoryEntry {
  type: MessageType;
  messageId: string;
  timestamp: number;
  from: string;
}

export interface ThreadSnapshot {
  conversationId: string;
  threadId: string;
  localAceId: string;
  peerAceId: string;
  state: ThreadState;
  history: ThreadHistoryEntry[];
}

export interface ThreadStateMachineOptions {
  localAceId: string;
  maxThreads?: number;
  maxHistoryPerThread?: number;
}

interface Thread {
  peer: string;
  state: ThreadState;
  history: ThreadHistoryEntry[];
}

function positiveInt(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1) {
    throw new ACEError('invalid_argument', `${what} must be a positive integer`);
  }
  return v;
}

function key(c: string, t: string): string {
  return `${c}\u0000${t}`;
}

/**
 * Per-(conversationId, threadId) economic flow seen from `localAceId`.
 * Bounds reject new work and never evict; `remove()` drops a thread explicitly.
 */
export class ThreadStateMachine {
  readonly localAceId: string;
  readonly #maxThreads: number;
  readonly #maxHistory: number;
  readonly #threads = new Map<string, Thread>();

  constructor(opts: ThreadStateMachineOptions) {
    if (typeof opts !== 'object' || opts === null || !isACEId(opts.localAceId)) {
      throw new ACEError('invalid_argument', 'localAceId must be an ACE ID');
    }
    this.localAceId = opts.localAceId;
    this.#maxThreads = positiveInt(opts.maxThreads ?? 100_000, 'maxThreads');
    this.#maxHistory = positiveInt(opts.maxHistoryPerThread ?? 1_000, 'maxHistoryPerThread');
  }

  /** Check order 1-7; returns the next state and the existing thread. */
  #decide(e: ThreadEvent, body: unknown, checkRefs = true): [ThreadState, Thread | undefined] {
    if (!isThreadId(e.threadId)) throw new ACEError('invalid_envelope', 'economic messages require a valid threadId');
    const local = this.localAceId;
    if ((local !== e.from && local !== e.to) || e.from === e.to) {
      throw new ACEError('wrong_party', 'the local identity is not exactly one party of this message');
    }
    const thread = this.#threads.get(key(e.conversationId, e.threadId));
    if (thread !== undefined) {
      const parties = new Set([local, thread.peer]);
      if (!parties.has(e.from) || !parties.has(e.to)) {
        throw new ACEError('wrong_party', 'message is not between the thread\'s two parties');
      }
    }
    const state: ThreadState = thread ? thread.state : 'idle';
    const rule = TERMINAL.has(state) ? undefined : TRANSITIONS.find(([s, t]) => s === state && t === e.type);
    if (rule === undefined) throw new ACEError('transition_not_allowed', `'${e.type}' is not allowed in state '${state}'`);
    const [, , next, role] = rule;
    if (thread !== undefined) {
      const senderRole: Role = e.from === thread.history[0].from ? 'buyer' : 'seller';
      if (senderRole !== role) throw new ACEError('wrong_role', `'${e.type}' in state '${state}' must come from the ${role}`);
    }
    const field = REFERENCE_FIELDS[e.type];
    if (checkRefs && field !== undefined) {
      const ref = typeof body === 'object' && body !== null ? (body as Record<string, unknown>)[field] : undefined;
      if (typeof ref !== 'string') throw new ACEError('invalid_body', `${e.type}.${field} is required`);
      const h = thread!.history;
      const expected = h[h.length - (e.type === 'invoice' ? 2 : 1)].messageId;
      if (ref !== expected) throw new ACEError('bad_reference', `${e.type}.${field} does not reference the required message`);
    }
    if (thread === undefined) {
      if (this.#threads.size >= this.#maxThreads) throw new ACEError('limit_exceeded', `thread limit ${this.#maxThreads} reached`);
    } else if (thread.history.length >= this.#maxHistory) {
      throw new ACEError('limit_exceeded', `thread history limit ${this.#maxHistory} reached`);
    }
    return [next, thread];
  }

  #commit(e: ThreadEvent, next: ThreadState, thread: Thread | undefined): void {
    const entry: ThreadHistoryEntry = { type: e.type, messageId: e.messageId, timestamp: e.timestamp, from: e.from };
    if (thread === undefined) {
      const peer = e.from === this.localAceId ? e.to : e.from;
      this.#threads.set(key(e.conversationId, e.threadId!), { peer, state: next, history: [entry] });
    } else {
      thread.state = next;
      thread.history.push(entry);
    }
  }

  static #checkEvent(e: unknown): ThreadEvent {
    if (typeof e !== 'object' || e === null) throw new ACEError('invalid_argument', 'expected a ThreadEvent');
    const ev = e as ThreadEvent;
    if (!isMessageType(ev.type)) throw new ACEError('invalid_envelope', 'unknown message type');
    return ev;
  }

  /** Throw the deterministic error `apply` would throw; never mutates. */
  check(e: ThreadEvent, body: unknown): void {
    const ev = ThreadStateMachine.#checkEvent(e);
    if (!isEconomicType(ev.type)) return;
    this.#decide(ev, body);
  }

  /** Check and apply; returns the resulting state (non-economic: the current state, `idle` without threadId). */
  apply(e: ThreadEvent, body: unknown): ThreadState {
    const ev = ThreadStateMachine.#checkEvent(e);
    if (!isEconomicType(ev.type)) {
      return typeof ev.threadId === 'string' ? this.getState(ev.conversationId, ev.threadId) : 'idle';
    }
    const [next, thread] = this.#decide(ev, body);
    this.#commit(ev, next, thread);
    return next;
  }

  getState(conversationId: string, threadId: string): ThreadState {
    return this.#threads.get(key(conversationId, threadId))?.state ?? 'idle';
  }

  getSnapshot(conversationId: string, threadId: string): ThreadSnapshot | null {
    const t = this.#threads.get(key(conversationId, threadId));
    if (t === undefined) return null;
    return {
      conversationId, threadId, localAceId: this.localAceId, peerAceId: t.peer, state: t.state,
      history: t.history.map((h) => ({ ...h })),
    };
  }

  /** Economic types `senderAceId` may send next, in table order (limits ignored). */
  allowedTypes(conversationId: string, threadId: string, senderAceId: string): MessageType[] {
    const t = this.#threads.get(key(conversationId, threadId));
    if (t === undefined) return ['rfq'];
    if ((senderAceId !== this.localAceId && senderAceId !== t.peer) || TERMINAL.has(t.state)) return [];
    const role: Role = senderAceId === t.history[0].from ? 'buyer' : 'seller';
    return TRANSITIONS.filter(([s, , , r]) => s === t.state && r === role).map(([, type]) => type);
  }

  isTerminal(conversationId: string, threadId: string): boolean {
    return TERMINAL.has(this.getState(conversationId, threadId));
  }

  remove(conversationId: string, threadId: string): boolean {
    return this.#threads.delete(key(conversationId, threadId));
  }

  exportState(): ThreadSnapshot[] {
    const out: ThreadSnapshot[] = [];
    for (const [k] of this.#threads) {
      const [c, t] = k.split('\u0000');
      out.push(this.getSnapshot(c, t)!);
    }
    return out.sort((a, b) => compareUtf8(a.conversationId, b.conversationId) || compareUtf8(a.threadId, b.threadId));
  }

  /**
   * Replay every snapshot's history under the party/role rules; any violation is
   * `invalid_argument`. Reference positions cannot be re-checked (bodies are not stored).
   */
  static fromState(snapshots: ThreadSnapshot[], opts: ThreadStateMachineOptions): ThreadStateMachine {
    const sm = new ThreadStateMachine(opts);
    const local = sm.localAceId;
    const bad = (msg: string) => new ACEError('invalid_argument', `fromState: ${msg}`);
    if (!Array.isArray(snapshots)) throw bad('snapshots must be an array');
    for (const snap of snapshots) {
      if (typeof snap !== 'object' || snap === null) throw bad('expected ThreadSnapshot entries');
      if (!isConversationId(snap.conversationId) || !isThreadId(snap.threadId)) throw bad('invalid conversationId or threadId');
      if (snap.localAceId !== local) throw bad('snapshot belongs to another local identity');
      if (!isACEId(snap.peerAceId) || snap.peerAceId === local) throw bad('invalid peerAceId');
      if (sm.#threads.has(key(snap.conversationId, snap.threadId))) throw bad('duplicate thread');
      if (!Array.isArray(snap.history) || snap.history.length === 0) throw bad('history must not be empty');
      for (const h of snap.history) {
        if (
          typeof h !== 'object' || h === null || !isEconomicType(h.type) || !isMessageId(h.messageId)
          || wireInt(h.timestamp) === null || (h.from !== local && h.from !== snap.peerAceId)
        ) {
          throw bad('invalid history entry');
        }
        const e: ThreadEvent = {
          conversationId: snap.conversationId, threadId: snap.threadId, type: h.type, messageId: h.messageId,
          timestamp: h.timestamp, from: h.from, to: h.from === local ? snap.peerAceId : local,
        };
        let decided: [ThreadState, Thread | undefined];
        try {
          decided = sm.#decide(e, null, false);
        } catch (err) {
          throw bad(err instanceof ACEError ? err.message : String(err));
        }
        sm.#commit(e, decided[0], decided[1]);
      }
      if (sm.getState(snap.conversationId, snap.threadId) !== snap.state) {
        throw bad('declared state does not match the replayed history');
      }
    }
    return sm;
  }
}
