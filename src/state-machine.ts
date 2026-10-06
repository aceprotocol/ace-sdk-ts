import type { MessageType } from './types.js';
import { isEconomicType, ECONOMIC_TYPES } from './types.js';

// === Thread States ===

export type ThreadState =
  | 'idle'       // No messages yet
  | 'rfq'        // RFQ sent/received
  | 'offered'    // Offer on the table
  | 'accepted'   // Offer accepted, awaiting settlement/delivery
  | 'rejected'   // Terminal: offer rejected
  | 'invoiced'   // Invoice issued, awaiting payment
  | 'paid'       // Payment confirmed, awaiting delivery
  | 'delivered'  // Work delivered, awaiting confirmation
  | 'confirmed'; // Terminal: deal complete

// === Transition Table ===

type TransitionKey = `${ThreadState}:${MessageType}`;

const TRANSITIONS: ReadonlyMap<TransitionKey, ThreadState> = new Map([
  // === Phase 1: Negotiation (linear, no loops) ===
  ['idle:rfq', 'rfq'],
  ['rfq:offer', 'offered'],
  ['offered:accept', 'accepted'],
  ['offered:reject', 'rejected'],
  ['offered:offer', 'offered'],       // Counter-offer

  // === Phase 2: Execution (linear, single round) ===

  // Settlement
  ['accepted:invoice', 'invoiced'],
  ['accepted:receipt', 'paid'],       // Pre-paid (no invoice needed)
  ['invoiced:receipt', 'paid'],

  // Delivery
  ['accepted:deliver', 'delivered'],   // Deliver-first (trust-based)
  ['paid:deliver', 'delivered'],       // Standard: deliver after payment
  ['delivered:confirm', 'confirmed'],
]);

// Rejected and confirmed are terminal — no outgoing economic transitions.
const TERMINAL_STATES: ReadonlySet<ThreadState> = new Set([
  'rejected',
  'confirmed',
]);

// === Validation ===

import { sanitizeForError, codePointLength, CONTROL_CHAR_PATTERN } from './utils.js';

const MAX_THREAD_ID_LENGTH = 256;

export function validateThreadId(threadId: string): void {
  if (typeof threadId !== 'string') {
    throw new Error('threadId must be a string');
  }
  if (threadId.length === 0) {
    throw new Error('threadId must not be empty');
  }
  if (codePointLength(threadId) > MAX_THREAD_ID_LENGTH) {
    throw new Error(`threadId exceeds max length of ${MAX_THREAD_ID_LENGTH} characters`);
  }
  if (CONTROL_CHAR_PATTERN.test(threadId)) {
    throw new Error('threadId must not contain control characters');
  }
}

// === Error ===

export class InvalidTransitionError extends Error {
  constructor(
    public readonly threadId: string,
    public readonly currentState: ThreadState,
    public readonly messageType: MessageType,
  ) {
    super(
      `Invalid transition: cannot process '${messageType}' in state '${currentState}' (thread: ${sanitizeForError(threadId)})`,
    );
    this.name = 'InvalidTransitionError';
  }
}

// === State Machine ===

interface ThreadEntry {
  conversationId: string;
  threadId: string;
  state: ThreadState;
  history: Array<{ type: MessageType; messageId: string; timestamp: number }>;
}

export interface ThreadSnapshot {
  conversationId: string;
  threadId: string;
  state: ThreadState;
  history: ReadonlyArray<{ type: MessageType; messageId: string; timestamp: number }>;
}

export interface ThreadStateMachineOptions {
  /** Maximum number of tracked threads (default 100,000). */
  maxThreads?: number;
  /** Maximum history entries per thread (default 1,000). */
  maxHistoryPerThread?: number;
}

/**
 * Resource limits are enforced by rejecting, never by evicting: forgetting a
 * thread would let a finished (terminal) deal be reopened from `idle`.
 */
export class ThreadStateMachine {
  private threads: Map<string, ThreadEntry>;
  readonly maxThreads: number;
  readonly maxHistoryPerThread: number;

  constructor(opts: ThreadStateMachineOptions = {}) {
    this.maxThreads = opts.maxThreads ?? 100_000;
    this.maxHistoryPerThread = opts.maxHistoryPerThread ?? 1_000;
    if (!Number.isSafeInteger(this.maxThreads) || this.maxThreads < 1) {
      throw new Error('maxThreads must be a positive integer');
    }
    if (!Number.isSafeInteger(this.maxHistoryPerThread) || this.maxHistoryPerThread < 1) {
      throw new Error('maxHistoryPerThread must be a positive integer');
    }
    this.threads = new Map();
  }

  // Length-prefixed composite key prevents collision between
  // conversationId="a:b" threadId="c" vs conversationId="a" threadId="b:c"
  private compositeKey(conversationId: string, threadId: string): string {
    return `${conversationId.length}:${conversationId}:${threadId}`;
  }

  /**
   * Validate and apply a state transition for a thread.
   * Non-economic messages (text, info) are always allowed and do not change state.
   * Returns the new state after transition.
   *
   * @throws InvalidTransitionError if the transition is not allowed
   * @throws Error if threadId is invalid or a resource limit is reached
   */
  transition(
    conversationId: string,
    threadId: string,
    messageType: MessageType,
    messageId: string,
    timestamp: number,
  ): ThreadState {
    if (!isEconomicType(messageType)) {
      return this.getState(conversationId, threadId);
    }

    validateThreadId(threadId);

    const key = this.compositeKey(conversationId, threadId);
    const thread = this.threads.get(key);
    const currentState: ThreadState = thread?.state ?? 'idle';

    if (TERMINAL_STATES.has(currentState)) {
      throw new InvalidTransitionError(threadId, currentState, messageType);
    }

    const transitionKey: TransitionKey = `${currentState}:${messageType}`;
    const nextState = TRANSITIONS.get(transitionKey);

    if (nextState === undefined) {
      throw new InvalidTransitionError(threadId, currentState, messageType);
    }
    this.checkLimits(thread);

    if (!thread) {
      this.threads.set(key, {
        conversationId,
        threadId,
        state: nextState,
        history: [{ type: messageType, messageId, timestamp }],
      });
    } else {
      thread.state = nextState;
      thread.history.push({ type: messageType, messageId, timestamp });
    }

    return nextState;
  }

  /**
   * Check if a transition would be valid without applying it.
   */
  canTransition(conversationId: string, threadId: string, messageType: MessageType): boolean {
    if (!isEconomicType(messageType)) {
      return true;
    }

    try {
      validateThreadId(threadId);
    } catch {
      return false;
    }

    const thread = this.threads.get(this.compositeKey(conversationId, threadId));
    const currentState: ThreadState = thread?.state ?? 'idle';

    if (TERMINAL_STATES.has(currentState)) {
      return false;
    }

    const key: TransitionKey = `${currentState}:${messageType}`;
    if (!TRANSITIONS.has(key)) {
      return false;
    }
    try {
      this.checkLimits(thread);
    } catch {
      return false;
    }
    return true;
  }

  private checkLimits(thread: ThreadEntry | undefined): void {
    if (!thread && this.threads.size >= this.maxThreads) {
      throw new Error(`Thread limit reached (${this.maxThreads})`);
    }
    if (thread && thread.history.length >= this.maxHistoryPerThread) {
      throw new Error(`Thread history exceeds maximum of ${this.maxHistoryPerThread} entries`);
    }
  }

  getState(conversationId: string, threadId: string): ThreadState {
    return this.threads.get(this.compositeKey(conversationId, threadId))?.state ?? 'idle';
  }

  getSnapshot(conversationId: string, threadId: string): ThreadSnapshot {
    const thread = this.threads.get(this.compositeKey(conversationId, threadId));
    return {
      conversationId,
      threadId,
      state: thread?.state ?? 'idle',
      history: thread ? copyHistory(thread.history) : [],
    };
  }

  allowedTypes(conversationId: string, threadId: string): MessageType[] {
    const currentState = this.getState(conversationId, threadId);

    if (TERMINAL_STATES.has(currentState)) {
      return [];
    }

    const allowed: MessageType[] = [];
    for (const [transKey] of TRANSITIONS) {
      const colonIdx = transKey.indexOf(':');
      const state = transKey.slice(0, colonIdx) as ThreadState;
      const type = transKey.slice(colonIdx + 1) as MessageType;
      if (state === currentState) {
        allowed.push(type);
      }
    }
    return allowed;
  }

  isTerminal(conversationId: string, threadId: string): boolean {
    return TERMINAL_STATES.has(this.getState(conversationId, threadId));
  }

  remove(conversationId: string, threadId: string): boolean {
    return this.threads.delete(this.compositeKey(conversationId, threadId));
  }

  export(): ThreadSnapshot[] {
    const snapshots: ThreadSnapshot[] = [];
    for (const [, thread] of this.threads) {
      snapshots.push({
        conversationId: thread.conversationId,
        threadId: thread.threadId,
        state: thread.state,
        history: copyHistory(thread.history),
      });
    }
    return snapshots;
  }

  // Derived from TRANSITIONS map + TERMINAL_STATES — no manual sync needed
  private static readonly VALID_STATES: ReadonlySet<string> = new Set<string>([
    'idle',
    ...TERMINAL_STATES,
    ...Array.from(TRANSITIONS.values()),
  ]);

  static fromExport(snapshots: ThreadSnapshot[], opts: ThreadStateMachineOptions = {}): ThreadStateMachine {
    const sm = new ThreadStateMachine(opts);
    if (!Array.isArray(snapshots) || snapshots.length > sm.maxThreads) {
      throw new Error(`fromExport: too many threads, max is ${sm.maxThreads}`);
    }
    for (const snap of snapshots) {
      if (!ThreadStateMachine.VALID_STATES.has(snap.state)) {
        throw new Error(`fromExport: invalid state '${String(snap.state).slice(0, 32)}'`);
      }
      validateThreadId(snap.threadId);
      if (typeof snap.conversationId !== 'string' || snap.conversationId === ''
        || codePointLength(snap.conversationId) > 256) {
        throw new Error('fromExport: invalid conversationId');
      }
      if (!Array.isArray(snap.history) || snap.history.length === 0) {
        throw new Error('fromExport: history must be a non-empty array');
      }
      if (snap.history.length > sm.maxHistoryPerThread) {
        throw new Error(`fromExport: history too large (${snap.history.length})`);
      }

      // Replay the history to verify it represents a valid transition sequence
      let replayState: ThreadState = 'idle';
      for (const entry of snap.history) {
        if (typeof entry?.messageId !== 'string') {
          throw new Error('fromExport: invalid history entry');
        }
        if (!Number.isSafeInteger(entry.timestamp) || entry.timestamp < 0) {
          throw new Error('fromExport: invalid history entry timestamp');
        }
        if (!ECONOMIC_TYPES.has(entry.type)) {
          throw new Error(`fromExport: unknown message type '${String(entry.type).slice(0, 32)}' in thread history`);
        }
        const transitionKey = `${replayState}:${entry.type}` as TransitionKey;
        const nextState = TRANSITIONS.get(transitionKey);
        if (nextState === undefined) {
          throw new Error(`fromExport: invalid transition '${entry.type}' from state '${replayState}'`);
        }
        replayState = nextState;
      }

      // Final replayed state must match the declared state
      if (replayState !== snap.state) {
        throw new Error(
          `fromExport: declared state '${snap.state}' does not match history replay '${replayState}'`,
        );
      }

      const key = sm.compositeKey(snap.conversationId, snap.threadId);
      if (sm.threads.has(key)) {
        throw new Error('fromExport: duplicate thread');
      }
      sm.threads.set(key, {
        conversationId: snap.conversationId,
        threadId: snap.threadId,
        state: snap.state,
        history: copyHistory(snap.history),
      });
    }
    return sm;
  }
}

function copyHistory(history: ThreadSnapshot['history']): ThreadEntry['history'] {
  return history.map(({ type, messageId, timestamp }) => ({ type, messageId, timestamp }));
}
