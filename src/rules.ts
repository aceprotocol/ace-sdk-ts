/** Profile rule hooks: the only place profile semantics (e.g. commerce state) enter the Inbox and Outbox. */
import { ACEError, asACEError } from './errors.js';
import type { JSONObject } from './types.js';

/** For `send`, `timestamp` is the time the Outbox entry was created. */
export interface RuleEvent {
  direction: 'send' | 'receive';
  from: string;
  to: string;
  messageId: string;
  timestamp: number;
  type: string;
  threadId?: string;
}

/** Internal: the event for a message; a null or undefined `threadId` means none. */
export function ruleEvent(direction: RuleEvent['direction'], m: Omit<RuleEvent, 'direction' | 'threadId'> & { threadId?: string | null }): RuleEvent {
  const { from, to, messageId, timestamp, type, threadId } = m;
  return { direction, from, to, messageId, timestamp, type, ...(threadId != null ? { threadId } : {}) };
}

/**
 * Rules for the message types a profile owns. `check` runs on send and on receive before anything is encrypted or
 * persisted and throws an `ACEError` to refuse (an inbound refusal is answered with a `rejected:<code>` receipt).
 * `commit` runs inside the persistence step: on receive with the delivery record; on send when the peer's `delivered`
 * receipt arrives (08 § Profile rules), never at enqueue. `commit` MUST be idempotent per `(direction, from, messageId)`:
 * crash recovery, a redelivered duplicate and a repeated receipt all run it again (06 § Crash recovery).
 */
export interface ProfileRules {
  types: readonly string[];
  check(event: RuleEvent, body: JSONObject): void | Promise<void>;
  commit(event: RuleEvent, body: JSONObject): void | Promise<void>;
}

/** Internal: the rules that own `type`. */
export function rulesFor(rules: readonly ProfileRules[], type: string): ProfileRules[] {
  return rules.filter((r) => r.types.includes(type));
}

/** Internal: run `check` of every owning rule; a non-ACE failure is `invalid_body`. */
export async function checkRules(rules: readonly ProfileRules[], event: RuleEvent, body: JSONObject): Promise<void> {
  for (const r of rulesFor(rules, event.type)) {
    try {
      await r.check(event, structuredClone(body));
    } catch (e) {
      if (e instanceof ACEError) throw e;
      throw new ACEError('invalid_body', 'profile rule rejected the message', { cause: e });
    }
  }
}

/** Internal: run `commit` of every owning rule; any failure is thrown as an ACEError (non-ACE: `storage_failed`). */
export async function commitRules(rules: readonly ProfileRules[], event: RuleEvent, body: JSONObject): Promise<void> {
  for (const r of rulesFor(rules, event.type)) {
    try {
      await r.commit(event, structuredClone(body));
    } catch (e) {
      throw asACEError(e, 'storage_failed');
    }
  }
}
