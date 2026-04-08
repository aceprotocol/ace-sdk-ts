import { describe, it, expect } from 'vitest';
import { ThreadStateMachine, InvalidTransitionError, validateThreadId } from '../src/state-machine.js';
import type { MessageType } from '../src/types.js';

function uuid(): string {
  return crypto.randomUUID();
}

const now = Math.floor(Date.now() / 1000);
const CONV_A = 'a'.repeat(64);
const CONV_B = 'b'.repeat(64);

describe('ThreadStateMachine', () => {
  // ============================================================
  // Standard Flow
  // ============================================================

  describe('standard flow', () => {
    it('completes full rfq → offer → accept → invoice → receipt → deliver → confirm', () => {
      const sm = new ThreadStateMachine();

      expect(sm.transition(CONV_A, 'deal-001', 'rfq', uuid(), now)).toBe('rfq');
      expect(sm.transition(CONV_A, 'deal-001', 'offer', uuid(), now)).toBe('offered');
      expect(sm.transition(CONV_A, 'deal-001', 'accept', uuid(), now)).toBe('accepted');
      expect(sm.transition(CONV_A, 'deal-001', 'invoice', uuid(), now)).toBe('invoiced');
      expect(sm.transition(CONV_A, 'deal-001', 'receipt', uuid(), now)).toBe('paid');
      expect(sm.transition(CONV_A, 'deal-001', 'deliver', uuid(), now)).toBe('delivered');
      expect(sm.transition(CONV_A, 'deal-001', 'confirm', uuid(), now)).toBe('confirmed');
    });
  });

  // ============================================================
  // Valid Variations
  // ============================================================

  describe('valid variations', () => {
    it('counter-offer: multiple offers before accept', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'offer', uuid(), now)).toBe('offered');
      expect(sm.transition(CONV_A, 't', 'offer', uuid(), now)).toBe('offered');
      expect(sm.transition(CONV_A, 't', 'accept', uuid(), now)).toBe('accepted');
    });

    it('reject after offer', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'reject', uuid(), now)).toBe('rejected');
      expect(sm.isTerminal(CONV_A, 't')).toBe(true);
    });

    it('deliver-first (trust-based, skip invoice/receipt)', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'deliver', uuid(), now)).toBe('delivered');
      expect(sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toBe('confirmed');
    });

    it('pre-paid: receipt directly after accept (no invoice)', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'receipt', uuid(), now)).toBe('paid');
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      sm.transition(CONV_A, 't', 'confirm', uuid(), now);
    });

  });

  // ============================================================
  // Real-World Commerce Scenarios
  // ============================================================

  describe('real-world scenarios', () => {
    it('SCENARIO: pre-paid API service — pay upfront, consume, confirm', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);

      // Pre-pay without invoice
      sm.transition(CONV_A, 't', 'receipt', uuid(), now);

      // Service delivered
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toBe('confirmed');
    });

    it('SCENARIO: free service (no payment involved)', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toBe('confirmed');
    });

    it('SCENARIO: counter-offer negotiation before deal', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now); // $100
      sm.transition(CONV_A, 't', 'offer', uuid(), now); // $80 counter
      sm.transition(CONV_A, 't', 'offer', uuid(), now); // $90 counter
      sm.transition(CONV_A, 't', 'accept', uuid(), now); // deal at $90
      sm.transition(CONV_A, 't', 'invoice', uuid(), now);
      sm.transition(CONV_A, 't', 'receipt', uuid(), now);
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toBe('confirmed');
    });
  });

  // ============================================================
  // Invalid Transitions
  // ============================================================

  describe('invalid transitions', () => {
    it('rejects offer before rfq', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 't', 'offer', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects accept before offer', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects reject before offer', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'reject', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects invoice before accept', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'invoice', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects deliver before accept', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'deliver', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects confirm before deliver', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects rfq after rfq (no double-rfq)', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects accept after accept', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects receipt before invoice or accept', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'receipt', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects going backwards: offer after accept', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'offer', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects going backwards: rfq after offer', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('rejects re-negotiation after accept (no rfq/offer/accept/reject)', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);

      expect(() => sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'offer', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'reject', uuid(), now)).toThrow(InvalidTransitionError);
    });
  });

  // ============================================================
  // Terminal State Enforcement
  // ============================================================

  describe('terminal state enforcement', () => {
    it('rejected is terminal — all economic messages blocked', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'reject', uuid(), now);

      const economicTypes: MessageType[] = [
        'rfq', 'offer', 'accept', 'reject', 'invoice',
        'receipt', 'deliver', 'confirm',
      ];
      for (const type of economicTypes) {
        expect(() => sm.transition(CONV_A, 't', type, uuid(), now)).toThrow(InvalidTransitionError);
      }
    });

    it('confirmed IS terminal', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      sm.transition(CONV_A, 't', 'confirm', uuid(), now);

      expect(sm.isTerminal(CONV_A, 't')).toBe(true);

      // No further economic transitions allowed
      expect(sm.canTransition(CONV_A, 't', 'invoice')).toBe(false);
      expect(sm.canTransition(CONV_A, 't', 'deliver')).toBe(false);
    });

    it('allows text/info after rejected', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'reject', uuid(), now);

      expect(sm.transition(CONV_A, 't', 'text', uuid(), now)).toBe('rejected');
      expect(sm.transition(CONV_A, 't', 'info', uuid(), now)).toBe('rejected');
    });
  });

  // ============================================================
  // Non-Economic Messages
  // ============================================================

  describe('non-economic messages', () => {
    it('text messages always allowed, never change state', () => {
      const sm = new ThreadStateMachine();

      expect(sm.transition(CONV_A, 't', 'text', uuid(), now)).toBe('idle');
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'text', uuid(), now)).toBe('rfq');
      expect(sm.getState(CONV_A, 't')).toBe('rfq');
    });

    it('info messages always allowed, never change state', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      expect(sm.transition(CONV_A, 't', 'info', uuid(), now)).toBe('offered');
    });

    it('text/info do not require valid threadId', () => {
      const sm = new ThreadStateMachine();
      expect(sm.transition(CONV_A, '', 'text', uuid(), now)).toBe('idle');
    });
  });

  // ============================================================
  // Conversation Isolation
  // ============================================================

  describe('conversation isolation', () => {
    it('same threadId in different conversations are independent', () => {
      const sm = new ThreadStateMachine();
      const threadId = 'deal-001';

      sm.transition(CONV_A, threadId, 'rfq', uuid(), now);
      sm.transition(CONV_A, threadId, 'offer', uuid(), now);

      expect(sm.getState(CONV_B, threadId)).toBe('idle');
      sm.transition(CONV_B, threadId, 'rfq', uuid(), now);

      expect(sm.getState(CONV_A, threadId)).toBe('offered');
      expect(sm.getState(CONV_B, threadId)).toBe('rfq');
    });

    it('different threadIds in same conversation are independent', () => {
      const sm = new ThreadStateMachine();

      sm.transition(CONV_A, 'deal-a', 'rfq', uuid(), now);
      sm.transition(CONV_A, 'deal-a', 'offer', uuid(), now);
      sm.transition(CONV_A, 'deal-b', 'rfq', uuid(), now);

      expect(sm.getState(CONV_A, 'deal-a')).toBe('offered');
      expect(sm.getState(CONV_A, 'deal-b')).toBe('rfq');
      expect(() => sm.transition(CONV_A, 'deal-b', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
    });
  });

  // ============================================================
  // ThreadId Validation
  // ============================================================

  describe('threadId validation', () => {
    it('rejects empty threadId for economic messages', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, '', 'rfq', uuid(), now)).toThrow(/must not be empty/);
    });

    it('rejects threadId exceeding max length', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'x'.repeat(257), 'rfq', uuid(), now)).toThrow(/exceeds max length/);
    });

    it('accepts threadId at exactly max length', () => {
      const sm = new ThreadStateMachine();
      expect(sm.transition(CONV_A, 'x'.repeat(256), 'rfq', uuid(), now)).toBe('rfq');
    });

    it('rejects threadId with null byte', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'deal\x00evil', 'rfq', uuid(), now)).toThrow(/control characters/);
    });

    it('rejects threadId with newline', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'deal\nevil', 'rfq', uuid(), now)).toThrow(/control characters/);
    });

    it('rejects threadId with tab', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'deal\tevil', 'rfq', uuid(), now)).toThrow(/control characters/);
    });

    it('rejects threadId with DEL character', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'deal\x7fevil', 'rfq', uuid(), now)).toThrow(/control characters/);
    });

    it('accepts unicode characters', () => {
      const sm = new ThreadStateMachine();
      expect(sm.transition(CONV_A, 'deal-交易-🤖', 'rfq', uuid(), now)).toBe('rfq');
    });

    it('accepts special printable characters', () => {
      const sm = new ThreadStateMachine();
      expect(sm.transition(CONV_A, 'deal-001/sub.task@2026', 'rfq', uuid(), now)).toBe('rfq');
    });
  });

  describe('validateThreadId (exported)', () => {
    it('throws on empty', () => {
      expect(() => validateThreadId('')).toThrow(/must not be empty/);
    });

    it('throws on control chars', () => {
      expect(() => validateThreadId('a\x00b')).toThrow(/control characters/);
    });

    it('passes for valid', () => {
      expect(() => validateThreadId('deal-001')).not.toThrow();
    });
  });

  // ============================================================
  // Composite Key Safety
  // ============================================================

  describe('composite key safety', () => {
    it('no collision between conversationId="a:b" threadId="c" and conversationId="a" threadId="b:c"', () => {
      const sm = new ThreadStateMachine();
      sm.transition('a:b', 'c', 'rfq', uuid(), now);
      expect(sm.getState('a:b', 'c')).toBe('rfq');
      expect(sm.getState('a', 'b:c')).toBe('idle');
    });

    it('no collision at length-prefix boundaries', () => {
      const sm = new ThreadStateMachine();
      sm.transition('ab', 'cd', 'rfq', uuid(), now);
      expect(sm.getState('a', 'b:cd')).toBe('idle');
      expect(sm.getState('ab:c', 'd')).toBe('idle');
    });
  });

  // ============================================================
  // canTransition
  // ============================================================

  describe('canTransition', () => {
    it('returns true for valid', () => {
      const sm = new ThreadStateMachine();
      expect(sm.canTransition(CONV_A, 'new', 'rfq')).toBe(true);
    });

    it('returns false for invalid', () => {
      const sm = new ThreadStateMachine();
      expect(sm.canTransition(CONV_A, 'new', 'offer')).toBe(false);
    });

    it('always true for non-economic', () => {
      const sm = new ThreadStateMachine();
      expect(sm.canTransition(CONV_A, 'any', 'text')).toBe(true);
      expect(sm.canTransition(CONV_A, 'any', 'info')).toBe(true);
    });

    it('false for invalid threadId', () => {
      const sm = new ThreadStateMachine();
      expect(sm.canTransition(CONV_A, '', 'rfq')).toBe(false);
    });

    it('false for terminal (rejected)', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'reject', uuid(), now);
      expect(sm.canTransition(CONV_A, 't', 'rfq')).toBe(false);
    });

    it('does not mutate state', () => {
      const sm = new ThreadStateMachine();
      sm.canTransition(CONV_A, 'new', 'rfq');
      expect(sm.getState(CONV_A, 'new')).toBe('idle');
    });
  });

  // ============================================================
  // allowedTypes
  // ============================================================

  describe('allowedTypes', () => {
    it('returns rfq for idle', () => {
      const sm = new ThreadStateMachine();
      expect(sm.allowedTypes(CONV_A, 'new')).toEqual(['rfq']);
    });

    it('returns offer for rfq', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(sm.allowedTypes(CONV_A, 't')).toEqual(['offer']);
    });

    it('returns accept, reject, offer for offered', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      const allowed = sm.allowedTypes(CONV_A, 't');
      expect(allowed).toContain('accept');
      expect(allowed).toContain('reject');
      expect(allowed).toContain('offer');
    });

    it('returns invoice, receipt, deliver for accepted', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      const allowed = sm.allowedTypes(CONV_A, 't');
      expect(allowed).toContain('invoice');
      expect(allowed).toContain('receipt');
      expect(allowed).toContain('deliver');
    });

    it('returns empty for confirmed (terminal)', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      sm.transition(CONV_A, 't', 'deliver', uuid(), now);
      sm.transition(CONV_A, 't', 'confirm', uuid(), now);
      expect(sm.allowedTypes(CONV_A, 't')).toEqual([]);
    });

    it('returns empty for rejected', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'reject', uuid(), now);
      expect(sm.allowedTypes(CONV_A, 't')).toEqual([]);
    });

  });

  // ============================================================
  // Snapshot & History
  // ============================================================

  describe('snapshot and history', () => {
    it('records message history', () => {
      const sm = new ThreadStateMachine();
      const id1 = uuid();
      const id2 = uuid();

      sm.transition(CONV_A, 't', 'rfq', id1, 1000);
      sm.transition(CONV_A, 't', 'offer', id2, 1001);

      const snap = sm.getSnapshot(CONV_A, 't');
      expect(snap.conversationId).toBe(CONV_A);
      expect(snap.threadId).toBe('t');
      expect(snap.state).toBe('offered');
      expect(snap.history).toHaveLength(2);
      expect(snap.history[0]).toEqual({ type: 'rfq', messageId: id1, timestamp: 1000 });
      expect(snap.history[1]).toEqual({ type: 'offer', messageId: id2, timestamp: 1001 });
    });

    it('returns idle snapshot for unknown', () => {
      const sm = new ThreadStateMachine();
      const snap = sm.getSnapshot(CONV_A, 'unknown');
      expect(snap.state).toBe('idle');
      expect(snap.history).toEqual([]);
    });
  });

  // ============================================================
  // Export / Import
  // ============================================================

  describe('export / import', () => {
    it('round-trips', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't1', 'rfq', uuid(), 1000);
      sm.transition(CONV_A, 't1', 'offer', uuid(), 1001);
      sm.transition(CONV_B, 't2', 'rfq', uuid(), 1002);

      const restored = ThreadStateMachine.fromExport(sm.export());

      expect(restored.getState(CONV_A, 't1')).toBe('offered');
      expect(restored.getState(CONV_B, 't2')).toBe('rfq');
      expect(restored.getSnapshot(CONV_A, 't1').history).toHaveLength(2);

      expect(() => restored.transition(CONV_A, 't1', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
      expect(restored.transition(CONV_A, 't1', 'accept', uuid(), now)).toBe('accepted');
    });

    it('exports empty as empty array', () => {
      expect(new ThreadStateMachine().export()).toEqual([]);
    });

    it('imports empty array', () => {
      const sm = ThreadStateMachine.fromExport([]);
      expect(sm.getState(CONV_A, 'any')).toBe('idle');
    });
  });

  // ============================================================
  // Remove
  // ============================================================

  describe('remove', () => {
    it('removes thread, resets to idle', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(sm.remove(CONV_A, 't')).toBe(true);
      expect(sm.getState(CONV_A, 't')).toBe('idle');
      expect(sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toBe('rfq');
    });

    it('returns false for non-existent', () => {
      const sm = new ThreadStateMachine();
      expect(sm.remove(CONV_A, 'x')).toBe(false);
    });

    it('only removes targeted thread', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 'keep', 'rfq', uuid(), now);
      sm.transition(CONV_A, 'remove', 'rfq', uuid(), now);
      sm.remove(CONV_A, 'remove');
      expect(sm.getState(CONV_A, 'keep')).toBe('rfq');
      expect(sm.getState(CONV_A, 'remove')).toBe('idle');
    });
  });

  // ============================================================
  // Attack Scenarios
  // ============================================================

  describe('attack scenarios', () => {
    it('ATTACK: state skip — idle to invoice', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 't', 'invoice', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: state skip — idle to accept', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 't', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: state skip — idle to deliver', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 't', 'deliver', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: state skip — idle to confirm', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 't', 'confirm', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: state skip — rfq to receipt', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      expect(() => sm.transition(CONV_A, 't', 'receipt', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: double-receipt in single cycle', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      sm.transition(CONV_A, 't', 'invoice', uuid(), now);
      sm.transition(CONV_A, 't', 'receipt', uuid(), now);
      // Cannot receipt again without new invoice
      expect(() => sm.transition(CONV_A, 't', 'receipt', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: terminal bypass — cannot reopen rejected deal', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'reject', uuid(), now);

      expect(() => sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'offer', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'invoice', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: cross-conversation hijack', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 'deal-001', 'rfq', uuid(), now);
      sm.transition(CONV_A, 'deal-001', 'offer', uuid(), now);

      // Attacker on different conversation can't accept
      expect(() => sm.transition(CONV_B, 'deal-001', 'accept', uuid(), now)).toThrow(InvalidTransitionError);
    });

    it('ATTACK: null byte injection', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'deal\x00-001', 'rfq', uuid(), now)).toThrow(/control characters/);
    });

    it('ATTACK: oversized threadId', () => {
      const sm = new ThreadStateMachine();
      expect(() => sm.transition(CONV_A, 'A'.repeat(10000), 'rfq', uuid(), now)).toThrow(/exceeds max length/);
    });

    it('ATTACK: re-negotiate after execution started', () => {
      const sm = new ThreadStateMachine();
      sm.transition(CONV_A, 't', 'rfq', uuid(), now);
      sm.transition(CONV_A, 't', 'offer', uuid(), now);
      sm.transition(CONV_A, 't', 'accept', uuid(), now);
      sm.transition(CONV_A, 't', 'invoice', uuid(), now);

      // Cannot go back to negotiation phase
      expect(() => sm.transition(CONV_A, 't', 'rfq', uuid(), now)).toThrow(InvalidTransitionError);
      expect(() => sm.transition(CONV_A, 't', 'offer', uuid(), now)).toThrow(InvalidTransitionError);
    });
  });

  // ============================================================
  // InvalidTransitionError properties
  // ============================================================

  describe('InvalidTransitionError', () => {
    it('exposes threadId, currentState, messageType', () => {
      const sm = new ThreadStateMachine();
      try {
        sm.transition(CONV_A, 'my-thread', 'offer', uuid(), now);
        expect.unreachable('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidTransitionError);
        const err = e as InvalidTransitionError;
        expect(err.threadId).toBe('my-thread');
        expect(err.currentState).toBe('idle');
        expect(err.messageType).toBe('offer');
        expect(err.name).toBe('InvalidTransitionError');
      }
    });
  });

  // ============================================================
  // Exhaustive: every MessageType × every state
  // ============================================================

  describe('exhaustive transition coverage', () => {
    const allEconomicTypes: MessageType[] = [
      'rfq', 'offer', 'accept', 'reject',
      'invoice', 'receipt',
      'deliver', 'confirm',
    ];

    function buildToState(sm: ThreadStateMachine, conv: string, thread: string, target: string): void {
      const paths: Record<string, MessageType[]> = {
        'idle': [],
        'rfq': ['rfq'],
        'offered': ['rfq', 'offer'],
        'accepted': ['rfq', 'offer', 'accept'],
        'invoiced': ['rfq', 'offer', 'accept', 'invoice'],
        'paid': ['rfq', 'offer', 'accept', 'invoice', 'receipt'],
        'delivered': ['rfq', 'offer', 'accept', 'invoice', 'receipt', 'deliver'],
        'confirmed': ['rfq', 'offer', 'accept', 'invoice', 'receipt', 'deliver', 'confirm'],
        'rejected': ['rfq', 'offer', 'reject'],
      };
      for (const type of paths[target]) {
        sm.transition(conv, thread, type, uuid(), now);
      }
    }

    const states = [
      'idle', 'rfq', 'offered', 'accepted',
      'invoiced', 'paid', 'delivered',
      'confirmed', 'rejected',
    ];

    for (const state of states) {
      for (const msgType of allEconomicTypes) {
        it(`${state} + ${msgType}: deterministic result`, () => {
          const sm = new ThreadStateMachine();
          const thread = `${state}-${msgType}`;
          buildToState(sm, CONV_A, thread, state);

          try {
            const result = sm.transition(CONV_A, thread, msgType, uuid(), now);
            expect(typeof result).toBe('string');
          } catch (e) {
            expect(e).toBeInstanceOf(InvalidTransitionError);
          }
        });
      }
    }
  });

  describe('fromExport thread count limit', () => {
    it('rejects import exceeding MAX_IMPORT_THREADS', () => {
      const huge = Array.from({ length: 100_001 }, (_, i) => ({
        conversationId: `c${i}`,
        threadId: `t${i}`,
        state: 'rfq' as const,
        history: [],
      }));
      expect(() => ThreadStateMachine.fromExport(huge)).toThrow(/too many threads/);
    });

    it('accepts import within MAX_IMPORT_THREADS', () => {
      const small = Array.from({ length: 3 }, (_, i) => ({
        conversationId: `c${i}`,
        threadId: `t${i}`,
        state: 'rfq' as const,
        history: [{ type: 'rfq' as const, messageId: crypto.randomUUID(), timestamp: Math.floor(Date.now() / 1000) }],
      }));
      expect(() => ThreadStateMachine.fromExport(small)).not.toThrow();
    });
  });
});
