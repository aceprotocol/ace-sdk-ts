// Principal binding (09-principal): types, bodies, records, rules, pipeline.
import { describe, expect, it } from 'vitest';
import { ACEError, ECONOMIC_TYPES, MESSAGE_TYPES, validateBody } from '../src/index.js';
import { PRINCIPAL_TYPES, isEconomicType, isPrincipalType } from '../src/types.js';
import { codeOf } from './helpers.js';

const CONV = 'ab'.repeat(32);
const MID = '00000000-0000-4000-8000-000000000001';

describe('principal types and bodies', () => {
  it('type lists', () => {
    expect(MESSAGE_TYPES.slice(-3)).toEqual(['request', 'decision', 'report']);
    expect(MESSAGE_TYPES).toHaveLength(13);
    expect(ECONOMIC_TYPES).toHaveLength(8);
    expect(PRINCIPAL_TYPES).toEqual(['request', 'decision', 'report']);
    for (const t of PRINCIPAL_TYPES) expect(isPrincipalType(t) && !isEconomicType(t)).toBe(true);
    expect(isPrincipalType('text')).toBe(false);
  });

  it('error codes are permanent', () => {
    expect(new ACEError('invalid_principal').category).toBe('permanent');
    expect(new ACEError('wrong_principal').isTransient).toBe(false);
  });

  it.each([
    ['request', { action: 'pay', summary: 'Pay 1 USDC' }],
    ['request', { action: 'x402.pay', summary: 's', amount: '1', currency: 'USDC', ttl: 60, details: { payTo: 'x' }, ref: { conversationId: CONV, messageId: MID, threadId: 't' } }],
    ['request', { action: 'a', summary: 's', ref: { conversationId: CONV, messageId: MID, threadId: null } }],
    ['decision', { requestId: MID, outcome: 'approve' }],
    ['decision', { requestId: MID, outcome: 'deny', reason: 'no', result: { x: 1 } }],
    ['report', { action: 'pay', summary: 'paid', outcome: 'skipped', proof: {}, requestId: MID }],
  ] as const)('valid %s %j', (t, body) => {
    expect(codeOf(() => validateBody(t, body as any))).toBe('ok');
  });

  it.each([
    ['request', { action: 'a' }],
    ['request', { action: 'a', summary: 's', details: 'x' }],
    ['request', { action: 'a', summary: 's', ttl: 1.5 }],
    ['request', { action: 'a', summary: 's', ref: [] }],
    ['request', { action: 'a', summary: 's', ref: { conversationId: CONV.toUpperCase(), messageId: MID } }],
    ['request', { action: 'a', summary: 's', ref: { conversationId: CONV, messageId: '0000000A-0000-4000-8000-00000000000A' } }],
    ['request', { action: 'a', summary: 's', ref: { conversationId: CONV } }],
    ['request', { action: 'a', summary: 's', ref: { conversationId: CONV, messageId: MID, threadId: '' } }],
    ['decision', { requestId: MID, outcome: 'maybe' }],
    ['decision', { requestId: MID, outcome: 'APPROVE' }],
    ['decision', { requestId: MID, outcome: 'approve', result: [] }],
    ['report', { action: 'a', summary: 's', outcome: 'done' }],
    ['report', { action: 'a', summary: 's', outcome: 'ok', proof: 'x' }],
  ] as const)('invalid %s %j', (t, body) => {
    expect(codeOf(() => validateBody(t, body as any))).toBe('invalid_body');
  });
});
