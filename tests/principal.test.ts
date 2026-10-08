// Principal binding (09-principal): types, bodies, records, rules, pipeline.
import { describe, expect, it } from 'vitest';
import {
  ACEError, ECONOMIC_TYPES, MESSAGE_TYPES, MemoryStore, PeerStore, SoftwareIdentity, createRegistrationFile, createRegistrationRequest,
  validateBody, verifyPeerRecord, verifyRegistrationFile, verifyRegistrationRequest,
} from '../src/index.js';
import { canonicalStateBytes, pairKey, toBase64, utf8 } from '../src/encoding.js';
import {
  PRINCIPAL_ROLES, checkPrincipalRules, createPrincipalRecord, fillDecision, isCaip10, loadRequestRecord, openRequestTo,
  parsePrincipalRecord, principalPayload, principalSignData, principalSignerFromIdentity, recordRequest, requestKey,
  senderPrincipalUsable, validatePrincipalRecord, type PrincipalContext,
} from '../src/principal.js';
import { buildSignData, encodePayload, signingAddress } from '../src/signing.js';
import { PRINCIPAL_TYPES, isEconomicType, isPrincipalType, type ParsedMessage, type PrincipalKey, type PrincipalRecord } from '../src/types.js';
import { codeOf, expectCode } from './helpers.js';

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

const ACC = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
const NOW = 1_800_000_000;
const MAX_LIFE = 31_622_400;

type RecOpts = Partial<{ roles: any; scope: string | null; expiresAt: number; issuedAt: number; account: string }>;

async function rec(owner: SoftwareIdentity, subject: SoftwareIdentity, o: RecOpts = {}): Promise<PrincipalRecord> {
  return createPrincipalRecord(principalSignerFromIdentity(owner), {
    subjectSigningPublicKey: subject.getSigningPublicKey(), account: o.account ?? ACC,
    roles: o.roles ?? ['agent', 'controller', 'agent'], scope: o.scope, expiresAt: o.expiresAt ?? NOW + 3600,
    issuedAt: o.issuedAt ?? NOW - 10,
  });
}

const keyOf = (id: SoftwareIdentity): PrincipalKey => ({ scheme: id.getSigningScheme(), publicKey: toBase64(id.getSigningPublicKey()) });

describe('principal records', () => {
  it('constants and CAIP-10', () => {
    expect(PRINCIPAL_ROLES).toEqual(['controller', 'agent']);
    expect(isCaip10(ACC)).toBe(true);
    expect(isCaip10('eip155:1:0xabc')).toBe(true);
    for (const v of ['solana:abc', 'SOL:x:y', 'ab:x:y', `a:b:${'c'.repeat(129)}`, 1, null, `${ACC}\n`]) expect(isCaip10(v)).toBe(false);
  });

  it.each(['ed25519', 'secp256k1'] as const)('create and validate (%s signer)', async (scheme) => {
    const owner = await SoftwareIdentity.generate(scheme);
    const subject = await SoftwareIdentity.generate('ed25519');
    const r = await rec(owner, subject, { scope: 'copy:solana,hl', expiresAt: NOW + 3600 });
    expect(r.roles).toEqual(['controller', 'agent']);
    expect(r.expiresAt).toBe(NOW + 3600);
    expect(validatePrincipalRecord(JSON.parse(JSON.stringify(r)), subject.getSigningPublicKey(), NOW)).toEqual(r);
    const spk = subject.getSigningPublicKey();
    expect(principalPayload(r, spk)).toEqual(
      encodePayload(ACC, 'controller,agent', scheme, r.signer.publicKey, toBase64(spk), 'copy:solana,hl', String(NOW + 3600)));
    expect(principalSignData(r, spk)).toEqual(buildSignData('principal', subject.getACEId(), NOW - 10, principalPayload(r, spk)));
  });

  it('scope null is absent, unknown members ignored, roles canonicalized', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('secp256k1');
    const r = await rec(owner, subject, { scope: null, roles: ['agent'] });
    expect('scope' in r).toBe(false);
    expect(r.roles).toEqual(['agent']);
    const spk = subject.getSigningPublicKey();
    expect(validatePrincipalRecord({ ...r, scope: null, extra: { x: 1 } }, spk, NOW)).toEqual(r);
    expect(parsePrincipalRecord({ ...r, extra: 1 })).toEqual(r);
    const r2 = await rec(owner, subject, { roles: ['controller', 'controller'] });
    expect(r2.roles).toEqual(['controller']);
  });

  it('local creation errors', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('ed25519');
    await expectCode(rec(owner, subject, { roles: ['owner'] }), 'invalid_argument');
    await expectCode(rec(owner, subject, { roles: 'agent' }), 'invalid_argument');
    await expectCode(rec(owner, subject, { roles: [] }), 'invalid_principal');
    await expectCode(rec(owner, subject, { account: 'solana:abc' }), 'invalid_principal');
    await expectCode(rec(owner, subject, { expiresAt: NOW - 10 }), 'invalid_principal');
    await expectCode(rec(owner, subject, { expiresAt: NOW - 10 + MAX_LIFE + 1 }), 'invalid_principal');
    await expectCode(rec(owner, subject, { scope: '' }), 'invalid_principal');
    // The signer is not asked to sign an invalid draft.
    let calls = 0;
    const signer = { ...principalSignerFromIdentity(owner), sign: async (d: Uint8Array) => { calls++; return owner.sign(d); } };
    await expectCode(createPrincipalRecord(signer, {
      subjectSigningPublicKey: subject.getSigningPublicKey(), account: ACC, roles: ['agent'], expiresAt: NOW, issuedAt: NOW,
    }), 'invalid_principal');
    expect(calls).toBe(0);
    expect(await createPrincipalRecord(signer, {
      subjectSigningPublicKey: subject.getSigningPublicKey(), account: ACC, roles: ['agent'], expiresAt: NOW + MAX_LIFE - 1, issuedAt: NOW - 1,
    })).toMatchObject({ roles: ['agent'] });
    expect(calls).toBe(1);
  });

  it.each([
    (d: any) => { d.account = 'solana:abc'; },
    (d: any) => { delete d.account; },
    (d: any) => { d.roles = []; },
    (d: any) => { d.roles = ['agent', 'controller']; },
    (d: any) => { d.roles = ['controller', 'controller']; },
    (d: any) => { d.roles = ['controller,agent']; },
    (d: any) => { d.roles = ['owner']; },
    (d: any) => { d.roles = 'agent'; },
    (d: any) => { delete d.signer; },
    (d: any) => { d.signer.scheme = 'p256'; },
    (d: any) => { d.signer.publicKey = 'QQ=='; },
    (d: any) => { d.issuedAt = '1'; },
    (d: any) => { d.issuedAt = NOW + 301; },
    (d: any) => { delete d.expiresAt; },
    (d: any) => { d.expiresAt = null; },
    (d: any) => { d.expiresAt = String(d.expiresAt); },
    (d: any) => { d.expiresAt = d.issuedAt; },
    (d: any) => { d.scope = ''; },
    (d: any) => { d.scope = 'x'.repeat(257); },
    (d: any) => { d.scope = 'a\nb'; },
    (d: any) => { d.scope = 'a\x7fb'; },
    (d: any) => { d.scope = 5; },
    (d: any) => { d.scope = 'changed'; },
    (d: any) => { delete d.scope; },
    (d: any) => { d.expiresAt += 1; },
    (d: any) => { delete d.signature; },
    (d: any) => { d.signature = '0x' + '11'.repeat(65); },
  ])('invalid record %#', async (m) => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('ed25519');
    const d: any = JSON.parse(JSON.stringify(await rec(owner, subject, { scope: 's', expiresAt: NOW + 10 })));
    m(d);
    expect(codeOf(() => validatePrincipalRecord(d, subject.getSigningPublicKey(), NOW))).toBe('invalid_principal');
  });

  it.each([null, [], 'x', 1])('non-object record %j', (d) => {
    expect(codeOf(() => validatePrincipalRecord(d, new Uint8Array(32), NOW))).toBe('invalid_principal');
  });

  it('scope counts code points; lifetime bound; subject mismatch and time bounds', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('ed25519');
    const other = await SoftwareIdentity.generate('ed25519');
    expect((await rec(owner, subject, { scope: '😀'.repeat(256) })).scope).toHaveLength(512);
    await expectCode(rec(owner, subject, { scope: '😀'.repeat(257) }), 'invalid_principal');
    const full = await rec(owner, subject, { issuedAt: NOW - 10, expiresAt: NOW - 10 + MAX_LIFE });
    expect(full.expiresAt - full.issuedAt).toBe(MAX_LIFE);
    const r = await rec(owner, subject, { expiresAt: NOW + 10 });
    expect(codeOf(() => validatePrincipalRecord(r, other.getSigningPublicKey(), NOW))).toBe('invalid_principal');
    expect(codeOf(() => validatePrincipalRecord(r, subject.getSigningPublicKey(), NOW + 10))).toBe('invalid_principal');
    expect(codeOf(() => validatePrincipalRecord(r, subject.getSigningPublicKey(), NOW + 9))).toBe('ok');
    const future = await rec(owner, subject, { issuedAt: NOW + 300, expiresAt: NOW + 600 });
    expect(codeOf(() => validatePrincipalRecord(future, subject.getSigningPublicKey(), NOW))).toBe('ok');
    expect(codeOf(() => validatePrincipalRecord(future, subject.getSigningPublicKey(), NOW - 1))).toBe('invalid_principal');
  });
});

describe('same-account rules', () => {
  async function setup() {
    const owner = await SoftwareIdentity.generate('ed25519');
    const ctrl = await SoftwareIdentity.generate('ed25519');
    const ctrl2 = await SoftwareIdentity.generate('secp256k1');
    const agentId = await SoftwareIdentity.generate('secp256k1');
    const pCtrl = await rec(owner, ctrl, { roles: ['controller'] });
    const pCtrl2 = await rec(owner, ctrl2, { roles: ['controller'] });
    const pAgent = await rec(owner, agentId, { roles: ['agent'] });
    const open = new Map<string, string>([[MID, ctrl.getACEId()]]);
    const ctx: PrincipalContext = {
      account: ACC, selfSigner: keyOf(owner),
      openRequestTo: (c, r) => (c === CONV ? open.get(r) ?? null : null),
    };
    const chk = (t: any, body: any, p: unknown, key: SoftwareIdentity, o: Partial<{ account: string | null; selfSigner: PrincipalKey; trustedSigners: PrincipalKey[]; now: number }> = {}) =>
      checkPrincipalRules(t, body, {
        conversationId: CONV, senderPrincipal: p, senderSigningPublicKey: key.getSigningPublicKey(),
        selfAccount: o.account === undefined ? ACC : o.account, openRequestTo: ctx.openRequestTo, now: o.now ?? NOW,
        selfSigner: 'selfSigner' in o ? o.selfSigner : ctx.selfSigner, trustedSigners: o.trustedSigners,
      });
    return { owner, ctrl, ctrl2, agentId, pCtrl, pCtrl2, pAgent, ctx, chk, open };
  }
  const req = { action: 'pay', summary: 's' };

  it('steps 1-7', async () => {
    const { ctrl, ctrl2, agentId, pCtrl, pCtrl2, pAgent, chk } = await setup();
    await chk('request', req, pAgent, agentId);
    await chk('report', { ...req, outcome: 'ok' }, pCtrl, ctrl);
    await chk('request', req, pCtrl, ctrl);
    await expectCode(chk('text', { message: 'x' }, pAgent, agentId), 'invalid_argument');
    await expectCode(chk('request', req, pAgent, agentId, { account: null }), 'wrong_principal');
    await expectCode(chk('request', req, null, agentId), 'wrong_principal');
    await expectCode(chk('request', req, undefined, agentId), 'wrong_principal');
    await expectCode(chk('request', req, pAgent, ctrl), 'wrong_principal');
    await expectCode(chk('request', req, pAgent, agentId, { now: pAgent.expiresAt }), 'wrong_principal');
    await expectCode(chk('request', req, pAgent, agentId, { account: 'eip155:1:0xabc' }), 'wrong_principal');
    await expectCode(chk('decision', { requestId: MID, outcome: 'approve' }, pAgent, agentId), 'wrong_principal');
    await expectCode(chk('decision', { requestId: '00000000-0000-4000-8000-000000000009', outcome: 'approve' }, pCtrl, ctrl), 'bad_reference');
    // R-P22: another controller of the same account is not the request's `to`.
    await expectCode(chk('decision', { requestId: MID, outcome: 'approve' }, pCtrl2, ctrl2), 'wrong_principal');
    await chk('decision', { requestId: MID, outcome: 'approve' }, pCtrl, ctrl);
  });

  it('decision without a ledger lookup is bad_reference; async lookup works', async () => {
    const { ctrl, pCtrl, owner } = await setup();
    const body = { requestId: MID, outcome: 'deny' };
    const base = { conversationId: CONV, senderPrincipal: pCtrl, senderSigningPublicKey: ctrl.getSigningPublicKey(), selfAccount: ACC, now: NOW, selfSigner: keyOf(owner) };
    await expectCode(checkPrincipalRules('decision', body, base), 'bad_reference');
    await checkPrincipalRules('decision', body, { ...base, openRequestTo: async () => ctrl.getACEId() });
    let seen: unknown[] = [];
    await expectCode(checkPrincipalRules('decision', body, { ...base, openRequestTo: (...a) => { seen = a; return null; } }), 'bad_reference');
    expect(seen).toEqual([CONV, MID, NOW]);
  });

  it('R-P21 signer binding', async () => {
    const { owner, agentId, pAgent, chk } = await setup();
    // Fail closed without selfSigner / trustedSigners for a non-eip155 account.
    await expectCode(chk('request', req, pAgent, agentId, { selfSigner: undefined }), 'wrong_principal');
    await chk('request', req, pAgent, agentId, { selfSigner: undefined, trustedSigners: [keyOf(owner)] });
    // A forged record: another key claims the same account string.
    const forger = await SoftwareIdentity.generate('ed25519');
    const forged = await rec(forger, agentId, { roles: ['agent'] });
    await expectCode(chk('request', req, forged, agentId), 'wrong_principal');
    await expectCode(chk('request', req, forged, agentId, { trustedSigners: [keyOf(owner)] }), 'wrong_principal');
    // Signer binding precedes the account comparison (both fail -> still wrong_principal).
    const other = await rec(forger, agentId, { roles: ['agent'], account: 'solana:abcd:x' });
    await expectCode(chk('request', req, other, agentId), 'wrong_principal');
  });

  it('R-P21 eip155 address derivation (case-insensitive)', async () => {
    const root = await SoftwareIdentity.generate('secp256k1');
    const edRoot = await SoftwareIdentity.generate('ed25519');
    const agentId = await SoftwareIdentity.generate('ed25519');
    const addr = signingAddress('secp256k1', root.getSigningPublicKey());
    for (const a of [addr, addr.toLowerCase(), '0x' + addr.slice(2).toUpperCase()]) {
      const account = `eip155:8453:${a}`;
      const p = await rec(root, agentId, { roles: ['agent'], account });
      await checkPrincipalRules('request', req, {
        conversationId: CONV, senderPrincipal: p, senderSigningPublicKey: agentId.getSigningPublicKey(), selfAccount: account, now: NOW,
      });
      const ctx: PrincipalContext = { account, openRequestTo: () => null };
      expect(senderPrincipalUsable(p, agentId.getSigningPublicKey(), ctx, NOW)).toBe(true);
    }
    // Wrong address, ed25519 signer, non-eip155 namespace: no derivation.
    const otherAddr = signingAddress('secp256k1', (await SoftwareIdentity.generate('secp256k1')).getSigningPublicKey());
    const cases: Array<[SoftwareIdentity, string]> = [
      [root, `eip155:8453:${otherAddr}`],
      [edRoot, `eip155:8453:${addr}`],
      [root, `eip155x:8453:${addr}`],
      [root, `solana:8453:${addr}`],
    ];
    for (const [signer, account] of cases) {
      const p = await rec(signer, agentId, { roles: ['agent'], account });
      await expectCode(checkPrincipalRules('request', req, {
        conversationId: CONV, senderPrincipal: p, senderSigningPublicKey: agentId.getSigningPublicKey(), selfAccount: account, now: NOW,
      }), 'wrong_principal');
    }
  });

  it('senderPrincipalUsable mirrors steps 2-5', async () => {
    const { owner, agentId, ctrl, pAgent, ctx } = await setup();
    const spk = agentId.getSigningPublicKey();
    expect(senderPrincipalUsable(pAgent, spk, ctx, NOW)).toBe(true);
    expect(senderPrincipalUsable(null, spk, ctx, NOW)).toBe(false);
    expect(senderPrincipalUsable(pAgent, ctrl.getSigningPublicKey(), ctx, NOW)).toBe(false);
    expect(senderPrincipalUsable(pAgent, spk, { ...ctx, selfSigner: undefined }, NOW)).toBe(false);
    expect(senderPrincipalUsable(pAgent, spk, { ...ctx, selfSigner: undefined, trustedSigners: [keyOf(owner)] }, NOW)).toBe(true);
    expect(senderPrincipalUsable(pAgent, spk, { ...ctx, account: 'eip155:1:0xabc' }, NOW)).toBe(false);
  });
});

describe('requests/ ledger', () => {
  const to = 'ace:sha256:' + 'cd'.repeat(32);
  const msg = (o: Partial<{ messageId: string; timestamp: number; to: string; conversationId: string }> = {}) =>
    ({ conversationId: CONV, messageId: MID, to, timestamp: NOW, ...o });
  const decision = (o: Partial<ParsedMessage> & { requestId?: string; outcome?: string } = {}): ParsedMessage => ({
    messageId: o.messageId ?? '00000000-0000-4000-8000-000000000002', from: o.from ?? to, to: 'ace:sha256:' + 'ef'.repeat(32),
    conversationId: CONV, type: 'decision', threadId: null, timestamp: o.timestamp ?? NOW + 5,
    body: { requestId: o.requestId ?? MID, outcome: o.outcome ?? 'approve' },
  });

  it('key and record shape', async () => {
    expect(requestKey(CONV, MID)).toBe(`requests/${pairKey(CONV, MID)}.json`);
    const store = new MemoryStore();
    await recordRequest(store, msg(), NOW + 1, 60);
    const raw = await store.read(requestKey(CONV, MID));
    expect(new TextDecoder().decode(raw!)).toBe(
      `{"conversationId":"${CONV}","decision":null,"expiresAt":${NOW + 60},"messageId":"${MID}","sentAt":${NOW + 1},"to":"${to}","version":1}`);
    expect(await loadRequestRecord(store, CONV, MID)).toEqual({ conversationId: CONV, decision: null, expiresAt: NOW + 60, messageId: MID, sentAt: NOW + 1, to });
    // Idempotent: a second call does not overwrite.
    await recordRequest(store, msg({ to: 'ace:sha256:' + '00'.repeat(32) }), NOW + 9);
    expect((await loadRequestRecord(store, CONV, MID))!.to).toBe(to);
    const m2 = '00000000-0000-4000-8000-000000000003';
    await recordRequest(store, msg({ messageId: m2 }), NOW);
    expect((await loadRequestRecord(store, CONV, m2))!.expiresAt).toBeNull();
    expect(await loadRequestRecord(store, CONV, '00000000-0000-4000-8000-000000000004')).toBeNull();
    await recordRequest(store, msg({ messageId: '00000000-0000-4000-8000-000000000005', timestamp: Number.MAX_SAFE_INTEGER - 1 }), NOW, 10);
    expect((await loadRequestRecord(store, CONV, '00000000-0000-4000-8000-000000000005'))!.expiresAt).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('recordRequest argument checks', async () => {
    const store = new MemoryStore();
    await expectCode(recordRequest(store, msg({ conversationId: 'x' }), NOW), 'invalid_argument');
    await expectCode(recordRequest(store, msg({ messageId: 'x' }), NOW), 'invalid_argument');
    await expectCode(recordRequest(store, msg({ to: 'x' }), NOW), 'invalid_argument');
    await expectCode(recordRequest(store, msg(), -1), 'invalid_argument');
    await expectCode(recordRequest(store, msg(), NOW, 1.5), 'invalid_argument');
    expect(await store.list('requests/')).toEqual([]);
  });

  it('openRequestTo: undecided and unexpired only', async () => {
    const store = new MemoryStore();
    await recordRequest(store, msg(), NOW, 60);
    expect(await openRequestTo(store, CONV, MID, NOW + 60)).toBe(to);
    expect(await openRequestTo(store, CONV, MID, NOW + 61)).toBeNull();
    expect(await openRequestTo(store, 'ab'.repeat(31) + 'cd', MID, NOW)).toBeNull();
    await fillDecision(store, decision());
    expect(await openRequestTo(store, CONV, MID, NOW)).toBeNull();
    const m2 = '00000000-0000-4000-8000-000000000003';
    await recordRequest(store, msg({ messageId: m2 }), NOW);
    expect(await openRequestTo(store, CONV, m2, Number.MAX_SAFE_INTEGER)).toBe(to);
  });

  it('fillDecision: first wins, replay no-op, R-P25, wrong decider', async () => {
    const store = new MemoryStore();
    await fillDecision(store, decision()); // unknown request: no-op
    expect(await store.list('requests/')).toEqual([]);
    await recordRequest(store, msg(), NOW, 60);
    const key = requestKey(CONV, MID);
    const before = await store.read(key);
    await expectCode(fillDecision(store, decision({ from: 'ace:sha256:' + '11'.repeat(32) })), 'wrong_principal');
    expect(await store.read(key)).toEqual(before);
    await fillDecision(store, decision({ outcome: 'deny' }));
    const filled = await loadRequestRecord(store, CONV, MID);
    expect(filled!.decision).toEqual({ messageId: '00000000-0000-4000-8000-000000000002', outcome: 'deny', timestamp: NOW + 5 });
    const after = await store.read(key);
    await fillDecision(store, decision({ outcome: 'deny' })); // replay
    expect(await store.read(key)).toEqual(after);
    await expectCode(fillDecision(store, decision({ messageId: '00000000-0000-4000-8000-000000000007' })), 'bad_reference');
    expect(await store.read(key)).toEqual(after);
  });

  it.each([
    (d: any) => { d.version = 2; },
    (d: any) => { delete d.version; },
    (d: any) => { d.to = 'x'; },
    (d: any) => { d.sentAt = -1; },
    (d: any) => { d.expiresAt = '1'; },
    (d: any) => { d.messageId = '00000000-0000-4000-8000-000000000009'; },
    (d: any) => { d.conversationId = 'cd'.repeat(32); },
    (d: any) => { d.decision = { messageId: 'x', outcome: 'approve', timestamp: 1 }; },
    (d: any) => { d.decision = { messageId: MID, outcome: 'maybe', timestamp: 1 }; },
    (d: any) => { d.decision = { messageId: MID, outcome: 'deny', timestamp: 1.5 }; },
    (d: any) => { d.decision = 'x'; },
  ])('corrupt record %# is storage_failed', async (m) => {
    const store = new MemoryStore();
    const d: any = { conversationId: CONV, decision: null, expiresAt: null, messageId: MID, sentAt: NOW, to, version: 1 };
    m(d);
    await store.write(requestKey(CONV, MID), canonicalStateBytes(d));
    await expectCode(loadRequestRecord(store, CONV, MID), 'storage_failed');
  });

  it('non-JSON / non-object record is storage_failed', async () => {
    const store = new MemoryStore();
    await store.write(requestKey(CONV, MID), utf8('nope'));
    await expectCode(loadRequestRecord(store, CONV, MID), 'storage_failed');
    await store.write(requestKey(CONV, MID), utf8('[1]'));
    await expectCode(loadRequestRecord(store, CONV, MID), 'storage_failed');
  });
});

async function peerRecord(id: SoftwareIdentity, profile: any, ts = NOW) {
  const req = await createRegistrationRequest(id, profile, ts);
  return { aceId: req.aceId, scheme: req.scheme, encryptionPublicKey: req.encryptionPublicKey, signingPublicKey: req.signingPublicKey,
    registrationSignature: req.signature, registeredAt: ts, profile: req.profile };
}

describe('principal in registration and peers', () => {
  it('registration request round trip and rejection', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('secp256k1');
    const other = await SoftwareIdentity.generate('ed25519');
    const good = await rec(owner, me);
    const req = await createRegistrationRequest(me, { name: 'A', principal: good }, NOW);
    const v = verifyRegistrationRequest(JSON.parse(JSON.stringify(req)), { clock: () => NOW });
    expect(v.peer.principal?.account).toBe(ACC);
    await expectCode(createRegistrationRequest(me, { name: 'A', principal: await rec(owner, other) }, NOW), 'invalid_principal');
    const bad = { ...req, profile: { name: 'A', principal: { ...good, roles: ['agent', 'controller'] } } };
    expect(codeOf(() => verifyRegistrationRequest(bad, { clock: () => NOW }))).toBe('invalid_principal');
  });

  it('peer record principal verified, expiry, subject', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('ed25519');
    const other = await SoftwareIdentity.generate('ed25519');
    const r: any = await peerRecord(me, { name: 'A', principal: await rec(owner, me, { expiresAt: NOW + 50 }) });
    expect(verifyPeerRecord(r, { clock: () => NOW }).principal?.roles).toEqual(['controller', 'agent']);
    expect(codeOf(() => verifyPeerRecord(r, { clock: () => NOW + 50 }))).toBe('invalid_principal');
    r.profile.principal = await rec(owner, other);
    expect(codeOf(() => verifyPeerRecord(r, { clock: () => NOW }))).toBe('invalid_principal');
  });

  it('registration file principal', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('secp256k1');
    const reg = createRegistrationFile(me, { name: 'M', endpoint: 'https://m.example/ace', principal: await rec(owner, me) });
    const peer = verifyRegistrationFile(reg, { pinnedAt: NOW, clock: () => NOW });
    expect(peer.profile).toEqual({ principal: reg.principal });
    expect(verifyRegistrationFile(createRegistrationFile(me, { name: 'M', endpoint: 'https://m.example/ace' }), { pinnedAt: 0 }).profile).toBeNull();
  });

  it('an expired pin still loads (re-verified at fetchedAt)', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('ed25519');
    let t = NOW;
    const store = new MemoryStore();
    await new PeerStore({ store, clock: () => t }).adopt(
      verifyPeerRecord(await peerRecord(me, { principal: await rec(owner, me, { expiresAt: NOW + 5 }) }), { clock: () => NOW }));
    t = NOW + 10_000;
    expect((await new PeerStore({ store, clock: () => t }).get(me.getACEId()))?.principal).toBeDefined();
  });

  it('registration payload carries the principal group (absent: eight empty fields)', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('ed25519');
    const a = await createRegistrationRequest(me, { name: 'A' }, NOW);
    const b = await createRegistrationRequest(me, { name: 'A', principal: await rec(owner, me) }, NOW);
    expect(a.authorization).not.toBe(b.authorization);
    const tampered = { ...b, profile: { name: 'A' } };
    expect(codeOf(() => verifyRegistrationRequest(tampered, { clock: () => NOW }))).toBe('invalid_authorization');
  });

  it('a registration file never removes or downgrades a cached principal (R-P26)', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('ed25519');
    const store = new MemoryStore();
    const ps = new PeerStore({ store, clock: () => NOW });
    const cached = await rec(owner, me, { issuedAt: NOW - 10 });
    await ps.adopt(verifyPeerRecord(await peerRecord(me, { name: 'Relay', principal: cached }), { clock: () => NOW }));
    const file = (principal?: PrincipalRecord) =>
      verifyRegistrationFile(createRegistrationFile(me, { name: 'M', endpoint: 'https://m.example/ace', principal }), { pinnedAt: NOW, clock: () => NOW });
    // no principal in file: cached kept, other members carry over
    let r = await ps.adopt(file());
    expect(r.peer.principal).toEqual(cached);
    expect(r.peer.profile?.name).toBe('Relay');
    // older issuedAt: kept
    r = await ps.adopt(file(await rec(owner, me, { issuedAt: NOW - 100 })));
    expect(r.peer.principal).toEqual(cached);
    // newer: replaces
    const newer = await rec(owner, me, { issuedAt: NOW - 5 });
    r = await ps.adopt(file(newer));
    expect(r.peer.principal).toEqual(newer);
    expect((await ps.get(me.getACEId()))?.principal).toEqual(newer);
    // a relay record without a principal clears it
    r = await ps.adopt(verifyPeerRecord(await peerRecord(me, { name: 'Relay' }, NOW + 1), { clock: () => NOW + 1 }));
    expect(r.peer.principal).toBeUndefined();
  });

  it('an expired cached principal is dropped, not carried, by a kept file candidate (R-P35)', async () => {
    const owner = await SoftwareIdentity.generate('ed25519');
    const me = await SoftwareIdentity.generate('ed25519');
    const store = new MemoryStore();
    let t = NOW;
    const ps = new PeerStore({ store, clock: () => t });
    await ps.adopt(verifyPeerRecord(await peerRecord(me, { name: 'Relay', principal: await rec(owner, me, { expiresAt: NOW + 5 }) }), { clock: () => NOW }));
    t = NOW + 100;
    const file = verifyRegistrationFile(createRegistrationFile(me, { name: 'M', endpoint: 'https://m.example/ace' }), { pinnedAt: NOW, clock: () => t });
    const r = await ps.adopt(file);
    expect(r.peer.principal).toBeUndefined();
    expect(r.peer.profile?.name).toBe('Relay');
    const got = await new PeerStore({ store, clock: () => t }).get(me.getACEId());
    expect(got?.principal).toBeUndefined();
    // an unexpired cached principal is still carried
    const me2 = await SoftwareIdentity.generate('ed25519');
    const keep = await rec(owner, me2, { expiresAt: NOW + 500 });
    await ps.adopt(verifyPeerRecord(await peerRecord(me2, { principal: keep }), { clock: () => NOW }));
    const r2 = await ps.adopt(verifyRegistrationFile(createRegistrationFile(me2, { name: 'M', endpoint: 'https://m.example/ace' }), { pinnedAt: NOW, clock: () => t }));
    expect(r2.peer.principal).toEqual(keep);
  });
});
