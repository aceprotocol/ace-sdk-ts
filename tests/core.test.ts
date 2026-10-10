import { toBase64 } from '../src/index.js';
// Core API: exports, messages, errors, peers, registration, profiles, SSRF blocklist.
import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';
import * as nodeApi from '../src/node.js';
import {
  ACEError, COMMERCE_EXT, ReplayDetector, SoftwareIdentity, ThreadStateMachine, VerifiedPeer, commerceExt, createMessage, createRegistrationFile,
  createRegistrationRequest,
  decodeEnvelope, extCanonical, fetchRegistrationFile, parseMessage, validateBody, validateCommerceExt, validateExt, validateProfile, verifyEnvelopeSignature,
  verifyRegistrationFile, verifyRegistrationRequest, type ACEIdentity, type ACEMessage,
} from '../src/index.js';
import { isBlockedAddress } from '../src/discovery.js';
import { expectCode, peerOf, codeOf } from './helpers.js';

const VALUE_EXPORTS = [
  'ACEError', 'MESSAGE_TYPES', 'ECONOMIC_TYPES', 'PRINCIPAL_TYPES', 'isMessageType', 'isEconomicType', 'isPrincipalType', 'SIGNING_SCHEMES', 'isSigningScheme',
  'MAX_PLAINTEXT_BYTES', 'MAX_PAYLOAD_BYTES', 'MAX_ENVELOPE_BYTES', 'MAX_DIRECT_BODY_BYTES', 'MAX_JSON_DEPTH', 'MAX_THREAD_ID_LENGTH',
  'MAX_OPEN_THREADS_PER_PEER', 'createRegistrationFile',
  'TIMESTAMP_WINDOW_SECONDS', 'OFFLINE_WINDOW_SECONDS', 'MAX_REGISTRATION_FILE_BYTES', 'MAX_INBOX_PAGE',
  'KEM_SEED_SIZE', 'KEM_PUBLIC_KEY_SIZE', 'KEM_CIPHERTEXT_SIZE', 'DEFAULT_REPLAY_CAPACITY',
  'MAX_EXT_KEYS', 'MAX_EXT_KEY_BYTES', 'MAX_EXT_BYTES', 'MAX_EXT_DEPTH',
  'COMMERCE_EXT', 'validateExt', 'validateCommerceExt', 'extCanonical', 'commerceExt', 'intentCommerceExt',
  'SoftwareIdentity', 'computeACEId', 'toBase64', 'fromBase64', 'computeConversationId', 'decryptWithSeed',
  'kemPublicKeyFromSeed', 'generateKemSeed', 'decodeEnvelope', 'verifyEnvelopeSignature', 'envelopeFingerprint',
  'isACEId', 'isMessageId', 'isThreadId', 'isConversationId', 'createMessage', 'parseMessage', 'validateBody',
  'VerifiedPeer', 'verifyPeerRecord', 'verifyRegistrationFile', 'fetchRegistrationFile', 'validateProfile', 'isBlockedAddress',
  'createRegistrationRequest', 'verifyRegistrationRequest', 'createAuthHeaders', 'parseAuthHeaders', 'verifyAuthHeaders',
  'isHttpsUrl', 'isWebhookSecret', 'signWebhookNotification', 'verifyWebhookNotification',
  'ReplayDetector', 'ThreadStateMachine', 'ThreadStore', 'PeerStore', 'Inbox', 'inboxPrincipalFromOwnRecord', 'Outbox', 'RelayClient', 'MemoryStore',
  'checkKey', 'checkLockName',
  'executionIntentDigest', 'executionGrantDigest', 'createExecutionGrant', 'verifyExecutionGrantChain', 'isExecutionUnits', 'ExecutionAuthority',
  'EXECUTION_REQUEST_TYPE', 'EXECUTION_REQUEST_SCHEMA', 'EXECUTION_REQUEST_SCHEMA_DIGEST', 'parseExecutionRequest',
  'knownSchemaDigest', 'AuditTree', 'auditCommitment', 'createAuditOpening', 'createAuditCheckpoint', 'verifyAuditInclusion', 'verifyAuditConsistency', 'verifyAuditCheckpoint',
  'auditCheckpointDigest', 'createAuditWitnessReceipt', 'verifyAuditWitnessReceipt', 'verifyAuditWitnessQuorum', 'AuditLog', 'AuditWitness',
  'PRINCIPAL_ROLES', 'isCaip10', 'principalSignerFromIdentity', 'principalPayload', 'principalSignData', 'createPrincipalRecord',
  'validatePrincipalRecord', 'parsePrincipalRecord', 'checkPrincipalRules', 'loadRequestRecord',
];

async function setup() {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  return { alice, bob, alicePeer: peerOf(alice), bobPeer: peerOf(bob) };
}

const now = () => Math.floor(Date.now() / 1000);

describe('exports', () => {
  it('index exports exactly the public list', async () => {
    expect(Object.keys(api).sort()).toEqual([...VALUE_EXPORTS].sort());
    expect(Object.keys(nodeApi).sort()).toEqual(['EtcdStore', 'FileStore', 'deliverDirectOrRelay', 'loadMLSEngine', 'postDirect']);
  });

  it('ACEError categories', async () => {
    expect(new ACEError('replay').category).toBe('permanent');
    expect(new ACEError('relay_unavailable').isTransient).toBe(true);
    expect(new ACEError('storage_failed').category).toBe('local');
    expect(new ACEError('handler_failed').isTransient).toBe(true);
    expect(() => new ACEError('nope' as never)).toThrow(TypeError);
    expect(new ACEError('lock_busy').category).toBe('local');
    expect(new ACEError('direct_rejected').category).toBe('permanent');
    expect(new ACEError('delivery_rejected', 'x', { remoteCode: 'invalid_envelope' })).toMatchObject({ category: 'permanent', isTransient: false, remoteCode: 'invalid_envelope' });
    expect(new ACEError('direct_unavailable').category).toBe('transient');
    expect(JSON.stringify(SoftwareIdentity.fromExport({ scheme: 'ed25519', signingPrivateKey: 'A'.repeat(43) + '=', encryptionPrivateKey: 'A'.repeat(43) + '=' }))).toBe('{}');
  });

  it('only the ./node entry and its private backends import node: modules statically', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const dir = new URL('../src/', import.meta.url);
    for (const f of readdirSync(dir)) {
      if (f === 'node.ts' || f === 'etcd-store.ts') continue;
      expect(readFileSync(new URL(f, dir), 'utf8'), f).not.toMatch(/^import[^;]*from 'node:/m);
    }
  });
});

describe('messages', () => {
  it('create → parse round trip for both schemes, economic and not', async () => {
    const { alice, bob, alicePeer, bobPeer } = await setup();
    const aThreads = new ThreadStateMachine({ localAceId: alice.getACEId() });
    const bThreads = new ThreadStateMachine({ localAceId: bob.getACEId() });
    const replay = new ReplayDetector();
    const env = await createMessage({ sender: alice, recipient: bobPeer, type: 'rfq', body: { need: 'x', extra: [1, { a: null }] }, threads: aThreads, threadId: 't' });
    expect(aThreads.getState(env.conversationId, 't')).toBe('rfq');
    const parsed = await parseMessage(env, bob, alicePeer, { threads: bThreads, replay });
    expect(parsed.body).toEqual({ need: 'x', extra: [1, { a: null }] });
    expect(bThreads.getState(env.conversationId, 't')).toBe('rfq');
    await expectCode(parseMessage(env, bob, alicePeer, { threads: bThreads, replay }), 'replay');
    const reply = await createMessage({ sender: bob, recipient: alicePeer, type: 'text', body: { message: 'hi' }, threads: bThreads });
    expect(reply.signature.value).toMatch(/^0x[0-9a-f]{130}$/);
    verifyEnvelopeSignature(reply, { scheme: 'secp256k1', signingPublicKey: bob.getSigningPublicKey() });
    await expectCode(async () => verifyEnvelopeSignature(reply, { scheme: 'ed25519', signingPublicKey: alice.getSigningPublicKey() }), 'scheme_mismatch');
    const p2 = await parseMessage(decodeEnvelope(JSON.parse(JSON.stringify(reply))), alice, bobPeer, { threads: aThreads, replay: new ReplayDetector() });
    expect(p2.threadId).toBeNull();
  });

  it('createMessage argument errors', async () => {
    const { alice, bobPeer } = await setup();
    const threads = new ThreadStateMachine({ localAceId: alice.getACEId() });
    const base = { sender: alice as ACEIdentity, recipient: bobPeer, threads };
    await expectCode(createMessage({ ...base, type: 'nope' as never, body: {} }), 'invalid_argument');
    await expectCode(createMessage({ ...base, type: 'rfq', body: { need: 'x' } }), 'invalid_argument');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x' }, threadId: '' }), 'invalid_argument');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x' }, timestamp: -1 }), 'invalid_argument');
    await expectCode(createMessage({ ...base, recipient: { ...bobPeer } as never, type: 'text', body: { message: 'x' } }), 'invalid_argument');
    await expectCode(createMessage({ ...base, threads: new ThreadStateMachine({ localAceId: bobPeer.aceId }), type: 'text', body: { message: 'x' } }), 'invalid_argument');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x', n: NaN } }), 'invalid_body');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x', d: new Date() as never } }), 'invalid_body');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x', u: undefined as never } }), 'invalid_body');
    let deep: Record<string, unknown> = {};
    const root = deep;
    for (let i = 0; i < 33; i++) { deep.a = {}; deep = deep.a as Record<string, unknown>; }
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x', ...root } as never }), 'invalid_body');
    await expectCode(createMessage({ ...base, type: 'text', body: { message: 'x'.repeat(65508) } }), 'limit_exceeded');
    await expectCode(createMessage({ ...base, type: 'accept', body: { offerId: 'x' }, threadId: 't' }), 'transition_not_allowed');
    expect(codeOf(() => validateBody('nope' as never, {}))).toBe('invalid_argument');
    expect(codeOf(() => validateBody('deliver', { type: 'inline' }))).toBe('invalid_body');
  });

  it('parseMessage order: wrong_recipient, from, scheme, conversation, floor, signature', async () => {
    const { alice, bob, alicePeer, bobPeer } = await setup();
    const carol = await SoftwareIdentity.generate('ed25519');
    const threads = () => new ThreadStateMachine({ localAceId: bob.getACEId() });
    const env = await createMessage({ sender: alice, recipient: bobPeer, type: 'text', body: { message: 'x' }, threads: new ThreadStateMachine({ localAceId: alice.getACEId() }) });
    const opts = () => ({ threads: threads(), replay: new ReplayDetector() });
    await expectCode(parseMessage(env, carol, alicePeer, { threads: new ThreadStateMachine({ localAceId: carol.getACEId() }), replay: new ReplayDetector() }), 'wrong_recipient');
    await expectCode(parseMessage(env, bob, peerOf(carol), opts()), 'invalid_envelope');
    await expectCode(parseMessage(env, bob, alicePeer, { ...opts(), floor: now() + 100 }), 'invalid_argument');
    await expectCode(parseMessage(env, bob, alicePeer, { ...opts(), clock: () => env.timestamp + 301 }), 'stale_timestamp');
    await expectCode(parseMessage(env, bob, alicePeer, { ...opts(), clock: () => env.timestamp - 301 }), 'stale_timestamp');
    const tampered: ACEMessage = { ...env, signature: { scheme: 'ed25519', value: env.signature.value.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) } };
    await expectCode(parseMessage(tampered, bob, alicePeer, opts()), 'invalid_signature');
    await expectCode(parseMessage({ ...env, signature: { scheme: 'secp256k1', value: '0x' + '0'.repeat(130) } }, bob, alicePeer, opts()), 'scheme_mismatch');
    await expectCode(parseMessage(env, bob, alicePeer, { threads: threads(), replay: {} as never }), 'invalid_argument');
  });

  it('decrypt failures: ACEError passes through, anything else is identity_unavailable; replay stays committed', async () => {
    const { alice, bob, alicePeer, bobPeer } = await setup();
    const env = await createMessage({ sender: alice, recipient: bobPeer, type: 'text', body: { message: 'x' }, threads: new ThreadStateMachine({ localAceId: alice.getACEId() }) });
    const broken: ACEIdentity = {
      getACEId: () => bob.getACEId(), getSigningScheme: () => bob.getSigningScheme(), getSigningPublicKey: () => bob.getSigningPublicKey(),
      getEncryptionPublicKey: () => bob.getEncryptionPublicKey(), sign: (d) => bob.sign(d),
      decrypt: async () => { throw new Error('keychain locked'); },
    };
    const replay = new ReplayDetector();
    const threads = new ThreadStateMachine({ localAceId: bob.getACEId() });
    const e = await expectCode(parseMessage(env, broken, alicePeer, { threads, replay: replay.clone() }), 'identity_unavailable');
    expect(e.isTransient).toBe(true);
    const failing: ACEIdentity = { ...broken, decrypt: async () => { throw new ACEError('decryption_failed', 'bad'); } };
    await expectCode(parseMessage(env, failing, alicePeer, { threads, replay }), 'decryption_failed');
    expect(replay.accepts(env.messageId, env.from, env.timestamp)).toBe(false);
  });
});

describe('peers and registration', () => {
  it('VerifiedPeer cannot be constructed or spoofed', async () => {
    const { bobPeer } = await setup();
    expect(() => new (VerifiedPeer as never as new () => unknown)()).toThrow(ACEError);
    const spoof = Object.create(VerifiedPeer.prototype);
    expect(codeOf(() => validateProfile({ name: '' }))).toBe('invalid_profile');
    await expectCode(createMessage({
      sender: await SoftwareIdentity.generate('ed25519'), recipient: spoof, type: 'text', body: { message: 'x' },
      threads: new ThreadStateMachine({ localAceId: bobPeer.aceId }),
    }), 'invalid_argument');
    expect(Object.isFrozen(bobPeer)).toBe(true);
    const k = bobPeer.encryptionPublicKey;
    k[0] ^= 1;
    expect(bobPeer.encryptionPublicKey[0]).not.toBe(k[0]);
    expect(bobPeer.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it('registration request round trip (keep / remove / replace)', async () => {
    const id = await SoftwareIdentity.generate('secp256k1');
    const t = now();
    const commerce = { 'urn:ace:commerce:1': { pricing: { currency: 'USDC', maxAmount: '1.5' }, chains: ['eip155:8453'] } };
    for (const profile of [undefined, null, { name: 'A', tags: ['x'], ext: commerce }]) {
      const req = await createRegistrationRequest(id, profile, t);
      const r = verifyRegistrationRequest(req, { clock: () => t });
      expect(r.request).toEqual(req);
      expect(r.peer.aceId).toBe(id.getACEId());
      expect(r.requestDigest).toMatch(/^[0-9a-f]{64}$/);
    }
    await expectCode(createRegistrationRequest(id, { ext: { 'urn:ace:commerce:1': { pricing: { currency: 'USDC', extra: 1 } } } } as never), 'invalid_profile');
  });

  it('rejects unsigned, substituted and timestamp-tampered registration key bindings', async () => {
    const victim = await SoftwareIdentity.generate('ed25519'), attacker = await SoftwareIdentity.generate('ed25519');
    const file = await createRegistrationFile(victim, { name: 'Victim', endpoint: 'https://victim.example' });
    expect(verifyRegistrationFile(file).aceId).toBe(victim.getACEId());
    const substituted = { ...file, signing: { ...file.signing, encryptionPublicKey: toBase64(attacker.getEncryptionPublicKey()) } };
    expect(codeOf(() => verifyRegistrationFile(substituted))).toBe('invalid_registration');
    expect(codeOf(() => verifyRegistrationFile({ ...file, registeredAt: file.registeredAt + 1 }))).toBe('invalid_registration');
    expect(codeOf(() => verifyRegistrationFile({ ...file, registrationSignature: undefined } as never))).toBe('invalid_registration');
  });

  it('registration files: tier, ed25519 address round trip, id hash', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    const reg = await createRegistrationFile(id, { name: 'A', endpoint: 'https://a.example', tier: 1 });
    expect(reg.tier).toBe(1);
    expect(verifyRegistrationFile(reg).registeredAt).toBe(reg.registeredAt);
    expect(codeOf(() => verifyRegistrationFile({ ...reg, id: 'ace:sha256:' + '0'.repeat(64) }))).toBe('invalid_registration');
    expect(codeOf(() => verifyRegistrationFile({ ...reg, endpoint: 'http://a.example' }))).toBe('invalid_registration');
    await expectCode(createRegistrationFile(id, { name: 'A\n', endpoint: 'https://a.example' }), 'invalid_registration');
  });

  it('createRegistrationFile works for any ACEIdentity (hardware-style wrapper), same as for the software identity', async () => {
    for (const scheme of ['ed25519', 'secp256k1'] as const) {
      const sw = await SoftwareIdentity.generate(scheme);
      const hw: ACEIdentity = { // no SoftwareIdentity behind the interface
        getACEId: () => sw.getACEId(), getSigningScheme: () => sw.getSigningScheme(),
        getSigningPublicKey: () => sw.getSigningPublicKey(), getEncryptionPublicKey: () => sw.getEncryptionPublicKey(),
        sign: (d) => sw.sign(d), decrypt: (k, p, c) => sw.decrypt(k, p, c),
      };
      const opts = {
        name: 'HW', endpoint: 'https://hw.example/ace', tier: 1 as const, hardwareBacking: 'secure-enclave' as const,
        ext: { 'urn:ace:commerce:1': { settlement: ['x402'], accounts: [{ network: 'eip155:8453', address: '0x7a3b' }] } },
      };
      const reg = await createRegistrationFile(hw, opts);
      const second = await createRegistrationFile(sw, { ...opts, timestamp: reg.registeredAt });
      expect({ ...reg, registrationSignature: '' }).toEqual({ ...second, registrationSignature: '' });
      expect(verifyRegistrationFile(second).aceId).toBe(sw.getACEId());
      expect(reg.signing.address).toBe(sw.getAddress());
      expect(verifyRegistrationFile(reg).aceId).toBe(sw.getACEId());
      await expectCode(createRegistrationFile(hw, { name: '', endpoint: 'https://hw.example/ace' }), 'invalid_registration');
    }
  });

  it('profiles: unknown fields dropped, nulls absent, legacy chains/pricing dropped', async () => {
    expect(validateProfile({ name: 'A', description: null, junk: 1 } as never)).toEqual({ name: 'A' });
    expect(validateProfile({ name: 'A', chains: ['eip155:1'], pricing: { currency: 'USDC' } } as never)).toEqual({ name: 'A' });
    expect(codeOf(() => validateProfile({ tags: ['UPPER'] }))).toBe('invalid_profile');
    expect(codeOf(() => validateProfile({ image: 'https://x.example/' + 'a'.repeat(600) }))).toBe('invalid_profile');
  });

  it('ext: namespaced keys, object values, limits, canonical form; empty or null is absent', async () => {
    const ok = { 'urn:ace:commerce:1': { chains: ['eip155:8453'] }, 'com.example:x': { b: 1, a: [null, true, '中文'] } };
    const p = validateProfile({ name: 'A', ext: ok });
    expect(p.ext).toEqual(ok);
    expect(Object.keys(p.ext!['com.example:x'])).toEqual(['a', 'b']); // re-canonicalised (sorted keys)
    expect(extCanonical(p.ext)).toBe('{"com.example:x":{"a":[null,true,"中文"],"b":1},"urn:ace:commerce:1":{"chains":["eip155:8453"]}}');
    expect(validateProfile({ name: 'A', ext: {} })).toEqual({ name: 'A' });
    expect(validateProfile({ name: 'A', ext: null } as never)).toEqual({ name: 'A' });
    expect(extCanonical(undefined)).toBe('');
    for (const ext of [
      'x', [], { 'urn:ace:commerce:1': 'x' }, { 'urn:ace:commerce:1': [] }, { 'no-colon': {} }, { 'Urn:x': {} }, { 'urn:x y': {} },
      { [`urn:${'a'.repeat(253)}`]: {} },
      Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`urn:n${i}`, {}])),
      { 'urn:big': { s: 'x'.repeat(4096) } },
      { 'urn:deep': { a: { b: { c: { d: { e: { f: { g: { h: {} } } } } } } } } },
      { 'urn:nan': { n: NaN } },
    ]) expect(codeOf(() => validateProfile({ ext } as never)), JSON.stringify(ext)?.slice(0, 60)).toBe('invalid_profile');
    expect(codeOf(() => validateProfile({ ext: { [`urn:${'a'.repeat(252)}`]: {} } }))).toBe('ok');
    expect(codeOf(() => validateProfile({ ext: Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`urn:n${i}`, {}])) }))).toBe('ok');
    expect(codeOf(() => validateProfile({ ext: { 'urn:deep': { a: { b: { c: { d: { e: { f: { g: {} } } } } } } } } }))).toBe('ok');
    // other namespaces are opaque; the commerce member is typed and strict
    expect(codeOf(() => validateProfile({ ext: { 'urn:other:1': { maxPrice: 1, whatever: [] } } }))).toBe('ok');
    const c = (v: unknown) => codeOf(() => validateProfile({ ext: { [COMMERCE_EXT]: v } } as never));
    expect(c({ chains: ['eip155:8453', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'], pricing: { currency: 'USDC' }, settlement: ['x402'], accounts: [{ network: 'eip155:1', address: '0x1' }] })).toBe('ok');
    for (const v of [
      [], { extra: {} }, { chains: 'eip155:1' }, { chains: ['EIP155:1'] }, { chains: Array(11).fill('eip155:1') },
      { pricing: { currency: '' } }, { pricing: { currency: 'USD', maxAmount: '1.' } }, { pricing: { currency: 'USDC', extra: 1 } }, { pricing: { maxAmount: '1' } },
      { pricing: { currency: 'a\u0000' } }, { pricing: { currency: 'x'.repeat(17) } }, { settlement: [1] }, { settlement: Array(11).fill('x') },
      { accounts: [{ network: 'eip155:1' }] }, { accounts: [{ network: 'bad', address: 'x' }] }, { accounts: [{ network: 'eip155:1', address: 'x', extra: 1 }] },
      { maxPrice: '1', currency: 'USDC' },
    ]) expect(c(v), JSON.stringify(v)).toBe('invalid_profile');
    expect(commerceExt(validateProfile({ ext: { [COMMERCE_EXT]: { chains: ['eip155:1'] } } }))).toEqual({ chains: ['eip155:1'] });
    expect(commerceExt(validateProfile({ name: 'A' }))).toBeUndefined();
    // intent carrier: maxPrice + currency, both or neither, invalid_argument
    expect(validateCommerceExt({ maxPrice: '5', currency: 'USDC' }, 'intent')).toEqual({ maxPrice: '5', currency: 'USDC' });
    expect(validateCommerceExt({}, 'intent')).toEqual({});
    for (const v of [{ maxPrice: '5' }, { currency: 'USDC' }, { maxPrice: '', currency: 'USDC' }, { maxPrice: '5', currency: 'x'.repeat(17) }, { maxPrice: '5', currency: 'USDC', chains: [] }, { chains: ['eip155:1'] }]) {
      expect(codeOf(() => validateCommerceExt(v, 'intent')), JSON.stringify(v)).toBe('invalid_argument');
    }
    expect(codeOf(() => validateExt({ 'urn:x': 1 }, 'intent'))).toBe('invalid_argument');
  });

  it('registration files carry ext into VerifiedPeer.profile.ext (same rules as a profile)', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    const ext = { [COMMERCE_EXT]: { settlement: ['x402'], accounts: [{ network: 'eip155:8453', address: '0x7a3b' }] }, 'urn:other:1': { k: 'v' } };
    const reg = await createRegistrationFile(id, { name: 'A', endpoint: 'https://a.example', ext });
    expect(reg.ext).toEqual(ext);
    const peer = verifyRegistrationFile(JSON.parse(JSON.stringify(reg)));
    expect(peer.profile).toEqual({ ext });
    expect(commerceExt(peer.profile)?.settlement).toEqual(['x402']);
    expect(verifyRegistrationFile({ ...reg, ext: {} }).profile).toBeNull(); // key binding does not cover ext
    const { ext: _e, ...noExt } = reg;
    expect(verifyRegistrationFile({ ...noExt, chains: [{ network: 'eip155:1', address: 'x' }], settlement: ['x'] } as never).profile).toBeNull(); // legacy members ignored
    expect(codeOf(() => verifyRegistrationFile({ ...reg, ext: { [COMMERCE_EXT]: { chains: ['bad'] } } }))).toBe('invalid_profile');
    expect(codeOf(() => verifyRegistrationFile({ ...reg, ext: { bad: {} } }))).toBe('invalid_profile');
    await expectCode(createRegistrationFile(id, { name: 'A', endpoint: 'https://a.example', ext: { [COMMERCE_EXT]: { maxPrice: '1', currency: 'USDC' } } }), 'invalid_profile');
  });

  it('SSRF blocklist', async () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '100.64.0.1', '169.254.169.254', '172.31.0.1', '192.168.1.1', '198.18.0.1',
      '224.0.0.1', '255.255.255.255', '0.0.0.0', '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::a00:1',
      'fe80::1', 'fd00::1', 'ff02::1', '2001:db8::1', '100::1']) expect(isBlockedAddress(ip), ip).toBe(true);
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700::1111', '::ffff:8.8.8.8', '64:ff9b::808:808', '172.32.0.1']) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it('fetchRegistrationFile argument checks', async () => {
    await expectCode(fetchRegistrationFile('not a domain'), 'invalid_argument');
    await expectCode(fetchRegistrationFile('example.com', { timeoutMs: 0 }), 'invalid_argument');
  });
});

describe('fetchRegistrationFile DNS pinning', () => {
  it('rejects if ANY resolved address is blocked, resolves once and connects only to the validated address', async () => {
    const { fetchRegistrationFileWith } = await import('../src/discovery.js');
    const net = await import('node:net');
    const calls: string[] = [];
    const lookupOf = (addrs: string[]) => async (host: string) => {
      calls.push(host);
      return addrs.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    };
    await expectCode(fetchRegistrationFileWith('agent.example.com', {}, { lookup: lookupOf(['93.184.216.34', '10.0.0.1']) }), 'blocked_address');
    await expectCode(fetchRegistrationFileWith('agent.example.com', {}, { lookup: lookupOf(['::ffff:127.0.0.1']) }), 'blocked_address');
    await expectCode(fetchRegistrationFileWith('agent.example.com', {}, { lookup: async () => { throw new Error('NXDOMAIN'); } }), 'fetch_failed');
    // a local TCP endpoint stands in for the validated address: the TLS handshake reaches it
    const seen: string[] = [];
    const server = net.createServer((sock) => {
      seen.push(sock.remoteAddress ?? '');
      sock.once('data', (d) => {
        seen.push(d.includes(Buffer.from('agent.example.com')) ? 'sni' : 'no-sni');
        sock.destroy();
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as import('node:net').AddressInfo).port;
    calls.length = 0;
    try {
      await expectCode(fetchRegistrationFileWith('agent.example.com', { allowPrivateAddresses: true, timeoutMs: 2000 },
        { lookup: lookupOf(['127.0.0.1']), port }), 'fetch_failed');
    } finally {
      server.close();
    }
    expect(calls).toEqual(['agent.example.com']); // resolved exactly once
    expect(seen).toEqual(['127.0.0.1', 'sni']); // connected to the pinned address with SNI = domain
  });
});
