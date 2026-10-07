// Core API: exports, messages, errors, peers, registration, profiles, SSRF blocklist.
import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';
import * as nodeApi from '../src/node.js';
import {
  ACEError, ReplayDetector, SoftwareIdentity, ThreadStateMachine, VerifiedPeer, createMessage, createRegistrationFile,
  createRegistrationRequest,
  decodeEnvelope, fetchRegistrationFile, parseMessage, validateBody, validateProfile, verifyEnvelopeSignature,
  verifyRegistrationFile, verifyRegistrationRequest, type ACEIdentity, type ACEMessage,
} from '../src/index.js';
import { isBlockedAddress } from '../src/discovery.js';
import { expectCode, peerOf, codeOf } from './helpers.js';

const VALUE_EXPORTS = [
  'ACEError', 'MESSAGE_TYPES', 'ECONOMIC_TYPES', 'isMessageType', 'isEconomicType',
  'MAX_PLAINTEXT_BYTES', 'MAX_PAYLOAD_BYTES', 'MAX_ENVELOPE_BYTES', 'MAX_JSON_DEPTH', 'MAX_THREAD_ID_LENGTH',
  'MAX_OPEN_THREADS_PER_PEER', 'PullResult', 'createRegistrationFile',
  'TIMESTAMP_WINDOW_SECONDS', 'OFFLINE_WINDOW_SECONDS', 'MAX_REGISTRATION_FILE_BYTES', 'MAX_INBOX_PAGE',
  'KEM_SEED_SIZE', 'KEM_PUBLIC_KEY_SIZE', 'KEM_CIPHERTEXT_SIZE', 'DEFAULT_REPLAY_CAPACITY',
  'SoftwareIdentity', 'computeACEId', 'toBase64', 'fromBase64', 'computeConversationId', 'decryptWithSeed',
  'kemPublicKeyFromSeed', 'generateKemSeed', 'decodeEnvelope', 'verifyEnvelopeSignature', 'envelopeFingerprint',
  'isACEId', 'isMessageId', 'isThreadId', 'isConversationId', 'createMessage', 'parseMessage', 'validateBody',
  'VerifiedPeer', 'verifyPeerRecord', 'verifyRegistrationFile', 'fetchRegistrationFile', 'validateProfile', 'isBlockedAddress',
  'createRegistrationRequest', 'verifyRegistrationRequest', 'createAuthHeaders', 'parseAuthHeaders', 'verifyAuthHeaders',
  'isHttpsUrl', 'isWebhookSecret', 'signWebhookNotification', 'verifyWebhookNotification',
  'ReplayDetector', 'ThreadStateMachine', 'ThreadStore', 'PeerStore', 'Inbox', 'Outbox', 'RelayClient', 'MemoryStore',
];

async function setup() {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  return { alice, bob, alicePeer: peerOf(alice), bobPeer: peerOf(bob) };
}

const now = () => Math.floor(Date.now() / 1000);

describe('exports', () => {
  it('index exports exactly the design list', () => {
    expect(Object.keys(api).sort()).toEqual([...VALUE_EXPORTS].sort());
    expect(Object.keys(nodeApi)).toEqual(['FileStore']);
  });

  it('ACEError categories', () => {
    expect(new ACEError('replay').category).toBe('permanent');
    expect(new ACEError('relay_unavailable').isTransient).toBe(true);
    expect(new ACEError('storage_failed').category).toBe('local');
    expect(new ACEError('handler_failed').isTransient).toBe(true);
    expect(() => new ACEError('nope' as never)).toThrow(TypeError);
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
    for (const profile of [undefined, null, { name: 'A', tags: ['x'], pricing: { currency: 'USDC', maxAmount: '1.5' } }]) {
      const req = await createRegistrationRequest(id, profile, t);
      const r = verifyRegistrationRequest(req, { clock: () => t });
      expect(r.request).toEqual(req);
      expect(r.peer.aceId).toBe(id.getACEId());
      expect(r.requestDigest).toMatch(/^[0-9a-f]{64}$/);
    }
    await expectCode(createRegistrationRequest(id, { pricing: { currency: 'USDC', extra: 1 } as never }), 'invalid_profile');
  });

  it('registration files: tier, ed25519 address round trip, id hash', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    const reg = id.toRegistrationFile({ name: 'A', endpoint: 'https://a.example', tier: 1 });
    expect(reg.tier).toBe(1);
    expect(verifyRegistrationFile(reg, { pinnedAt: 5 }).registeredAt).toBe(5);
    expect(codeOf(() => verifyRegistrationFile({ ...reg, id: 'ace:sha256:' + '0'.repeat(64) }))).toBe('invalid_registration');
    expect(codeOf(() => verifyRegistrationFile({ ...reg, endpoint: 'http://a.example' }))).toBe('invalid_registration');
    expect(codeOf(() => verifyRegistrationFile(reg, { pinnedAt: -1 }))).toBe('invalid_argument');
    expect(() => id.toRegistrationFile({ name: 'A\n', endpoint: 'https://a.example' })).toThrow(ACEError);
  });

  it('createRegistrationFile works for any ACEIdentity (hardware-style wrapper), same as toRegistrationFile', async () => {
    for (const scheme of ['ed25519', 'secp256k1'] as const) {
      const sw = await SoftwareIdentity.generate(scheme);
      const hw: ACEIdentity = { // no SoftwareIdentity behind the interface
        getACEId: () => sw.getACEId(), getSigningScheme: () => sw.getSigningScheme(),
        getSigningPublicKey: () => sw.getSigningPublicKey(), getEncryptionPublicKey: () => sw.getEncryptionPublicKey(),
        sign: (d) => sw.sign(d), decrypt: (k, p, c) => sw.decrypt(k, p, c),
      };
      const opts = { name: 'HW', endpoint: 'https://hw.example/ace', tier: 1 as const, hardwareBacking: 'secure-enclave' as const, settlement: ['x402'] };
      const reg = createRegistrationFile(hw, opts);
      expect(reg).toEqual(sw.toRegistrationFile(opts));
      expect(reg.signing.address).toBe(sw.getAddress());
      expect(verifyRegistrationFile(reg, { pinnedAt: 1 }).aceId).toBe(sw.getACEId());
      expect(codeOf(() => createRegistrationFile(hw, { name: '', endpoint: 'https://hw.example/ace' }))).toBe('invalid_registration');
    }
  });

  it('profiles: unknown fields dropped, nulls absent, strict pricing', () => {
    expect(validateProfile({ name: 'A', description: null, junk: 1 } as never)).toEqual({ name: 'A' });
    expect(codeOf(() => validateProfile({ pricing: { currency: '' } }))).toBe('invalid_profile');
    expect(codeOf(() => validateProfile({ pricing: { currency: 'USD', maxAmount: '1.' } }))).toBe('invalid_profile');
    expect(codeOf(() => validateProfile({ tags: ['UPPER'] }))).toBe('invalid_profile');
    expect(codeOf(() => validateProfile({ image: 'https://x.example/' + 'a'.repeat(600) }))).toBe('invalid_profile');
  });

  it('SSRF blocklist', () => {
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
