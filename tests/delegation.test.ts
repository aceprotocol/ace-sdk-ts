// The ace:delegation:1 profile (profiles/delegation.md): credentials, the descriptor extension, the hand-over message
// rule and NetworkClient.verifyDelegation; plus the core changes that came with it: ERC-8004 on the card record, signers
// at the log tail (01 § Operational signatures), card lookups that need a live descriptor (04 § Card record) and the
// one page default.
import { describe, expect, it } from 'vitest';
import {
  DELEGATION_PROFILE_ID, DELEGATION_TYPE, MAX_DELEGATION_CREDENTIAL_LIFETIME, MAX_DELEGATION_CREDENTIALS, MAX_INBOX_PAGE, MemoryStore,
  NetworkClient, PeerStore, ProfileSet, StorePrekeyVault, checkStrangerSource, createAuthHeaders, createCardRecord, createDelegationCredential,
  createDescriptor, createPacket, createPermit, decodePacket, delegationRules, fromBase64, packetSignPayload, signOperational, signingMessage,
  toBase64, validateDelegationExt, verifyCardBundle, verifyDelegationCredential, verifyPacketSignature, verifyPermit, verifySignature,
  encodePayload, type DelegationCredential, type NetworkClientOptions, type NetworkProfile, type ParsedMessage, type RuleEvent,
  type SoftwareIdentity,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, identity, stateOf } from './helpers.js';
import { withPrekey } from './helpers2.js';

const code = (c: string) => expect.objectContaining({ code: c });
const SOL = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
const REGISTRY = 'eip155:1:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432';
const MID = '8a4f6a2e-3c0b-4d1e-9f7a-1b2c3d4e5f60';
const DELEGATION = new ProfileSet(['delegation']).descriptors();

/** A clock reading `t`. */
const clockAt = (t: number) => Object.assign(new Clock(), { t });
/** An identity whose log starts 10 s before NOW. */
const someone = () => identity(clockAt(NOW - 10));

/** A signed PublishedAgent of `id` announcing `profiles`, with `ext`. */
async function source(id: SoftwareIdentity, profiles: NetworkProfile[], ext?: Record<string, never> | Record<string, object>) {
  const pk = await new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }).rotate(NOW);
  return createDescriptor(id, { relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles, now: NOW, ...(ext ? { ext: ext as never } : {}) });
}

const event = (direction: RuleEvent['direction'], from: string, to: string): RuleEvent => ({ direction, from, to, messageId: MID, timestamp: NOW, type: DELEGATION_TYPE });

/** NetworkClients over one FakeRelay sharing a clock. */
function world() {
  const clock = new Clock();
  const relay = new FakeRelay(clock.now);
  const urls: URL[] = [];
  const fetch = (input: string | URL | Request, init?: RequestInit) => {
    urls.push(new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url));
    return relay.fetch(input, init);
  };
  const agent = async (o: Partial<NetworkClientOptions> = {}) => {
    const client = await NetworkClient.open({ identity: await identity(clock), store: new MemoryStore(), relayUrl: relay.baseUrl, fetch, clock: clock.now, ...o });
    await client.publish();
    return client;
  };
  return { clock, relay, urls, agent };
}

describe('delegation profile', () => {
  it('credentialRoundTripAndExtShape', async () => {
    const subject = await someone();
    const s = subject.getACEId();
    const issuers = await Promise.all(Array.from({ length: MAX_DELEGATION_CREDENTIALS + 1 }, someone));
    const creds = await Promise.all(issuers.map((i) => createDelegationCredential(i, s, { now: NOW })));
    const c = creds[0];
    expect(Object.keys(c).sort()).toEqual(['expiresAt', 'issuedAt', 'issuer', 'signature', 'subject']);
    expect([c.issuer, c.subject]).toEqual([issuers[0].getACEId(), s]);
    expect(c.expiresAt - c.issuedAt).toBe(MAX_DELEGATION_CREDENTIAL_LIFETIME);
    expect(verifyDelegationCredential(c, stateOf(issuers[0]), NOW)).toEqual(c);
    // signed with the profile's own action, never a core one
    expect(() => verifyDelegationCredential(c, stateOf(issuers[1]), NOW)).toThrow(code('invalid_authorization'));
    expect(validateDelegationExt({ credentials: creds.slice(0, 4) }, s, NOW)).toEqual(creds.slice(0, 4));
    for (const bad of [
      { credentials: creds }, // five
      { credentials: [] },
      { credentials: [c, c] }, // one issuer twice
      { credentials: creds.slice(0, 1), x: 1 },
      [c],
    ]) expect(() => validateDelegationExt(bad, s, NOW)).toThrow(code('invalid_authorization'));
    expect(() => validateDelegationExt({ credentials: [c] }, issuers[1].getACEId(), NOW)).toThrow(code('invalid_authorization')); // another subject
    expect(() => validateDelegationExt({ credentials: [{ ...c, subject: c.issuer }] }, c.issuer, NOW)).toThrow(code('invalid_authorization')); // issuer == subject
    expect(() => validateDelegationExt({ credentials: [{ ...c, expiresAt: c.issuedAt + 604_801 }] }, s, NOW)).toThrow(code('invalid_authorization'));
    await expect(createDelegationCredential(issuers[0], s, { now: NOW, ttl: 604_801 })).rejects.toThrow(code('invalid_argument'));
    await expect(createDelegationCredential(issuers[0], issuers[0].getACEId(), { now: NOW })).rejects.toThrow(code('invalid_argument'));
    expect((await createDelegationCredential(issuers[0], s, { now: NOW, ttl: 60 })).expiresAt).toBe(NOW + 60);
    // the extension is checked by descriptor verification (shape only)
    const subj = await someone();
    const ext = { [DELEGATION_PROFILE_ID]: { credentials: [await createDelegationCredential(issuers[0], subj.getACEId(), { now: NOW })] } };
    expect((await source(subj, DELEGATION, ext)).descriptor.ext).toEqual(ext);
    // the subject is not the descriptor's
    await expect(source(subj, DELEGATION, { [DELEGATION_PROFILE_ID]: { credentials: [c] } })).rejects.toThrow(code('invalid_authorization'));
  });

  it('verifyRejectsExpiredAndTampered', async () => {
    const issuer = await someone(), s = (await someone()).getACEId();
    const c = await createDelegationCredential(issuer, s, { now: NOW, ttl: 60 });
    expect(() => verifyDelegationCredential(c, stateOf(issuer), NOW + 60)).toThrow(code('invalid_authorization'));
    // the descriptor extension does not check expiry
    expect(validateDelegationExt({ credentials: [c] }, s, NOW + 60)).toEqual([c]);
    const sig = fromBase64(c.signature.value);
    sig[0] ^= 1;
    const tampered: DelegationCredential = { ...c, signature: { ...c.signature, value: toBase64(sig) } };
    expect(() => verifyDelegationCredential(tampered, stateOf(issuer), NOW)).toThrow(code('invalid_authorization'));
    // a new dlg supersedes the key: stale_peer_binding passes through
    await issuer.delegate({ now: NOW + 1 });
    expect(() => verifyDelegationCredential(c, stateOf(issuer, NOW + 1), NOW + 1)).toThrow(code('stale_peer_binding'));
  });

  it('ruleRequiresIssuerFromAndSubjectTo', async () => {
    const clock = new Clock();
    const [dave, bob, carol] = await Promise.all([identity(clock), identity(clock), identity(clock)]);
    const D = dave.getACEId(), B = bob.getACEId(), C = carol.getACEId();
    const bobPeers = new PeerStore({ store: new MemoryStore(), clock: clock.now });
    const rules = delegationRules(bobPeers, B);
    expect(rules.types).toEqual([DELEGATION_TYPE]);
    const c = await createDelegationCredential(dave, B, { now: NOW });
    await expect(rules.check(event('receive', D, B), { credential: c } as never)).rejects.toThrow(code('invalid_body')); // the sender is not pinned
    await bobPeers.adopt(dave.getKel());
    await rules.check(event('receive', D, B), { credential: c } as never);
    await rules.commit(event('receive', D, B), { credential: c } as never);
    const carolC = await createDelegationCredential(carol, B, { now: NOW });
    await bobPeers.adopt(carol.getKel());
    await expect(rules.check(event('receive', D, B), { credential: carolC } as never)).rejects.toThrow(code('invalid_body')); // issuer != from
    await expect(rules.check(event('receive', D, C), { credential: c } as never)).rejects.toThrow(code('invalid_body')); // subject != to
    // not the issuer's signature
    await expect(rules.check(event('receive', D, B), { credential: { ...carolC, issuer: D } } as never)).rejects.toThrow(code('invalid_body'));
    clock.t = c.expiresAt;
    await expect(rules.check(event('receive', D, B), { credential: c } as never)).rejects.toThrow(code('invalid_body')); // expired
    // on send: the sender is the issuer (its own credential), no pin needed
    const senderRules = delegationRules(new PeerStore({ store: new MemoryStore(), clock: clock.now }), D);
    clock.t = NOW;
    await senderRules.check(event('send', D, B), { credential: c } as never);
    await expect(senderRules.check(event('send', D, C), { credential: c } as never)).rejects.toThrow(code('invalid_body'));
  });

  it('networkVerifyDelegationPinsTheIssuer', async () => {
    const w = world();
    const dave = await w.agent({ contact: 'open' }), bob = await w.agent();
    const D = dave.identity.getACEId(), B = bob.identity.getACEId();
    const c = await createDelegationCredential(dave.identity, B, { now: w.clock.t });
    expect(await bob.peers.get(D)).toBeNull();
    expect(await bob.verifyDelegation(c)).toEqual(c);
    expect(await bob.peers.get(D)).not.toBeNull();
    const stranger = await identity(clockAt(w.clock.t - 10));
    const unknown = await createDelegationCredential(stranger, B, { now: w.clock.t });
    await expect(bob.verifyDelegation(unknown)).rejects.toThrow(code('unknown_peer'));
    await expect(bob.verifyDelegation({ ...c, expiresAt: 'x' })).rejects.toThrow(code('invalid_authorization'));
    await Promise.all([dave.close(), bob.close()]);
  });

  it('networkClientInstallsTheDelegationRule', async () => {
    const w = world();
    const dave = await w.agent({ contact: 'open', profiles: ['text', 'delegation'] });
    const received: ParsedMessage[] = [];
    const bob = await w.agent({ profiles: ['text', 'delegation'], onMessage: (m) => { received.push(m); } });
    const D = dave.identity.getACEId(), B = bob.identity.getACEId();
    await bob.connect(D, { profile: DELEGATION_PROFILE_ID });
    await dave.pull();
    await dave.accept(B);
    await bob.pull();
    const c = await createDelegationCredential(dave.identity, B, { now: w.clock.t });
    // checked on send: the subject must be the recipient
    await expect(dave.send(B, DELEGATION_TYPE, { credential: { ...c, subject: D } } as never)).rejects.toThrow(code('invalid_body'));
    await dave.send(B, DELEGATION_TYPE, { credential: c } as never);
    await bob.pull();
    expect(received.filter((m) => m.type === DELEGATION_TYPE).map((m) => m.body)).toEqual([{ credential: c }]);
    await Promise.all([dave.close(), bob.close()]);
  });

  it('signerTimestampIsTheLogTail', async () => {
    const me = await someone(), peer = await someone();
    await me.delegate({ now: NOW + 100 });
    const st = stateOf(me, NOW + 100);
    const pk = await new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }).rotate(NOW);
    const content = withPrekey({ type: 'ace:text:1', schemaDigest: new ProfileSet(['text']).digestOf('ace:text:1')!, body: { message: 'hi' } });
    const p = await createPacket({ identity: me, to: peer.getACEId(), prekey: { id: pk.id, publicKey: pk.publicKey }, content, timestamp: NOW });
    expect(p.timestamp).toBe(NOW + 100);
    verifyPacketSignature(decodePacket(p), st, NOW + 100);
    const permit = await createPermit(me, peer.getACEId(), { now: NOW });
    expect(permit.issuedAt).toBe(NOW + 100);
    verifyPermit(permit, st, peer.getACEId(), NOW + 100);
    const aud = 'https://relay.example';
    const h = await createAuthHeaders(me, { action: 'inbox-ack', through: '1-0' }, NOW, { audience: aud });
    expect(h['X-ACE-Timestamp']).toBe(String(NOW + 100));
    const message = signingMessage(me.getACEId(), NOW + 100, Number(h['X-ACE-Seq']), encodePayload(aud, h['X-ACE-Nonce'], encodePayload('1-0')));
    expect(verifySignature(message, 'inbox-ack', fromBase64(h['X-ACE-Signature']), st.signing!.publicKey)).toBe(true);
    // a packet signed one second before the dlg's ts does not verify (signed while live)
    const q = decodePacket(p);
    const early = decodePacket({ ...p, timestamp: NOW + 99, signature: await signOperational(me, NOW + 99, packetSignPayload(q), 'packet') });
    expect(() => verifyPacketSignature(early, st, NOW + 100)).toThrow(code('stale_peer_binding'));
  });

  it('cardRecordErc8004', async () => {
    const i = await someone();
    const entry = { agentRegistry: REGISTRY, agentId: '42' }, native = { agentRegistry: SOL, agentId: 'Ab12' };
    const base = { home: RELAY, contact: 'closed', listed: false } as const;
    const bundle = await createCardRecord(i, { ...base, erc8004: [entry, native], now: NOW });
    expect(verifyCardBundle(bundle, NOW).record.erc8004).toEqual([entry, native]);
    expect(verifyCardBundle(await createCardRecord(i, { ...base, now: NOW + 1 }), NOW + 1).record.erc8004).toBeUndefined();
    for (const bad of [
      [{ agentRegistry: REGISTRY, agentId: '042' }], // leading zero under eip155
      [{ agentRegistry: SOL, agentId: 'a-b' }],
      [entry, entry],
      Array.from({ length: 5 }, (_, n) => ({ agentRegistry: REGISTRY, agentId: String(n) })),
      [],
    ]) {
      expect(() => verifyCardBundle({ kel: bundle.kel, card: { ...bundle.card, erc8004: bad } }, NOW)).toThrow(code('invalid_authorization'));
      await expect(createCardRecord(i, { ...base, erc8004: bad, now: NOW })).rejects.toThrow(code('invalid_authorization'));
    }
  });

  it('lookupCardNeedsALiveDescriptor', async () => {
    const w = world();
    const alice = await w.agent({ contact: 'open', handle: 'alice', pay: [SOL] });
    const A = alice.identity.getACEId();
    // Alice is offline past her descriptor's lifetime: her card is served, no descriptor.
    w.clock.advance(8 * 86_400);
    for (const target of [A, `@alice@${new URL(RELAY).host}`]) {
      const bob = await NetworkClient.open({ identity: await identity(w.clock), store: new MemoryStore(), relayUrl: w.relay.baseUrl, fetch: w.relay.fetch, clock: w.clock.now });
      await expect(bob.lookupCard(target)).rejects.toThrow(code('unknown_peer'));
      expect(await bob.peers.get(A)).toBeNull();
      await bob.close();
    }
    await alice.close();
  });

  it('directoryDefaultLimitIsMaxInboxPage', async () => {
    const w = world();
    const bob = await w.agent();
    await bob.discover();
    await bob.relay.directory();
    expect(w.urls.filter((u) => u.pathname === '/v1/cards').map((u) => u.searchParams.get('limit'))).toEqual([String(MAX_INBOX_PAGE), String(MAX_INBOX_PAGE)]);
    await bob.close();
  });

  it('strangerSourceWithDelegationExtCostsOnlyItsOwnKel', async () => {
    const subj = await someone();
    const creds = await Promise.all(Array.from({ length: 4 }, async () => createDelegationCredential(await someone(), subj.getACEId(), { now: NOW })));
    const src = await source(subj, DELEGATION, { [DELEGATION_PROFILE_ID]: { credentials: creds } });
    checkStrangerSource(src);
    expect(() => checkStrangerSource({ ...src, kel: Array.from({ length: 33 }, () => src.kel[0]) })).toThrow(code('not_permitted'));
  });

  it('extSizeBoundIs32768', async () => {
    const subj = await someone();
    const big: NetworkProfile[] = [{ id: 'x:big:1', digest: '0'.repeat(64) }];
    // {"x:big:1":{"v":"…"}} is 20 bytes around the string
    await expect(source(subj, big, { 'x:big:1': { v: 'a'.repeat(32768 - 19) } })).rejects.toThrow(code('invalid_authorization'));
    expect((await source(subj, big, { 'x:big:1': { v: 'a'.repeat(32768 - 20) } })).descriptor.ext).toBeDefined();
  });
});
