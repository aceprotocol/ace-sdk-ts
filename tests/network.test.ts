import { describe, expect, it } from 'vitest';
import { ACEError, MemoryStore, NetworkClient, ProfileSet, createDelegationCredential, createDescriptor, createInvitation, verifyInvitation, verifyKel, MAX_PERMIT_LIFETIME } from './sdk.js';
import { Clock, FakeRelay, RELAY, agent, identity } from './helpers.js';

describe('NetworkClient', () => {
  it('contact flow, delivery with receipts, permit renewal through receipts', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, handle: 'alice', acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();

    // discovery and handle
    expect((await bob.client.discover()).cards.map((c) => c.aceId)).toEqual([A]);
    expect((await bob.client.lookup('@alice@relay.test')).descriptor.aceId).toBe(A);
    // a typed address: the leading @ optional, any ASCII case; never a Unicode case fold (U+212A KELVIN SIGN)
    expect((await bob.client.lookup('Alice@Relay.Test')).descriptor.aceId).toBe(A);
    await expect(bob.client.lookup('@\u212Aalice@relay.test')).rejects.toMatchObject({ code: 'invalid_argument' });
    // bob (closed, unlisted) is absent from the directory but resolvable by ACE ID
    expect((await alice.client.agent(B)).descriptor.aceId).toBe(B);
    expect((await alice.client.lookupCard(B)).record).toMatchObject({ contact: 'closed', listed: false });
    expect((await bob.client.lookupCard('@alice@relay.test')).record).toMatchObject({ aceId: A, handle: 'alice', contact: 'open', listed: true });

    await bob.client.connect(A, { profile: 'ace:text:1', note: 'hello from bob' });
    expect((await bob.client.admission.get(A))!.status).toBe('pending');
    const [contact] = await alice.client.pull();
    expect(contact).toMatchObject({ kind: 'contact', event: { stranger: true, body: { kind: 'request', note: 'hello from bob' } } });
    expect((await alice.client.admission.get(B))!.status).toBe('admitted'); // acceptProfiles rule
    const [answer] = await bob.client.pull();
    expect(answer).toMatchObject({ kind: 'contact', event: { body: { kind: 'accepted' } } });
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');

    // delivery is confirmed only by a receipt
    const entry = await bob.client.send(A, 'ace:text:1', { message: 'hi alice' });
    expect(entry.status).toBe('pending');
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    expect(alice.received.map((m) => m.body.message)).toEqual(['hi alice']);
    expect((await bob.client.pull())[0].kind).toBe('receipt');
    expect((await bob.client.outbox.get(entry.messageId))!.status).toBe('delivered');

    // 16 days later: descriptors republished (prekeys rotated), alice refreshes bob's private descriptor with
    // bob's permit, and bob's receipt carries a renewed permit
    clock.advance(16 * 86400);
    await alice.client.publish();
    await bob.client.publish();
    const oldPermit = (await alice.client.admission.heldPermit(B))!;
    await alice.client.send(B, 'ace:text:1', { message: 'still there?' });
    expect((await bob.client.pull())[0].kind).toBe('delivered');
    expect((await alice.client.pull())[0].kind).toBe('receipt');
    const renewed = (await alice.client.admission.heldPermit(B))!;
    expect(renewed.issuedAt).toBeGreaterThan(oldPermit.issuedAt);
    expect(renewed.expiresAt).toBe(clock.t + MAX_PERMIT_LIFETIME);
  });

  it('a stranger request to an open identity without a rule waits for an explicit accept; blocks drop', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    expect(await alice.client.admission.get(B)).toBeNull();
    expect((await alice.client.requests()).map((r) => r.from)).toEqual([B]);
    await alice.client.accept(B);
    await bob.client.pull();
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');

    await alice.client.block(B);
    expect(relay.blocks.get(`${A}|${B}`)).toEqual({ blocked: true, revision: 1 });
    const e = await bob.client.send(A, 'ace:text:1', { message: 'x' });
    expect(e.code).toBe('not_permitted'); // the relay refuses, the Outbox keeps retrying until expiry
    await alice.client.unblock(B);
    expect(relay.blocks.get(`${A}|${B}`)).toEqual({ blocked: false, revision: 2 });
  });

  it('a blocked stranger\'s contact request reads like one to a closed peer (05 § Blocks)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const open = await agent(relay, clock, { contact: 'open', listed: true });
    const closed = await agent(relay, clock);
    const bob = await agent(relay, clock);
    await open.client.block(bob.id.getACEId());
    const refusal = (target: string) => bob.client.connect(target, { profile: 'ace:text:1' }).then(() => null, (e: unknown) => e as ACEError);
    const blocked = (await refusal(open.id.getACEId()))!, shut = (await refusal(closed.id.getACEId()))!;
    expect(blocked).toBeInstanceOf(ACEError);
    expect({ code: blocked.code, message: blocked.message, status: blocked.status, relayCode: blocked.relayCode })
      .toEqual({ code: 'not_permitted', message: shut.message, status: undefined, relayCode: undefined });
  });

  it('rejected:unknown_prekey refreshes the descriptor and retries; outbox backs off and expires', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();

    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    const e = await bob.client.send(A, 'ace:text:1', { message: 'x' });
    expect(e).toMatchObject({ status: 'pending', attempts: 1, code: 'relay_unavailable', nextAttemptAt: clock.t + 60 });
    clock.advance(60);
    expect((await bob.client.flush())[0]).toMatchObject({ attempts: 2, nextAttemptAt: clock.t + 120 });

    // alice loses her prekeys (new vault): the packet is rejected with unknown_prekey
    await alice.client.vault.rotate(clock.t);
    for (const k of await alice.store.list('prekeys.json')) await alice.store.delete(k);
    await alice.client.publish({ force: true });
    expect((await alice.client.pull())[0]).toMatchObject({ kind: 'rejected', error: { code: 'unknown_prekey' } });
    await bob.client.pull();
    const after = (await bob.client.outbox.get(e.messageId))!;
    expect(after).toMatchObject({ status: 'pending', code: 'unknown_prekey' });
    await bob.client.flush();
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    await bob.client.pull();
    expect((await bob.client.outbox.get(e.messageId))!.status).toBe('delivered');

    // expiry after the offline window
    const lost = await bob.client.outbox.enqueue({ to: A, type: 'ace:text:1', body: { message: 'never' } });
    relay.inject.push(...Array.from({ length: 100 }, () => ({ path: '/v1/send', status: 503, code: 'internal_error' })));
    await bob.client.outbox.attempt(lost.messageId);
    clock.advance(604_801);
    expect(await bob.client.outbox.attempt(lost.messageId)).toMatchObject({ status: 'expired', code: 'expired' });
  });

  it('invitations: two closed agents pair; importing never admits, creating admits the invitee', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    // bob shares his descriptor with alice out of band; alice invites him
    const inv = await alice.client.createInvitation(await bob.client.publish(), { profile: 'ace:text:1' });
    expect(inv.agent.descriptor.aceId).toBe(A);
    expect(inv.permit).toMatchObject({ issuer: A, subject: B });
    expect((await alice.client.admission.get(B))!.status).toBe('admitted');
    // a third party cannot use bob's invitation
    const carol = await agent(relay, clock);
    await expect(carol.client.importInvitation(inv)).rejects.toMatchObject({ code: 'invalid_authorization' });
    await expect(bob.client.importInvitation({ ...inv, extra: 1 })).rejects.toMatchObject({ code: 'invalid_authorization' });
    // bob imports: agent pinned, permit held, alice NOT admitted
    expect((await bob.client.importInvitation(inv)).descriptor.aceId).toBe(A);
    expect(await bob.client.admission.get(A)).toBeNull();
    // alice holds no permit from bob: the send fails at once and stores nothing (06 § Outbox)
    await expect(alice.client.send(B, 'ace:text:1', { message: 'early' })).rejects.toMatchObject({ code: 'not_permitted' });
    expect(await alice.client.outbox.list()).toEqual([]);
    expect(await bob.client.pull()).toEqual([]);
    // bob connects to private alice with the held permit; alice accepts automatically (bob is admitted there)
    await bob.client.connect(A, { profile: 'ace:text:1' });
    expect((await alice.client.pull())[0]).toMatchObject({ kind: 'contact' });
    expect((await bob.client.pull())[0]).toMatchObject({ kind: 'contact', event: { body: { kind: 'accepted' } } });
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');
    await bob.client.send(A, 'ace:text:1', { message: 'paired' });
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    expect(alice.received.map((m) => m.body.message)).toEqual(['paired']);
  });

  it('invitation helpers: createInvitation needs the own agent; verifyInvitation binds subject and issuer', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    const B = bob.id.getACEId();
    await expect(createInvitation(alice.id, await bob.client.publish(), B)).rejects.toMatchObject({ code: 'invalid_argument' });
    const inv = await createInvitation(alice.id, await alice.client.publish(), B, { now: clock.t });
    expect(verifyInvitation(inv, B, clock.t).permit.subject).toBe(B);
    expect(() => verifyInvitation(inv, alice.id.getACEId(), clock.t)).toThrow(/invalid_authorization/);
    const forged = { agent: await bob.client.publish(), permit: inv.permit };
    expect(() => verifyInvitation(forged, B, clock.t)).toThrow(/invalid_authorization/);
  });

  it('enqueue to a peer without any resolvable descriptor fails unknown_peer at once and queues nothing', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await identity(clock); // never published
    await expect(alice.client.outbox.enqueue({ to: bob.getACEId(), type: 'ace:text:1', body: { message: 'x' } })).rejects.toMatchObject({ code: 'unknown_peer' });
    expect(await alice.client.outbox.list()).toEqual([]);
  });

  it('open wires the store, message log and commerce rules', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const client = await NetworkClient.open({
      identity: await identity(clock), store: new MemoryStore(), relayUrl: relay.baseUrl, profiles: ['text', 'commerce'],
      fetch: relay.fetch, clock: clock.now,
    });
    expect(client.profiles.descriptors().map((p) => p.id)).toEqual(['ace:text:1', 'ace:commerce:1']);
    expect(client.messages).not.toBeNull();
    expect(client.threads).not.toBeNull();
    const self = await client.publish();
    expect(self.descriptor.profiles).toEqual(new ProfileSet(['text', 'commerce']).descriptors());
    await client.close();
  });

  it('open takes a ready RelayClient and opens send-only clients beside a receiver', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const store = new MemoryStore(), identityA = await identity(clock);
    await expect(NetworkClient.open({ identity: identityA, store, clock: clock.now })).rejects.toMatchObject({ code: 'invalid_argument' });
    const receiver = await NetworkClient.open({ identity: identityA, store, relay: relay.client(), clock: clock.now, messageLog: false });
    expect(receiver.relay.baseUrl).toBe(relay.baseUrl);
    expect(receiver.messages).toBeNull();
    const sender = await NetworkClient.open({ identity: identityA, store, relay: relay.client(), clock: clock.now, receive: false });
    expect(() => sender.inbox).toThrow(/receive role/);
    await expect(NetworkClient.open({ identity: identityA, store, relay: relay.client(), clock: clock.now })).rejects.toMatchObject({ code: 'lock_busy' });
    await receiver.close();
  });

  it('publish registers the current KEL when the relay lacks it (not_registered, then kel_conflict after a rotation)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const id = await identity(clock);
    const client = await NetworkClient.open({ identity: id, store: new MemoryStore(), relay: relay.client(), clock: clock.now });
    await client.publish();
    expect(relay.registrations).toBe(1);
    await client.publish({ force: true });
    expect(relay.registrations).toBe(1);
    clock.advance(10);
    await id.rotate({ now: clock.t });
    const after = await client.publish();
    expect(relay.registrations).toBe(2);
    expect(relay.kels.get(id.getACEId())!.lastHash).toBe(verifyKel(id.getKel(), clock.t).lastHash);
    expect(relay.descriptors.get(id.getACEId())).toEqual(after);
  });

  it('verifyDelegation names this identity as subject; an expired credential is null', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const issuer = await agent(relay, clock, { contact: 'open', listed: true });
    const subject = await agent(relay, clock);
    const S = subject.id.getACEId();
    await subject.client.lookup(issuer.id.getACEId()); // pins the issuer
    const entry = { kel: issuer.id.getKel(), credential: await createDelegationCredential(issuer.id, S, { now: clock.t, ttl: 60 }) };
    expect((await subject.client.verifyDelegation(entry))!.issuer).toBe(issuer.id.getACEId());
    await expect(issuer.client.verifyDelegation(entry)).rejects.toMatchObject({ code: 'invalid_authorization' });
    clock.advance(61);
    expect(await subject.client.verifyDelegation(entry)).toBeNull();
  });

  it('the test relay streams catch-up and new packets over /v1/listen', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    await bob.client.connect(alice.id.getACEId(), { profile: 'ace:text:1' });
    const ctrl = new AbortController();
    const kinds: string[] = [];
    for await (const out of alice.client.follow({ signal: ctrl.signal })) {
      kinds.push(out.kind);
      ctrl.abort();
    }
    expect(kinds).toEqual(['contact']);
  });

  it('wake hints go to the home relay (07 § Wake hints)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const A = alice.id.getACEId();
    await alice.client.setWake('https://push.example/ace', 'w'.repeat(32));
    expect(relay.wakes.get(A)).toEqual({ gateway: 'https://push.example/ace', token: 'w'.repeat(32) });
    await alice.client.clearWake();
    await alice.client.clearWake(); // idempotent
    expect(relay.wakes.has(A)).toBe(false);
    // Malformed gateways and tokens are covered by the vectors (auth.wake.invalid).
    relay.inject.push({ path: '/v1/wake', status: 404, code: 'not_found' });
    await expect(alice.client.setWake('https://push.example/ace', 'w'.repeat(32))).rejects.toMatchObject({ code: 'relay_rejected', relayCode: 'not_found' });
  });

  describe('descriptor routes', () => {
    const B = 'https://relay-b.test';
    const setup = async () => {
      const clock = new Clock();
      const relay = new FakeRelay(clock.now), relayB = new FakeRelay(clock.now, B);
      const alice = await agent(relay, clock);
      const { prekey, profiles } = relay.descriptors.get(alice.id.getACEId())!.descriptor;
      const descriptor = (relays: string[], ttl?: number) => {
        clock.advance(1);
        return createDescriptor(alice.id, { relays, prekey, profiles, now: clock.t, ...(ttl !== undefined ? { ttl } : {}) });
      };
      const paths: string[] = [];
      const fetch = relay.fetch;
      relay.fetch = (input, init) => { paths.push(new URL(String(input)).pathname); return fetch(input, init); };
      const bob = await agent(relay, clock, {
        foreignRelay: (url) => { if (url !== B) throw new ACEError('blocked_address', url); return relayB.client(); },
      });
      return { clock, relay, relayB, alice, A: alice.id.getACEId(), descriptor, paths, bob };
    };

    it('every route is tried: one replaying an older descriptor never blocks a lookup the next route serves', async () => {
      const { clock, relay, relayB, alice, A, descriptor, bob } = await setup();
      // Relay B keeps serving an older revision; the home relay serves the newest.
      const old = await descriptor([B, RELAY]);
      await relayB.client().register(alice.id);
      await relayB.client().publishDescriptor(old);
      const held = await descriptor([B, RELAY], 60);
      const newest = await descriptor([RELAY]);
      await relay.client().publishDescriptor(newest);
      await bob.client.importAgent(held);
      clock.advance(120); // the held one expired: refreshed from its routes, relay B first (stale_peer_binding there)
      expect(await bob.client.agent(A)).toEqual(newest);
    });

    it('a cached descriptor no longer bound to the pin is refreshed from its relays and the home relay; a bound one from its relays alone', async () => {
      const { clock, alice, A, descriptor, paths, bob } = await setup();
      await bob.client.importAgent(await descriptor([B]));
      paths.length = 0;
      const asked = () => paths.filter((p) => p.startsWith('/v1/descriptor/'));
      // Bound: a refresh asks its relays alone (relay B does not serve it), never the home relay.
      await expect(bob.client.agent(A, { refresh: true })).rejects.toMatchObject({ code: 'unknown_peer' });
      expect(asked()).toEqual([]);
      // Alice's key moves on: the cached descriptor was signed under a superseded key, so the home relay is asked too.
      await alice.id.delegate({ now: clock.t });
      await bob.client.peers.adopt(alice.id.getKel());
      const current = await alice.client.publish();
      expect(await bob.client.agent(A)).toEqual(current);
      expect(asked()).toHaveLength(1);
    });

    it('a cached descriptor whose delegation issuer\'s pin advanced is refreshed from its relays and the home relay', async () => {
      const { clock, relay, alice, A, descriptor, paths, bob } = await setup();
      const dave = await identity(clock);
      const { prekey, profiles } = relay.descriptors.get(A)!.descriptor;
      clock.advance(1);
      const credential = await createDelegationCredential(dave, A, { now: clock.t, ttl: 86_400 });
      const delegated = await createDescriptor(alice.id, { relays: [B], prekey, profiles, now: clock.t, delegations: [{ kel: dave.getKel(), credential }] });
      await bob.client.peers.adopt(dave.getKel());
      await bob.client.importAgent(delegated);
      // Dave's key moves on: the entry no longer verifies under his pin, so the descriptor is no longer bound.
      clock.advance(1);
      await dave.delegate({ now: clock.t });
      await bob.client.peers.adopt(dave.getKel());
      const current = await descriptor([RELAY]);
      await relay.client().publishDescriptor(current);
      paths.length = 0;
      expect(await bob.client.agent(A)).toEqual(current);
      expect(paths.filter((p) => p.startsWith('/v1/descriptor/'))).toHaveLength(1);
    });
  });
});
