import { describe, expect, it } from 'vitest';
import { MemoryStore, NetworkClient, ProfileSet, createDelegationCredential, createInvitation, verifyInvitation, verifyKel, MAX_PERMIT_LIFETIME } from './sdk.js';
import { Clock, FakeRelay, agent, identity } from './helpers.js';

describe('NetworkClient', () => {
  it('contact flow, delivery with receipts, permit renewal through receipts', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { visibility: 'public', handle: 'alice', acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();

    // discovery and handle
    expect((await bob.client.discover()).agents.map((a) => a.descriptor.aceId)).toEqual([A]);
    expect((await bob.client.lookup('@alice@relay.test')).descriptor.aceId).toBe(A);
    // bob (private) cannot be looked up anonymously
    await expect(alice.client.agent(B)).rejects.toMatchObject({ code: 'unknown_peer' });

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

  it('a stranger request to a public identity without a rule waits for an explicit accept; blocks drop', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { visibility: 'public' });
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

  it('rejected:unknown_prekey refreshes the descriptor and retries; outbox backs off and expires', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { visibility: 'public', acceptProfiles: ['ace:text:1'] });
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

  it('invitations: two private agents pair; importing never admits, creating admits the invitee', async () => {
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
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    await expect(alice.client.outbox.enqueue({ to: bob.id.getACEId(), type: 'ace:text:1', body: { message: 'x' } })).rejects.toMatchObject({ code: 'unknown_peer' });
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
    const issuer = await agent(relay, clock, { visibility: 'public' });
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
    const alice = await agent(relay, clock, { visibility: 'public', acceptProfiles: ['ace:text:1'] });
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
});
