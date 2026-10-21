// Admission (ace-spec/05): only local actions change admission; contact replies count only for our own pending request.
import { describe, expect, it } from 'vitest';
import {
  ACEError, MemoryStore, NetworkClient, ProfileSet, canonicalStateBytes, contactContent, createInvitation, createPacket, createPermit, sha256Hex,
  type ParsedMessage, type PrivateContent,
} from './sdk.js';
import { CONTACT_REQUEST_TTL_SECONDS, MAX_PENDING_CONTACT_REQUESTS } from '../src/limits.js';
import { Clock, FakeRelay, agent, type TestAgent } from './helpers.js';

const text = new ProfileSet(['text']);
const msg = (message: string): PrivateContent => ({ type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message } });

/** A packet from `from` to `to`, encrypted to `to`'s current published prekey (bypasses relays and the Outbox). */
async function direct(from: TestAgent, to: TestAgent, content: PrivateContent, clock: Clock) {
  const prekey = (await to.client.publish()).descriptor.prekey;
  return createPacket({ identity: from.id, to: to.id.getACEId(), prekey, content, timestamp: clock.t });
}

async function contact(from: TestAgent, to: TestAgent, kind: 'request' | 'accepted' | 'rejected', profile: string, clock: Clock) {
  const source = await from.client.publish();
  const permit = kind === 'rejected' ? undefined : await createPermit(from.id, to.id.getACEId(), { now: clock.t });
  return direct(from, to, contactContent({ kind, profile, note: '', source, ...(permit ? { permit } : {}) }), clock);
}

describe('admission', () => {
  it('connect records pending; a request never admits by itself; a stranger may send nothing else', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    expect((await bob.client.admission.get(A))).toMatchObject({ status: 'pending', profile: 'ace:text:1' });
    expect((await alice.client.pull())[0]).toMatchObject({ kind: 'contact', event: { stranger: true } });
    expect(await alice.client.admission.get(B)).toBeNull();
    expect(await alice.client.inbox.receive(await direct(bob, alice, msg('let me in'), clock))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(alice.received).toEqual([]);
  });

  it('a stranger\'s contact is checked against an existing pin: a source older than the pin is dropped', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const carol = await agent(relay, clock);
    const stale = await contact(carol, alice, 'request', 'ace:text:1', clock); // signed under carol's first delegation
    await carol.id.delegate({ now: clock.t });
    await alice.client.importAgent(await carol.client.publish()); // pinned, not admitted: carol is still a stranger
    expect(await alice.client.inbox.receive(stale)).toMatchObject({ kind: 'dropped', error: { code: 'stale_peer_binding' } });
    expect(await alice.client.requests()).toEqual([]);
    expect(await alice.client.inbox.receive(await contact(carol, alice, 'request', 'ace:text:1', clock))).toMatchObject({ kind: 'contact' });
  });

  it('a known peer\'s contact source extends the pin but does not confirm it live', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const bob = await agent(relay, clock);
    const carol = await agent(relay, clock, { contact: 'open', listed: true });
    const C = carol.id.getACEId();
    await bob.client.connect(C, { profile: 'ace:text:1' });
    expect(await bob.client.peers.kelLive(C)).toBe(true); // fetched from carol's relay
    const served = relay.descriptors.get(C)!;
    await carol.id.delegate({ now: clock.t });
    const accepted = await contact(carol, bob, 'accepted', 'ace:text:1', clock);
    relay.descriptors.set(C, served); // the relay still serves the old descriptor: the refresh does not reach the packet
    await bob.client.inbox.receive(accepted);
    expect((await bob.client.peers.get(C))!.events).toEqual(carol.id.getKel());
    // Self-signed by the sender: a holder of a superseded key could sign one too.
    expect(await bob.client.peers.kelLive(C)).toBe(false);
  });

  it('an accepted reply from a peer we never contacted is dropped and admits nothing', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const carol = await agent(relay, clock);
    const out = await bob.client.inbox.receive(await contact(carol, bob, 'accepted', 'ace:text:1', clock));
    expect(out.kind).toBe('dropped');
    expect(await bob.client.admission.get(carol.id.getACEId())).toBeNull();
  });

  it('an accepted reply for another profile than the pending request is ignored', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const both = { profiles: ['text' as const, 'commerce' as const] };
    const bob = await agent(relay, clock, both);
    const carol = await agent(relay, clock, { ...both, contact: 'open', listed: true });
    const C = carol.id.getACEId();
    await bob.client.connect(C, { profile: 'ace:text:1' });
    await bob.client.inbox.receive(await contact(carol, bob, 'accepted', 'ace:commerce:1', clock));
    expect((await bob.client.admission.get(C))).toMatchObject({ status: 'pending', profile: 'ace:text:1' });
    // the matching reply admits
    await bob.client.inbox.receive(await contact(carol, bob, 'accepted', 'ace:text:1', clock));
    expect((await bob.client.admission.get(C))!.status).toBe('admitted');
  });

  it('an accepted reply from an already admitted peer changes nothing', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();
    const before = await bob.client.admission.get(A);
    expect(before!.status).toBe('admitted');
    await bob.client.inbox.receive(await contact(alice, bob, 'accepted', 'ace:text:1', clock));
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');
  });

  it('a rejected reply removes our pending entry', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await alice.client.reject(B);
    expect(await alice.client.requests()).toEqual([]);
    // 05 § Flow: the rejected reply reaches the (closed) requester through the permit carried in its request
    expect((await bob.client.pull()).map((o) => o.kind)).toEqual(['contact']);
    expect(await bob.client.admission.get(A)).toBeNull();
  });

  it('acceptProfiles never overrides a block', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const B = bob.id.getACEId();
    await alice.client.block(B);
    await expect(bob.client.connect(alice.id.getACEId(), { profile: 'ace:text:1' })).rejects.toMatchObject({ code: 'not_permitted' });
    expect(await alice.client.inbox.receive(await contact(bob, alice, 'request', 'ace:text:1', clock))).toMatchObject({ kind: 'dropped' });
    expect((await alice.client.admission.get(B))!.status).toBe('blocked');
    expect(await alice.client.requests()).toEqual([]);
  });

  it('a block survives a restart; unblock makes the peer a stranger again', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();
    await alice.client.block(B);
    await alice.client.close();
    const received: ParsedMessage[] = [];
    const reopened = await NetworkClient.open({
      identity: alice.id, store: alice.store, relay: relay.client(), clock: clock.now,
      contact: 'open', listed: true, onMessage: (m) => { received.push(m); },
      foreignRelay: () => { throw new ACEError('blocked_address', 'no foreign relays in tests'); },
    });
    expect((await reopened.admission.get(B))!.status).toBe('blocked');
    const again = { ...alice, client: reopened };
    expect(await reopened.inbox.receive(await direct(bob, again, msg('blocked?'), clock))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    await reopened.unblock(B);
    expect(await reopened.admission.get(B)).toBeNull();
    expect(await reopened.inbox.receive(await direct(bob, again, msg('stranger'), clock))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(received).toEqual([]);
    await reopened.close();
  });

  it('importing an invitation lets us reach the inviter but never admits it', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock); // private
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.importInvitation(await createInvitation(alice.id, await alice.client.publish(), B, { now: clock.t }));
    expect((await bob.client.admission.get(A))?.status).not.toBe('admitted');
    expect((await bob.client.admission.get(A))?.status).not.toBe('pending');
    // inbound packets from the issuer are still a stranger's
    expect(await bob.client.inbox.receive(await direct(alice, bob, msg('hi bob'), clock))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(bob.received).toEqual([]);
    // the permit still resolves the issuer's private descriptor
    clock.advance(86_401);
    await alice.client.publish();
    expect((await bob.client.agent(A, { refresh: true })).descriptor.aceId).toBe(A);
  });

  it('an invitation for another subject is refused on import', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock);
    const carol = await agent(relay, clock);
    const forCarol = await createInvitation(alice.id, await alice.client.publish(), carol.id.getACEId(), { now: clock.t });
    await expect(bob.client.importInvitation(forCarol)).rejects.toMatchObject({ code: 'invalid_authorization' });
    expect(await bob.client.admission.heldPermit(alice.id.getACEId())).toBeNull();
    expect(await bob.client.admission.get(alice.id.getACEId())).toBeNull();
  });

  it('a corrupt admission store is never read as admission (storage_failed)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const store = alice.store as MemoryStore;
    const keys = await store.list('admission/');
    expect(keys).toEqual([]);
    const { sha256Hex } = await import('./sdk.js');
    const id = 'ace:sha256:' + '1'.repeat(64);
    await store.write(`admission/peers/${sha256Hex(id)}.json`, new TextEncoder().encode(JSON.stringify({ aceId: 'ace:sha256:' + '2'.repeat(64), status: 'admitted', updatedAt: 0 })));
    await expect(alice.client.admission.get(id)).rejects.toMatchObject({ code: 'storage_failed' });
  });

  it('accept never clears a block: a residual request from a blocked peer is not_permitted, the relay block unchanged', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    const [held] = await alice.client.requests();
    await alice.client.block(B);
    expect(await alice.client.requests()).toEqual([]); // blocking discards the held request
    // Simulate a residual record written by an older SDK; saveRequest now rejects blocked peers.
    await alice.store.write(`admission/requests/${sha256Hex(B)}.json`, canonicalStateBytes(held!));
    await expect(alice.client.accept(B)).rejects.toMatchObject({ code: 'not_permitted' });
    expect((await alice.client.admission.get(B))!.status).toBe('blocked');
    expect(relay.blocks.get(`${A}|${B}`)).toEqual({ blocked: true, revision: 1 });
  });

  it('a concurrent block and accept never end admitted', async () => {
    for (const blockFirst of [false, true]) {
      const clock = new Clock();
      const relay = new FakeRelay(clock.now);
      const alice = await agent(relay, clock, { contact: 'open', listed: true });
      const bob = await agent(relay, clock);
      const A = alice.id.getACEId(), B = bob.id.getACEId();
      await bob.client.connect(A, { profile: 'ace:text:1' });
      await alice.client.pull();
      const ops = [() => alice.client.accept(B), () => alice.client.block(B)];
      if (blockFirst) ops.reverse();
      await Promise.allSettled(ops.map((f) => f()));
      expect((await alice.client.admission.get(B))!.status).toBe('blocked');
      expect(relay.blocks.get(`${A}|${B}`)?.blocked).toBe(true);
    }
  });

  it('M1: connect never clears a block; only the explicit unblock does', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const B = bob.id.getACEId();
    await alice.client.block(B);
    await expect(alice.client.connect(B, { profile: 'ace:text:1' })).rejects.toMatchObject({ code: 'not_permitted' });
    expect((await alice.client.admission.get(B))!.status).toBe('blocked');
    await alice.client.unblock(B);
    await alice.client.connect(B, { profile: 'ace:text:1' });
    expect((await alice.client.admission.get(B))!.status).toBe('pending');
  });

  it('M3: held requests are one per sender, expire after 24 h, and the oldest is evicted when full', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const book = alice.client.admission;
    const src = await alice.client.publish();
    const req = (n: number, note = '') => ({
      from: 'ace:sha256:' + n.toString(16).padStart(64, '0'), messageId: '6f9619ff-8b86-4011-b42d-00c04fc964ff', profile: 'ace:text:1', note,
      source: src, permit: {} as never, receivedAt: clock.t,
    });
    for (let i = 1; i <= MAX_PENDING_CONTACT_REQUESTS; i++) { clock.advance(1); await book.saveRequest(req(i)); }
    clock.advance(1); await book.saveRequest(req(1, 'again')); // replaced, now the newest
    expect((await book.requests()).length).toBe(MAX_PENDING_CONTACT_REQUESTS);
    clock.advance(1); await book.saveRequest(req(99)); // full: the oldest (2) is evicted
    const held = (await book.requests()).map((r) => r.from);
    expect(held).not.toContain(req(2).from);
    expect(held.slice(-2)).toEqual([req(1).from, req(99).from]);
    expect((await book.request(req(1).from))!.note).toBe('again');
    clock.advance(CONTACT_REQUEST_TTL_SECONDS);
    expect(await book.requests()).toEqual([]);
    expect(await book.request(req(99).from)).toBeNull();
    await expect(alice.client.accept(req(99).from)).rejects.toMatchObject({ code: 'invalid_argument' });
  });

  it('after a signing-key change, maintain pushes fresh permits to admitted peers', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock); // private
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();
    expect((await alice.client.admission.get(B))!.status).toBe('admitted');
    const old = (await alice.client.admission.heldPermit(B))!.signature.seq;
    clock.advance(10);
    await bob.id.delegate({ now: clock.t });
    await bob.client.maintain(); // republishes (registering the new KEL) and re-sends a request carrying a fresh permit
    expect((await bob.client.admission.get(A))!.issued!.seq).toBe(bob.id.getSigningSeq()); // once per delegation
    const sends = relay.sent.length;
    await bob.client.maintain();
    expect(relay.sent.length).toBe(sends);
    await alice.client.pull(); // accepted automatically (bob is admitted), answered `accepted`
    const fresh = (await alice.client.admission.heldPermit(B))!;
    expect(fresh.signature.seq).toBe(bob.id.getSigningSeq());
    expect(fresh.signature.seq).not.toBe(old);
    await bob.client.pull();
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');
    const sent = await alice.client.send(B, 'ace:text:1', { message: 'still reachable' });
    await bob.client.pull();
    await alice.client.pull();
    expect((await alice.client.outbox.get(sent.messageId))!.status).toBe('delivered');
  });
});
