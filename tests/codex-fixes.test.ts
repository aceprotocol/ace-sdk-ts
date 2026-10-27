// Regression tests for the 2026-10-16 codex review fixes (docs/superpowers/plans/2026-10-16-codex-fixes.md).
import { describe, expect, it } from 'vitest';
import {
  AdmissionBook, Inbox, StorePrekeyVault, MemoryStore, OFFLINE_WINDOW_SECONDS, Outbox, PeerStore, ProfileSet, TIMESTAMP_WINDOW_SECONDS,
  ThreadStore, commerceRules, createDescriptor, createPermit, NetworkClient, createPacket, decodePacket,
  type ACEStore, type ParsedMessage, type ReceiptBody,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, identity } from './helpers.js';
import { withPrekey } from './helpers2.js';

const lastPrekey = (relay: FakeRelay) => decodePacket(relay.sent.at(-1)!.packet).encryption.prekey;
/** Queue and attempt a message without `send`'s permit gate (these tests exercise the transport, not admission). */
const queue = async (client: NetworkClient, to: string, message: string) => {
  const e = await client.outbox.enqueue({ to, type: 'ace:text:1', body: { message } });
  return (await client.outbox.attempt(e.messageId)) ?? e;
};

describe('A: cached descriptors are bound to the current pins', () => {
  it('a rotated holder replaces a descriptor its old key signed with a later issuedAt', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const B = bob.id.getACEId();
    const evil = await new StorePrekeyVault(new MemoryStore(), { clock: clock.now }).rotate(clock.t);
    const forged = await createDescriptor(bob.id, {
      relays: [RELAY], prekey: { id: evil.id, publicKey: evil.publicKey }, profiles: bob.client.profiles.descriptors(),
      now: clock.t + TIMESTAMP_WINDOW_SECONDS,
    });
    await alice.client.importAgent(forged);
    clock.advance(10);
    await bob.id.delegate({ now: clock.t });
    await alice.client.admission.holdPermit(await createPermit(bob.id, alice.id.getACEId(), { now: clock.t })); // 06 § Outbox step 3
    const fresh = await bob.client.publish();
    expect(fresh.descriptor.issuedAt).toBeLessThan(forged.descriptor.issuedAt);
    expect((await alice.client.importAgent(fresh)).descriptor.prekey.id).toBe(fresh.descriptor.prekey.id);
    await queue(alice.client, B, 'hi');
    expect(lastPrekey(relay)).toBe(fresh.descriptor.prekey.id);
  });

  it('a pin advanced through another path makes the cached descriptor stale; a failed refresh never falls back', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const B = bob.id.getACEId();
    const old = (await alice.client.agent(B)).descriptor.prekey.id;
    const rotate = async () => {
      clock.advance(10);
      await bob.id.delegate({ now: clock.t });
      
      await bob.client.vault.rotate(clock.t);
      const a = await bob.client.publish();
      await alice.client.peers.adopt(bob.id.getKel()); // e.g. a contact `source`
      await alice.client.admission.holdPermit(await createPermit(bob.id, alice.id.getACEId(), { now: clock.t })); // 06 § Outbox step 3
      return a.descriptor.prekey.id;
    };
    const next = await rotate();
    expect(next).not.toBe(old);
    await queue(alice.client, B, 'one');
    expect(lastPrekey(relay)).toBe(next);

    await rotate();
    relay.descriptors.delete(B);
    const sent = relay.sent.length;
    await expect(alice.client.agent(B)).rejects.toMatchObject({ code: 'unknown_peer' });
    expect(await queue(alice.client, B, 'two')).toMatchObject({ status: 'pending', code: 'unknown_peer' });
    expect(relay.sent.length).toBe(sent);
  });

  it('a KEL-stale cached descriptor never receives the permit: its routes get only the anonymous lookup', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now), EVIL = 'https://evil.test', evil = new FakeRelay(clock.now, EVIL);
    const seen: string[] = [];
    const inner = evil.fetch;
    evil.fetch = async (input, init) => { seen.push(`${init?.method ?? 'GET'} ${String(init?.body ?? '')}`); return inner(input, init); };
    const alice = await agent(relay, clock, { foreignRelay: () => evil.client() });
    const bob = await agent(relay, clock); // private
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await alice.client.importAgent(await bob.client.publish());
    await alice.client.admission.holdPermit(await createPermit(bob.id, A, { now: clock.t }));
    const pk = await new StorePrekeyVault(new MemoryStore(), { clock: clock.now }).rotate(clock.t);
    // signed by bob's current key (e.g. stolen), naming the attacker's relay
    await alice.client.importAgent(await createDescriptor(bob.id, {
      relays: [EVIL], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: bob.client.profiles.descriptors(), now: clock.t + 1,
    }));
    clock.advance(10);
    await bob.id.delegate({ now: clock.t }); // bob recovers by rotating
    await alice.client.peers.adopt(bob.id.getKel());
    await bob.client.publish();
    expect((await alice.client.agent(B)).descriptor.relays).toEqual([RELAY]); // refreshed from the home relay
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.filter((r) => r.includes('permit'))).toEqual([]);
  });

  it('a permit signed by the issuer\'s superseded key is never presented after the issuer rotates', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const seen: string[] = [];
    const inner = relay.fetch;
    relay.fetch = async (input, init) => { seen.push(`${String(input)} ${String(init?.body ?? '')}`); return inner(input, init); };
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock); // private
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    await alice.client.importAgent(await bob.client.publish());
    await alice.client.admission.holdPermit(await createPermit(bob.id, A, { now: clock.t }));
    clock.advance(10);
    await bob.id.delegate({ now: clock.t });
    
    await alice.client.importAgent(await bob.client.publish()); // bound to the advanced pin
    seen.length = 0;
    await expect(alice.client.send(B, 'ace:text:1', { message: 'hi' })).rejects.toMatchObject({ code: 'not_permitted' });
    // an Outbox attempt without a live permit fails before posting: never the stranger path (06 § Outbox step 3)
    expect(await queue(alice.client, B, 'hi')).toMatchObject({ status: 'pending', code: 'not_permitted' });
    await alice.client.agent(B, { refresh: true }).catch(() => undefined);
    expect(seen.filter((r) => r.includes('/v1/send'))).toEqual([]);
    expect(seen.filter((r) => r.includes('"permit"'))).toEqual([]);
  });

  it('a pin advanced through another path while a descriptor is imported never returns that descriptor', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const old = await bob.client.publish();
    clock.advance(10);
    await bob.id.delegate({ now: clock.t });
    // another path (e.g. a contact `source`) pins bob's newer KEL after the import read the pin, before it takes the
    // `peers` lock (pin and cache are written together under that lock, so nothing can intervene later)
    const adopt = alice.client.peers.adopt.bind(alice.client.peers) as (kel: unknown, o?: unknown) => Promise<unknown>;
    (alice.client.peers as { adopt: unknown }).adopt = async (kel: unknown, o?: unknown) => {
      await adopt(bob.id.getKel());
      return adopt(kel, o);
    };
    await expect(alice.client.importAgent(old)).rejects.toMatchObject({ code: 'stale_peer_binding' });
    expect(await alice.client.store.list('network/agents/')).toEqual([]); // the stale descriptor was never cached
  });

  it('under an unchanged KEL an expired newer descriptor is never rolled back to an older, longer-lived one', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const make = async (now: number, ttl: number) => {
      const pk = await new StorePrekeyVault(new MemoryStore(), { clock: clock.now }).rotate(clock.t);
      return createDescriptor(bob.id, { relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: bob.client.profiles.descriptors(), now, ttl });
    };
    const older = await make(clock.t, 86400);
    const newer = await make(clock.t + 1, 60);
    await alice.client.importAgent(newer);
    clock.advance(120);
    await expect(alice.client.importAgent(older)).rejects.toMatchObject({ code: 'stale_peer_binding' });
    // the cache keeps the newer (expired) revision: the next use refreshes, never rolls back
    relay.descriptors.delete(bob.id.getACEId());
    await expect(alice.client.agent(bob.id.getACEId())).rejects.toMatchObject({ code: 'unknown_peer' });
  });
});

/** A store over shared data that "dies" (every later call throws) at a chosen operation; a restart is a new view. */
class CrashStore implements ACEStore {
  dead = false;
  readonly #locks = new MemoryStore();
  constructor(readonly data: MemoryStore, readonly crashAt: (op: string, key: string) => boolean = () => false) {}
  #do<T>(op: string, key: string, f: () => Promise<T>): Promise<T> {
    if (this.dead || this.crashAt(op, key)) { this.dead = true; return Promise.reject(new Error('process died')); }
    return f();
  }
  read(k: string) { return this.#do('read', k, () => this.data.read(k)); }
  write(k: string, v: Uint8Array) { return this.#do('write', k, () => this.data.write(k, v)); }
  delete(k: string) { return this.#do('delete', k, () => this.data.delete(k)); }
  list(p: string) { return this.#do('list', p, () => this.data.list(p)); }
  lock(name: string, o?: { timeoutMs?: number }) { return this.#locks.lock(name, o); }
}

describe('B: inbox recovery re-commits profile rules', () => {
  const commerce = new ProfileSet(['commerce']);
  async function world() {
    const clock = new Clock();
    const me = await identity(clock), sender = await identity(clock);
    const data = new MemoryStore(), vault = new StorePrekeyVault(new MemoryStore(), { clock: clock.now });
    const pk = await vault.rotate(NOW);
    await new PeerStore({ store: data, clock: clock.now }).adopt(sender.getKel());
    await new AdmissionBook(data).update(sender.getACEId(), () => ({ aceId: sender.getACEId(), status: 'admitted', updatedAt: NOW }));
    const host = new Set<string>(); // the host's store, idempotent by messageId
    const receipts: ReceiptBody[] = [];
    const open = (store: ACEStore, onMessage = (m: ParsedMessage) => { host.add(m.messageId); }) => Inbox.open({
      identity: me, store, vault, profiles: commerce, peers: new PeerStore({ store, clock: clock.now }), admission: new AdmissionBook(store),
      rules: [commerceRules(new ThreadStore(store, me.getACEId()))], clock: clock.now, onMessage, sendReceipt: async (_to, b) => { receipts.push(b); },
    });
    const packet = await createPacket({
      identity: sender, to: me.getACEId(), prekey: { id: pk.id, publicKey: pk.publicKey }, timestamp: clock.t,
      content: withPrekey({ type: 'ace:commerce:rfq:1', schemaDigest: commerce.digestOf('ace:commerce:rfq:1')!, threadId: 'job', body: { need: 'logo' } }),
    });
    /** The redelivered packet is a duplicate answered `delivered`; the host and the thread hold the message once. */
    const check = async (inbox: Inbox) => {
      expect((await inbox.receive(packet)).kind).toBe('duplicate');
      expect(receipts.at(-1)).toEqual({ messageId: packet.messageId, outcome: 'delivered' });
      expect([...host]).toEqual([packet.messageId]);
      const t = await new ThreadStore(data, me.getACEId()).get(sender.getACEId(), 'job');
      expect(t?.history.map((h) => h.messageId)).toEqual([packet.messageId]);
    };
    return { data, host, open, packet, check };
  }

  let journalWrites = 0;
  const points: Array<[string, (op: string, key: string) => boolean, boolean]> = [
    ['after the journal write', (op, k) => op === 'write' && k.startsWith('commerce/threads/'), false],
    ['after commitRules', () => false, true],
    ['after onMessage, before done', (op, k) => op === 'write' && k.startsWith('inbox/journal/') && ++journalWrites === 2, false],
  ];
  it.each(points)('a crash %s recovers on open', async (_n, crashAt, crashInHost) => {
    journalWrites = 0;
    const w = await world();
    const s1 = new CrashStore(w.data, crashAt);
    const inbox1 = await w.open(s1, crashInHost ? () => { s1.dead = true; throw new Error('process died'); } : undefined);
    expect((await inbox1.receive(w.packet)).kind).toBe('deferred');
    expect(s1.dead).toBe(true);
    await w.check(await w.open(new CrashStore(w.data)));
  });

  it('the duplicate path finishes a pending entry the same way', async () => {
    const w = await world();
    let revived = false;
    const s = new CrashStore(w.data, (op, k) => !revived && op === 'write' && k.startsWith('commerce/threads/'));
    const inbox = await w.open(s);
    expect((await inbox.receive(w.packet)).kind).toBe('deferred');
    s.dead = false;
    revived = true;
    await w.check(inbox);
  });
});

describe('C: expired means outcome unknown; receipts settle it', () => {
  it('an abandoned RFQ the seller processed settles on the late receipt and the thread continues', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const make = async (o: object) => {
      const client = await NetworkClient.open({ identity: await identity(clock), store: new MemoryStore(), relayUrl: relay.baseUrl, profiles: ['commerce'], fetch: relay.fetch, clock: clock.now, ...o });
      return { client, threads: client.threads, messages: client.messages };
    };
    const s = await make({ contact: 'open', listed: true, acceptProfiles: ['ace:commerce:1'] });
    const b = await make({});
    for (const c of [s, b]) { await c.client.publish(); }
    const S = s.client.identity.getACEId(), B = b.client.identity.getACEId();
    await b.client.connect(S, { profile: 'ace:commerce:1' });
    await s.client.pull();
    await b.client.pull();
    const rfq = await b.client.send(S, 'ace:commerce:rfq:1', { need: 'logo' }, { threadId: 'job' });
    await b.client.outbox.abandon(rfq.messageId);
    expect(await b.client.outbox.get(rfq.messageId)).toMatchObject({ status: 'expired', expiredAt: clock.t });
    expect(await b.client.outbox.prune()).toBe(0); // a fresh expired entry is kept
    expect((await s.client.pull())[0].kind).toBe('delivered');
    const offer = await s.client.send(B, 'ace:commerce:offer:1', { price: '5', currency: 'USDC' }, { threadId: 'job' });
    expect((await b.client.pull()).map((o) => o.kind)).toEqual(['receipt', 'delivered']);
    const settled = (await b.client.outbox.get(rfq.messageId))!;
    expect(settled.status).toBe('delivered');
    expect(settled.expiredAt).toBeUndefined();
    expect((await b.threads!.get(S, 'job'))!.history.map((h) => h.messageId)).toEqual([rfq.messageId, offer.messageId]);
    await b.client.send(S, 'ace:commerce:accept:1', { offerId: offer.messageId }, { threadId: 'job' });
    await s.client.pull();
    await b.client.pull();
    expect((await b.threads!.get(S, 'job'))!.state).toBe('accepted');
    expect((await s.threads!.get(B, 'job'))!.state).toBe('accepted');
  });

  it('late rejected receipts settle an expired entry, unknown_prekey is ignored; prune waits out the retention', async () => {
    const clock = new Clock();
    const me = await identity(clock), peer = await identity(clock);
    const ob = new Outbox({ identity: me, store: new MemoryStore(), profiles: new ProfileSet(['text']), transport: async () => ({ prekey: 'a'.repeat(64) }), clock: clock.now });
    const to = peer.getACEId();
    const a = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'a' } });
    await ob.attempt(a.messageId);
    await ob.abandon(a.messageId);
    expect(await ob.onReceipt(to, { messageId: a.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: 'a'.repeat(64) })).toBeNull();
    const b = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'b' } });
    await ob.abandon(b.messageId);
    expect(await ob.onReceipt(to, { messageId: b.messageId, outcome: 'rejected', code: 'invalid_body' })).toMatchObject({ status: 'rejected', code: 'invalid_body' });
    expect(await ob.prune()).toBe(0); // settled and expired entries stay visible for the offline window
    clock.advance(OFFLINE_WINDOW_SECONDS - 1);
    expect(await ob.prune()).toBe(0);
    clock.advance(1);
    expect(await ob.prune()).toBe(2);
  });
});
