import { describe, expect, it } from 'vitest';
import {
  MemoryStore, NetworkClient, contactContent, createCardRecord, createPacket, verifyCardBundle, isCaip10Account, MAX_CARD_RECORD_BYTES,
  sha256Hex, type CardBundle,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, identity, stateOf } from './helpers.js';

const code = (c: string) => expect.objectContaining({ code: c });
const SOL = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';

async function aliceCard(extra: Partial<Parameters<typeof createCardRecord>[1]> = {}) {
  const id = await identity();
  const bundle = await createCardRecord(id, { home: RELAY, handle: 'alice', card: { name: 'Alice' }, pay: [SOL], contact: 'open', listed: false, now: NOW, ...extra });
  return { id, bundle };
}
const withRecord = (b: CardBundle, patch: Record<string, unknown>): unknown => ({ kel: b.kel, card: { ...b.card, ...patch } });

describe('card record', () => {
  it('round-trips a signed card', async () => {
    const { id, bundle } = await aliceCard();
    const v = verifyCardBundle(bundle, NOW);
    expect(v.aceId).toBe(id.getACEId());
    expect(v.record.handle).toBe('alice');
    expect(v.record.contact).toBe('open');
    expect(v.record.pay).toEqual([SOL]);
    expect(v.kelState.aceId).toBe(id.getACEId());
    // no expiry: a year later it still verifies
    expect(verifyCardBundle(bundle, NOW + 365 * 86400 - 1).record.listed).toBe(false);
    expect(() => verifyCardBundle(withRecord(bundle, { listed: true }), NOW)).toThrow(code('invalid_authorization'));
  });

  it('rejects unknown member', async () => {
    const { bundle } = await aliceCard();
    expect(() => verifyCardBundle(withRecord(bundle, { visibility: 'public' }), NOW)).toThrow(code('invalid_authorization'));
    expect(() => verifyCardBundle({ ...bundle, extra: 1 }, NOW)).toThrow(code('invalid_authorization'));
    expect(() => verifyCardBundle(withRecord(bundle, { contact: 'public' }), NOW)).toThrow(code('invalid_authorization'));
  });

  it('rejects 9 pay accounts', async () => {
    const { bundle } = await aliceCard();
    const nine = Array.from({ length: 9 }, (_, i) => `eip155:1:0x${String(i).padStart(40, '0')}`);
    expect(() => verifyCardBundle(withRecord(bundle, { pay: nine }), NOW)).toThrow(code('invalid_authorization'));
    await expect(aliceCard({ pay: nine })).rejects.toThrow(code('invalid_authorization'));
    await expect(aliceCard({ pay: [] })).rejects.toThrow(code('invalid_authorization'));
  });

  it('rejects duplicate pay', async () => {
    const { bundle } = await aliceCard();
    expect(() => verifyCardBundle(withRecord(bundle, { pay: [SOL, SOL] }), NOW)).toThrow(code('invalid_authorization'));
  });

  it('rejects bad CAIP-10', async () => {
    const { bundle } = await aliceCard();
    expect(isCaip10Account(SOL)).toBe(true);
    expect(isCaip10Account('solana:7xKX')).toBe(false);
    expect(() => verifyCardBundle(withRecord(bundle, { pay: ['solana:7xKX'] }), NOW)).toThrow(code('invalid_authorization'));
  });

  it('rejects oversized record', async () => {
    const { bundle } = await aliceCard();
    const big = withRecord(bundle, { card: { name: 'Alice', description: 'x'.repeat(MAX_CARD_RECORD_BYTES) } });
    expect(() => verifyCardBundle(big, NOW)).toThrow(expect.objectContaining({ code: 'invalid_authorization', message: expect.stringMatching(/16384/) }));
  });

  it('rejects a future issuedAt, a bad home and a bad handle', async () => {
    const { bundle } = await aliceCard({ now: NOW + 301 });
    expect(() => verifyCardBundle(bundle, NOW)).toThrow(code('invalid_authorization'));
    await expect(aliceCard({ home: 'https://Relay.test/' })).rejects.toThrow(code('invalid_authorization'));
    await expect(aliceCard({ handle: 'Al' })).rejects.toThrow(code('invalid_authorization'));
  });

  it('card signed by superseded key is stale', async () => {
    const { id, bundle } = await aliceCard();
    await id.delegate({ now: NOW });
    expect(() => verifyCardBundle({ kel: id.getKel(), card: bundle.card }, NOW)).toThrow(code('stale_peer_binding'));
  });
});

describe('card record over the relay', () => {
  it('resolveHandle rejects foreign home', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now, 'https://relay.a');
    const alice = await agent(relay, clock, { contact: 'open' });
    const bob = await agent(relay, clock);
    // A relay serving, under @alice@relay.a, a record whose home is another relay.
    const foreign = await createCardRecord(alice.id, { home: 'https://relay.b', handle: 'alice', contact: 'open', listed: false, now: clock.t + 1 });
    relay.cards.set(alice.id.getACEId(), foreign);
    relay.handles.set('alice', alice.id.getACEId());
    await expect(bob.client.lookupCard('@alice@relay.a')).rejects.toThrow(code('unknown_peer'));
  });

  it('pinned handle mismatch is invalid_authorization', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    expect((await bob.client.lookupCard('@alice@relay.test')).record.handle).toBe('alice');
    // A record of the same identity without the pinned handle (a conformant relay refuses to store it).
    relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, contact: 'open', listed: false, now: clock.t + 1 }));
    await expect(bob.client.lookupCard(A)).rejects.toThrow(code('invalid_authorization'));
  });

  it('handles are set once: a second, different handle is refused; dropping the handle is refused; a taken one is handle_taken', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' });
    const mallory = await agent(relay, clock);
    const card = (o: { handle?: string; now: number }, who = alice) => createCardRecord(who.id, { home: RELAY, contact: 'closed', listed: false, ...o });
    await expect(relay.client().publishCard(await card({ handle: 'alice2', now: clock.t + 1 }))).rejects.toMatchObject({ relayCode: 'invalid_argument' });
    await expect(relay.client().publishCard(await card({ now: clock.t + 2 }))).rejects.toMatchObject({ relayCode: 'invalid_argument' });
    await expect(relay.client().publishCard(await card({ handle: 'alice', now: clock.t + 3 }, mallory))).rejects.toMatchObject({ relayCode: 'handle_taken' });
    await relay.client().publishCard(await card({ handle: 'alice', now: clock.t + 4 }));
    expect((await relay.client().handle('alice')).card.aceId).toBe(alice.id.getACEId());
  });

  it('a handle lookup is checked against the handle pin too', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    expect((await bob.client.lookup('@alice@relay.test')).descriptor.aceId).toBe(A); // pins A -> alice
    // A relay that binds a second handle to the same identity at the same home
    relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, handle: 'alice2', contact: 'open', listed: false, now: clock.t + 1 }));
    relay.handles.set('alice2', A);
    await expect(bob.client.lookup('@alice2@relay.test')).rejects.toThrow(code('invalid_authorization'));
    await expect(bob.client.lookupCard('@alice2@relay.test')).rejects.toThrow(code('invalid_authorization'));
  });

  it('moving home: the old relay keeps the binding, resolves unknown_peer and never reassigns the handle', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' });
    const mallory = await agent(relay, clock);
    const A = alice.id.getACEId();
    await relay.client().publishCard(await createCardRecord(alice.id, { home: 'https://relay-b.test', contact: 'closed', listed: false, now: clock.t + 1 }));
    expect((await relay.client().card(A)).card.home).toBe('https://relay-b.test');
    expect(relay.handles.get('alice')).toBe(A);
    await expect(relay.client().handle('alice')).rejects.toThrow(code('unknown_peer'));
    const taken = await createCardRecord(mallory.id, { home: RELAY, handle: 'alice', contact: 'closed', listed: false, now: clock.t + 2 });
    await expect(relay.client().publishCard(taken)).rejects.toMatchObject({ relayCode: 'handle_taken' });
    // a client that pinned alice at the old home accepts the record at the new home
    const bob = await agent(relay, clock);
    await bob.client.lookupCard(A);
  });

  it('lookupCard pins the KEL before trusting the card', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', pay: [SOL] });
    const A = alice.id.getACEId();
    const old = relay.cards.get(A)!;
    // A new dlg replaces the signing key (say, stolen); the owner re-signs the card.
    clock.advance(10);
    await alice.id.delegate({ now: clock.t });
    await alice.client.maintain();
    // A relay replays the record signed under the superseded delegation, with the KEL prefix it verifies under.
    relay.cards.set(A, old);
    const bob = await agent(relay, clock);
    expect(await bob.client.peers.get(A)).toBeNull();
    await expect(bob.client.lookupCard(A)).rejects.toThrow(code('stale_peer_binding'));
    // The KEL was pinned from the descriptor lookup, before the card was checked.
    expect((await bob.client.peers.get(A))?.events.length).toBe(alice.id.getKel().length);
  });

  it('lookupCard falls back to the bundle KEL when no live descriptor', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice', pay: [SOL] });
    const A = alice.id.getACEId();
    // Alice is offline past her descriptor's lifetime: the relay serves her card record but no descriptor.
    clock.advance(8 * 86400);
    await expect(relay.client().getDescriptor(A)).rejects.toThrow(code('unknown_peer'));
    for (const target of [A, '@alice@relay.test']) {
      const bob = await agent(relay, clock);
      const v = await bob.client.lookupCard(target);
      expect(v.kelLive).toBe(false);
      expect(v.record).toMatchObject({ aceId: A, handle: 'alice', pay: [SOL] });
      // The bundle's KEL is pinned, under the same rules as a descriptor's.
      expect((await bob.client.peers.get(A))?.lastHash).toBe(stateOf(alice.id, clock.t).lastHash);
      // The card pin still applies: a rollback is refused.
      relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, handle: 'alice', contact: 'closed', listed: false, now: v.record.issuedAt - 1 }));
      await expect(bob.client.lookupCard(target)).rejects.toThrow(code('stale_descriptor'));
      relay.cards.set(A, v.bundle);
    }
    // Any other descriptor failure (here a tampered one) still fails the lookup, pinning nothing.
    const carol = await agent(relay, clock);
    relay.descriptors.set(A, { ...relay.descriptors.get(A)!, descriptor: { ...relay.descriptors.get(A)!.descriptor, expiresAt: clock.t + 3600 } });
    await expect(carol.client.lookupCard(A)).rejects.toThrow(code('invalid_authorization'));
    expect(await carol.client.peers.get(A)).toBeNull();
  });

  it('kelLive is true with a live descriptor', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    expect((await bob.client.lookupCard(alice.id.getACEId())).kelLive).toBe(true);
    const carol = await agent(relay, clock);
    expect((await carol.client.lookupCard('@alice@relay.test')).kelLive).toBe(true);
  });

  it('unparseable pin is storage_failed', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.lookupCard('@alice@relay.test');
    // A damaged pin is a storage failure, never "no pin" (which would accept a rollback or a rebinding).
    const cardPin = `network/handles/${sha256Hex(A)}.json`;
    const ownerPin = `network/handle-owners/${sha256Hex(`${RELAY} alice`)}.json`;
    for (const key of [cardPin, ownerPin]) {
      const good = await bob.store.read(key);
      expect(good).not.toBeNull();
      for (const bad of ['not json', '[]', 'null', '"x"']) {
        await bob.store.write(key, new TextEncoder().encode(bad));
        await expect(bob.client.lookupCard('@alice@relay.test')).rejects.toThrow(code('storage_failed'));
      }
      await bob.store.write(key, good!);
    }
    expect((await bob.client.lookupCard('@alice@relay.test')).record.aceId).toBe(A);
  });

  it('handle resolving to a new aceId is invalid_authorization', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const mallory = await agent(relay, clock, { contact: 'open' });
    const bob = await agent(relay, clock);
    const M = mallory.id.getACEId();
    expect((await bob.client.lookupCard('@alice@relay.test')).record.aceId).toBe(alice.id.getACEId());
    // The relay rebinds the handle to another identity (bindings are permanent: detectable misbehavior).
    relay.cards.set(M, await createCardRecord(mallory.id, { home: RELAY, handle: 'alice', contact: 'open', listed: false, now: clock.t + 1 }));
    relay.handles.set('alice', M);
    await expect(bob.client.lookupCard('@alice@relay.test')).rejects.toThrow(code('invalid_authorization'));
    await expect(bob.client.lookup('@alice@relay.test')).rejects.toThrow(code('invalid_authorization'));
    // The reverse pin is durable.
    const again = await NetworkClient.open({ identity: bob.id, store: bob.store, relay: relay.client(), clock: clock.now, receive: false });
    await expect(again.lookupCard('@alice@relay.test')).rejects.toThrow(code('invalid_authorization'));
    await again.close();
  });

  it('refused card leaves descriptor unpublished', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    await agent(relay, clock, { handle: 'alice' });
    const id = await identity(clock);
    const late = await NetworkClient.open({ identity: id, store: new MemoryStore(), relay: relay.client(), clock: clock.now, receive: false, handle: 'alice' });
    await expect(late.publish()).rejects.toMatchObject({ relayCode: 'handle_taken' });
    expect(relay.cards.has(id.getACEId())).toBe(false);
    expect(relay.descriptors.has(id.getACEId())).toBe(false);
    await late.close();
  });

  it('a new dlg re-signs the card at upkeep', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    const before = (await bob.client.lookupCard(A)).record.signature.seq;
    clock.advance(10);
    await alice.id.delegate({ now: clock.t });
    await alice.client.maintain();
    const after = await bob.client.lookupCard(A);
    expect(after.record.signature.seq).toBeGreaterThan(before);
    expect(after.record.handle).toBe('alice');
  });

  it('older card is rejected after a newer one', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    const seen = await bob.client.lookupCard(A);
    // A relay rolling back to an older record (other pay accounts, contact closed) is refused on every path.
    relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, handle: 'alice', pay: [SOL], contact: 'closed', listed: false, now: seen.record.issuedAt - 1 }));
    await expect(bob.client.lookupCard(A)).rejects.toThrow(code('stale_descriptor'));
    await expect(bob.client.lookupCard('@alice@relay.test')).rejects.toThrow(code('stale_descriptor'));
    await expect(bob.client.lookup('@alice@relay.test')).rejects.toThrow(code('stale_descriptor'));
  });

  it('equal issuedAt with different claims is rejected', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    const seen = await bob.client.lookupCard(A);
    expect((await bob.client.lookupCard(A)).record).toEqual(seen.record); // the identical record again is fine
    relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, handle: 'alice', contact: 'open', listed: true, now: seen.record.issuedAt }));
    await expect(bob.client.lookupCard(A)).rejects.toThrow(code('stale_descriptor'));
  });

  it('newer card updates the pin', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', handle: 'alice' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    const first = relay.cards.get(A)!;
    await bob.client.lookupCard(A);
    const newer = await createCardRecord(alice.id, { home: RELAY, handle: 'alice', pay: [SOL], contact: 'closed', listed: false, now: first.card.issuedAt + 5 });
    relay.cards.set(A, newer);
    expect((await bob.client.lookupCard(A)).record.contact).toBe('closed');
    // the pin moved to the newer record and persists in the store: the first one is now a rollback
    relay.cards.set(A, first);
    await expect(bob.client.lookupCard(A)).rejects.toThrow(code('stale_descriptor'));
    const again = await NetworkClient.open({ identity: bob.id, store: bob.store, relay: relay.client(), clock: clock.now, receive: false });
    await expect(again.lookupCard(A)).rejects.toThrow(code('stale_descriptor'));
    await again.close();
  });

  it('no card means closed', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    // Bob is configured open but has published only a descriptor, no card record.
    const bobId = await identity(clock);
    const bob = await NetworkClient.open({ identity: bobId, store: new MemoryStore(), relay: relay.client(), clock: clock.now, contact: 'open' });
    const pk = await bob.vault.rotate(clock.t);
    await bob.relay.register(bobId);
    const { createDescriptor } = await import('./sdk.js');
    const desc = await createDescriptor(bobId, { relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: bob.profiles.descriptors(), now: clock.t });
    await bob.relay.publishDescriptor(desc);
    const alice = await agent(relay, clock);
    await alice.client.importAgent(desc);
    // connect refuses: no card record means closed
    await expect(alice.client.connect(bobId.getACEId(), { profile: 'ace:text:1' })).rejects.toThrow(code('not_permitted'));
    // a stranger's contact request that reaches bob anyway is dropped by the endpoint
    const source = await alice.client.publish();
    const packet = await createPacket({
      identity: alice.id, to: bobId.getACEId(), prekey: desc.descriptor.prekey, timestamp: clock.t,
      content: contactContent({ kind: 'request', profile: 'ace:text:1', note: '', source, permit: await (await import('./sdk.js')).createPermit(alice.id, bobId.getACEId(), { now: clock.t }) }),
    });
    relay.queues.set(bobId.getACEId(), [{ streamId: `${clock.t * 1000}-0`, packet, raw: JSON.stringify(packet) }]);
    const [outcome] = await bob.pull();
    expect(outcome).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted', message: expect.stringMatching(/sender is not admitted/) } });
    expect(await bob.requests()).toEqual([]);
  });

  it('closed agent can still connect to an open owner', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const b = await agent(relay, clock, { contact: 'open' });
    const a = await agent(relay, clock); // closed by default
    await a.client.connect(b.id.getACEId(), { profile: 'ace:text:1' });
    await b.client.pull();
    expect((await b.client.requests()).map((r) => r.from)).toEqual([a.id.getACEId()]);
    // and the closed one is not reachable by strangers
    await expect(b.client.connect(a.id.getACEId(), { profile: 'ace:text:1' })).rejects.toThrow(code('not_permitted'));
  });
});
