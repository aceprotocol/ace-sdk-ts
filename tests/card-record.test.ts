import { describe, expect, it } from 'vitest';
import {
  MemoryStore, NetworkClient, contactContent, createCardRecord, createPacket, verifyCardBundle, isCaip10Account, MAX_CARD_RECORD_BYTES,
  type CardBundle,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, identity } from './helpers.js';

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
    expect(outcome.kind).toBe('dropped');
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
