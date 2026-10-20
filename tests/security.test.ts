// Regression tests for the 2026-10-13 security review fixes.
import { describe, expect, it } from 'vitest';
import {
  CONTACT_SCHEMA_DIGEST, MemoryStore, NetworkClient, Outbox, ProfileSet, RelayClient, contactContent, createDescriptor, createPermit,
  type PublishedAgent,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, identity } from './helpers.js';
import { inboxWorld, text } from './helpers2.js';

describe('security fixes', () => {
  it('a permit sent to a relay must authorize that packet', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const carol = await identity(clock);
    const permit = await createPermit(carol, bob.id.getACEId(), { now: NOW });
    const pre = (await alice.client.publish()).descriptor.prekey;
    const { createPacket } = await import('./sdk.js');
    const packet = await createPacket({ identity: bob.id, to: alice.id.getACEId(), prekey: pre, content: { type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message: 'x' } }, timestamp: NOW });
    await expect(relay.client().send(packet, permit)).rejects.toMatchObject({ code: 'invalid_argument' });
  });

  it('no permit is presented to a relay the issuer never named in a signed descriptor', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const bob = await agent(relay, clock);
    const alice = await agent(relay, clock);
    const B = bob.id.getACEId();
    // alice holds a permit from bob but no descriptor of his: only the anonymous lookup is used, never the permit
    await alice.client.importAgent(await bob.client.publish());
    await alice.client.admission.holdPermit(await createPermit(bob.id, alice.id.getACEId(), { now: NOW }));
    await alice.store.delete(`network/agents/${(await import('./sdk.js')).sha256Hex(B)}.json`);
    const before = relay.sent.length;
    const seen: unknown[] = [];
    const orig = relay.route.bind(relay);
    relay.route = async (m, url, h, body) => { if (body !== undefined) seen.push(body); return orig(m, url, h, body); };
    expect((await alice.client.agent(B)).descriptor.aceId).toBe(B);
    expect(seen).toEqual([]);
    expect(relay.sent.length).toBe(before);
  });

  it('holding a permit never admits the issuer', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const bob = await agent(relay, clock);
    const alice = await agent(relay, clock);
    await alice.client.importAgent(await bob.client.publish());
    await alice.client.admission.holdPermit(await createPermit(bob.id, alice.id.getACEId(), { now: NOW }));
    expect(await alice.client.admission.get(bob.id.getACEId())).toBeNull();
    expect((await alice.client.admission.heldPermit(bob.id.getACEId()))!.issuer).toBe(bob.id.getACEId());
  });

  it('a corrupt admission record is storage_failed, never absent or admitted', async () => {
    const w = await inboxWorld();
    const { sha256Hex } = await import('./sdk.js');
    await w.store.write(`admission/peers/${sha256Hex(w.sender.getACEId())}.json`, new TextEncoder().encode('{"aceId":"x","status":"admitted","updatedAt":1}'));
    await expect(w.admission.get(w.sender.getACEId())).rejects.toMatchObject({ code: 'storage_failed' });
    const out = await w.inbox.receive(await w.pack(w.sender, { type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message: 'x' } }));
    expect(out.kind).toBe('deferred');
  });

  it('a contact from an admitted but unpinned peer is authenticated by its source, not dropped', async () => {
    const w = await inboxWorld({ admit: false, contact: () => 'closed' });
    await w.admission.update(w.sender.getACEId(), () => ({ aceId: w.sender.getACEId(), status: 'pending', profile: 'ace:text:1', updatedAt: NOW }));
    const source = await createDescriptor(w.sender, { relays: [RELAY], prekey: w.prekey, profiles: text.descriptors(), now: NOW });
    const permit = await createPermit(w.sender, w.me.getACEId(), { now: NOW });
    const out = await w.inbox.receive(await w.pack(w.sender, contactContent({ kind: 'accepted', profile: 'ace:text:1', note: '', source, permit })));
    expect(out.kind).toBe('contact');
    expect(CONTACT_SCHEMA_DIGEST).toMatch(/^[0-9a-f]{64}$/);
    expect((await w.peers.get(w.sender.getACEId()))!.aceId).toBe(w.sender.getACEId());
  });

  it('a send-only client takes no receive lock and writes no inbox state', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const a = await agent(relay, clock);
    const sender = await NetworkClient.open({ identity: a.id, store: a.store, relay: relay.client(), clock: clock.now, receive: false });
    expect(() => sender.inbox).toThrow();
    const before = await a.store.read('inbox/replay.json');
    await sender.publish();
    await sender.close();
    expect(await a.store.read('inbox/replay.json')).toEqual(before);
    await a.client.close();
  });

  it('registration timestamps stay strictly increasing across RelayClients sharing a store', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const id = await identity(clock);
    const store = new MemoryStore();
    const stamps: number[] = [];
    const orig = relay.route.bind(relay);
    relay.route = async (m, url, h, body) => { if (url.pathname === '/v1/register') stamps.push(body.timestamp); return orig(m, url, h, body); };
    const mk = () => new RelayClient(RELAY, { fetch: relay.fetch, clock: clock.now, store });
    await mk().register(id);
    await mk().register(id);
    expect(stamps[1]).toBe(stamps[0] + 1);
  });

  it('an unknown_prekey receipt during an in-flight attempt is merged, and corrupt entries are storage_failed', async () => {
    const clock = new Clock();
    const id = await identity(clock), peer = await identity(clock);
    const store = new MemoryStore();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let calls = 0;
    const outbox: Outbox = new Outbox({
      identity: id, store, profiles: text, clock: clock.now,
      transport: async () => { calls++; if (calls === 2) await gate; return { prekey: calls === 1 ? 'a'.repeat(64) : 'b'.repeat(64) }; },
    });
    const e = await outbox.enqueue({ to: peer.getACEId(), type: 'ace:text:1', body: { message: 'x' } });
    await outbox.attempt(e.messageId);
    clock.advance(60);
    const inflight = outbox.attempt(e.messageId);
    await new Promise((r) => setTimeout(r, 10));
    await outbox.onReceipt(peer.getACEId(), { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: 'a'.repeat(64) });
    release();
    const after = (await inflight)!;
    expect(after.rejectedPrekey).toBe('a'.repeat(64));
    expect(after.nextAttemptAt).toBeLessThanOrEqual(clock.t);
    await store.write(`outbox/${(await import('./sdk.js')).sha256Hex(e.messageId)}.json`, new TextEncoder().encode('{"messageId":5}'));
    await expect(outbox.list()).rejects.toMatchObject({ code: 'storage_failed' });
  });

  it('directory entries that do not match the query are skipped; a lookup must return the requested identity', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const orig = relay.route.bind(relay);
    relay.route = async (m, url, h, body) => {
      if (url.pathname === '/v1/descriptors') return { agents: [await alice.client.publish()], cursor: null };
      if (url.pathname.startsWith('/v1/descriptor/')) return (relay.descriptors.get(bob.id.getACEId()) as PublishedAgent);
      return orig(m, url, h, body);
    };
    expect(await bob.client.discover({ profile: 'ace:commerce:1' })).toEqual({ agents: [], cursor: null });
    expect((await bob.client.discover({ profile: 'ace:text:1' })).agents.map((x) => x.descriptor.aceId)).toEqual([alice.id.getACEId()]);
    await expect(relay.client().getDescriptor(alice.id.getACEId())).rejects.toMatchObject({ code: 'relay_protocol_error' });
  });
});
