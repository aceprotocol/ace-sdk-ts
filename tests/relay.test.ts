// RelayClient against a local fake relay (08-relay); PeerStore; Inbox.pull / follow end to end.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ACEError, MemoryStore, PeerStore, RelayClient, SoftwareIdentity, verifyPeerRecord, type ReceiveOutcome,
} from '../src/index.js';
import { parseSSE } from '../src/relay.js';
import { toBase64 } from '../src/encoding.js';
import { FakeRelay } from './fake-relay.js';
import { expectCode } from './helpers.js';
import { Agent, Clock } from './pipeline.js';

let relay: FakeRelay;
let clock: Clock;

beforeEach(async () => {
  clock = new Clock(Math.floor(Date.now() / 1000));
  relay = await new FakeRelay(clock.fn).start();
});
afterEach(async () => {
  await relay.close();
});

function client(o: { timeoutMs?: number } = {}): RelayClient {
  return new RelayClient(relay.url + '/', { clock: clock.fn, reconnectBaseMs: 5, ...o });
}

async function registered(name: string, scheme: 'ed25519' | 'secp256k1' = 'ed25519'): Promise<Agent> {
  const c = client();
  const a = await Agent.create(name, scheme, clock, new MemoryStore(), c);
  await c.register(a.identity, { name, tags: ['test'] });
  return a;
}

function stream(text: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream({
    start(c) {
      for (const t of text) c.enqueue(enc.encode(t));
      c.close();
    },
  });
}

describe('SSE parser', () => {
  it('handles CRLF / CR / LF, split chunks, comments, multi-line data and BOM', async () => {
    const events = [];
    for await (const e of parseSSE(stream(['﻿id: 1-0\r\nevent: catchup\r\ndata: {"a":\r', '\n', 'data: 1}\r\n\r\n: hb\n\nid: 2-0\revent: message\rdata: {}\r\r']))) {
      if (e.event !== ':') events.push(e);
    }
    expect(events).toEqual([
      { id: '1-0', event: 'catchup', data: '{"a":\n1}' },
      { id: '2-0', event: 'message', data: '{}' },
    ]);
  });

  it('rejects oversized frames', async () => {
    const big = 'x'.repeat(131072 + 600);
    await expectCode((async () => { for await (const _ of parseSSE(stream([`data: ${big}\n\n`]))) { /* drain */ } })(), 'relay_protocol_error');
  });
});

describe('RelayClient', () => {
  it('normalizes the base URL', () => {
    expect(new RelayClient('HTTPS://Relay.Example/').baseUrl).toBe('https://relay.example');
    expect(new RelayClient('https://relay.example/base/').baseUrl).toBe('https://relay.example/base');
    expect(() => new RelayClient('ftp://x')).toThrow(ACEError);
    expect(() => new RelayClient('https://x/?q=1')).toThrow(ACEError);
  });

  it('register / lookupPeer / discover / unregister', async () => {
    const c = client();
    const alice = await SoftwareIdentity.generate('ed25519');
    expect(await c.register(alice, { name: 'Alice' })).toEqual({ status: 'registered' });
    clock.t += 1;
    expect(await c.register(alice)).toEqual({ status: 'refreshed' });
    const peer = await c.lookupPeer(alice.getACEId());
    expect(peer.aceId).toBe(alice.getACEId());
    expect(peer.source).toBe('relay');
    expect(peer.profile).toEqual({ name: 'Alice' });
    await expectCode(c.lookupPeer('ace:sha256:' + '0'.repeat(64)), 'unknown_peer');
    const rec = { ...relay.identities.get(alice.getACEId())! };
    relay.extraAgents.push({ ...rec, registeredAt: rec.registeredAt + 1 }); // bad binding
    const d = await c.discover({ q: 'alice' });
    expect(d.agents.map((a) => a.aceId)).toEqual([alice.getACEId()]);
    expect(d.rejected).toBe(1);
    await c.unregister(alice);
    await expectCode(c.lookupPeer(alice.getACEId()), 'unknown_peer');
    await expectCode(c.unregister(alice), 'not_registered');
  });

  it('a relay answering for another ACE ID is invalid_peer', async () => {
    const c = client();
    const a = await SoftwareIdentity.generate('ed25519');
    const b = await SoftwareIdentity.generate('ed25519');
    await c.register(a);
    await c.register(b);
    relay.identities.set(b.getACEId(), relay.identities.get(a.getACEId())!);
    await expectCode(c.lookupPeer(b.getACEId()), 'invalid_peer');
  });

  it('error mapping and Retry-After', async () => {
    const c = client();
    const a = await SoftwareIdentity.generate('ed25519');
    relay.inject.push({ path: '/v1/peer', status: 429, code: 'rate_limited', headers: { 'Retry-After': '7' } });
    const e = await expectCode(c.lookupPeer(a.getACEId()), 'relay_unavailable');
    expect(e.retryAfterSeconds).toBe(7);
    expect(e.isTransient).toBe(true);
    relay.inject.push({ path: '/v1/peer', status: 503, code: 'down' });
    await expectCode(c.lookupPeer(a.getACEId()), 'relay_unavailable');
    relay.inject.push({ path: '/v1/register', status: 409, code: 'identity_conflict' });
    const r = await expectCode(c.register(a), 'relay_rejected');
    expect(r.status).toBe(409);
    expect(r.relayCode).toBe('identity_conflict');
    await expectCode(new RelayClient('http://127.0.0.1:1', { timeoutMs: 500 }).lookupPeer(a.getACEId()), 'relay_unavailable');
  });

  it('authenticated calls use strictly increasing timestamps and retry once on 409 replay', async () => {
    const a = await registered('a');
    const c = a.relay!;
    await c.fetchInbox(a.identity);
    await c.fetchInbox(a.identity);
    relay.inject.push({ path: '/v1/inbox', status: 409, code: 'replay' });
    await c.fetchInbox(a.identity, { since: '5-0', limit: 10 });
    const ts = relay.authTimestamps;
    expect(ts.length).toBe(3);
    expect(ts[1]).toBeGreaterThan(ts[0]);
    expect(ts[2]).toBeGreaterThan(ts[1]);
  });

  it('send: duplicates ok, expired → envelope_expired, unknown recipient → unknown_peer', async () => {
    const alice = await registered('alice');
    const bob = await registered('bob', 'secp256k1');
    const peer = await alice.peers.resolve(bob.id);
    const p = await alice.outbox.stage({ recipient: peer, type: 'text', body: { message: 'hi' }, requestId: 'x' });
    await alice.relay!.send(p.message);
    await alice.relay!.send(p.message);
    clock.t += 1000;
    const late = await alice.outbox.stage({ recipient: peer, type: 'text', body: { message: 'late' } });
    clock.t += 1000;
    await expectCode(alice.relay!.send(late.message), 'envelope_expired');
    await alice.relay!.send(p.message); // stored duplicate is ok even when stale
    await alice.relay!.unregister(alice.identity);
    await expectCode(alice.relay!.send(p.message), 'not_registered');
    await bob.relay!.unregister(bob.identity);
  });

  it('intents', async () => {
    const a = await registered('a');
    const r = await a.relay!.postIntent(a.identity, { need: 'gpu', tags: ['gpu', 'ml'], maxPrice: '5', currency: 'USDC', ttl: 60 });
    expect(r.expiresAt).toBe(clock.t + 60);
    const l = await a.relay!.listIntents({});
    expect(l.intents).toEqual([{ intentId: r.intentId, from: a.id, need: 'gpu', tags: ['gpu', 'ml'], maxPrice: '5', currency: 'USDC', ttl: 60, createdAt: clock.t, expiresAt: clock.t + 60 }]);
    await expectCode(a.relay!.postIntent(a.identity, { need: 'x', tags: ['a,b'], ttl: 1 }), 'invalid_argument');
  });

  it('listen: catchup then live, reconnect after drain and dropped streams, resume point, abort', async () => {
    const a = await registered('a');
    for (let i = 0; i < 3; i++) relay.enqueueRaw(a.id, { n: i });
    relay.drainAfter = 2;
    relay.dropListens = 0;
    const ctrl = new AbortController();
    const seen: Array<[string, unknown, boolean]> = [];
    const it = a.relay!.listen(a.identity, { signal: ctrl.signal });
    for await (const ev of it) {
      seen.push([ev.streamId, ev.message, ev.catchup]);
      if (seen.length === 3) {
        relay.dropListens = 2; // the next two connections close without events
        // force a reconnect by draining the current stream
        relay.drainAfter = 0;
        relay.enqueueRaw(a.id, { n: 3 });
      }
      if (seen.length === 4) {
        relay.enqueueRaw(a.id, { n: 4 });
      }
      if (seen.length === 5) ctrl.abort();
    }
    expect(seen.map((s) => (s[1] as { n: number }).n)).toEqual([0, 1, 2, 3, 4]);
    expect(seen[0][2]).toBe(true);
    const listens = relay.requests.filter(([, p]) => p === '/v1/listen').length;
    expect(listens).toBeGreaterThanOrEqual(4);
  });

  it('listen: non-retryable status throws its mapped error; repeated failures → relay_unavailable', async () => {
    const stranger = await SoftwareIdentity.generate('ed25519');
    await expectCode((async () => { for await (const _ of client().listen(stranger)) { /* none */ } })(), 'not_registered');
    const a = await registered('a');
    for (let i = 0; i < 10; i++) relay.inject.push({ path: '/v1/listen', status: 503, code: 'down', headers: { 'Retry-After': '0' } });
    await expectCode((async () => { for await (const _ of a.relay!.listen(a.identity)) { /* none */ } })(), 'relay_unavailable');
  });
});

describe('PeerStore', () => {
  it('resolve adopts relay bindings, rotates on newer keys, falls back to the pin', async () => {
    const bob = await registered('bob');
    const alice = await registered('alice');
    const first = await alice.peers.resolve(bob.id);
    expect(first.source).toBe('relay');
    expect((await alice.peers.get(bob.id))!.registeredAt).toBe(first.registeredAt);
    // rotation: bob re-registers with a new encryption key
    const rotated = SoftwareIdentity.fromExport({ ...bob.identity.exportPrivateKey(), encryptionPrivateKey: toBase64(crypto.getRandomValues(new Uint8Array(32))) });
    clock.t += 10;
    expect(await bob.relay!.register(rotated)).toEqual({ status: 'rotated' });
    expect(toBase64((await alice.peers.resolve(bob.id)).encryptionPublicKey)).toBe(toBase64(first.encryptionPublicKey)); // fresh pin
    const after = await alice.peers.resolve(bob.id, { maxAgeSeconds: 0 });
    expect(toBase64(after.encryptionPublicKey)).toBe(toBase64(rotated.getEncryptionPublicKey()));
    // relay down: a stale pin is still returned when maxAge > 0
    relay.inject.push({ path: '/v1/peer', status: 503, code: 'down' });
    clock.t += 100000;
    expect((await alice.peers.resolve(bob.id)).aceId).toBe(bob.id);
    relay.inject.push({ path: '/v1/peer', status: 503, code: 'down' });
    await expectCode(alice.peers.resolve(bob.id, { maxAgeSeconds: 0 }), 'relay_unavailable');
  });

  it('a registration file never rotates a pinned key; corrupt pins are storage_failed', async () => {
    const clock2 = new Clock();
    const store = new MemoryStore();
    const peers = new PeerStore({ store, clock: clock2.fn });
    const bob = await SoftwareIdentity.generate('secp256k1');
    const reg = bob.toRegistrationFile({ name: 'Bob', endpoint: 'https://bob.example/ace' });
    const p = await peers.pinRegistrationFile(reg);
    expect(p.registeredAt).toBe(clock2.t);
    expect((await peers.adopt(p)).outcome).toBe('unchanged');
    const other = SoftwareIdentity.fromExport({ ...bob.exportPrivateKey(), encryptionPrivateKey: toBase64(new Uint8Array(32).fill(7)) });
    await expectCode(peers.pinRegistrationFile(other.toRegistrationFile({ name: 'Bob', endpoint: 'https://bob.example/ace' }), { pinnedAt: clock2.t + 100 }), 'stale_peer_binding');
    await expectCode(peers.resolve('ace:sha256:' + '1'.repeat(64)), 'unknown_peer');
    const [key] = await store.list('peers/');
    const doc = JSON.parse(new TextDecoder().decode((await store.read(key))!));
    doc.signingPublicKey = toBase64(new Uint8Array(33).fill(2));
    const bytes = new TextEncoder().encode(JSON.stringify(doc));
    await store.write(key, bytes);
    await expectCode(peers.get(bob.getACEId()), 'storage_failed');
    await expectCode(peers.adopt(p), 'storage_failed');
    expect(await store.read(key)).toEqual(bytes);
    await peers.remove(bob.getACEId());
    expect(await peers.get(bob.getACEId())).toBeNull();
  });
});

describe('end to end over the relay', () => {
  it('stage/deliver → Inbox.pull, then follow live; cursor persists', async () => {
    const alice = await registered('alice');
    const bob = await registered('bob', 'secp256k1');
    const bobPeer = await alice.peers.resolve(bob.id);
    for (let i = 0; i < 3; i++) {
      const p = await alice.outbox.stage({ recipient: bobPeer, type: 'text', body: { message: `m${i}` } });
      await alice.outbox.deliver(p.requestId, (env) => alice.relay!.send(env));
    }
    const inbox = await bob.open();
    expect(await inbox.pull(bob.relay!, { limit: 2 })).toEqual({ delivered: 3, duplicates: 0, quarantined: 0, blocked: null });
    expect(inbox.cursor(bob.relay!.baseUrl)).toBe('1003-0');
    expect(await inbox.pull(bob.relay!)).toEqual({ delivered: 0, duplicates: 0, quarantined: 0, blocked: null });
    const rfq = await alice.outbox.stage({ recipient: bobPeer, type: 'rfq', body: { need: 'gpu' }, threadId: 'deal' });
    const ctrl = new AbortController();
    const outcomes: ReceiveOutcome[] = [];
    const following = (async () => {
      for await (const o of inbox.follow(bob.relay!, { signal: ctrl.signal })) {
        outcomes.push(o);
        ctrl.abort();
      }
    })();
    await alice.outbox.deliver(rfq.requestId, (env) => alice.relay!.send(env));
    await following;
    expect(outcomes.map((o) => o.kind)).toEqual(['delivered']);
    expect(bob.host.calls.length).toBe(4);
    expect(inbox.cursor(bob.relay!.baseUrl)).toBe('1004-0');
    // pull blocked by a retryable failure
    relay.inject.push({ path: '/v1/inbox', status: 503, code: 'down' });
    const r = await inbox.pull(bob.relay!);
    expect(r.blocked?.code).toBe('relay_unavailable');
    await inbox.close();
  });
});
