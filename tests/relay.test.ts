// RelayClient against a local fake relay (08-relay); PeerStore.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ACEError, MemoryStore, PeerStore, RelayClient, SoftwareIdentity, createRegistrationFile, intentCommerceExt, verifyPeerRecord,
} from '../src/index.js';
import { parseSSE } from '../src/relay.js';
import { toBase64 } from '../src/encoding.js';
import { FakeRelay, RawFrame } from './fake-relay.js';
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

  it('dispatches only events with data; id and event do not carry over to the next event', async () => {
    const events = [];
    for await (const e of parseSSE(stream(['id: 1-0\nevent: message\n\ndata: a\n\nid: 2-0\nevent: drain\n\nevent: x\ndata: b\n\n']))) {
      if (e.event !== ':') events.push(e);
    }
    expect(events).toEqual([{ id: '', event: 'message', data: 'a' }, { id: '', event: 'x', data: 'b' }]);
  });

  it('rejects oversized frames', async () => {
    const big = 'x'.repeat(131072 + 600);
    await expectCode((async () => { for await (const _ of parseSSE(stream([`data: ${big}\n\n`]))) { /* drain */ } })(), 'relay_protocol_error');
  });
});

describe('RelayClient', () => {
  it('normalizes the base URL', async () => {
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
    const ext = { 'urn:ace:commerce:1': { maxPrice: '5', currency: 'USDC' }, 'urn:other:1': { z: 1, a: 'x' } };
    const r = await a.relay!.postIntent(a.identity, { need: 'gpu', tags: ['gpu', 'ml'], ext, ttl: 60 });
    expect(r.expiresAt).toBe(clock.t + 60);
    const l = await a.relay!.listIntents({});
    expect(l.intents).toEqual([{ intentId: r.intentId, from: a.id, need: 'gpu', tags: ['gpu', 'ml'], ttl: 60, ext, createdAt: clock.t, expiresAt: clock.t + 60 }]);
    expect(intentCommerceExt(l.intents[0])).toEqual({ maxPrice: '5', currency: 'USDC' });
    expect(relay.bodies.filter(([p]) => p === '/v1/intents').map(([, b]) => b)).toEqual([{ need: 'gpu', tags: ['gpu', 'ml'], ttl: 60, ext }]);
    await expectCode(a.relay!.postIntent(a.identity, { need: 'x', tags: ['a,b'], ttl: 1 }), 'invalid_argument');
    await expectCode(a.relay!.postIntent(a.identity, { need: 'x', ext: { 'urn:ace:commerce:1': { maxPrice: '5' } }, ttl: 1 }), 'invalid_argument');
    await expectCode(a.relay!.postIntent(a.identity, { need: 'x', ext: { bad: {} }, ttl: 1 }), 'invalid_argument');
    // an empty ext is absent: not sent, not signed
    await a.relay!.postIntent(a.identity, { need: 'y', ext: {}, ttl: 1 });
    expect(relay.bodies.filter(([p]) => p === '/v1/intents').map(([, b]) => b).at(-1)).toEqual({ need: 'y', tags: [], ttl: 1 });
    expect((await a.relay!.listIntents({})).intents.at(-1)).not.toHaveProperty('ext');
  });

  it('sets, reads and clears a webhook', async () => {
    const a = await registered('alice');
    await a.relay!.setWebhook(a.identity, { url: 'https://agent.example.com/wake', secret: '0123456789abcdef0123456789abcdef' });
    expect(await a.relay!.getWebhook(a.identity)).toMatchObject({ url: 'https://agent.example.com/wake', status: 'active', failures: 0 });
    await a.relay!.clearWebhook(a.identity);
    expect(await a.relay!.getWebhook(a.identity)).toBeNull();
    await expectCode(a.relay!.setWebhook(a.identity, { url: 'http://x.example', secret: '0123456789abcdef0123456789abcdef' }), 'invalid_argument');
    relay.inject.push({ path: '/v1/webhook', status: 400, code: 'invalid_webhook' });
    const e = await expectCode(a.relay!.setWebhook(a.identity, { url: 'https://10.0.0.1/wake', secret: '0123456789abcdef0123456789abcdef' }), 'relay_rejected');
    expect(e.relayCode).toBe('invalid_webhook');
  });

  it('fake relay PUT /v1/webhook rejects non-string url/secret with 400 invalid_argument', async () => {
    for (const body of [{ url: 5, secret: '0123456789abcdef0123456789abcdef' }, { url: 'https://agent.example.com/wake', secret: null }, {}]) {
      const r = await fetch(relay.url + '/v1/webhook', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      expect(r.status).toBe(400);
      expect(await r.json()).toMatchObject({ error: 'invalid_argument' });
    }
  });

  it('getWebhook: optional fields are accepted when well-formed, and a present malformed one (incl. null) is relay_protocol_error', async () => {
    const a = await registered('alice');
    const base = { url: 'https://agent.example.com/wake', status: 'active', failures: 0, updatedAt: 1741000000 };
    const injectWebhook = (extra: Record<string, unknown>) => relay.inject.push({ path: '/v1/webhook', status: 200, body: { webhook: { ...base, ...extra } } });
    injectWebhook({ lastDeliveredAt: 1741000000, lastError: 'http_500' });
    expect(await a.relay!.getWebhook(a.identity)).toEqual({ ...base, lastDeliveredAt: 1741000000, lastError: 'http_500' });
    injectWebhook({});
    expect(await a.relay!.getWebhook(a.identity)).toEqual(base);
    for (const extra of [{ lastDeliveredAt: 'yesterday' }, { lastDeliveredAt: 1.5 }, { lastDeliveredAt: -1 }, { lastDeliveredAt: null }, { lastError: 42 }, { lastError: null }]) {
      injectWebhook(extra);
      await expectCode(a.relay!.getWebhook(a.identity), 'relay_protocol_error');
    }
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
      seen.push([ev.streamId, JSON.parse(ev.data), ev.catchup]);
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

  // A fetch that ignores the abort signal: models undici not cancelling an already-streaming body.
  const deafFetch: typeof fetch = (input, init) => {
    const { signal: _ignored, ...rest } = init ?? {};
    return fetch(input, rest);
  };

  async function until(cond: () => boolean, ms = 2000): Promise<void> {
    const end = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > end) throw new Error('condition not met in time');
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  it('listen: abort during a heartbeat-only stream terminates promptly and closes the connection', async () => {
    const a = await registered('a');
    relay.heartbeatMs = 10;
    const c = new RelayClient(relay.url, { clock: clock.fn, reconnectBaseMs: 5, fetch: deafFetch });
    const ctrl = new AbortController();
    const done = (async () => {
      for await (const _ of c.listen(a.identity, { signal: ctrl.signal })) throw new Error('no messages expected');
    })();
    await until(() => relay.openListens === 1);
    await new Promise((r) => setTimeout(r, 60)); // several heartbeats in flight
    const t0 = Date.now();
    ctrl.abort();
    await done;
    expect(Date.now() - t0).toBeLessThan(500);
    await until(() => relay.openListens === 0);
  });

  it('listen: consumer break closes the connection server-side', async () => {
    const a = await registered('a');
    relay.enqueueRaw(a.id, { n: 0 });
    const c = new RelayClient(relay.url, { clock: clock.fn, reconnectBaseMs: 5, fetch: deafFetch });
    for await (const ev of c.listen(a.identity)) {
      expect(JSON.parse(ev.data)).toEqual({ n: 0 });
      break;
    }
    await until(() => relay.openListens === 0);
  });

  it('listen: an error thrown in at the yield propagates as is (no reconnect) and closes the connection', async () => {
    const a = await registered('a');
    const thrown = [new ACEError('relay_unavailable', 'from the consumer'), new Error('consumer bug')];
    for (const err of thrown) {
      relay.enqueueRaw(a.id, { n: 0 });
      const gen = a.relay!.listen(a.identity);
      expect(JSON.parse((await gen.next()).value!.data)).toEqual({ n: 0 });
      await expect(gen.throw(err)).rejects.toBe(err);
      await until(() => relay.openListens === 0);
    }
    expect(relay.requests.filter(([, p]) => p === '/v1/listen').length).toBe(2);
  });

  it('listen: onOpen runs per connection; an exception from it ends the iteration (no reconnect)', async () => {
    const a = await registered('a');
    relay.dropListens = 2;
    let opens = 0;
    const boom = new Error('host hook failed');
    await expect((async () => {
      for await (const _ of a.relay!.listen(a.identity, { onOpen: () => { if (++opens === 3) throw boom; } })) { /* none */ }
    })()).rejects.toBe(boom);
    expect(opens).toBe(3);
    expect(relay.requests.filter(([, p]) => p === '/v1/listen').length).toBe(3);
  });

  it('listen: abort during a backoff sleep resolves promptly', async () => {
    const a = await registered('a');
    relay.inject.push({ path: '/v1/listen', status: 503, code: 'down', headers: { 'Retry-After': '30' } });
    const ctrl = new AbortController();
    const done = (async () => {
      for await (const _ of a.relay!.listen(a.identity, { signal: ctrl.signal })) { /* none */ }
    })();
    await until(() => relay.requests.some(([, p]) => p === '/v1/listen'));
    await new Promise((r) => setTimeout(r, 30)); // now sleeping ~30 s
    const t0 = Date.now();
    ctrl.abort();
    await done;
    expect(Date.now() - t0).toBeLessThan(500);
    expect(relay.requests.filter(([, p]) => p === '/v1/listen').length).toBe(1);
  });

  it('parseSSE: abort ends a pending read and cancels the body', async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
    const ctrl = new AbortController();
    const it = parseSSE(body, undefined, ctrl.signal);
    const next = it.next();
    ctrl.abort();
    expect((await next).done).toBe(true);
    expect(cancelled).toBe(true);
  });

  it('listen: non-retryable status throws its mapped error; repeated failures → relay_unavailable', async () => {
    const stranger = await SoftwareIdentity.generate('ed25519');
    await expectCode((async () => { for await (const _ of client().listen(stranger)) { /* none */ } })(), 'not_registered');
    const a = await registered('a');
    for (let i = 0; i < 10; i++) relay.inject.push({ path: '/v1/listen', status: 503, code: 'down', headers: { 'Retry-After': '0' } });
    const fast = new RelayClient(relay.url, { clock: clock.fn, reconnectBaseMs: 0 }); // no backoff sleeps: fast under load
    await expectCode((async () => { for await (const _ of fast.listen(a.identity)) { /* none */ } })(), 'relay_unavailable');
    expect(relay.requests.filter(([, p]) => p === '/v1/listen').length).toBe(11);
  });
});

describe('RelayClient strictness', () => {
  it('a 3xx is relay_protocol_error and is never followed (requests and listen)', async () => {
    const a = await registered('a');
    for (const status of [301, 302, 307, 308]) {
      relay.inject.push({ path: '/v1/peer', status, code: 'moved', headers: { Location: `${relay.url}/v1/peer?aceId=${a.id}` } });
      const e = await expectCode(a.relay!.lookupPeer(a.id), 'relay_protocol_error');
      expect(e.status).toBe(status);
    }
    expect(relay.requests.filter(([, p]) => p === '/v1/peer').length).toBe(4); // never followed
    relay.inject.push({ path: '/v1/listen', status: 302, code: 'moved', headers: { Location: '/elsewhere' } });
    await expectCode((async () => { for await (const _ of a.relay!.listen(a.identity)) { /* none */ } })(), 'relay_protocol_error');
  });

  it('429: rate_limited is transient with Retry-After; other codes are relay_rejected without it', async () => {
    const a = await registered('a');
    relay.inject.push({ path: '/v1/inbox', status: 429, code: 'rate_limited', headers: { 'Retry-After': '3' } });
    const t = await expectCode(a.relay!.fetchInbox(a.identity), 'relay_unavailable');
    expect(t.retryAfterSeconds).toBe(3);
    relay.inject.push({ path: '/v1/intents', status: 429, code: 'max_open_intents', headers: { 'Retry-After': '3' } });
    const r = await expectCode(a.relay!.postIntent(a.identity, { need: 'x', ttl: 60 }), 'relay_rejected');
    expect([r.relayCode, r.retryAfterSeconds, r.isTransient]).toEqual(['max_open_intents', undefined, false]);
  });

  it('page cursors are strict: wrong type or absent is relay_protocol_error', async () => {
    const a = await registered('a');
    for (const cursor of [5, {}, undefined]) {
      relay.inject.push({ path: '/v1/discover', status: 200, body: { agents: [], ...(cursor === undefined ? {} : { cursor }) } });
      await expectCode(a.relay!.discover(), 'relay_protocol_error');
      relay.inject.push({ path: '/v1/intents', status: 200, body: { intents: [], ...(cursor === undefined ? {} : { cursor }) } });
      await expectCode(a.relay!.listIntents(), 'relay_protocol_error');
    }
    for (const cursor of [5, 'latest', undefined]) {
      relay.inject.push({ path: '/v1/inbox', status: 200, body: { messages: [], ...(cursor === undefined ? {} : { cursor }) } });
      await expectCode(a.relay!.fetchInbox(a.identity), 'relay_protocol_error');
    }
    relay.inject.push({ path: '/v1/discover', status: 200, body: { agents: [], cursor: 'opaque' } });
    expect((await a.relay!.discover()).cursor).toBe('opaque');
    relay.inject.push({ path: '/v1/inbox', status: 200, body: { messages: [], cursor: null } });
    expect((await a.relay!.fetchInbox(a.identity)).cursor).toBeNull();
    relay.inject.push({ path: '/v1/peer', status: 200, body: undefined });
    await expectCode(a.relay!.lookupPeer(a.id), 'relay_protocol_error'); // empty 2xx body
  });

  it('listIntents: a present but malformed optional field is relay_protocol_error', async () => {
    const a = await registered('a');
    const base = { intentId: 'i', from: a.id, need: 'x', tags: [], ttl: 60, createdAt: 1, expiresAt: 61 };
    for (const extra of [{ ext: 5 }, { ext: [] }, { ext: { bad: {} } }, { ext: { 'urn:x': 'y' } }, { ext: { 'urn:ace:commerce:1': { maxPrice: '1' } } }, { from: 'someone' }]) {
      relay.inject.push({ path: '/v1/intents', status: 200, body: { intents: [{ ...base, ...extra }], cursor: null } });
      await expectCode(a.relay!.listIntents(), 'relay_protocol_error');
    }
  });

  it('discover sends the account param', async () => {
    const a = await registered('a');
    const acc = 'eip155:1:0x' + 'ab'.repeat(20);
    await a.relay!.discover({ account: acc });
    const q = relay.queries.filter(([p]) => p === '/v1/discover').map(([, x]) => x.account);
    expect(q).toEqual([acc]);
  });

  it('tags are string arrays (joined with ","); postIntent always sends tags', async () => {
    const a = await registered('a');
    await a.relay!.discover({ tags: ['gpu', 'ml'] });
    await a.relay!.listIntents({ tags: ['gpu'] });
    await a.relay!.discover({ tags: [] });
    const q = relay.queries.filter(([p]) => p === '/v1/discover' || p === '/v1/intents').map(([, x]) => x.tags);
    expect(q).toEqual(['gpu,ml', 'gpu', undefined]);
    await expectCode(a.relay!.discover({ tags: ['a,b'] }), 'invalid_argument');
    await expectCode(a.relay!.listIntents({ tags: 'gpu' as never }), 'invalid_argument');
    await a.relay!.postIntent(a.identity, { need: 'x', ttl: 60 });
    expect(relay.bodies.filter(([p]) => p === '/v1/intents').map(([, b]) => b)).toEqual([{ need: 'x', tags: [], ttl: 60 }]);
  });

  it('listen: comments (heartbeats) do not reset the failure count; 10 broken streams → relay_unavailable', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    let connects = 0;
    const broken: typeof fetch = async () => {
      connects++;
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new TextEncoder().encode(': hb\n\n: hb\r\n\r\n'));
          c.error(new Error('connection reset'));
        },
      });
      return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
    };
    const c = new RelayClient('https://relay.example', { fetch: broken, reconnectBaseMs: 0 });
    await expectCode((async () => { for await (const _ of c.listen(id)) { /* none */ } })(), 'relay_unavailable');
    expect(connects).toBe(10);
  });

  it('listen: 200, `connected`, then an end (no progress) is a failure; 10 of them → relay_unavailable', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    let connects = 0;
    const empty: typeof fetch = async () => {
      connects++;
      return new Response('event: connected\ndata: {}\n\n: hb\n\n', { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
    };
    // base 1 ms: backoff 1, 2, 4 … 256 ms between the 10 connects (>= 511 ms in total)
    const c = new RelayClient('https://relay.example', { fetch: empty, reconnectBaseMs: 1 });
    const started = Date.now();
    await expectCode((async () => { for await (const _ of c.listen(id)) { /* none */ } })(), 'relay_unavailable');
    expect(connects).toBe(10);
    expect(Date.now() - started).toBeGreaterThanOrEqual(500);
  });

  it('listen: a clean end after an event frame (drain included) reconnects at once', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    const bodies = ['id: 1-0\nevent: message\ndata: {}\n\n', 'event: drain\ndata: {}\n\n', 'id: 2-0\nevent: message\ndata: {}\n\n'];
    const urls: string[] = [];
    const seq: typeof fetch = async (input) => {
      urls.push(String(input));
      return new Response(bodies.shift() ?? '', { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
    };
    // a huge base delay: any backoff sleep would time the test out
    const c = new RelayClient('https://relay.example', { fetch: seq, reconnectBaseMs: 1_000_000 });
    const got: string[] = [];
    for await (const ev of c.listen(id)) {
      got.push(ev.streamId);
      if (got.length === 2) break;
    }
    expect(got).toEqual(['1-0', '2-0']);
    expect(urls).toHaveLength(3);
  });

  it('listen yields raw frame data (the SecureMailbox decides what it is)', async () => {
    const bob = await registered('bob', 'secp256k1');
    relay.enqueueRaw(bob.id, new RawFrame('not json'));
    const gen = bob.relay!.listen(bob.identity);
    expect((await gen.next()).value).toMatchObject({ data: 'not json', catchup: true });
    await gen.return();
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

  it('signed files rotate only forward; corrupt pins are storage_failed', async () => {
    const clock2 = new Clock();
    const store = new MemoryStore();
    const peers = new PeerStore({ store, clock: clock2.fn });
    const bob = await SoftwareIdentity.generate('secp256k1');
    const reg = await createRegistrationFile(bob, { name: 'Bob', endpoint: 'https://bob.example/ace', timestamp: clock2.t });
    const p = await peers.pinRegistrationFile(reg);
    expect(p.registeredAt).toBe(clock2.t);
    expect((await peers.adopt(p)).outcome).toBe('unchanged');
    const other = SoftwareIdentity.fromExport({ ...bob.exportPrivateKey(), encryptionPrivateKey: toBase64(new Uint8Array(32).fill(7)) });
    await expectCode(peers.pinRegistrationFile(await createRegistrationFile(other, { name: 'Bob', endpoint: 'https://bob.example/ace', timestamp: clock2.t })), 'stale_peer_binding');
    clock2.t += 100;
    expect((await peers.pinRegistrationFile(await createRegistrationFile(other, { name: 'Bob', endpoint: 'https://bob.example/ace', timestamp: clock2.t }))).encryptionPublicKey).toEqual(other.getEncryptionPublicKey());
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
