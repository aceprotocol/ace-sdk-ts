import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { RelayClient } from '../src/relay.js';
import { SecureTransport } from '../src/secure-transport.js';
import { SecureMailbox, SecureRelayReplies, deliverSecure, openSecureMailbox, type DirectReply } from '../src/secure-mailbox.js';
import type { MLSEngine } from '../src/session.js';
import { createMessage } from '../src/index.js';
import { Agent, Clock } from './pipeline.js';
import { FakeRelay, RawFrame } from './fake-relay.js';
import { expectCode, wire } from './helpers.js';

const path = process.env.ACE_MLS_WASM;
describe.skipIf(!path)('secure network boundary', () => {
  let engine: MLSEngine & { free(): void };
  beforeAll(async () => {
    const url = pathToFileURL(path!), module = await import(/* @vite-ignore */ url.href);
    await module.default({ module_or_path: await readFile(new URL('./ace_session_core_bg.wasm', url)) });
    engine = new module.SessionEngine();
  });
  afterAll(() => engine?.free());
  async function setup() {
    const clock = new Clock(Math.floor(Date.now() / 1000));
    const server = await new FakeRelay(clock.fn).start();
    const relayA = new RelayClient(server.url, { clock: clock.fn }), relayB = new RelayClient(server.url, { clock: clock.fn });
    const a = await Agent.create('a', 'ed25519', clock, undefined, relayA);
    const b = await Agent.create('b', 'secp256k1', clock, undefined, relayB);
    await relayA.register(a.identity); await relayB.register(b.identity);
    await a.pin(b); await b.pin(a);
    await SecureTransport.setPeerAllowed(a.store, b.id, true); await SecureTransport.setPeerAllowed(b.store, a.id, true);
    const ta = new SecureTransport(a.identity, engine, a.store, clock.fn), tb = new SecureTransport(b.identity, engine, b.store, clock.fn);
    const ma = await SecureMailbox.open({ identity: a.identity, store: a.store, peers: a.peers, relay: relayA, secure: ta, inbox: await a.open(), closeTransport: false });
    const mb = await SecureMailbox.open({ identity: b.identity, store: b.store, peers: b.peers, relay: relayB, secure: tb, inbox: await b.open(), closeTransport: false });
    return { a, b, ta, tb, ma, mb, relayA, relayB, server, async close() { await ma.close(); await mb.close(); await ta.close(); await tb.close(); await server.close(); } };
  }
  it('delivers in both directions concurrently over the relay, ignores control frames in the application log', async () => {
    const s = await setup(), stop = new AbortController();
    const followers = [s.ma.follow(s.relayA, { signal: stop.signal }), s.mb.follow(s.relayB, { signal: stop.signal })]
      .map(async stream => { for await (const outcome of stream) expect(outcome.kind).not.toBe('quarantined'); });
    try {
      const pa = await s.b.peer(s.a), pb = await s.a.peer(s.b);
      const da = new SecureRelayReplies(s.a.identity, s.ta, s.relayA, pb, p => s.relayA.send(p));
      const db = new SecureRelayReplies(s.b.identity, s.tb, s.relayB, pa, p => s.relayB.send(p));
      const [a, b] = await Promise.all([
        s.a.outbox.stage({ recipient: pb, type: 'text', body: { message: 'A' } }),
        s.b.outbox.stage({ recipient: pa, type: 'text', body: { message: 'B' } }),
      ]);
      await Promise.all([
        s.a.outbox.deliver(a.requestId, p => s.ta.deliver(p, pb, (p, r) => da.exchange(p, r))),
        s.b.outbox.deliver(b.requestId, p => s.tb.deliver(p, pa, (p, r) => db.exchange(p, r))),
      ]);
      expect(s.a.host.calls).toHaveLength(1); expect(s.b.host.calls).toHaveLength(1);
      expect(await s.a.outbox.pending()).toEqual([]); expect(await s.b.outbox.pending()).toEqual([]);
      expect(s.server.stored.size).toBe(8); // Four authenticated control packets in each direction.
    } finally { stop.abort(); await Promise.all(followers); await s.close(); }
  }, 15_000);
  it('openSecureMailbox + deliverSecure: the glue helpers compose the same boundary (receive lock, transport, engine disposal)', async () => {
    const s = await setup(), stop = new AbortController();
    const c = await Agent.create('c', 'ed25519', s.a.clock, undefined, s.relayB);
    await s.relayB.register(c.identity);
    await c.pin(s.a); await s.a.pin(c);
    await SecureTransport.setPeerAllowed(c.store, s.a.id, true); await SecureTransport.setPeerAllowed(s.a.store, c.id, true);
    const free = vi.fn();
    // The test engine outlives this mailbox: a view without `free` is what a host sharing one engine passes.
    const mc = await openSecureMailbox({ identity: c.identity, store: c.store, peers: c.peers, relay: s.relayB, clock: s.a.clock.fn,
      engine: { execute: (command: Uint8Array) => engine.execute(command), free }, inbox: { commerce: true, onMessage: c.host.fn, clock: s.a.clock.fn } });
    const following = (async () => { for await (const outcome of mc.follow(s.relayB, { signal: stop.signal })) expect(outcome.kind).toBe('delivered'); })();
    try {
      const pending = await s.a.outbox.stage({ recipient: await s.a.peer(c), type: 'text', body: { message: 'via glue' } });
      await deliverSecure(s.a.outbox, pending.requestId, { identity: s.a.identity, secure: s.ta, relay: s.relayA, peer: await s.a.peer(c) });
      expect(c.host.calls).toEqual([[s.a.id, pending.message.messageId]]);
      expect(await s.a.outbox.pending()).toEqual([]);
      await expectCode(c.store.lock('receive', { timeoutMs: 0 }), 'receiver_busy');
    } finally {
      stop.abort(); await following;
      await mc.close();
      expect(free).toHaveBeenCalledTimes(1);
      await (await c.store.lock('receive', { timeoutMs: 0 }))();
      await s.close();
    }
  }, 15_000);
  it('quarantines malformed SSE and static downgrade packets, then retains the durable cursor across reopen', async () => {
    const s = await setup(), stop = new AbortController();
    try {
      const pending = await s.a.outbox.stage({ recipient: await s.a.peer(s.b), type: 'text', body: { message: 'static downgrade' } });
      await s.relayA.send(pending.message);
      const pulled = await s.mb.pull(s.relayB);
      expect(pulled.blocked).toBeNull(); expect(pulled.quarantined).toBe(1);
      let live!: () => void; const connected = new Promise<void>(r => { live = r; });
      const following = (async () => {
        for await (const outcome of s.mb.follow(s.relayB, { signal: stop.signal, onLive: live })) {
          expect(outcome).toMatchObject({ kind: 'quarantined', error: { code: 'invalid_envelope' } });
          stop.abort();
        }
      })();
      await connected;
      const cursor = s.server.enqueueRaw(s.b.id, new RawFrame('not JSON'));
      await following;
      expect(s.mb.cursor(s.relayB)).toBe(cursor);
      await s.mb.close();
      const reopened = await SecureMailbox.open({ ...s.mb.options, inbox: await s.b.open() });
      try { expect(reopened.cursor(s.relayB)).toBe(cursor); expect((await reopened.pull(s.relayB)).outcomes).toEqual([]); }
      finally { await reopened.close(); }
      expect(s.b.host.calls).toHaveLength(0);
    } finally { stop.abort(); await s.close(); }
  }, 10_000);
  it('pull: invalid page bounds and a failed inbox fetch are blocked; follow throws the failed initial pull before onLive', async () => {
    const s = await setup();
    try {
      for (const bad of [{ maxPages: 0 }, { maxPages: 1.5 }, { limit: 0 }, { limit: 101 }]) {
        const r = await s.mb.pull(s.relayB, bad);
        expect([r.blocked?.code, r.outcomes, r.hasMore]).toEqual(['invalid_argument', [], false]);
      }
      s.server.inject.push({ path: '/v1/inbox', status: 503, code: 'down' });
      const r = await s.mb.pull(s.relayB);
      expect([r.blocked?.code, r.outcomes]).toEqual(['relay_unavailable', []]);
      s.server.inject.push({ path: '/v1/inbox', status: 503, code: 'down' });
      let live = 0;
      await expectCode((async () => { for await (const _ of s.mb.follow(s.relayB, { onLive: () => live++ })) { /* none */ } })(), 'relay_unavailable');
      expect(live).toBe(0);
    } finally { await s.close(); }
  });
  it('receiveDirect: a handshake answers 200 per frame and commits once; a static envelope is 400 secure_delivery_required; an Inbox rejection is an accepted frame whose receipt rejects', async () => {
    const s = await setup();
    try {
      const peer = await s.a.peer(s.b), replies: DirectReply[] = [];
      const pending = await s.a.outbox.stage({ recipient: peer, type: 'text', body: { message: 'direct' } });
      // the sender posts each frame to the endpoint; the signed reply comes back through the relay
      const da = new SecureRelayReplies(s.a.identity, s.ta, s.relayA, peer, async packet => { replies.push(await s.mb.receiveDirect(wire({ message: packet }))); });
      await s.a.outbox.deliver(pending.requestId, p => s.ta.deliver(p, peer, (p, r) => da.exchange(p, r)));
      expect(replies.map(r => [r.status, r.body.ok, r.outcome?.kind])).toEqual([[200, true, undefined], [200, true, 'delivered']]);
      expect(s.b.host.calls).toHaveLength(1);
      // a static application envelope never reaches the Inbox: refused at the boundary with the session-core code
      // (08 § Receiver), nothing persisted; the pull/quarantine outcome keeps invalid_body
      const stale = await s.mb.receiveDirect(wire({ message: pending.message }));
      expect(stale).toMatchObject({ status: 400, body: { ok: false, error: 'secure_delivery_required' },
        outcome: { kind: 'quarantined', error: { code: 'invalid_body', message: 'invalid_body: secure_delivery_required' } } });
      expect(await s.b.store.list('quarantine/')).toEqual([]);
      // a commerce message without a thread passes the handshake and is rejected by the Inbox: the frame is accepted (200),
      // the record is persisted under quarantine/ and the sender learns the code from the receipt
      const bad = await createMessage({ sender: s.a.identity, recipient: peer, type: 'rfq', body: { need: 'x' }, timestamp: s.a.clock.t });
      replies.length = 0;
      const dd = new SecureRelayReplies(s.a.identity, s.ta, s.relayA, peer, async packet => { replies.push(await s.mb.receiveDirect(wire({ message: packet }))); });
      await expect(s.ta.deliver(bad, peer, (p, r) => dd.exchange(p, r))).rejects.toMatchObject({ code: 'delivery_rejected', remoteCode: 'invalid_envelope' });
      expect(replies.map(r => [r.status, r.body.ok, r.outcome?.kind])).toEqual([[200, true, undefined], [200, true, 'quarantined']]);
      expect(replies[1].outcome).toMatchObject({ kind: 'quarantined', error: { code: 'invalid_envelope' }, fingerprint: expect.any(String) });
      expect(await s.b.store.list('quarantine/')).toHaveLength(1);
      expect(s.b.host.calls).toHaveLength(1);
    } finally { await s.close(); }
  }, 15_000);
  it('SecureRelayReplies waits no longer than the attempt is valid: an expired route sends nothing', async () => {
    const s = await setup();
    try {
      const sent: unknown[] = [];
      const replies = new SecureRelayReplies(s.a.identity, s.ta, s.relayA, await s.a.peer(s.b), async p => { sent.push(p); });
      const packet = await createMessage({ sender: s.a.identity, recipient: await s.a.peer(s.b), type: 'text', body: { message: 'x' }, timestamp: s.a.clock.t });
      const route = { attempt: 'a'.repeat(64), kind: 'offer', expiresAt: s.a.clock.t };
      await expect(replies.exchange(packet, route)).rejects.toMatchObject({ code: 'delivery_expired' });
      expect(sent).toEqual([]);
    } finally { await s.close(); }
  });
  it('an unadmitted stranger is refused before any peer resolution: no relay lookup, no pin', async () => {
    const s = await setup();
    try {
      const c = await Agent.create('c', 'ed25519', s.a.clock);
      await c.pin(s.b);
      const stranger = (await c.outbox.stage({ recipient: await c.peer(s.b), type: 'text', body: { message: 'hi' } })).message;
      const resolve = vi.spyOn(s.b.peers, 'resolve');
      const lookups = () => s.server.requests.filter(([, path]) => path === '/v1/peer').length;
      const before = lookups(), pinned = await s.b.store.list('peers/');
      s.server.enqueueRaw(s.b.id, stranger);
      const pulled = await s.mb.pull(s.relayB);
      expect(pulled.blocked).toBeNull();
      expect(pulled.outcomes).toMatchObject([{ kind: 'quarantined', error: { code: 'invalid_body', message: 'invalid_body: delivery_peer_disabled' }, fingerprint: expect.any(String) }]);
      expect(await s.mb.receiveDirect(wire({ message: stranger }))).toMatchObject({ status: 400, body: { ok: false, error: 'delivery_peer_disabled' } });
      expect(resolve).not.toHaveBeenCalled();
      expect(lookups()).toBe(before);
      expect(await s.b.store.list('peers/')).toEqual(pinned);
      expect(s.b.host.calls).toHaveLength(0);
    } finally { await s.close(); }
  });
  it('rejects invalid direct UTF-8/JSON and returns retryable storage errors without pretending to acknowledge', async () => {
    const s = await setup();
    try {
      expect(await s.mb.receiveDirect(new Uint8Array([255]))).toMatchObject({ status: 400, body: { ok: false } });
      expect(await s.mb.receiveDirect(new TextEncoder().encode('{bad'))).toMatchObject({ status: 400, body: { ok: false } });
      const peer = await s.a.peer(s.b);
      const pending = await s.a.outbox.stage({ recipient: peer, type: 'text', body: { message: 'disk failure' } });
      const broken = vi.spyOn(s.b.store, 'read').mockRejectedValueOnce(Error('disk failure'));
      try {
        await expect(s.ta.deliver(pending.message, peer, async packet => {
          const reply = await s.mb.receiveDirect(new TextEncoder().encode(JSON.stringify({ message: packet })));
          expect(reply).toMatchObject({ status: 503, body: { ok: false, error: 'storage_failed' }, outcome: { kind: 'retryable' } });
          throw Error('no receipt');
        })).rejects.toThrow('no receipt');
      } finally { broken.mockRestore(); }
      expect(s.b.host.calls).toHaveLength(0);
    } finally { await s.close(); }
  });
});
