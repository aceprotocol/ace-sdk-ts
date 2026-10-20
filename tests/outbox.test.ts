// Outbox (ace-spec/06 § Outbox), mirroring sdk-py tests/test_outbox.py.
import { describe, expect, it, vi } from 'vitest';
import {
  ACEError, MemoryStore, OFFLINE_WINDOW_SECONDS, Outbox, ProfileSet, decodePacket,
  type OutboxTransport, type ProfileRules,
} from './sdk.js';
import { Clock, FakeRelay, agent, identity } from './helpers.js';

async function setup(transport: OutboxTransport, rules: ProfileRules[] = []) {
  const clock = new Clock();
  const me = await identity(clock), peer = await identity(clock);
  const store = new MemoryStore();
  const ob = new Outbox({ identity: me, store, profiles: new ProfileSet(['text']), transport, rules, clock: clock.now });
  return { clock, me, peer, store, ob, to: peer.getACEId() };
}

const ok: OutboxTransport = async () => ({ prekey: 'a'.repeat(64) });

describe('Outbox', () => {
  it('backs off 60 s · 2^(n-1), capped at 3600 s', async () => {
    const { ob, to, clock } = await setup(async () => { throw new ACEError('relay_unavailable', 'down'); });
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    const delays: number[] = [];
    for (let i = 0; i < 8; i++) {
      const r = (await ob.attempt(e.messageId))!;
      delays.push(r.nextAttemptAt - clock.t);
      clock.t = r.nextAttemptAt;
    }
    expect(delays).toEqual([60, 120, 240, 480, 960, 1920, 3600, 3600]);
  });

  it('enqueue validates type, body, recipient and messageId; receipts and contacts never enter it', async () => {
    const { ob, to, me } = await setup(ok);
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 1 } })).rejects.toMatchObject({ code: 'invalid_body' });
    await expect(ob.enqueue({ to, type: 'ace:commerce:rfq:1', body: { need: 'x' } })).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(ob.enqueue({ to: me.getACEId(), type: 'ace:text:1', body: { message: 'self' } })).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' }, messageId: 'NOT-A-UUID' })).rejects.toMatchObject({ code: 'invalid_argument' });
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' }, messageId: e.messageId })).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(ob.enqueue({ to, type: 'ace:receipt:1', body: { messageId: e.messageId, outcome: 'delivered' } })).rejects.toBeInstanceOf(ACEError);
    expect((await ob.list()).map((x) => x.content.type)).toEqual(['ace:text:1']);
  });

  it('profile rules: check runs before persisting (a refusal stores nothing); commit runs on the delivered receipt', async () => {
    const commit = vi.fn();
    let refuse = false;
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check: () => { if (refuse) throw new ACEError('wrong_role', 'no'); }, commit }];
    const { ob, to, clock } = await setup(ok, rules);
    const created = clock.t;
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'a' } });
    expect(commit).not.toHaveBeenCalled();
    refuse = true;
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'b' } })).rejects.toMatchObject({ code: 'wrong_role' });
    expect(await ob.list()).toHaveLength(1);
    clock.advance(5);
    await ob.onReceipt(to, { messageId: e.messageId, outcome: 'delivered' });
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0]).toMatchObject({ direction: 'send', type: 'ace:text:1', messageId: e.messageId, timestamp: created });
    await ob.onReceipt(to, { messageId: e.messageId, outcome: 'delivered' }); // a second receipt changes nothing
    expect(commit).toHaveBeenCalledOnce();
  });

  it('a rule-governed thread is busy until the receipt; rejected, expired or abandoned release it unchanged', async () => {
    const commit = vi.fn();
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check: () => undefined, commit }];
    const { ob, to, clock } = await setup(ok, rules);
    const send = (threadId?: string) => ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' }, ...(threadId ? { threadId } : {}) });
    const a = await send('t1');
    expect(await ob.busy(to, 't1')).toBe(a.messageId);
    await expect(send('t1')).rejects.toMatchObject({ code: 'thread_busy' });
    await send('t2'); // other threads and thread-less messages are independent
    await send();
    await ob.onReceipt(to, { messageId: a.messageId, outcome: 'rejected', code: 'bad_reference' });
    expect(commit).not.toHaveBeenCalled();
    expect(await ob.busy(to, 't1')).toBeNull();
    const b = await send('t1');
    await ob.abandon(b.messageId);
    const c = await send('t1');
    await ob.attempt(c.messageId);
    clock.advance(OFFLINE_WINDOW_SECONDS + 1);
    expect(await ob.attempt(c.messageId)).toMatchObject({ status: 'expired' });
    const d = await send('t1');
    await ob.onReceipt(to, { messageId: d.messageId, outcome: 'delivered' });
    expect(commit.mock.calls.map(([ev]) => ev.messageId)).toEqual([d.messageId]);
    await send('t1');
  });

  it('a message type no rule governs never locks a thread', async () => {
    const { ob, to } = await setup(ok);
    await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' }, threadId: 't' });
    await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'y' }, threadId: 't' });
    expect(await ob.busy(to, 't')).toBeNull();
  });

  it('enqueue fails with unknown_peer when no descriptor resolves (nothing stored); transient failures are rethrown', async () => {
    const clock = new Clock();
    const me = await identity(clock), peer = await identity(clock);
    let fail: ACEError = new ACEError('unknown_peer', 'nope');
    const ob = new Outbox({ identity: me, store: new MemoryStore(), profiles: new ProfileSet(['text']), transport: ok, clock: clock.now, resolvePeer: async () => { throw fail; } });
    const to = peer.getACEId();
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } })).rejects.toMatchObject({ code: 'unknown_peer' });
    fail = new ACEError('not_permitted', 'private');
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } })).rejects.toMatchObject({ code: 'unknown_peer' });
    fail = new ACEError('relay_unavailable', 'down');
    await expect(ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } })).rejects.toMatchObject({ code: 'relay_unavailable' });
    expect(await ob.list()).toEqual([]);
  });

  it('a relay {ok:true} is not delivery; failures back off, honour Retry-After, then expire after the offline window', async () => {
    let fail: ACEError | null = null;
    const transport = vi.fn<OutboxTransport>(async () => { if (fail) throw fail; return { prekey: 'b'.repeat(64) }; });
    const { ob, to, clock } = await setup(transport);
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    expect(await ob.attempt(e.messageId)).toMatchObject({ status: 'pending', attempts: 1, nextAttemptAt: clock.t + 60 });
    fail = new ACEError('relay_unavailable', 'down');
    clock.advance(60);
    expect(await ob.attempt(e.messageId)).toMatchObject({ status: 'pending', attempts: 2, code: 'relay_unavailable', nextAttemptAt: clock.t + 120 });
    expect(await ob.flush()).toEqual([]); // not due
    clock.advance(120);
    fail = new ACEError('relay_unavailable', 'slow down', { retryAfterSeconds: 1000 });
    expect((await ob.flush())[0]).toMatchObject({ attempts: 3, nextAttemptAt: clock.t + 1000 });
    fail = new ACEError('not_permitted', 'blocked');
    clock.advance(1000);
    expect((await ob.flush())[0]).toMatchObject({ status: 'pending', code: 'not_permitted' }); // relay errors never end it
    clock.advance(OFFLINE_WINDOW_SECONDS);
    expect((await ob.flush())[0]).toMatchObject({ status: 'expired', code: 'expired' });
    expect(transport).toHaveBeenCalledTimes(4);
    expect(transport.mock.calls.every(([a]) => a.messageId === e.messageId)).toBe(true);
  });

  it('a transport limit_exceeded never ends the message (only local refusals are final)', async () => {
    const transport = vi.fn<OutboxTransport>(async () => { throw new ACEError('limit_exceeded', 'relay cap'); });
    const { ob, to } = await setup(transport);
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    expect(await ob.attempt(e.messageId)).toMatchObject({ status: 'pending', code: 'limit_exceeded' });
  });

  it('an attempt in flight is not started twice', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const transport = vi.fn<OutboxTransport>(async () => { await gate; return { prekey: 'c'.repeat(64) }; });
    const { ob, to } = await setup(transport);
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    const first = ob.attempt(e.messageId);
    await new Promise((r) => setTimeout(r, 10));
    const second = await ob.attempt(e.messageId);
    expect(second!.attempts).toBe(0);
    release();
    expect((await first)!.attempts).toBe(1);
    expect(transport).toHaveBeenCalledOnce();
  });

  it('receipts settle the entry; a receipt from another identity or for an unknown message is ignored', async () => {
    const { ob, to, me } = await setup(ok);
    const a = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'a' } });
    const b = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'b' } });
    await ob.attempt(a.messageId);
    await ob.attempt(b.messageId);
    expect(await ob.onReceipt(me.getACEId(), { messageId: a.messageId, outcome: 'delivered' })).toBeNull();
    expect(await ob.onReceipt(to, { messageId: crypto.randomUUID(), outcome: 'delivered' })).toBeNull();
    expect((await ob.get(a.messageId))!.status).toBe('pending');
    expect(await ob.onReceipt(to, { messageId: a.messageId, outcome: 'delivered' })).toMatchObject({ status: 'delivered' });
    expect(await ob.onReceipt(to, { messageId: b.messageId, outcome: 'rejected', code: 'invalid_body' })).toMatchObject({ status: 'rejected', code: 'invalid_body' });
    // settled entries stay settled
    expect(await ob.onReceipt(to, { messageId: b.messageId, outcome: 'delivered' })).toBeNull();
    expect(await ob.attempt(a.messageId)).toMatchObject({ status: 'delivered', attempts: 1 });
  });

  it('rejected:unknown_prekey refreshes and retries; it is final when the peer still publishes the prekey used', async () => {
    let current = 'd'.repeat(64);
    const transport = vi.fn<OutboxTransport>(async (a) => {
      if (a.avoidPrekey !== undefined && a.avoidPrekey === current) throw new ACEError('unknown_prekey', 'still current');
      return { prekey: current };
    });
    const { ob, to } = await setup(transport);
    const e = await ob.enqueue({ to, type: 'ace:text:1', body: { message: 'x' } });
    await ob.attempt(e.messageId);
    // L1: a receipt naming another attempt's prekey (late or replayed), or none, is ignored
    expect(await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: 'f'.repeat(64) })).toBeNull();
    expect(await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey' })).toBeNull();
    expect(await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: current })).toMatchObject({ status: 'pending', code: 'unknown_prekey' });
    expect(await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: current })).toBeNull(); // once
    current = 'e'.repeat(64); // the peer rotated
    expect(await ob.attempt(e.messageId)).toMatchObject({ status: 'pending', lastPrekey: current });
    expect(transport.mock.calls[1][0]).toMatchObject({ refresh: true, avoidPrekey: 'd'.repeat(64) });
    // a replay of the first receipt (prekey d…) no longer counts
    expect(await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: 'd'.repeat(64) })).toBeNull();
    // again rejected, and this time the peer still publishes it: final
    await ob.onReceipt(to, { messageId: e.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: current });
    expect(await ob.attempt(e.messageId)).toMatchObject({ status: 'rejected', code: 'unknown_prekey' });
  });

  it('each attempt re-encrypts to the current prekey with the same messageId and a fresh timestamp', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();
    const before = relay.sent.length;
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    const e = await bob.client.send(A, 'ace:text:1', { message: 'retry me' });
    expect(e).toMatchObject({ status: 'pending', attempts: 1 });
    clock.advance(60);
    await bob.client.flush();
    // the descriptor expires and alice rotates her prekey: the next attempt uses the new one
    clock.advance(86_400 + 1);
    const fresh = await alice.client.publish();
    await bob.client.publish(); // so alice can route the receipt
    await bob.client.outbox.attempt(e.messageId);
    const packets = relay.sent.slice(before).map((s) => decodePacket(s.packet)).filter((p) => p.messageId === e.messageId);
    expect(packets).toHaveLength(2);
    expect(packets[1].timestamp).toBeGreaterThan(packets[0].timestamp);
    expect(packets[0].encryption.kemCiphertext).not.toBe(packets[1].encryption.kemCiphertext);
    expect(packets[1].encryption.prekey).toBe(fresh.descriptor.prekey.id);
    expect(packets[0].encryption.prekey).not.toBe(fresh.descriptor.prekey.id);
    expect((await bob.client.outbox.get(e.messageId))!.status).toBe('pending'); // queued is not delivered
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    await bob.client.pull();
    expect((await bob.client.outbox.get(e.messageId))!.status).toBe('delivered');
  });

  it('contact packets and receipts are never stored in the Outbox', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    await bob.client.connect(alice.id.getACEId(), { profile: 'ace:text:1' });
    await alice.client.pull(); // auto-accept: an accepted contact back
    await bob.client.pull();
    await bob.client.send(alice.id.getACEId(), 'ace:text:1', { message: 'x' });
    await alice.client.pull(); // a receipt back
    expect((await alice.client.outbox.list()).length).toBe(0);
    expect((await bob.client.outbox.list()).map((e) => e.content.type)).toEqual(['ace:text:1']);
  });
});
