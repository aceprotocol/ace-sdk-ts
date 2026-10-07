// Outbox: stage / deliver / resign / abandon / pending; ThreadStore pruning.
import { describe, expect, it } from 'vitest';
import { ACEError, Outbox, ThreadStore, type ACEMessage } from '../src/index.js';
import { sha256Hex } from '../src/encoding.js';
import { threadKey } from '../src/thread-store.js';
import { expectCode, wire } from './helpers.js';
import { Agent, Clock, json } from './pipeline.js';

const outboxKey = (rid: string) => `outbox/${sha256Hex(rid)}.json`;

async function pair() {
  const clock = new Clock();
  const alice = await Agent.create('alice', 'ed25519', clock);
  const bob = await Agent.create('bob', 'secp256k1', clock);
  await alice.pin(bob);
  await bob.pin(alice);
  return { clock, alice, bob };
}

const expired = async () => {
  throw new ACEError('envelope_expired', 'stale', { status: 400, relayCode: 'envelope_expired' });
};

describe('Outbox', () => {
  it('stage (economic) persists the thread and the pending send in one record; idempotent by requestId', async () => {
    const { clock, alice, bob } = await pair();
    const peer = await alice.peer(bob);
    const p = await alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'req-1' });
    expect(p.status).toBe('pending');
    expect(p.stagedAt).toBe(clock.t);
    const rec = json(await alice.store.read(threadKey(p.message.conversationId, 'd')));
    expect(rec.state).toBe('rfq');
    expect(rec.pending).toEqual({ message: p.message, requestId: 'req-1', stagedAt: clock.t, status: 'pending' });
    const again = await alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 'other' }, threadId: 'zzz', requestId: 'req-1' });
    expect(again).toEqual(p);
    await alice.outbox.stage({ recipient: peer, type: 'text', body: { message: 'x' }, requestId: 'req-2' });
    await expectCode(alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 'y' }, threadId: 'd', requestId: 'req-3' }), 'pending_send_conflict');
    expect((await alice.outbox.pending()).map((x) => x.requestId)).toEqual(['req-1', 'req-2']);
  });

  it('stage validation writes nothing', async () => {
    const { alice, bob } = await pair();
    const peer = await alice.peer(bob);
    for (const rid of ['', 'x'.repeat(257), 'a\nb', 5 as unknown as string]) {
      await expectCode(alice.outbox.stage({ recipient: peer, type: 'text', body: { message: 'x' }, requestId: rid }), 'invalid_argument');
    }
    await expectCode(alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 'x' } }), 'invalid_argument');
    await expectCode(alice.outbox.stage({ recipient: peer, type: 'offer', body: { price: '1', currency: 'USDC' }, threadId: 'd' }), 'transition_not_allowed');
    await expectCode(alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 5 }, threadId: 'd' }), 'invalid_body');
    await expectCode(alice.outbox.stage({ recipient: {} as never, type: 'text', body: { message: 'x' } }), 'invalid_argument');
    expect(await alice.outbox.pending()).toEqual([]);
    expect(await alice.store.list('')).toEqual(await alice.store.list('peers/'));
  });

  it('stage (non-economic) writes outbox/<sha256(requestId)>.json', async () => {
    const { alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'info', body: { message: 'hello' }, requestId: 'i1' });
    expect(json(await alice.store.read(outboxKey('i1')))).toEqual({ ...p, version: 1 });
    expect(await alice.store.list('threads/')).toEqual([]);
  });

  it('deliver acknowledges on success and leaves state unchanged on failure', async () => {
    const { alice, bob } = await pair();
    const peer = await alice.peer(bob);
    const p = await alice.outbox.stage({ recipient: peer, type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r' });
    const n = await alice.outbox.stage({ recipient: peer, type: 'text', body: { message: 'hi' }, requestId: 't' });
    for (const rid of ['r', 't']) {
      await expectCode(alice.outbox.deliver(rid, async () => { throw new ACEError('relay_unavailable', 'down'); }), 'relay_unavailable');
    }
    await expect(alice.outbox.deliver('r', async () => { throw new Error('bug'); })).rejects.toThrow('bug');
    expect(new Set((await alice.outbox.pending()).map((x) => x.requestId))).toEqual(new Set(['r', 't']));
    const sent: ACEMessage[] = [];
    await alice.outbox.deliver('r', async (e) => { sent.push(e); });
    await alice.outbox.deliver('t', async (e) => { sent.push(e); });
    expect(sent.map((e) => e.messageId)).toEqual([p.message.messageId, n.message.messageId]);
    expect(await alice.outbox.pending()).toEqual([]);
    expect(await alice.store.list('outbox/')).toEqual([]);
    const snap = (await new ThreadStore({ store: alice.store, localAceId: alice.id }).get(p.message.conversationId, 'd'))!;
    expect(snap.state).toBe('rfq');
    expect(snap.history.length).toBe(1);
    await expectCode(alice.outbox.deliver('r', async () => {}), 'invalid_argument');
  });

  it('envelope_expired → expired → resign (same messageId, ciphertext reused, new timestamp) → deliver', async () => {
    const { clock, alice, bob } = await pair();
    const t0 = clock.t;
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r' });
    await expectCode(alice.outbox.resign('r'), 'invalid_argument');
    clock.t += 1000;
    await expectCode(alice.outbox.deliver('r', expired), 'envelope_expired');
    const [pending] = await alice.outbox.pending();
    expect(pending.status).toBe('expired');
    expect(pending.message).toEqual(p.message);
    await expectCode(alice.outbox.deliver('r', async () => {}), 'envelope_expired');
    const r = await alice.outbox.resign('r');
    expect(r.status).toBe('pending');
    expect(r.message.messageId).toBe(p.message.messageId);
    expect(r.message.encryption).toEqual(p.message.encryption);
    expect(r.message.timestamp).toBe(t0 + 1000);
    expect(r.message.signature.value).not.toBe(p.message.signature.value);
    expect(r.stagedAt).toBe(t0);
    const snap = (await new ThreadStore({ store: alice.store, localAceId: alice.id }).get(p.message.conversationId, 'd'))!;
    expect(snap.history[0].timestamp).toBe(t0 + 1000);
    expect(snap.state).toBe('rfq');
    const got: ACEMessage[] = [];
    await alice.outbox.deliver('r', async (e) => { got.push(e); });
    const inbox = await bob.open();
    const out = await inbox.receive(wire(got[0]), { kind: 'relay', relayUrl: 'https://r.example', streamId: '1-0' });
    expect(out.kind).toBe('delivered');
    if (out.kind === 'delivered') expect(out.message.timestamp).toBe(t0 + 1000);
  });

  it('resign (non-economic)', async () => {
    const { clock, alice, bob } = await pair();
    await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'hi' }, requestId: 't' });
    await expectCode(alice.outbox.deliver('t', expired), 'envelope_expired');
    clock.t += 50;
    const r = await alice.outbox.resign('t');
    expect(r.message.timestamp).toBe(clock.t);
    expect(json(await alice.store.read(outboxKey('t'))).status).toBe('pending');
  });

  it('abandon drops the head entry; unknown requestId is a no-op', async () => {
    const { alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r' });
    await alice.outbox.abandon('r');
    expect(await alice.store.read(threadKey(p.message.conversationId, 'd'))).toBeNull();
    await alice.outbox.abandon('r');
    const first = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r1' });
    await alice.outbox.deliver('r1', async () => {});
    const inbox = await bob.open();
    await inbox.receive(wire(first.message), { kind: 'direct' });
    const offer = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '3', currency: 'USDC' }, threadId: 'd', requestId: 'o1' });
    await bob.outbox.abandon('o1');
    const snap = (await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(offer.message.conversationId, 'd'))!;
    expect(snap.state).toBe('rfq');
    expect(snap.history.map((h) => h.type)).toEqual(['rfq']);
    const again = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '4', currency: 'USDC' }, threadId: 'd', requestId: 'o2' });
    expect(again.message.messageId).not.toBe(offer.message.messageId);
    await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'x' }, requestId: 't' });
    await alice.outbox.abandon('t');
    expect(await alice.store.read(outboxKey('t'))).toBeNull();
  });

  it('ThreadStore prunes old terminal threads (at most hourly) and removes on request', async () => {
    const { clock, alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'old', requestId: 'a' });
    await alice.outbox.deliver('a', async () => {});
    const inbox = await bob.open();
    await inbox.receive(wire(p.message), { kind: 'direct' });
    const rej = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'reject', body: { reason: 'busy' }, threadId: 'old', requestId: 'r' });
    await bob.outbox.deliver('r', async () => {});
    const store = new ThreadStore({ store: bob.store, localAceId: bob.id, clock: clock.fn });
    expect((await store.get(rej.message.conversationId, 'old'))!.state).toBe('rejected');
    expect(await store.allowedTypes(rej.message.conversationId, 'old', alice.id)).toEqual([]);
    clock.t += 30 * 86400 + 10;
    const fresh = await Outbox.open({ identity: bob.identity, store: bob.store, clock: clock.fn });
    const keep = await fresh.stage({ recipient: await bob.peer(alice), type: 'rfq', body: { need: 'new' }, threadId: 'new', requestId: 'n' });
    expect((await store.list()).map((s) => s.threadId)).toEqual(['new']);
    expect(await store.remove(keep.message.conversationId, 'new')).toBe(true);
    expect(await store.list()).toEqual([]);
  });

  it('a corrupt thread record is storage_failed and never reset', async () => {
    const { alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r' });
    const key = threadKey(p.message.conversationId, 'd');
    const rec = json(await alice.store.read(key));
    rec.state = 'paid';
    const bytes = new TextEncoder().encode(JSON.stringify(rec));
    await alice.store.write(key, bytes);
    const ts = new ThreadStore({ store: alice.store, localAceId: alice.id });
    await expectCode(ts.get(p.message.conversationId, 'd'), 'storage_failed');
    await expectCode(alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd' }), 'storage_failed');
    expect(await alice.store.read(key)).toEqual(bytes);
  });
});
