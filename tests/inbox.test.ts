// Inbox: commit order, recovery, crash injection, quarantine, cursor rules.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ACEError, Inbox, MemoryStore, Outbox, PeerStore, RelayClient, ReplayDetector, ThreadStateMachine, ThreadStore, createMessage,
  envelopeFingerprint, type ACEMessage, type ReceiveSource,
} from '../src/index.js';
import { FileStore } from '../src/node.js';
import { pairKey, stringifySorted } from '../src/encoding.js';
import { threadIndexKey, threadKey } from '../src/thread-store.js';
import { expectCode } from './helpers.js';
import { Agent, Clock, CountingStore, cloneStore, json } from './pipeline.js';

const RELAY = 'https://Relay.Example/';
const SRC = 'https://relay.example';
const SRC_RELAY = new RelayClient(RELAY); // baseUrl === SRC
const relaySrc = (n: number): ReceiveSource => ({ kind: 'relay', relayUrl: RELAY, streamId: `${n}-0` });
const deliveryKey = (from: string, id: string) => `deliveries/${pairKey(from, id)}.json`;

async function pair() {
  const clock = new Clock();
  const alice = await Agent.create('alice', 'ed25519', clock);
  const bob = await Agent.create('bob', 'secp256k1', clock);
  await alice.pin(bob);
  await bob.pin(alice);
  return { clock, alice, bob };
}

async function rfq(alice: Agent, bob: Agent, threadId = 'deal-1'): Promise<ACEMessage> {
  return (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'translate' }, threadId })).message;
}

const temps: string[] = [];
afterEach(() => {
  for (const t of temps.splice(0)) rmSync(t, { recursive: true, force: true });
});

describe('Inbox', () => {
  it('open creates replay.json and holds the receive lock', async () => {
    const { clock, bob } = await pair();
    const inbox = await bob.open({ offlineWindowSeconds: 1000 });
    expect(json(await bob.store.read('replay.json'))).toEqual({ entries: [], horizon: clock.t - 1001, senderHorizons: {}, version: 1 });
    await expectCode(bob.open(), 'receiver_busy');
    await inbox.close();
    await inbox.close();
    await (await bob.open()).close();
  });

  it('replay state missing beside inbound history is storage_failed; outbox-only threads are not', async () => {
    const { alice, bob } = await pair();
    await rfq(alice, bob); // alice has an outbox-only thread
    await (await alice.open()).close();
    const inbox = await bob.open();
    await inbox.receive(await rfq(alice, bob, 'deal-2'), relaySrc(1));
    await inbox.close();
    await bob.store.delete('replay.json');
    await expectCode(bob.open(), 'storage_failed');
    await bob.store.write('replay.json', new TextEncoder().encode('{"version":2}'));
    await expectCode(bob.open(), 'storage_failed');
  });

  it('delivered: commit order and persisted formats; duplicates advance the cursor only', async () => {
    const { alice, bob } = await pair();
    const env = await rfq(alice, bob);
    const counting = new CountingStore(bob.store);
    const inbox = await bob.open({ store: counting });
    expect(counting.writes).toEqual(['replay.json']);
    counting.writes = [];
    const out = await inbox.receive(env, relaySrc(7));
    expect(out.kind).toBe('delivered');
    if (out.kind === 'delivered') expect(out.message.body).toEqual({ need: 'translate' });
    const dkey = deliveryKey(alice.id, env.messageId);
    const tkey = threadKey(env.conversationId, 'deal-1');
    // a new open thread is indexed before its record is written
    expect(counting.writes).toEqual([dkey, threadIndexKey(alice.id), tkey, 'replay.json', dkey, 'cursors.json']);
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    expect(inbox.cursor(SRC_RELAY)).toBe('7-0');
    const rec = json(await bob.store.read(dkey));
    expect(Object.keys(rec).sort()).toEqual(['fingerprint', 'message', 'receivedAt', 'source', 'status', 'thread', 'version']);
    expect(rec.status).toBe('acked');
    expect(rec.source).toBe('relay');
    expect(rec.fingerprint).toBe(envelopeFingerprint(env));
    expect(Object.keys(rec.message).sort()).toEqual(['body', 'conversationId', 'from', 'messageId', 'threadId', 'timestamp', 'to', 'type']);
    expect(rec.thread.state).toBe('rfq');
    expect(json(await bob.store.read('cursors.json'))).toEqual({ cursors: { [SRC]: '7-0' }, version: 1 });
    const raw = new TextDecoder().decode((await bob.store.read(tkey))!);
    const thread = JSON.parse(raw);
    expect(thread.pending).toBeNull();
    expect(thread.peerAceId).toBe(alice.id);
    expect(raw).toBe(stringifySorted(thread)); // sorted keys, compact
    counting.writes = [];
    expect((await inbox.receive(env, relaySrc(9))).kind).toBe('duplicate');
    expect(counting.writes).toEqual(['cursors.json']);
    expect((await inbox.receive(env, relaySrc(8))).kind).toBe('duplicate');
    expect(inbox.cursor(SRC_RELAY)).toBe('9-0');
    expect((await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('rfq');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
  });

  it('non-economic and direct; direct freshness window; no quarantine record for direct', async () => {
    const { clock, alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'hi' } });
    const inbox = await bob.open();
    const out = await inbox.receive(p.message, { kind: 'direct' });
    expect(out.kind).toBe('delivered');
    if (out.kind === 'delivered') expect(out.message.threadId).toBeNull();
    const rec = json(await bob.store.read(deliveryKey(alice.id, p.message.messageId)));
    expect(rec.thread).toBeNull();
    expect(rec.source).toBe('direct');
    expect(await bob.store.list('cursors.json')).toEqual([]);
    clock.t += 301;
    const p2 = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'late' } });
    clock.t += 301;
    const late = await inbox.receive(p2.message, { kind: 'direct' });
    expect(late.kind).toBe('quarantined');
    if (late.kind === 'quarantined') {
      expect(late.error.code).toBe('stale_timestamp');
      expect(late.fingerprint).toBe(envelopeFingerprint(p2.message));
    }
    expect(await bob.store.list('quarantine/')).toEqual([]);
    expect((await inbox.receive(p2.message, relaySrc(1))).kind).toBe('delivered');
  });

  it('decode failure and unknown peer are quarantined', async () => {
    const { clock, bob } = await pair();
    const inbox = await bob.open();
    const out = await inbox.receive({ ace: '1.0' }, relaySrc(1));
    expect(out).toMatchObject({ kind: 'quarantined', fingerprint: null });
    if (out.kind === 'quarantined') expect(out.error.code).toBe('invalid_envelope');
    expect(inbox.cursor(SRC_RELAY)).toBe('1-0');
    expect(await bob.store.list('quarantine/')).toEqual([]);
    const eve = await Agent.create('eve', 'ed25519', clock);
    await eve.pin(bob);
    const env = (await eve.outbox.stage({ recipient: await eve.peer(bob), type: 'text', body: { message: 'x' } })).message;
    const q = await inbox.receive(env, relaySrc(2));
    expect(q.kind).toBe('quarantined');
    if (q.kind !== 'quarantined') return;
    expect(q.error.code).toBe('unknown_peer');
    const rec = json(await bob.store.read(`quarantine/${q.fingerprint}.json`));
    expect(rec.code).toBe('unknown_peer');
    expect(rec.source).toBe('relay');
    expect(rec.envelope).toEqual(env);
    expect(Object.keys(rec).sort()).toEqual(['code', 'envelope', 'fingerprint', 'quarantinedAt', 'reason', 'source', 'version']);
    expect((await inbox.receive(env, { kind: 'direct' })).kind).toBe('quarantined');
    expect((await bob.store.list('quarantine/')).length).toBe(1);
  });

  it('quarantine is capped at 1000 (trimmed to 900) without listing on every insert', async () => {
    const clock = new Clock();
    const store = new CountingStore(new MemoryStore());
    const alice = await Agent.create('alice', 'ed25519', clock);
    const bob = await Agent.create('bob', 'ed25519', clock, store);
    await alice.pin(bob);
    await bob.pin(alice);
    const env = await rfq(alice, bob);
    const inbox = await bob.open();
    for (let n = 0; n <= 1000; n++) {
      // a fresh messageId under the old signature: invalid_signature, a new fingerprint
      const forged = { ...env, messageId: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}` };
      const out = await inbox.receive(forged, relaySrc(n + 1));
      expect(out.kind === 'quarantined' && out.error.code).toBe('invalid_signature');
    }
    expect((await store.inner.list('quarantine/')).length).toBe(900);
    expect(store.lists.filter((p) => p === 'quarantine/')).toHaveLength(1); // the first insert only
    await inbox.close();
  });

  it('a verified message rejected by the state machine is quarantined and stays one-shot', async () => {
    const { clock, alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    expect((await inbox.receive(env, relaySrc(1))).kind).toBe('delivered');
    const snap = (await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!;
    // alice (the buyer) forges a seller move with a machine in which bob is the buyer
    const machine = ThreadStateMachine.fromState([{
      conversationId: env.conversationId, threadId: 'deal-1', localAceId: alice.id, peerAceId: bob.id, state: 'rfq',
      history: [{ ...snap.history[0], from: bob.id }],
    }], { localAceId: alice.id });
    const offer = await createMessage({
      sender: alice.identity, recipient: await alice.peer(bob), type: 'offer', body: { price: '1', currency: 'USDC' },
      threads: machine, threadId: 'deal-1', timestamp: clock.t,
    });
    const out = await inbox.receive(offer, relaySrc(2));
    expect(out.kind).toBe('quarantined');
    if (out.kind !== 'quarantined') return;
    expect(out.error.code).toBe('wrong_role');
    expect(await bob.store.read(`quarantine/${out.fingerprint}.json`)).not.toBeNull();
    expect(inbox.cursor(SRC_RELAY)).toBe('2-0');
    expect((await inbox.receive(offer, relaySrc(3))).kind).toBe('duplicate');
    await inbox.close();
    const again = await bob.open();
    expect((await again.receive(offer, relaySrc(4))).kind).toBe('duplicate');
    expect((await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('rfq');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
  });

  it('a transient peer error is retryable and does not advance the cursor', async () => {
    const { clock, alice, bob } = await pair();
    const down = { lookupPeer: async () => { throw new ACEError('relay_unavailable', 'down'); } };
    const store = new MemoryStore();
    const inbox = await Inbox.open({
      identity: bob.identity, store, peers: new PeerStore({ store, relay: down as never, clock: clock.fn }),
      onMessage: bob.host.fn, clock: clock.fn,
    });
    const out = await inbox.receive(await rfq(alice, bob), relaySrc(5));
    expect(out.kind).toBe('retryable');
    if (out.kind === 'retryable') expect(out.error.code).toBe('relay_unavailable');
    expect(inbox.cursor(SRC_RELAY)).toBeNull();
    expect(await store.list('deliveries/')).toEqual([]);
  });

  it('handler failure, then redelivery hands over once', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    bob.host.fail = true;
    const out = await inbox.receive(env, relaySrc(1));
    expect(out.kind).toBe('retryable');
    if (out.kind === 'retryable') expect(out.error.code).toBe('handler_failed');
    expect(inbox.cursor(SRC_RELAY)).toBeNull();
    bob.host.fail = false;
    expect((await inbox.receive(env, relaySrc(1))).kind).toBe('delivered');
    expect(inbox.cursor(SRC_RELAY)).toBe('1-0');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
  });

  it('recovery hands over pending records; a failing handler makes open throw handler_failed', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    bob.host.fail = true;
    await inbox.receive(env, relaySrc(1));
    await inbox.close();
    await expectCode(bob.open(), 'handler_failed');
    bob.host.fail = false;
    const again = await bob.open();
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    expect(json(await bob.store.read(deliveryKey(alice.id, env.messageId))).status).toBe('acked');
    expect((await again.receive(env, relaySrc(1))).kind).toBe('duplicate');
  });

  it('recovery refuses a delivery record that diverges from the stored thread', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    await inbox.receive(env, relaySrc(1));
    await inbox.close();
    const tkey = threadKey(env.conversationId, 'deal-1');
    const rec = json(await bob.store.read(tkey));
    rec.history[0].messageId = crypto.randomUUID();
    await bob.store.write(tkey, new TextEncoder().encode(JSON.stringify(rec)));
    await expectCode(bob.open(), 'storage_failed');
  });

  it('a re-sent copy below the floor is stale once its delivery record is gone', async () => {
    const { clock, alice, bob } = await pair();
    const inbox = await bob.open({ offlineWindowSeconds: 1000 });
    const env = await rfq(alice, bob);
    expect((await inbox.receive(env, relaySrc(1))).kind).toBe('delivered');
    clock.t += 2000;
    const late = (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'later' } })).message;
    expect((await inbox.receive(late, relaySrc(2))).kind).toBe('delivered'); // floor raises H
    await inbox.close();
    const reopened = await bob.open({ offlineWindowSeconds: 1000 }); // recovery deletes covered acked records
    expect(await bob.store.list('deliveries/')).toEqual([deliveryKey(alice.id, late.messageId)]);
    const out = await reopened.receive(env, relaySrc(3));
    expect(out.kind).toBe('quarantined');
    if (out.kind === 'quarantined') expect(out.error.code).toBe('stale_timestamp');
    expect(bob.host.calls.length).toBe(2);
  });

  it('an inbound reply clears a pending send it proves delivered', async () => {
    const { alice, bob } = await pair();
    const aInbox = await alice.open();
    const bInbox = await bob.open();
    const sent = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r1' });
    expect((await bInbox.receive(sent.message, relaySrc(1))).kind).toBe('delivered');
    const offer = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '5', currency: 'USDC' }, threadId: 'd' });
    expect((await alice.outbox.pending()).map((p) => p.requestId)).toEqual(['r1']);
    expect((await aInbox.receive(offer.message, relaySrc(1))).kind).toBe('delivered');
    expect(await alice.outbox.pending()).toEqual([]);
    expect((await new ThreadStore({ store: alice.store, localAceId: alice.id }).get(sent.message.conversationId, 'd'))!.state).toBe('offered');
  });

  it('onMessage may stage a reply on the same thread (threads lock is not held during hand-over)', async () => {
    const { alice, bob } = await pair();
    const env = await rfq(alice, bob);
    const store = bob.store;
    const inbox = await Inbox.open({
      identity: bob.identity, store, peers: new PeerStore({ store, clock: bob.clock.fn }), clock: bob.clock.fn,
      onMessage: async (m) => {
        await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '1', currency: 'USDC' }, threadId: m.threadId!, requestId: `reply-${m.messageId}` });
      },
    });
    expect((await inbox.receive(env, relaySrc(1))).kind).toBe('delivered');
    expect((await new ThreadStore({ store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('offered');
    await inbox.close();
  });

  it('a failed quarantine write is retryable and does not advance the cursor', async () => {
    const { clock, bob } = await pair();
    const eve = await Agent.create('eve', 'ed25519', clock);
    await eve.pin(bob);
    const env = (await eve.outbox.stage({ recipient: await eve.peer(bob), type: 'text', body: { message: 'x' } })).message;
    await (await bob.open()).close();
    const inbox = await bob.open({ store: new CountingStore(bob.store, 1) });
    const out = await inbox.receive(env, relaySrc(1));
    expect(out.kind).toBe('retryable');
    expect(inbox.cursor(SRC_RELAY)).toBeNull();
    expect(await bob.store.list('quarantine/')).toEqual([]);
  });
});

// --- crash injection ---------------------------------------------------------------------

/** bob (buyer) has a pending rfq; alice's offer arrives. */
async function scenario(clock: Clock) {
  const alice = await Agent.create('alice', 'ed25519', clock);
  const bob = await Agent.create('bob', 'secp256k1', clock);
  await alice.pin(bob);
  await bob.pin(alice);
  const aInbox = await alice.open();
  const sent = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r1' });
  await aInbox.receive(sent.message, relaySrc(1));
  const offer = (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'offer', body: { price: '5', currency: 'USDC' }, threadId: 'd' })).message;
  await (await bob.open()).close(); // creates replay.json
  return { bob, offer };
}

const COMMIT_STEPS = [1, 2, 3, 4, 5]; // delivery, thread, replay, ack, cursor

describe('crash injection', () => {
  for (const backend of ['memory', 'file'] as const) {
    it.each(COMMIT_STEPS)(`${backend}: failing write %i of the commit`, async (failAt) => {
      const clock = new Clock();
      const { bob, offer } = await scenario(clock);
      let base;
      if (backend === 'file') {
        const dir = mkdtempSync(join(tmpdir(), 'ace-crash-'));
        temps.push(dir);
        base = await cloneStore(bob.store, new FileStore(join(dir, 'bob')));
      } else {
        base = await cloneStore(bob.store);
      }
      const conv = offer.conversationId;
      const failing = new CountingStore(base, failAt);
      const inbox = await bob.open({ store: failing });
      const out = await inbox.receive(offer, relaySrc(3));
      expect(out.kind).toBe('retryable');
      if (out.kind === 'retryable') expect(out.error.code).toBe('storage_failed');
      if (failAt > 1) {
        const later = await inbox.receive(offer, relaySrc(3));
        expect(later.kind).toBe('retryable');
        if (later.kind === 'retryable') expect(later.error.message).toContain('failed state');
      }
      await inbox.close(); // the process "dies"

      const threads = new ThreadStore({ store: base, localAceId: bob.id });
      if (failAt > 2) expect((await threads.get(conv, 'd'))!.state).toBe('offered'); // never rolled back

      const recovered = await bob.open({ store: base });
      if (failAt > 1) {
        const snap = (await threads.get(conv, 'd'))!;
        expect(snap.state).toBe('offered');
        expect(snap.history.map((h) => h.type)).toEqual(['rfq', 'offer']);
        expect((await threads.loadRecord(conv, 'd'))!.pending).toBeNull(); // delivery proven by the offer
      }
      const redelivered = await recovered.receive(offer, relaySrc(3)); // cursor was not advanced
      expect(redelivered.kind).toBe(failAt === 1 ? 'delivered' : 'duplicate');
      expect(recovered.cursor(SRC_RELAY)).toBe('3-0');
      expect((await threads.get(conv, 'd'))!.state).toBe('offered');
      expect([...bob.host.effects.keys()]).toEqual([`${offer.from}|${offer.messageId}`]); // nothing lost, no duplicate effect
      // onMessage runs twice only when the crash hit the ack write after the hand-over
      expect(bob.host.calls.length).toBe(failAt === 4 ? 2 : 1);
      const replay = ReplayDetector.fromState(json(await base.read('replay.json')), { capacity: 100000 });
      expect(replay.accepts(offer.messageId, offer.from, offer.timestamp)).toBe(false);
      await recovered.close();
      const third = await bob.open({ store: base });
      expect((await third.receive(offer, relaySrc(4))).kind).toBe('duplicate');
      expect(bob.host.calls.length).toBe(failAt === 4 ? 2 : 1);
      await third.close();
    });
  }
});

describe('crash between delivery and thread writes, then Outbox', () => {
  it('Outbox.open repairs the thread, a staged reply extends it, and Inbox.open recovers without divergence', async () => {
    const clock = new Clock();
    const alice = await Agent.create('alice', 'ed25519', clock);
    const bob = await Agent.create('bob', 'secp256k1', clock);
    await alice.pin(bob);
    await bob.pin(alice);
    const env = await rfq(alice, bob, 'd');
    await (await bob.open()).close();
    const failing = new CountingStore(bob.store, 2); // 1 = delivery record, 2 = thread record
    const inbox = await bob.open({ store: failing });
    expect((await inbox.receive(env, relaySrc(1))).kind).toBe('retryable');
    // while failed, the instance keeps holding `threads`
    await expectCode(bob.store.lock('threads', { timeoutMs: 50 }), 'storage_failed');
    await inbox.close(); // the process "dies"; `threads` is released
    const threads = new ThreadStore({ store: bob.store, localAceId: bob.id });
    expect(await threads.get(env.conversationId, 'd')).toBeNull(); // thread write was lost

    const outbox = await Outbox.open({ identity: bob.identity, store: bob.store, clock: clock.fn });
    expect((await threads.get(env.conversationId, 'd'))!.state).toBe('rfq'); // repaired from deliveries/
    expect(bob.host.calls).toEqual([]); // Outbox.open never hands over
    const offer = await outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '2', currency: 'USDC' }, threadId: 'd' });
    expect((await threads.get(env.conversationId, 'd'))!.history.map((h) => h.type)).toEqual(['rfq', 'offer']);

    const recovered = await bob.open(); // no divergence: the stored history extends the delivery snapshot
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    expect((await recovered.receive(env, relaySrc(1))).kind).toBe('duplicate');
    const snap = (await threads.get(env.conversationId, 'd'))!;
    expect(snap.state).toBe('offered');
    expect(snap.history.map((h) => h.messageId)).toEqual([env.messageId, offer.message.messageId]);
    await recovered.close();
  });
});
