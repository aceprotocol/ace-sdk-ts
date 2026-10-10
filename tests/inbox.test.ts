// Inbox: commit order, recovery, crash injection, quarantine rules.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ACEError, Inbox, MemoryStore, Outbox, PeerStore, ReplayDetector, ThreadStateMachine, ThreadStore, createMessage,
  envelopeFingerprint, type ACEMessage, type ACEStore,
} from '../src/index.js';
import { FileStore } from '../src/node.js';
import { pairKey, stringifySorted } from '../src/encoding.js';
import { ThreadRecords, threadIndexKey, threadKey } from '../src/thread-store.js';
import { expectCode, wire } from './helpers.js';
import { Agent, Clock, CountingStore, cloneStore, json } from './pipeline.js';

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
    await inbox.receive(wire(await rfq(alice, bob, 'deal-2')));
    await inbox.close();
    await bob.store.delete('replay.json');
    await expectCode(bob.open(), 'storage_failed');
    await bob.store.write('replay.json', new TextEncoder().encode('{"version":2}'));
    await expectCode(bob.open(), 'storage_failed');
  });

  it('delivered: commit order and persisted formats; duplicates write nothing', async () => {
    const { alice, bob } = await pair();
    const env = await rfq(alice, bob);
    const counting = new CountingStore(bob.store);
    const inbox = await bob.open({ store: counting });
    expect(counting.writes).toEqual(['replay.json']);
    counting.writes = [];
    const out = await inbox.receive(wire(env));
    expect(out.kind).toBe('delivered');
    if (out.kind === 'delivered') expect(out.message.body).toEqual({ need: 'translate' });
    const dkey = deliveryKey(alice.id, env.messageId);
    const tkey = threadKey(env.conversationId, 'deal-1');
    // a new open thread is indexed before its record is written
    // the delivery record journals the seen-store commit; replay.json follows at close (or every 1024)
    expect(counting.writes).toEqual([dkey, threadIndexKey(alice.id), tkey, dkey]);
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    const rec = json(await bob.store.read(dkey));
    expect(Object.keys(rec).sort()).toEqual(['fingerprint', 'message', 'receivedAt', 'status', 'thread', 'version']);
    expect(rec.status).toBe('acked');
    expect(rec.fingerprint).toBe(envelopeFingerprint(env));
    expect(Object.keys(rec.message).sort()).toEqual(['body', 'conversationId', 'from', 'messageId', 'schemaDigest', 'threadId', 'timestamp', 'to', 'type']);
    expect(rec.thread.state).toBe('rfq');
    const raw = new TextDecoder().decode((await bob.store.read(tkey))!);
    const thread = JSON.parse(raw);
    expect(thread.pending).toBeNull();
    expect(thread.peerAceId).toBe(alice.id);
    expect(raw).toBe(stringifySorted(thread)); // sorted keys, compact
    counting.writes = [];
    expect((await inbox.receive(wire(env))).kind).toBe('duplicate');
    expect(counting.writes).toEqual([]);
    expect((await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('rfq');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    await inbox.close();
    expect(counting.writes).toEqual(['replay.json']);
  });

  it('delivery records journal the seen store between writes of replay.json', async () => {
    const { clock, alice, bob } = await pair();
    // quota 1: the second message evicts the first and raises H[alice] over it, in memory only
    const send = async (message: string) => (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message } })).message;
    const first = await send('one');
    clock.t += 1;
    const second = await send('two');
    const inbox = await bob.open({ capacity: 16 });
    expect((await inbox.receive(wire(first))).kind).toBe('delivered');
    expect((await inbox.receive(wire(second))).kind).toBe('delivered');
    expect(await bob.store.list('deliveries/')).toHaveLength(2);
    const crashed = await cloneStore(bob.store); // the process dies: replay.json was never rewritten
    await inbox.close();
    const replayOf = async (store: ACEStore) => ReplayDetector.fromState(json(await store.read('replay.json')), { capacity: 16 });
    expect((await replayOf(crashed)).accepts(first.messageId, first.from, first.timestamp)).toBe(true);
    const reopened = await bob.open({ store: crashed, capacity: 16 });
    expect((await reopened.receive(wire(first))).kind).toBe('duplicate');
    expect((await reopened.receive(wire(second))).kind).toBe('duplicate');
    expect(bob.host.calls).toHaveLength(2);
    await reopened.close();
    // written: the first message's covered record is pruned, the second kept
    expect((await replayOf(crashed)).accepts(first.messageId, first.from, first.timestamp)).toBe(false);
    expect(await crashed.list('deliveries/')).toHaveLength(1);
  });

  it('non-economic: no thread snapshot; no freshness window beyond the replay floor (that is the MLS handshake\'s job)', async () => {
    const { clock, alice, bob } = await pair();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'hi' } });
    const inbox = await bob.open();
    const out = await inbox.receive(wire(p.message));
    expect(out.kind).toBe('delivered');
    if (out.kind === 'delivered') expect(out.message.threadId).toBeNull();
    const rec = json(await bob.store.read(deliveryKey(alice.id, p.message.messageId)));
    expect(rec.thread).toBeNull();
    expect(Object.keys(rec).sort()).toEqual(['fingerprint', 'message', 'receivedAt', 'status', 'thread', 'version']);
    clock.t += 301;
    const p2 = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'late' } });
    clock.t += 301;
    expect((await inbox.receive(wire(p2.message))).kind).toBe('delivered');
    expect(bob.host.calls).toEqual([[alice.id, p.message.messageId], [alice.id, p2.message.messageId]]);
  });

  it('decode failure and unknown peer are quarantined', async () => {
    const { clock, bob } = await pair();
    const inbox = await bob.open();
    const out = await inbox.receive(wire({ ace: '2.0' }));
    expect(out).toMatchObject({ kind: 'quarantined', fingerprint: null });
    if (out.kind === 'quarantined') expect(out.error.code).toBe('invalid_envelope');
    expect(await bob.store.list('quarantine/')).toEqual([]);
    const eve = await Agent.create('eve', 'ed25519', clock);
    await eve.pin(bob);
    const env = (await eve.outbox.stage({ recipient: await eve.peer(bob), type: 'text', body: { message: 'x' } })).message;
    const q = await inbox.receive(wire(env));
    expect(q.kind).toBe('quarantined');
    if (q.kind !== 'quarantined') return;
    expect(q.error.code).toBe('unknown_peer');
    const rec = json(await bob.store.read(`quarantine/${q.fingerprint}.json`));
    expect(rec.code).toBe('unknown_peer');
    expect(rec.envelope).toEqual(env);
    expect(Object.keys(rec).sort()).toEqual(['code', 'envelope', 'fingerprint', 'quarantinedAt', 'reason', 'version']);
    expect((await inbox.receive(wire(env))).kind).toBe('quarantined'); // persisted again under the same fingerprint
    expect((await bob.store.list('quarantine/')).length).toBe(1);
  });

  it('quarantine is capped at 1000 (trimmed to 900) without listing on every insert', async () => {
    // 999 older records are seeded directly (no crypto), so the test is fast and deterministic
    const clock = new Clock();
    const store = new CountingStore(new MemoryStore());
    const alice = await Agent.create('alice', 'ed25519', clock);
    const bob = await Agent.create('bob', 'ed25519', clock, store);
    await alice.pin(bob);
    await bob.pin(alice);
    const env = await rfq(alice, bob);
    for (let n = 0; n < 999; n++) {
      const fp = n.toString(16).padStart(64, '0');
      await store.inner.write(`quarantine/${fp}.json`, wire({
        code: 'invalid_signature', envelope: env, fingerprint: fp, quarantinedAt: clock.t - 1000 + n, reason: 'seeded', version: 1,
      }));
    }
    const inbox = await bob.open();
    const fresh: string[] = [];
    for (let n = 0; n < 2; n++) {
      // a fresh messageId under the old signature: invalid_signature, a new fingerprint
      const forged = { ...env, messageId: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}` };
      const out = await inbox.receive(wire(forged));
      expect(out.kind === 'quarantined' && out.error.code).toBe('invalid_signature');
      if (out.kind === 'quarantined') fresh.push(`quarantine/${out.fingerprint}.json`);
    }
    const left = await store.inner.list('quarantine/');
    expect(left.length).toBe(900);
    for (const k of fresh) expect(left).toContain(k); // the oldest were trimmed
    expect(store.lists.filter((p) => p === 'quarantine/')).toHaveLength(1); // the first insert only
    await inbox.close();
  });

  it('a verified message rejected by the state machine is quarantined and stays one-shot', async () => {
    const { clock, alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    expect((await inbox.receive(wire(env))).kind).toBe('delivered');
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
    const out = await inbox.receive(wire(offer));
    expect(out.kind).toBe('quarantined');
    if (out.kind !== 'quarantined') return;
    expect(out.error.code).toBe('wrong_role');
    expect(await bob.store.read(`quarantine/${out.fingerprint}.json`)).not.toBeNull();
    expect((await inbox.receive(wire(offer))).kind).toBe('duplicate');
    await inbox.close();
    const again = await bob.open();
    expect((await again.receive(wire(offer))).kind).toBe('duplicate');
    expect((await new ThreadStore({ store: bob.store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('rfq');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
  });

  it('a transient peer error is retryable and leaves no record', async () => {
    const { clock, alice, bob } = await pair();
    const down = { lookupPeer: async () => { throw new ACEError('relay_unavailable', 'down'); } };
    const store = new MemoryStore();
    const inbox = await Inbox.open({ commerce: true,
      identity: bob.identity, store, peers: new PeerStore({ store, relay: down as never, clock: clock.fn }),
      onMessage: bob.host.fn, clock: clock.fn,
    });
    const out = await inbox.receive(wire(await rfq(alice, bob)));
    expect(out.kind).toBe('retryable');
    if (out.kind === 'retryable') expect(out.error.code).toBe('relay_unavailable');
    expect(await store.list('deliveries/')).toEqual([]);
  });

  it('handler failure, then redelivery hands over once', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    bob.host.fail = true;
    const out = await inbox.receive(wire(env));
    expect(out.kind).toBe('retryable');
    if (out.kind === 'retryable') expect(out.error.code).toBe('handler_failed');
    bob.host.fail = false;
    expect((await inbox.receive(wire(env))).kind).toBe('delivered');
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
  });

  it('recovery hands over pending records; a failing handler makes open throw handler_failed', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    bob.host.fail = true;
    await inbox.receive(wire(env));
    await inbox.close();
    await expectCode(bob.open(), 'handler_failed');
    bob.host.fail = false;
    const again = await bob.open();
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    expect(json(await bob.store.read(deliveryKey(alice.id, env.messageId))).status).toBe('acked');
    expect((await again.receive(wire(env))).kind).toBe('duplicate');
  });

  it('recovery refuses a delivery record that diverges from the stored thread', async () => {
    const { alice, bob } = await pair();
    const inbox = await bob.open();
    const env = await rfq(alice, bob);
    await inbox.receive(wire(env));
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
    expect((await inbox.receive(wire(env))).kind).toBe('delivered');
    clock.t += 2000;
    const late = (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'later' } })).message;
    expect((await inbox.receive(wire(late))).kind).toBe('delivered'); // floor raises H
    await inbox.close();
    const reopened = await bob.open({ offlineWindowSeconds: 1000 }); // recovery deletes covered acked records
    expect(await bob.store.list('deliveries/')).toEqual([deliveryKey(alice.id, late.messageId)]);
    const out = await reopened.receive(wire(env));
    expect(out.kind).toBe('quarantined');
    if (out.kind === 'quarantined') expect(out.error.code).toBe('stale_timestamp');
    expect(bob.host.calls.length).toBe(2);
  });

  it('an inbound reply clears a pending send it proves delivered', async () => {
    const { alice, bob } = await pair();
    const aInbox = await alice.open();
    const bInbox = await bob.open();
    const sent = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'd', requestId: 'r1' });
    expect((await bInbox.receive(wire(sent.message))).kind).toBe('delivered');
    const offer = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '5', currency: 'USDC' }, threadId: 'd' });
    expect((await alice.outbox.pending()).map((p) => p.requestId)).toEqual(['r1']);
    expect((await aInbox.receive(wire(offer.message))).kind).toBe('delivered');
    expect(await alice.outbox.pending()).toEqual([]);
    expect((await new ThreadStore({ store: alice.store, localAceId: alice.id }).get(sent.message.conversationId, 'd'))!.state).toBe('offered');
  });

  it('onMessage may stage a reply on the same thread (threads lock is not held during hand-over)', async () => {
    const { alice, bob } = await pair();
    const env = await rfq(alice, bob);
    const store = bob.store;
    const inbox = await Inbox.open({ commerce: true,
      identity: bob.identity, store, peers: new PeerStore({ store, clock: bob.clock.fn }), clock: bob.clock.fn,
      onMessage: async (m) => {
        await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '1', currency: 'USDC' }, threadId: m.threadId!, requestId: `reply-${m.messageId}` });
      },
    });
    expect((await inbox.receive(wire(env))).kind).toBe('delivered');
    expect((await new ThreadStore({ store, localAceId: bob.id }).get(env.conversationId, 'deal-1'))!.state).toBe('offered');
    await inbox.close();
  });

  it('a failed quarantine write is retryable', async () => {
    const { clock, bob } = await pair();
    const eve = await Agent.create('eve', 'ed25519', clock);
    await eve.pin(bob);
    const env = (await eve.outbox.stage({ recipient: await eve.peer(bob), type: 'text', body: { message: 'x' } })).message;
    await (await bob.open()).close();
    const inbox = await bob.open({ store: new CountingStore(bob.store, 1) });
    const out = await inbox.receive(wire(env));
    expect(out.kind).toBe('retryable');
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
  await aInbox.receive(wire(sent.message));
  const offer = (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'offer', body: { price: '5', currency: 'USDC' }, threadId: 'd' })).message;
  await (await bob.open()).close(); // creates replay.json
  return { bob, offer };
}

const COMMIT_STEPS = [1, 2, 3, 4]; // delivery, operation archive, thread, ack (replay.json follows at close)

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
      const out = await inbox.receive(wire(offer));
      expect(out.kind).toBe('retryable');
      if (out.kind === 'retryable') expect(out.error.code).toBe('storage_failed');
      if (failAt > 1) {
        const later = await inbox.receive(wire(offer));
        expect(later.kind).toBe('retryable');
        if (later.kind === 'retryable') expect(later.error.message).toContain('failed state');
      }
      await inbox.close(); // the process "dies"

      const threads = new ThreadStore({ store: base, localAceId: bob.id });
      if (failAt > 3) expect((await threads.get(conv, 'd'))!.state).toBe('offered'); // never rolled back

      const recovered = await bob.open({ store: base });
      if (failAt > 1) {
        const snap = (await threads.get(conv, 'd'))!;
        expect(snap.state).toBe('offered');
        expect(snap.history.map((h) => h.type)).toEqual(['rfq', 'offer']);
        expect((await new ThreadRecords({ store: base, localAceId: bob.id }).loadRecord(conv, 'd'))!.pending).toBeNull(); // delivery proven by the offer
      }
      const redelivered = await recovered.receive(wire(offer));
      expect(redelivered.kind).toBe(failAt === 1 ? 'delivered' : 'duplicate');
      expect((await threads.get(conv, 'd'))!.state).toBe('offered');
      expect([...bob.host.effects.keys()]).toEqual([`${offer.from}|${offer.messageId}`]); // nothing lost, no duplicate effect
      // onMessage runs twice only when the crash hit the ack write after the hand-over
      expect(bob.host.calls.length).toBe(failAt === 4 ? 2 : 1);
      await recovered.close();
      const replay = ReplayDetector.fromState(json(await base.read('replay.json')), { capacity: 100000 });
      expect(replay.accepts(offer.messageId, offer.from, offer.timestamp)).toBe(false);
      const third = await bob.open({ store: base });
      expect((await third.receive(wire(offer))).kind).toBe('duplicate');
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
    expect((await inbox.receive(wire(env))).kind).toBe('retryable');
    // while failed, the instance keeps holding `threads`
    await expectCode(bob.store.lock('threads', { timeoutMs: 50 }), 'lock_busy');
    await inbox.close(); // the process "dies"; `threads` is released
    const threads = new ThreadStore({ store: bob.store, localAceId: bob.id });
    expect(await threads.get(env.conversationId, 'd')).toBeNull(); // thread write was lost

    const outbox = await Outbox.open({ commerce: true, identity: bob.identity, store: bob.store, clock: clock.fn });
    expect((await threads.get(env.conversationId, 'd'))!.state).toBe('rfq'); // repaired from deliveries/
    expect(bob.host.calls).toEqual([]); // Outbox.open never hands over
    const offer = await outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '2', currency: 'USDC' }, threadId: 'd' });
    expect((await threads.get(env.conversationId, 'd'))!.history.map((h) => h.type)).toEqual(['rfq', 'offer']);

    const recovered = await bob.open(); // no divergence: the stored history extends the delivery snapshot
    expect(bob.host.calls).toEqual([[alice.id, env.messageId]]);
    expect((await recovered.receive(wire(env))).kind).toBe('duplicate');
    const snap = (await threads.get(env.conversationId, 'd'))!;
    expect(snap.state).toBe('offered');
    expect(snap.history.map((h) => h.messageId)).toEqual([env.messageId, offer.message.messageId]);
    await recovered.close();
  });
});

describe('raw bytes and recovery rules', () => {
  it('receive takes bytes: oversize or non-JSON is quarantined (no record without an envelope); misuse throws', async () => {
    const { bob } = await pair();
    const inbox = await bob.open();
    for (const raw of [new TextEncoder().encode('not json'), new Uint8Array([0x22, 0xff, 0x22]), new Uint8Array(131073).fill(0x20)]) {
      const out = await inbox.receive(raw);
      expect(out).toMatchObject({ kind: 'quarantined', fingerprint: null });
      if (out.kind === 'quarantined') expect(out.error.code).toBe('invalid_envelope');
    }
    expect(await bob.store.list('quarantine/')).toEqual([]);
    await expectCode(inbox.receive({ ace: '2.0' } as never), 'invalid_argument');
    await inbox.close();
    await expectCode(inbox.receive(wire({})), 'invalid_argument');
  });

  it('Inbox.open pre-validates capacity', async () => {
    const { bob } = await pair();
    for (const capacity of [0, -1, 1.5, '10' as never]) await expectCode(bob.open({ capacity } as never), 'invalid_argument');
    expect(await bob.store.list('')).not.toContain('locks/receive.lock');
    await (await bob.open()).close(); // the receive lock was never taken
  });

  it('the quarantine reason is the raw error message (no "code: " prefix)', async () => {
    const { clock, bob } = await pair();
    const inbox = await bob.open();
    const eve = await Agent.create('eve', 'ed25519', clock);
    await eve.pin(bob);
    const env = (await eve.outbox.stage({ recipient: await eve.peer(bob), type: 'text', body: { message: 'x' } })).message;
    const q = await inbox.receive(wire(env));
    if (q.kind !== 'quarantined') throw new Error('expected quarantine');
    const rec = json(await bob.store.read(`quarantine/${q.fingerprint}.json`));
    expect(rec.code).toBe('unknown_peer');
    expect(rec.reason).not.toMatch(/^unknown_peer: /);
    expect(`unknown_peer: ${rec.reason}`).toBe(q.error.message);
    await inbox.close();
  });

  it('only delivered outcomes count towards the deliveries sweep', async () => {
    const { bob } = await pair();
    const store = new CountingStore(bob.store);
    const inbox = await bob.open({ store });
    const before = store.lists.filter((p) => p === 'deliveries/').length;
    for (let i = 0; i < 1100; i++) await inbox.receive(new TextEncoder().encode('x'));
    expect(store.lists.filter((p) => p === 'deliveries/').length).toBe(before);
    await inbox.close();
  });

  it('recovery skips acked records covered by the replay horizon (pruned threads stay pruned)', async () => {
    const { alice, bob } = await pair();
    const env = await rfq(alice, bob, 'p');
    const inbox = await bob.open();
    expect((await inbox.receive(wire(env))).kind).toBe('delivered');
    await inbox.close();
    const dkey = deliveryKey(alice.id, env.messageId);
    expect(json(await bob.store.read(dkey)).status).toBe('acked');
    const threads = new ThreadStore({ store: bob.store, localAceId: bob.id });
    expect(await threads.remove(env.conversationId, 'p')).toBe(true); // as if pruned
    // the horizon moves past the message (e.g. the offline window elapsed)
    await bob.store.write('replay.json', wire({ entries: [], horizon: env.timestamp, senderHorizons: {}, version: 1 }));
    await Outbox.open({ commerce: true, identity: bob.identity, store: bob.store, clock: bob.clock.fn });
    expect(await threads.get(env.conversationId, 'p')).toBeNull();
    const again = await bob.open();
    expect(await threads.get(env.conversationId, 'p')).toBeNull();
    expect(await bob.store.read(dkey)).toBeNull();
    expect(bob.host.calls).toHaveLength(1);
    await again.close();
  });
});
