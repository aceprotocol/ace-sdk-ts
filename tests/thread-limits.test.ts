// Open-thread bound per peer (04 § Open-thread bound) and idle-thread retention.
import { describe, expect, it } from 'vitest';
import {
  MAX_OPEN_THREADS_PER_PEER, MemoryStore, ThreadStore, computeConversationId, type ACEStore, type ThreadSnapshot,
} from '../src/index.js';
import { sha256Hex } from '../src/encoding.js';
import { THREAD_RETENTION_SECONDS, threadIndexKey, threadKey } from '../src/thread-store.js';
import { expectCode } from './helpers.js';
import { Agent, Clock } from './pipeline.js';

const RELAY_SRC = { kind: 'relay', relayUrl: 'https://relay.example', streamId: '1-0' } as const;

function rfqSnapshot(local: string, peer: string, conversationId: string, threadId: string, ts: number, from = peer): ThreadSnapshot {
  return {
    conversationId, threadId, localAceId: local, peerAceId: peer, state: 'rfq',
    history: [{ type: 'rfq', messageId: crypto.randomUUID(), timestamp: ts, from }],
  };
}

/** `n` open threads (an rfq from `peer`) in the conversation. */
async function fill(store: ACEStore, local: string, peer: string, conversationId: string, n: number, ts: number): Promise<ThreadStore> {
  const threads = new ThreadStore({ store, localAceId: local, clock: () => ts });
  for (let i = 0; i < n; i++) await threads.saveRecord({ snapshot: rfqSnapshot(local, peer, conversationId, `fill-${i}`, ts), pending: null });
  return threads;
}

async function pair() {
  const clock = new Clock();
  const alice = await Agent.create('alice', 'ed25519', clock);
  const bob = await Agent.create('bob', 'secp256k1', clock);
  await alice.pin(bob);
  await bob.pin(alice);
  const conv = computeConversationId(alice.identity.getEncryptionPublicKey(), bob.identity.getEncryptionPublicKey());
  return { clock, alice, bob, conv };
}

describe('open-thread bound per peer', () => {
  it('index format: threads/index/<sha256(peer)>.json, sorted record keys without .json', async () => {
    const store = new MemoryStore();
    const { alice, bob, conv } = await pair();
    const threads = await fill(store, bob.id, alice.id, conv, 2, 1000);
    expect(threadIndexKey(alice.id)).toBe(`threads/index/${sha256Hex(alice.id)}.json`);
    const entries = ['fill-0', 'fill-1'].map((t) => threadKey(conv, t).slice(0, -5)).sort();
    expect(new TextDecoder().decode((await store.read(threadIndexKey(alice.id)))!)).toBe(JSON.stringify({ open: entries, version: 1 }));
    expect((await threads.listRecords()).length).toBe(2); // the index is not a thread record
    expect(await threads.openThreadCount(alice.id)).toBe(2);
    // a terminal thread leaves the index; removing the last open thread deletes it
    const done = (await threads.loadRecord(conv, 'fill-0'))!.snapshot;
    await threads.saveRecord({ snapshot: { ...done, state: 'rejected', history: [...done.history, { type: 'reject', messageId: crypto.randomUUID(), timestamp: 1001, from: bob.id }] }, pending: null });
    expect(await threads.openThreadCount(alice.id)).toBe(1);
    expect(await threads.remove(conv, 'fill-1')).toBe(true);
    expect(await store.read(threadIndexKey(alice.id))).toBeNull();
  });

  it('receive: a message opening thread 1001 is quarantined limit_exceeded; stage throws; existing threads unaffected', async () => {
    const { clock, alice, bob, conv } = await pair();
    const inbox = await bob.open(); // replay state first: the filled threads model earlier receipts
    const threads = await fill(bob.store, bob.id, alice.id, conv, MAX_OPEN_THREADS_PER_PEER, clock.t);
    const env = (await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'rfq', body: { need: 'x' }, threadId: 'one-more' })).message;
    const out = await inbox.receive(env, RELAY_SRC);
    expect(out.kind).toBe('quarantined');
    if (out.kind === 'quarantined') expect(out.error.code).toBe('limit_exceeded');
    expect(bob.host.calls).toEqual([]);
    expect(await threads.get(conv, 'one-more')).toBeNull();
    // sender side: pre-checked before any crypto
    await expectCode(bob.outbox.stage({ recipient: await bob.peer(alice), type: 'rfq', body: { need: 'y' }, threadId: 'mine' }), 'limit_exceeded');
    // an existing thread still advances (bob replies with an offer)
    const offer = await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'offer', body: { price: '1', currency: 'USDC' }, threadId: 'fill-7' });
    expect(offer.message.type).toBe('offer');
    // freeing a slot allows a new thread again
    await threads.remove(conv, 'fill-0');
    await bob.outbox.stage({ recipient: await bob.peer(alice), type: 'rfq', body: { need: 'y' }, threadId: 'mine' });
    expect(await threads.openThreadCount(alice.id)).toBe(MAX_OPEN_THREADS_PER_PEER);
    await inbox.close();
  });

  it('at the bound, stale index entries (crash leftovers) are reconciled', async () => {
    const store = new MemoryStore();
    const { alice, bob, conv } = await pair();
    const threads = await fill(store, bob.id, alice.id, conv, 3, 1000);
    const real = JSON.parse(new TextDecoder().decode((await store.read(threadIndexKey(alice.id)))!)).open as string[];
    const ghosts = Array.from({ length: MAX_OPEN_THREADS_PER_PEER }, (_, i) => `threads/${sha256Hex(`ghost-${i}`)}`);
    await store.write(threadIndexKey(alice.id), new TextEncoder().encode(JSON.stringify({ open: [...real, ...ghosts].sort(), version: 1 })));
    expect(await threads.openThreadCount(alice.id)).toBe(3);
    expect(JSON.parse(new TextDecoder().decode((await store.read(threadIndexKey(alice.id)))!)).open).toEqual(real);
    await store.write(threadIndexKey(alice.id), new TextEncoder().encode('{"open":[1],"version":1}'));
    await expectCode(threads.openThreadCount(alice.id), 'storage_failed');
  });
});

describe('retention', () => {
  it('prunes idle non-terminal threads without a local entry; keeps those with one', async () => {
    const store = new MemoryStore();
    const { alice, bob, conv } = await pair();
    const old = 10_000;
    const now = old + THREAD_RETENTION_SECONDS + 1;
    const seed = new ThreadStore({ store, localAceId: bob.id, clock: () => old });
    await seed.saveRecord({ snapshot: rfqSnapshot(bob.id, alice.id, conv, 'idle', old), pending: null });
    await seed.saveRecord({ snapshot: rfqSnapshot(bob.id, alice.id, conv, 'mine', old, bob.id), pending: null });
    await seed.saveRecord({ snapshot: rfqSnapshot(bob.id, alice.id, conv, 'recent', now - 10), pending: null });
    const later = new ThreadStore({ store, localAceId: bob.id, clock: () => now });
    await later.saveRecord({ snapshot: rfqSnapshot(bob.id, alice.id, conv, 'trigger', now), pending: null });
    expect((await later.list()).map((s) => s.threadId).sort()).toEqual(['mine', 'recent', 'trigger']);
    expect(await later.openThreadCount(alice.id)).toBe(3);
  });
});
