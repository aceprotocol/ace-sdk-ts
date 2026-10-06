import { afterEach, expect, it, vi } from 'vitest';
import { SoftwareIdentity, createMessage, parseMessage, ReplayDetector, ThreadStateMachine } from '../src/index.js';
import type { ACEMessage } from '../src/index.js';

async function setup() {
  const [alice, bob] = await Promise.all([SoftwareIdentity.generate('ed25519'), SoftwareIdentity.generate('ed25519')]);
  const now = Math.floor(Date.now() / 1000);
  const create = (timestamp: number) => createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp });
  const parse = (msg: ACEMessage, replayDetector: ReplayDetector, oldestTimestamp?: number) =>
    parseMessage(msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector, oldestTimestamp });
  // A store that has been running since before the receiver went offline.
  const runningStore = (capacity?: number) => ReplayDetector.fromExport({ horizon: now - 7200, senderHorizons: {}, entries: [] }, capacity);
  return { bob, now, create, parse, runningStore };
}

afterEach(() => { vi.useRealTimers(); });

it('online: a max-future-drift message cannot be replayed after 5 minutes', async () => {
  vi.useFakeTimers({ now: Date.now() });
  const { now, create, parse } = await setup();
  const store = new ReplayDetector();
  const msg = await create(now + 300);
  await parse(msg, store);
  vi.advanceTimersByTime(450_000);
  await expect(parse(msg, store)).rejects.toThrow(/Replay/);
});

it('offline floor admits backlog once and rejects future/too-old messages', async () => {
  const { now, create, parse, runningStore } = await setup();
  const store = runningStore();
  const old = await create(now - 3600);
  await expect(parse(old, store)).rejects.toThrow(/Timestamp/);
  expect((await parse(old, store, now - 7200)).body).toEqual({ message: 'offline' });
  await expect(parse(old, store, now - 7200)).rejects.toThrow(/Replay/);
  for (const timestamp of [now + 3600, now - 7201]) {
    await expect(parse(await create(timestamp), store, now - 7200)).rejects.toThrow(/Timestamp/);
  }
});

it('a fresh store rejects backlog it cannot vouch for', async () => {
  const { now, create, parse } = await setup();
  await expect(parse(await create(now - 3600), new ReplayDetector(), now - 7200)).rejects.toThrow(/Replay/);
});

it('backlog evicted at capacity cannot be replayed', async () => {
  const { now, create, parse, runningStore } = await setup();
  const store = runningStore(1);
  const [a, b] = await Promise.all([create(now - 3600), create(now - 1800)]);
  await parse(a, store, now - 7200);
  await parse(b, store, now - 7200);
  await expect(parse(a, store, now - 7200)).rejects.toThrow(/Replay/);
});

it('a flood from one sender does not block others', async () => {
  const { bob, now, create, parse } = await setup();
  const mallory = await SoftwareIdentity.generate('ed25519');
  const store = new ReplayDetector(3);
  for (let i = 0; i < 4; i++) {
    const flood = await createMessage({ sender: mallory, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'flood' }, stateMachine: new ThreadStateMachine(), timestamp: now + 300 });
    await parseMessage(flood, bob, mallory.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: store });
  }
  expect((await parse(await create(now), store)).body).toEqual({ message: 'offline' });
});

it('backlog evicted by the online floor cannot be replayed', async () => {
  const { now, create, parse, runningStore } = await setup();
  const store = runningStore();
  const [backlog, fresh] = await Promise.all([create(now - 3600), create(now)]);
  await parse(backlog, store, now - 7200);
  await parse(fresh, store);
  expect(store.horizon).toBe(now - 3600);
  await expect(parse(backlog, store, now - 7200)).rejects.toThrow(/Replay/);
});
