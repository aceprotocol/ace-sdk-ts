import { expect, it, vi } from 'vitest';
import { SoftwareIdentity, createMessage, parseMessage, ReplayDetector, ThreadStateMachine } from '../src/index.js';
import type { ACEMessage } from '../src/index.js';

async function setup() {
  const [alice, bob] = await Promise.all([SoftwareIdentity.generate('ed25519'), SoftwareIdentity.generate('ed25519')]);
  const now = Math.floor(Date.now() / 1000);
  const create = (timestamp: number) => createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp });
  const parse = (msg: ACEMessage, opts: Parameters<typeof parseMessage>[3]) => parseMessage(msg, bob, alice.getSigningPublicKey(), opts);
  return { alice, now, create, parse };
}

it('offline policy admits backlog, requires replay protection and rejects future/too-old messages', async () => {
  const { alice, now, create, parse } = await setup();
  const opts = { stateMachine: new ThreadStateMachine(), senderEncryptionPubKey: alice.getEncryptionPublicKey(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector(100_000, 7500) };
  const old = await create(now - 3600);
  await expect(parse(old, { ...opts, oldestTimestamp: undefined })).rejects.toThrow(/Timestamp/);
  await expect(parse(old, { ...opts, replayDetector: undefined })).rejects.toThrow(/ReplayDetector/);
  expect((await parse(old, opts)).body).toEqual({ message: 'offline' });
  await expect(parse(old, opts)).rejects.toThrow(/Replay/);
  for (const timestamp of [now + 3600, now - 7201]) {
    await expect(parse(await create(timestamp), opts)).rejects.toThrow(/Timestamp/);
  }
});

it('offline policy rejects a ReplayDetector whose TTL does not cover the window', async () => {
  const { now, create, parse } = await setup();
  const msg = await create(now - 3600);
  await expect(parse(msg, { stateMachine: new ThreadStateMachine(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector() })).rejects.toThrow(/ttlSeconds/);
});

it('offline backlog cannot be replayed once the default 300 s TTL would have elapsed', async () => {
  vi.useFakeTimers({ now: Date.now() });
  try {
    const { now, create, parse } = await setup();
    const elapsedSeconds = 600;
    // TTL covers the acceptance window as it stands after the clock advances.
    const opts = { stateMachine: new ThreadStateMachine(), oldestTimestamp: now - 3600, replayDetector: new ReplayDetector(100_000, 3600 + elapsedSeconds + 300) };
    const msg = await create(now - 1800);
    await parse(msg, opts);
    vi.advanceTimersByTime(elapsedSeconds * 1000);
    await expect(parse(msg, opts)).rejects.toThrow(/Replay/);
  } finally {
    vi.useRealTimers();
  }
});

it('offline policy fails closed instead of evicting when the ReplayDetector is full', async () => {
  const { now, create, parse } = await setup();
  const opts = { stateMachine: new ThreadStateMachine(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector(1, 7500) };
  const [first, second] = await Promise.all([create(now - 60), create(now - 60)]);
  await parse(first, opts);
  await expect(parse(second, opts)).rejects.toThrow(/capacity/);
  await expect(parse(first, opts)).rejects.toThrow(/Replay/);
});
