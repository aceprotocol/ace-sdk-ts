import { expect, it, vi } from 'vitest';
import { SoftwareIdentity, createMessage, parseMessage, ReplayDetector, ThreadStateMachine } from '../src/index.js';
it('offline policy admits backlog, requires replay protection and rejects future/too-old messages', async () => {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const create = (timestamp: number) => createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp });
  const opts = { stateMachine: new ThreadStateMachine(), senderEncryptionPubKey: alice.getEncryptionPublicKey(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector(100_000, 7500) };
  const old = await create(now - 3600);
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), { ...opts, oldestTimestamp: undefined })).rejects.toThrow(/Timestamp/);
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), { ...opts, replayDetector: undefined })).rejects.toThrow(/ReplayDetector/);
  expect((await parseMessage(old, bob, alice.getSigningPublicKey(), opts)).body).toEqual({ message: 'offline' });
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Replay/);
  for (const timestamp of [now + 3600, now - 7201]) {
    await expect(parseMessage(await create(timestamp), bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Timestamp/);
  }
});

it('offline policy rejects a ReplayDetector whose TTL does not cover the window', async () => {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const msg = await createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp: now - 3600 });
  await expect(parseMessage(msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector() })).rejects.toThrow(/ttlSeconds/);
});

it('offline backlog cannot be replayed after the default TTL elapses', async () => {
  vi.useFakeTimers({ now: Date.now() });
  try {
    const alice = await SoftwareIdentity.generate('ed25519');
    const bob = await SoftwareIdentity.generate('ed25519');
    const now = Math.floor(Date.now() / 1000);
    const oldestTimestamp = now - 3600;
    const replayDetector = new ReplayDetector(100_000, 3600 + 300);
    const msg = await createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp: now - 1800 });
    const opts = { stateMachine: new ThreadStateMachine(), oldestTimestamp, replayDetector };
    await parseMessage(msg, bob, alice.getSigningPublicKey(), opts);
    vi.advanceTimersByTime(600_000); // past the 300 s default TTL
    await expect(parseMessage(msg, bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Replay|ttlSeconds/);
  } finally {
    vi.useRealTimers();
  }
});

it('offline policy fails closed instead of evicting when the ReplayDetector is full', async () => {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const replayDetector = new ReplayDetector(1, 7500);
  const create = () => createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp: now - 60 });
  const opts = { stateMachine: new ThreadStateMachine(), oldestTimestamp: now - 7200, replayDetector };
  const first = await create();
  await parseMessage(first, bob, alice.getSigningPublicKey(), opts);
  await expect(parseMessage(await create(), bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/capacity/);
  await expect(parseMessage(first, bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Replay/);
});
