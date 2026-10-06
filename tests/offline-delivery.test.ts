import { expect, it } from 'vitest';
import { SoftwareIdentity, createMessage, parseMessage, ReplayDetector, ThreadStateMachine } from '../src/index.js';
it('offline policy admits backlog, requires replay protection and rejects future/too-old messages', async () => {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const create = (timestamp: number) => createMessage({ sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(), type: 'text', body: { message: 'offline' }, stateMachine: new ThreadStateMachine(), timestamp });
  const opts = { stateMachine: new ThreadStateMachine(), senderEncryptionPubKey: alice.getEncryptionPublicKey(), oldestTimestamp: now - 7200, replayDetector: new ReplayDetector() };
  const old = await create(now - 3600);
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), { ...opts, oldestTimestamp: undefined })).rejects.toThrow(/Timestamp/);
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), { ...opts, replayDetector: undefined })).rejects.toThrow(/ReplayDetector/);
  expect((await parseMessage(old, bob, alice.getSigningPublicKey(), opts)).body).toEqual({ message: 'offline' });
  await expect(parseMessage(old, bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Replay/);
  for (const timestamp of [now + 3600, now - 7201]) {
    await expect(parseMessage(await create(timestamp), bob, alice.getSigningPublicKey(), opts)).rejects.toThrow(/Timestamp/);
  }
});
