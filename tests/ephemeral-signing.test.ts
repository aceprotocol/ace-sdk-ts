import { describe, it, expect } from 'vitest';
import {
  SoftwareIdentity, createMessage, parseMessage,
  ThreadStateMachine, ReplayDetector, toBase64,
} from '../src/index.js';
import { x25519 } from '@noble/curves/ed25519.js';

// The ephemeral public key is part of the signed commitment (#6): swapping it must
// break signature verification, not merely fail decryption later.
describe('ephemeral public key is signed', () => {
  it('tampering the ephemeral key fails signature verification', async () => {
    const sender = await SoftwareIdentity.generate('ed25519');
    const receiver = await SoftwareIdentity.generate('ed25519');

    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'text',
      body: { message: 'hi' },
      stateMachine: new ThreadStateMachine(),
    });

    // Swap in a different valid ephemeral X25519 key, as a malicious relay might.
    msg.encryption.ephemeralPubKey = toBase64(x25519.getPublicKey(x25519.utils.randomSecretKey()));

    await expect(
      parseMessage(msg, receiver, sender.getSigningPublicKey(), {
        stateMachine: new ThreadStateMachine(),
        replayDetector: new ReplayDetector(),
      }),
    ).rejects.toThrow(/Signature verification failed/);
  });
});
