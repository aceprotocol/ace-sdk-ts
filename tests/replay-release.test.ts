/**
 * Replay reservation rule.
 *
 * A failure BEFORE the signature verifies releases the reservation: an
 * unsigned envelope that reuses a victim's messageId with a malformed
 * kemCiphertext/payload/signature must not be able to make the genuine
 * message look like a replay later.
 *
 * Once the signature has verified, the reservation is kept on ANY later
 * failure (decrypt, body schema, state machine): an authentic message is
 * one-shot regardless of outcome.
 */
import { describe, it, expect } from 'vitest';
import {
  SoftwareIdentity, createMessage, parseMessage, ThreadStateMachine, ReplayDetector, type ACEMessage,
} from '../src/index.js';

async function pair() {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  const msg = await createMessage({
    sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
    type: 'text', body: { message: 'hi' }, stateMachine: new ThreadStateMachine(),
  });
  return { alice, bob, msg };
}

describe('replay reservation is released on pre-signature failures', () => {
  for (const field of ['kemCiphertext', 'payload'] as const) {
    it(`invalid Base64 in encryption.${field}`, async () => {
      const { alice, bob, msg } = await pair();
      const forged: ACEMessage = { ...msg, encryption: { ...msg.encryption, [field]: '!!!not-base64!!!' } };
      const detector = new ReplayDetector();
      await expect(
        parseMessage(forged, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector }),
      ).rejects.toThrow();
      const parsed = await parseMessage(msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector });
      expect(parsed.body).toEqual({ message: 'hi' });
    });
  }

  it('invalid signature encoding', async () => {
    const { alice, bob, msg } = await pair();
    const forged: ACEMessage = { ...msg, signature: { ...msg.signature, value: '!!!not-base64!!!' } };
    const detector = new ReplayDetector();
    await expect(
      parseMessage(forged, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector }),
    ).rejects.toThrow();
    const parsed = await parseMessage(msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector });
    expect(parsed.body).toEqual({ message: 'hi' });
  });
});

describe('replay reservation is kept once the signature has verified', () => {
  it('decryption failure after a valid signature consumes the messageId', async () => {
    const alice = await SoftwareIdentity.generate('ed25519');
    const bob = await SoftwareIdentity.generate('ed25519');
    const carol = await SoftwareIdentity.generate('ed25519');
    // Addressed to Bob, signed by Alice, but encrypted for Carol's key:
    // the signature verifies, AES-GCM decryption by Bob fails.
    const msg = await createMessage({
      sender: alice, recipientPubKey: carol.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
      type: 'text', body: { message: 'hi' }, stateMachine: new ThreadStateMachine(),
    });
    const detector = new ReplayDetector();
    const err = await parseMessage(
      msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector },
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    // It got past the signature check and failed at decryption.
    expect((err as Error).message).not.toMatch(/Signature verification failed/);
    // The authentic message is one-shot: its messageId stays reserved.
    expect(detector.checkAndReserve(msg.messageId)).toBe(false);
    // A second delivery of the same authentic envelope is rejected as a replay.
    await expect(
      parseMessage(msg, bob, alice.getSigningPublicKey(), { stateMachine: new ThreadStateMachine(), replayDetector: detector }),
    ).rejects.toThrow(/Replay detected/);
  });
});
