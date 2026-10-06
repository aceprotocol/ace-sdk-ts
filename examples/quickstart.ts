import {
  SoftwareIdentity, createMessage, parseMessage,
  ThreadStateMachine, ReplayDetector,
} from '../src/index.js';

const alice = await SoftwareIdentity.generate('ed25519');
const bob = await SoftwareIdentity.generate('ed25519');
const message = await createMessage({
  sender: alice,
  recipientPubKey: bob.getEncryptionPublicKey(),
  recipientACEId: bob.getACEId(),
  type: 'rfq',
  body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  threadId: 'translation-1',
  stateMachine: new ThreadStateMachine(),
});

// The keys are trusted here because both identities were created locally.
export const parsed = await parseMessage(message, bob, alice.getSigningPublicKey(), {
  senderEncryptionPubKey: alice.getEncryptionPublicKey(),
  expectedScheme: alice.getSigningScheme(),
  stateMachine: new ThreadStateMachine(),
  replayDetector: new ReplayDetector(),
});
console.log(parsed.body);
