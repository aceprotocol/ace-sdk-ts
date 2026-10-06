import {
  SoftwareIdentity, createMessage, parseMessage, verifyRegistrationFile,
  ThreadStateMachine, ReplayDetector, MemoryStore, RelayClient, PeerStore, Outbox, Inbox,
  type ParsedMessage,
} from '../src/index.js';

// 1. Pure local: two in-process identities, no relay, no storage.
export async function local(): Promise<ParsedMessage> {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  // Peers are verified bindings; here from each other's registration files.
  const alicePeer = verifyRegistrationFile(alice.toRegistrationFile({ name: 'Alice', endpoint: 'https://alice.example/ace' }));
  const bobPeer = verifyRegistrationFile(bob.toRegistrationFile({ name: 'Bob', endpoint: 'https://bob.example/ace' }));

  const message = await createMessage({
    sender: alice, recipient: bobPeer, type: 'rfq', threadId: 'translation-1',
    body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
    threads: new ThreadStateMachine({ localAceId: alice.getACEId() }),
  });
  return parseMessage(message, bob, alicePeer, {
    threads: new ThreadStateMachine({ localAceId: bob.getACEId() }),
    replay: new ReplayDetector(),
  });
}

// 2. Over a relay: durable send (Outbox) and exactly-once receive (Inbox).
//    Use FileStore from '@ace-protocol/sdk/node' instead of MemoryStore to persist state.
export async function overRelay(relayUrl: string): Promise<ParsedMessage[]> {
  const relay = new RelayClient(relayUrl);
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  await relay.register(alice, { name: 'Alice', tags: ['buyer'] });
  await relay.register(bob, { name: 'Bob', tags: ['translation'] });

  // Alice resolves Bob through the relay (binding verified, pinned under the rollback barrier).
  const aliceStore = new MemoryStore();
  const alicePeers = new PeerStore({ store: aliceStore, relay });
  const outbox = await Outbox.open({ identity: alice, store: aliceStore });
  const pending = await outbox.stage({
    recipient: await alicePeers.resolve(bob.getACEId()), type: 'rfq', threadId: 'translation-1',
    body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  });
  await outbox.deliver(pending.requestId, (env) => relay.send(env));

  // Bob drains his relay inbox; onMessage must persist its effect idempotently.
  const received: ParsedMessage[] = [];
  const bobStore = new MemoryStore();
  const inbox = await Inbox.open({
    identity: bob, store: bobStore, peers: new PeerStore({ store: bobStore, relay }),
    onMessage: (m) => { received.push(m); },
  });
  try {
    const result = await inbox.pull(relay);
    if (result.blocked) throw result.blocked;
    // For live delivery: for await (const outcome of inbox.follow(relay, { signal })) { ... }
  } finally {
    await inbox.close();
  }
  return received;
}

export const parsed = await local();
console.log(parsed.body);
if (process.env.ACE_RELAY_URL) console.log((await overRelay(process.env.ACE_RELAY_URL)).map((m) => m.body));
