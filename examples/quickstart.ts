import {
  SoftwareIdentity, createMessage, createRegistrationFile, parseMessage, verifyRegistrationFile,
  ThreadStateMachine, ReplayDetector, MemoryStore, RelayClient, PeerStore, Outbox, Inbox,
  type ParsedMessage,
} from '../src/index.js';

// 1. Low-level application codec only; never send this inner envelope directly over a network.
export async function local(): Promise<ParsedMessage> {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  // Peers are verified bindings; here from each other's registration files
  // (createRegistrationFile works for any ACEIdentity, hardware-backed ones included).
  const alicePeer = verifyRegistrationFile(await createRegistrationFile(alice, { name: 'Alice', endpoint: 'https://alice.example/ace' }));
  const bobPeer = verifyRegistrationFile(await createRegistrationFile(bob, { name: 'Bob', endpoint: 'https://bob.example/ace' }));

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

// 2. Authenticated network delivery. Both locally created demo peers are explicitly
// admitted; production must verify identities through a trusted pairing flow.
// MemoryStore/onMessage below illustrate the API, not crash-durable host storage.
export async function overRelay(relayUrl: string): Promise<ParsedMessage[]> {
  const { loadMLSEngine } = await import('@ace-protocol/sdk/node');
  const { SecureTransport } = await import('../src/secure-transport.js');
  const { openSecureMailbox, deliverSecure } = await import('../src/secure-mailbox.js');
  const relay = new RelayClient(relayUrl);
  const alice = await SoftwareIdentity.generate('ed25519'), bob = await SoftwareIdentity.generate('ed25519');
  await relay.register(alice, { name: 'Alice' }); await relay.register(bob, { name: 'Bob' });
  const aliceStore = new MemoryStore(), bobStore = new MemoryStore();
  const alicePeers = new PeerStore({ store: aliceStore, relay }), bobPeers = new PeerStore({ store: bobStore, relay });
  await SecureTransport.setPeerAllowed(aliceStore, bob.getACEId(), true);
  await SecureTransport.setPeerAllowed(bobStore, alice.getACEId(), true);
  const engine = await loadMLSEngine();
  const received: ParsedMessage[] = [];
  // Bob's receive side in one call: Inbox + SecureTransport + SecureMailbox; its close() frees the engine.
  const mailbox = await openSecureMailbox({ identity: bob, store: bobStore, peers: bobPeers, relay, engine,
    inbox: { commerce: true, onMessage: message => { received.push(message); } } });
  const stop = new AbortController();
  const listening = (async () => {
    for await (const outcome of mailbox.follow(relay, { signal: stop.signal })) {
      if (outcome.kind === 'quarantined' || outcome.kind === 'retryable') throw outcome.error;
    }
  })();
  const sender = new SecureTransport(alice, engine, aliceStore);
  try {
    const peer = await alicePeers.resolve(bob.getACEId());
    const outbox = await Outbox.open({ identity: alice, store: aliceStore, commerce: true });
    const pending = await outbox.stage({ recipient: peer, type: 'rfq', threadId: 'translation-1',
      body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' } });
    // Success means Bob durably accepted the application message, not just relay storage.
    // On failure, retain this requestId and retry it; never create a new financial operation.
    await deliverSecure(outbox, pending.requestId, { identity: alice, secure: sender, relay, peer });
    return received;
  } finally {
    stop.abort();
    // Close every user of the engine before the mailbox frees it.
    try { await listening; } finally { try { await sender.close(); } finally { await mailbox.close(); } }
  }
}

export const parsed = await local();
console.log(parsed.body);
if (process.env.ACE_RELAY_URL) console.log((await overRelay(process.env.ACE_RELAY_URL)).map((m) => m.body));
