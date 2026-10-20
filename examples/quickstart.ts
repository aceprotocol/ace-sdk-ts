import { MemoryStore, NetworkClient, SoftwareIdentity, type ParsedMessage } from '@ace-protocol/sdk';

// Two agents on one relay. Alice is open to contact requests and auto-accepts text contacts; Bob is closed and connects to her.
// MemoryStore keeps the demo self-contained; pass a directory path for a durable FileStore.
export async function demo(relayUrl: string): Promise<ParsedMessage[]> {
  const received: ParsedMessage[] = [];
  const alice = await NetworkClient.open({
    identity: await SoftwareIdentity.generate(), store: new MemoryStore(), relayUrl,
    profiles: ['text'], contact: 'open', listed: true, acceptProfiles: ['ace:text:1'],
    onMessage: (m) => { received.push(m); },
  });
  const bob = await NetworkClient.open({ identity: await SoftwareIdentity.generate(), store: new MemoryStore(), relayUrl, profiles: ['text'] });
  try {
    for (const client of [alice, bob]) await client.publish(); // registers at the relay on demand
    const aliceId = alice.identity.getACEId();

    await bob.connect(aliceId, { profile: 'ace:text:1', note: 'hi, I am Bob' }); // contact request (encrypted note)
    await alice.pull();                                                       // auto-accepted by acceptProfiles
    await bob.pull();                                                         // Bob receives the accepted reply

    const entry = await bob.send(aliceId, 'ace:text:1', { message: 'Hello Alice' });
    await alice.pull();                                                       // delivered + receipt sent
    await bob.pull();                                                         // receipt: the Outbox entry is delivered
    console.log((await bob.outbox.get(entry.messageId))?.status);
    return received;
  } finally {
    await alice.close();
    await bob.close();
  }
}

if (process.env.ACE_RELAY_URL) console.log((await demo(process.env.ACE_RELAY_URL)).map((m) => m.body));
