// Test helpers: identities and agents over the in-memory relay of src/testing.ts, and an Inbox over local stores.
import { vi } from 'vitest';
import {
  ACEError, AdmissionBook, Inbox, MemoryStore, NetworkClient, PeerStore, ProfileSet, SoftwareIdentity, StorePrekeyVault, checkPacketTime,
  createPacket, createPermit, decodePacket, decodePrivateContent, decryptPacket, prekeyPublicKey, toBase64, verifyKel, verifyPacketSignature,
  type InboxOptions, type KelState, type NetworkClientOptions, type ParsedMessage, type Prekey, type PrekeyVault, type PrivateContent,
  type ReceiptBody, type Signer,
} from './sdk.js';
import { FakeRelay } from '../src/testing.js';

export { FakeRelay, RELAY } from '../src/testing.js';
export const NOW = 1_760_140_800;

export class Clock {
  t = NOW;
  now = () => this.t;
  advance(s: number) { this.t += s; }
}

export async function identity(clock: Clock = new Clock()): Promise<SoftwareIdentity> {
  return SoftwareIdentity.generate({ now: clock.t });
}

/** Hold a permit `issuer` issues `holder` at `now`, under `holder`'s pin of the issuer (as if it arrived in a packet). */
export async function holdPermitFrom(holder: TestAgent, issuer: SoftwareIdentity, now: number): Promise<void> {
  const pin = await holder.client.peers.get(issuer.getACEId());
  if (pin === null) throw new Error('the issuer is not pinned');
  await holder.client.admission.holdPermit(await createPermit(issuer, holder.id.getACEId(), { now }), pin, holder.id.getACEId(), now);
}

export interface TestAgent {
  id: SoftwareIdentity;
  client: NetworkClient;
  store: MemoryStore;
  received: ParsedMessage[];
}

export async function agent(relay: FakeRelay, clock: Clock, o: Partial<NetworkClientOptions> = {}): Promise<TestAgent> {
  const id = await identity(clock);
  const store = new MemoryStore();
  const received: ParsedMessage[] = [];
  const client = await NetworkClient.open({
    identity: id, store, relay: relay.client(), clock: clock.now,
    onMessage: (m) => { received.push(m); }, foreignRelay: () => { throw new ACEError('blocked_address', 'no foreign relays in tests'); },
    ...o,
  });
  await client.publish(); // registers on demand
  return { id, client, store, received };
}

export function stateOf(id: SoftwareIdentity, now = NOW): KelState {
  return verifyKel(id.getKel(), now);
}

/** An admitted pair over one FakeRelay: alice open and auto-accepting text, bob connected to her. `both` configures both clients, `bob` bob alone. */
export async function pair(o: { both?: Partial<NetworkClientOptions>; bob?: Partial<NetworkClientOptions> } = {}) {
  const clock = new Clock(), relay = new FakeRelay(clock.now);
  const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'], ...o.both });
  const bob = await agent(relay, clock, { ...o.both, ...o.bob });
  await bob.client.connect(alice.id.getACEId(), { profile: 'ace:text:1' });
  await alice.client.pull();
  await bob.client.pull();
  return { clock, relay, alice, bob, a: alice.id.getACEId(), b: bob.id.getACEId() };
}


export const text = new ProfileSet(['text']);

/** 06 steps 1, 4, 5 and 6 for a pinned sender: decode, recipient, operational signature, time window, decrypt. */
export async function openPacket(value: unknown, o: { recipient: string; sender: Signer; vault: PrekeyVault; now: number }) {
  const packet = decodePacket(value);
  if (packet.to !== o.recipient) throw new ACEError('wrong_recipient', 'packet is not addressed to this identity');
  verifyPacketSignature(packet, o.sender, o.now);
  checkPacketTime(packet, o.now);
  return { packet, content: decodePrivateContent(await decryptPacket(packet, o.vault)) };
}
/** A peer prekey for private content: the Base64 X-Wing public key of a random seed (04 § Peer prekeys). */
export const somePrekey = (): string => toBase64(prekeyPublicKey(crypto.getRandomValues(new Uint8Array(32))));
const PEER_PREKEY = somePrekey();
/** `content` with a peer prekey, as the sending transport adds one to every packet (kept when it already has one). */
export const withPrekey = <T extends object>(content: T): T & { prekey: string } => ({ prekey: PEER_PREKEY, ...content });
export const msg = (message: string): PrivateContent => withPrekey({ type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message } });

export interface InboxWorld {
  clock: Clock;
  me: SoftwareIdentity;
  sender: SoftwareIdentity;
  store: MemoryStore;
  vault: StorePrekeyVault;
  prekey: Prekey;
  peers: PeerStore;
  admission: AdmissionBook;
  inbox: Inbox;
  receipts: Array<[string, ReceiptBody]>;
  delivered: ParsedMessage[];
  refreshPeer: ReturnType<typeof vi.fn>;
  options: InboxOptions;
  pack(from: SoftwareIdentity, content: PrivateContent, ts?: number, messageId?: string, prekey?: Prekey): ReturnType<typeof createPacket>;
}

/** An Inbox for `me` with `sender` pinned and admitted (unless `admit: false`). */
export async function inboxWorld(opts: Partial<InboxOptions> & { admit?: boolean; sender?: SoftwareIdentity; world?: Clock } = {}): Promise<InboxWorld> {
  const { admit, sender: given, world, ...o } = opts;
  const clock = world ?? new Clock();
  const me = await identity(clock), sender = given ?? await identity(clock);
  const store = new MemoryStore(), vault = new StorePrekeyVault(new MemoryStore(), { clock: clock.now });
  const pk = await vault.rotate(NOW);
  const prekey = { id: pk.id, publicKey: pk.publicKey };
  const peers = new PeerStore({ store, clock: clock.now }), admission = new AdmissionBook(store, { clock: clock.now });
  if (admit !== false) {
    await peers.adopt(sender.getKel());
    await admission.update(sender.getACEId(), () => ({ aceId: sender.getACEId(), status: 'admitted', updatedAt: NOW }));
  }
  const receipts: Array<[string, ReceiptBody]> = [];
  const delivered: ParsedMessage[] = [];
  const refreshPeer = vi.fn(async () => {});
  const options: InboxOptions = {
    identity: me, store, vault, profiles: text, peers, admission, clock: clock.now, refreshPeer,
    onMessage: (m) => { delivered.push(m); }, sendReceipt: async (to, b) => { receipts.push([to, b]); }, ...o,
  };
  const inbox = await Inbox.open(options);
  const pack = (from: SoftwareIdentity, content: PrivateContent, ts = clock.t, messageId?: string, pre: Prekey = prekey) =>
    createPacket({ identity: from, to: me.getACEId(), prekey: pre, content: withPrekey(content), timestamp: ts, ...(messageId ? { messageId } : {}) });
  return { clock, me, sender, store, vault, prekey, peers, admission, inbox, receipts, delivered, refreshPeer, options, pack };
}
