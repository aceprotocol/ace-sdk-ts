// Extra helpers for the pipeline, outbox and admission tests (helpers.ts stays untouched).
import { vi } from 'vitest';
import {
  ACEError, AdmissionBook, Inbox, prekeyPublicKey, toBase64, StorePrekeyVault, MemoryStore, PeerStore, ProfileSet, checkPacketTime, createPacket, decodePacket, decodePrivateContent, decryptPacket,
  verifyPacketSignature, type KelState, type PrekeyVault, type InboxOptions, type ParsedMessage, type Prekey, type PrivateContent, type ReceiptBody, type SoftwareIdentity,
} from './sdk.js';
import { Clock, NOW, identity } from './helpers.js';

export const text = new ProfileSet(['text']);

/** 06 steps 1, 4, 5 and 6 for a pinned sender: decode, recipient, operational signature, time window, decrypt. */
export async function openPacket(value: unknown, o: { recipient: string; sender: KelState; vault: PrekeyVault; now: number }) {
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
