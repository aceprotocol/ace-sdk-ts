import { describe, expect, it, vi } from 'vitest';
import {
  ACEError, AdmissionBook, Inbox, StorePrekeyVault, MemoryStore, PeerStore, ProfileSet, createPacket, receiptContent,
  type InboxOptions, type ParsedMessage, type PrivateContent, type ReceiptBody, type SoftwareIdentity,
} from './sdk.js';
import { Clock, FakeRelay, NOW, identity } from './helpers.js';

const text = new ProfileSet(['text']);
const commerce = new ProfileSet(['commerce']);
const msg = (message: string): PrivateContent => ({ type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message } });

async function setup(o: Partial<InboxOptions> & { admit?: boolean } = {}) {
  const clock = new Clock();
  const me = await identity(clock), sender = await identity(clock);
  const store = new MemoryStore(), vault = new StorePrekeyVault(new MemoryStore(), { clock: clock.now });
  const pk = await vault.rotate(NOW);
  const prekey = { id: pk.id, publicKey: pk.publicKey };
  const peers = new PeerStore({ store, clock: clock.now }), admission = new AdmissionBook(store);
  if (o.admit !== false) {
    await peers.adopt(sender.getKel());
    await admission.update(sender.getACEId(), () => ({ aceId: sender.getACEId(), status: 'admitted', updatedAt: NOW }));
  }
  const receipts: Array<[string, ReceiptBody]> = [];
  const delivered: ParsedMessage[] = [];
  const refreshPeer = vi.fn(async () => {});
  const inbox = await Inbox.open({
    identity: me, store, vault, profiles: text, peers, admission, clock: clock.now, refreshPeer,
    onMessage: (m) => { delivered.push(m); }, sendReceipt: async (to, b) => { receipts.push([to, b]); }, ...o,
  });
  const pack = (from: SoftwareIdentity, content: PrivateContent, ts = clock.t, messageId?: string) =>
    createPacket({ identity: from, to: me.getACEId(), prekey, content, timestamp: ts, ...(messageId ? { messageId } : {}) });
  return { clock, me, sender, store, inbox, receipts, delivered, refreshPeer, pack, peers };
}

describe('Inbox', () => {
  it('delivers once, answers duplicates delivered', async () => {
    const t = await setup();
    const p = await t.pack(t.sender, msg('hi'));
    expect((await t.inbox.receive(p)).kind).toBe('delivered');
    expect((await t.inbox.receive(p)).kind).toBe('duplicate');
    expect(t.delivered).toHaveLength(1);
    expect(t.receipts.map(([, b]) => b.outcome)).toEqual(['delivered', 'delivered']);
  });

  it('admission before lookup: a stranger to a private identity is dropped without lookup or pin', async () => {
    const t = await setup({ admit: false });
    const out = await t.inbox.receive(await t.pack(t.sender, msg('hello')));
    expect(out).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(t.refreshPeer).not.toHaveBeenCalled();
    expect(await t.peers.get(t.sender.getACEId())).toBeNull();
    expect(t.receipts).toEqual([]);
  });

  it('a stranger to a public identity may only send a contact request', async () => {
    const t = await setup({ admit: false, visibility: () => 'public' });
    const out = await t.inbox.receive(await t.pack(t.sender, msg('hello')));
    expect(out).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(t.refreshPeer).not.toHaveBeenCalled();
  });

  it('an uninstalled (type, schemaDigest) is rejected:unsupported_schema', async () => {
    const t = await setup();
    const rfq: PrivateContent = { type: 'ace:commerce:rfq:1', schemaDigest: commerce.digestOf('ace:commerce:rfq:1')!, threadId: 't', body: { need: 'x' } };
    expect(await t.inbox.receive(await t.pack(t.sender, rfq))).toMatchObject({ kind: 'rejected', error: { code: 'unsupported_schema' } });
    expect(await t.inbox.receive(await t.pack(t.sender, { ...msg('x'), body: { message: 5 } }))).toMatchObject({ kind: 'rejected', error: { code: 'invalid_body' } });
    expect(t.receipts.map(([, b]) => b.code)).toEqual(['unsupported_schema', 'invalid_body']);
    expect(t.delivered).toEqual([]);
  });

  it('beyond the replay horizon is dropped (replay_horizon) without a receipt, never delivered', async () => {
    const t = await setup({ capacity: 16 }); // sender quota 1
    expect((await t.inbox.receive(await t.pack(t.sender, msg('1'), NOW))).kind).toBe('delivered');
    expect((await t.inbox.receive(await t.pack(t.sender, msg('2'), NOW + 1))).kind).toBe('delivered'); // evicts #1, raises H[sender]
    const late = await t.inbox.receive(await t.pack(t.sender, msg('3'), NOW));
    expect(late).toMatchObject({ kind: 'dropped', error: { code: 'replay_horizon' } });
    expect(t.receipts.map(([, r]) => r.outcome)).toEqual(['delivered', 'delivered']);
  });

  it('signature, timestamp and decryption failures are silent drops', async () => {
    const t = await setup();
    const other = await identity(t.clock);
    const p = await t.pack(t.sender, msg('x'));
    expect((await t.inbox.receive({ ...p, signature: (await t.pack(other, msg('x'))).signature })).kind).toBe('dropped');
    expect((await t.inbox.receive(await t.pack(t.sender, msg('x'), NOW - 604_801))).kind).toBe('dropped');
    expect((await t.inbox.receive({ not: 'a packet' })).kind).toBe('dropped');
    expect(t.receipts).toEqual([]);
  });

  it('receipts are handed to onReceipt and never answered', async () => {
    const onReceipt = vi.fn();
    const t = await setup({ onReceipt });
    const out = await t.inbox.receive(await t.pack(t.sender, receiptContent({ messageId: crypto.randomUUID(), outcome: 'delivered' })));
    expect(out.kind).toBe('receipt');
    expect(onReceipt).toHaveBeenCalledOnce();
    expect(t.receipts).toEqual([]);
  });

  it('capacity holds without acknowledging; a poison packet is quarantined after three failed attempts', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    let fail: 'capacity' | 'crash' | null = 'capacity';
    const t = await setup({
      checkCapacity: () => { if (fail === 'capacity') throw new ACEError('receiver_capacity', 'full'); },
      onMessage: () => { if (fail === 'crash') throw new Error('boom'); },
    });
    const rc = relay.client();
    await rc.register(t.me);
    await rc.register(t.sender);
    // deliver straight into the fake queue (the inbox under test owns the admission decision)
    relay.queues.set(t.me.getACEId(), [{ streamId: '1-0', packet: await t.pack(t.sender, msg('p')), raw: '' }]);
    expect((await t.inbox.pull(rc))[0]).toMatchObject({ kind: 'deferred', error: { code: 'receiver_capacity' } });
    expect(relay.pending(t.me.getACEId())).toBe(1);
    fail = 'crash';
    for (let i = 0; i < 2; i++) expect((await t.inbox.pull(rc))[0].kind).toBe('deferred');
    expect(relay.pending(t.me.getACEId())).toBe(1);
    expect((await t.inbox.pull(rc))[0].kind).toBe('dropped');
    expect(relay.pending(t.me.getACEId())).toBe(0);
    const keys = await t.store.list('inbox/quarantine/');
    expect(keys).toHaveLength(1);
    // metadata only, never the ciphertext: a record is a few hundred bytes
    const rec = JSON.parse(new TextDecoder().decode((await t.store.read(keys[0]))!));
    expect(Object.keys(rec).sort()).toEqual(['code', 'fingerprint', 'packet', 'quarantinedAt', 'reason']);
    expect(Object.keys(rec.packet).sort()).toEqual(['ace', 'from', 'messageId', 'prekey', 'timestamp', 'to']);
    expect(rec.packet.from).toBe(t.sender.getACEId());
    expect(JSON.stringify(rec).length).toBeLessThan(1024);
  });

  it('the quarantine is bounded: past 1000 records the oldest are pruned down to 900', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const t = await setup({ onMessage: () => { throw new Error('boom'); } });
    for (let i = 0; i < 1000; i++) {
      await t.store.write(`inbox/quarantine/${i.toString(16).padStart(64, '0')}.json`, new TextEncoder().encode(`{"quarantinedAt":${i}}`));
    }
    const rc = relay.client();
    await rc.register(t.me);
    relay.queues.set(t.me.getACEId(), [{ streamId: '1-0', packet: await t.pack(t.sender, msg('p')), raw: '' }]);
    for (let i = 0; i < 3; i++) await t.inbox.pull(rc);
    const keys = await t.store.list('inbox/quarantine/');
    expect(keys).toHaveLength(900);
    expect(keys).not.toContain(`inbox/quarantine/${'0'.repeat(64)}.json`);
  });

  it('recovers a pending hand-over after a crash', async () => {
    let crash = true;
    const seen: string[] = [];
    const t = await setup({ onMessage: (m) => { if (crash) throw new Error('crash'); seen.push(m.messageId); } });
    const p = await t.pack(t.sender, msg('x'));
    expect((await t.inbox.receive(p)).kind).toBe('deferred');
    crash = false;
    expect((await t.inbox.receive(p)).kind).toBe('duplicate');
    expect(seen).toEqual([p.messageId]);
  });
});
