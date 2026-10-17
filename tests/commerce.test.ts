import { describe, expect, it, vi } from 'vitest';
import { MemoryStore, MessageLog, ThreadStore, commerceRules, NetworkClient, type RuleEvent, type ParsedMessage } from './sdk.js';
import { Clock, FakeRelay, NOW, identity } from './helpers.js';

const buyer = `ace:sha256:${'b'.repeat(64)}`, seller = `ace:sha256:${'5'.repeat(64)}`;
const ev = (type: string, from: string, messageId: string, threadId: string | null = 't1'): RuleEvent =>
  ({ direction: from === seller ? 'send' : 'receive', from, to: from === buyer ? seller : buyer, messageId, timestamp: NOW, type: `ace:commerce:${type}:1`, ...(threadId ? { threadId } : {}) });
const id = () => crypto.randomUUID();

describe('commerceRules', () => {
  it('runs rfq → offer → accept → invoice → payment → deliver → confirm with references and roles', async () => {
    const threads = new ThreadStore(new MemoryStore(), seller);
    const rules = commerceRules(threads);
    const step = async (type: string, from: string, body: Record<string, unknown>, mid = id()) => {
      await rules.check(ev(type, from, mid), body as never);
      await rules.commit(ev(type, from, mid), body as never);
      return mid;
    };
    await expect(rules.check(ev('rfq', buyer, id(), null), { need: 'x' })).rejects.toMatchObject({ code: 'invalid_body' });
    await step('rfq', buyer, { need: 'translate' });
    expect((await threads.get(buyer, 't1'))!.state).toBe('requested');
    await expect(rules.check(ev('accept', buyer, id()), { offerId: id() })).rejects.toMatchObject({ code: 'transition_not_allowed' });
    await expect(rules.check(ev('offer', buyer, id()), { price: '1', currency: 'USDC' })).rejects.toMatchObject({ code: 'wrong_role' });
    const offer = await step('offer', seller, { price: '10', currency: 'USDC' });
    await expect(rules.check(ev('accept', buyer, id()), { offerId: id() })).rejects.toMatchObject({ code: 'bad_reference' });
    await step('accept', buyer, { offerId: offer });
    const badInvoice = { offerId: offer, amount: '10', currency: 'USDC', settlement: { method: 'stablecoin', asset: 'eip155:8453/erc20:0xabc' } };
    await expect(rules.check(ev('invoice', seller, id()), badInvoice)).rejects.toMatchObject({ code: 'invalid_body' });
    await expect(rules.check(ev('invoice', seller, id()), { ...badInvoice, settlement: { method: 'stripe-link', url: 'https://buy.stripe.com/x', recipient: 'r' } })).rejects.toMatchObject({ code: 'invalid_body' });
    const invoice = await step('invoice', seller, { ...badInvoice, settlement: { ...badInvoice.settlement, recipient: '0xseller', memo: 'order-1' } });
    await expect(rules.check(ev('payment', buyer, id()), { referenceId: invoice, amount: '10', currency: 'USDC', settlement: { method: 'stablecoin', proof: { paymentId: 'p' } } })).rejects.toMatchObject({ code: 'invalid_body' });
    await step('payment', buyer, { referenceId: invoice, amount: '10', currency: 'USDC', settlement: { method: 'stablecoin', proof: { txHash: '0x1' } } });
    await expect(rules.check(ev('deliver', seller, id()), { type: 'inline' })).rejects.toMatchObject({ code: 'invalid_body' });
    const deliver = await step('deliver', seller, { type: 'inline', content: 'bonjour' });
    await step('confirm', buyer, { deliverId: deliver });
    const t = (await threads.get(buyer, 't1'))!;
    expect(t.state).toBe('confirmed');
    expect(t.history.map((h) => h.type.split(':')[2])).toEqual(['rfq', 'offer', 'accept', 'invoice', 'payment', 'deliver', 'confirm']);
    await expect(rules.check(ev('offer', seller, id()), { price: '1', currency: 'USDC' })).rejects.toMatchObject({ code: 'transition_not_allowed' });
    expect(await threads.openCount(buyer)).toBe(0);
  });

  it('end to end over a relay: the receiver rejects an out-of-order commerce message', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const make = async (o: object) => {
      const client = await NetworkClient.open({ identity: await identity(clock), store: new MemoryStore(), relayUrl: relay.baseUrl, profiles: ['commerce'], fetch: relay.fetch, clock: clock.now, ...o });
      return { client, threads: client.threads, messages: client.messages };
    };
    const s = await make({ visibility: 'public', acceptProfiles: ['ace:commerce:1'] });
    const b = await make({});
    for (const c of [s, b]) { await c.client.publish(); }
    const S = s.client.identity.getACEId();
    await b.client.connect(S, { profile: 'ace:commerce:1' });
    await s.client.pull();
    await b.client.pull();
    await b.client.send(S, 'ace:commerce:rfq:1', { need: 'logo' }, { threadId: 'job-1' });
    expect((await s.client.pull())[0].kind).toBe('delivered');
    expect((await s.threads!.get(b.client.identity.getACEId(), 'job-1'))!.state).toBe('requested');
    expect((await s.messages!.list()).map((m: ParsedMessage) => m.type)).toEqual(['ace:commerce:rfq:1']);
    // the buyer's state moves only with the seller's delivered receipt; until then the thread is busy
    expect(await b.threads!.get(S, 'job-1')).toBeNull();
    await expect(b.client.send(S, 'ace:commerce:rfq:1', { need: 'again' }, { threadId: 'job-1' })).rejects.toMatchObject({ code: 'thread_busy' });
    expect((await b.client.pull())[0].kind).toBe('receipt');
    expect((await b.threads!.get(S, 'job-1'))!.state).toBe('requested');
    // the buyer's own outbound rules refuse sending an offer
    await expect(b.client.send(S, 'ace:commerce:offer:1', { price: '1', currency: 'USDC' }, { threadId: 'job-1' })).rejects.toMatchObject({ code: 'wrong_role' });
  });
});

describe('commerce sender state', () => {
  it('glare: crossing messages on one thread are both rejected thread_busy and neither side changes state', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const make = async (o: object) => {
      const client = await NetworkClient.open({ identity: await identity(clock), store: new MemoryStore(), relayUrl: relay.baseUrl, profiles: ['commerce'], fetch: relay.fetch, clock: clock.now, ...o });
      return { client, threads: client.threads, messages: client.messages };
    };
    const s = await make({ visibility: 'public', acceptProfiles: ['ace:commerce:1'] });
    const b = await make({});
    for (const c of [s, b]) { await c.client.publish(); }
    const S = s.client.identity.getACEId(), B = b.client.identity.getACEId();
    await b.client.connect(S, { profile: 'ace:commerce:1' });
    await s.client.pull();
    await b.client.pull();
    await b.client.send(S, 'ace:commerce:rfq:1', { need: 'logo' }, { threadId: 'j' });
    await s.client.pull();
    await b.client.pull();
    const offer1 = await s.client.send(B, 'ace:commerce:offer:1', { price: '5', currency: 'USDC' }, { threadId: 'j' });
    await b.client.pull();
    await s.client.pull();
    expect((await s.threads!.get(B, 'j'))!.state).toBe('offered');
    // crossing: the buyer accepts offer1 while the seller counter-offers
    const accept = await b.client.send(S, 'ace:commerce:accept:1', { offerId: offer1.messageId }, { threadId: 'j' });
    const offer2 = await s.client.send(B, 'ace:commerce:offer:1', { price: '4', currency: 'USDC' }, { threadId: 'j' });
    expect((await s.client.pull())[0]).toMatchObject({ kind: 'rejected', error: { code: 'thread_busy' } });
    const got = await b.client.pull();
    expect(got.map((o) => o.kind)).toEqual(['rejected', 'receipt']);
    await s.client.pull();
    expect(await b.client.outbox.get(accept.messageId)).toMatchObject({ status: 'rejected', code: 'thread_busy' });
    expect(await s.client.outbox.get(offer2.messageId)).toMatchObject({ status: 'rejected', code: 'thread_busy' });
    for (const [t, peer] of [[s.threads!, B], [b.threads!, S]] as const) {
      const snap = (await t.get(peer, 'j'))!;
      expect([snap.state, snap.history.at(-1)!.messageId]).toEqual(['offered', offer1.messageId]);
    }
    // both threads are free again
    await b.client.send(S, 'ace:commerce:accept:1', { offerId: offer1.messageId }, { threadId: 'j' });
    await s.client.pull();
    await b.client.pull();
    expect((await b.threads!.get(S, 'j'))!.state).toBe('accepted');
    expect((await s.threads!.get(B, 'j'))!.state).toBe('accepted');
  });
});

describe('MessageLog', () => {
  it('saves idempotently, caps unread, filters and acks', async () => {
    const log = new MessageLog(new MemoryStore(), { maxUnread: 2, clock: () => NOW });
    const m = (n: number, type = 'ace:text:1'): ParsedMessage => ({ messageId: crypto.randomUUID(), from: buyer, to: seller, timestamp: NOW + n, conversation: 'c', type, schemaDigest: 'd', threadId: null, body: { message: String(n) } });
    const a = m(1), b = m(2, 'x:y:1'), c = m(3);
    expect(await log.save(a)).toBe('saved');
    expect(await log.save(a)).toBe('duplicate');
    await log.save(b);
    await expect(log.checkCapacity(c)).rejects.toMatchObject({ code: 'receiver_capacity' });
    await log.checkCapacity(a);
    expect((await log.list({ type: 'x:y:1' })).map((x) => x.messageId)).toEqual([b.messageId]);
    expect(await log.ack([{ from: buyer, messageId: a.messageId }])).toBe(1);
    await log.checkCapacity(c);
    expect((await log.list()).map((x) => x.messageId)).toEqual([b.messageId]);
    expect((await log.list({ unreadOnly: false })).length).toBe(2);
  });

  it('counts, lists and expires through its index without reading every message', async () => {
    let t = NOW;
    const store = new MemoryStore();
    const log = new MessageLog(store, { maxUnread: 100, retentionSeconds: 100, clock: () => t });
    const m = (n: number): ParsedMessage => ({ messageId: crypto.randomUUID(), from: buyer, to: seller, timestamp: NOW, conversation: 'c', type: 'ace:text:1', schemaDigest: 'd', threadId: null, body: { message: String(n) } });
    const all = [];
    for (let i = 0; i < 30; i++) { const x = m(i); all.push(x); await log.save(x); t++; }
    await log.ack(all.slice(0, 20).map((x) => ({ from: x.from, messageId: x.messageId })));
    const reads = vi.spyOn(store, 'read');
    expect(await log.unreadCount()).toBe(10);
    expect(reads).not.toHaveBeenCalled();
    expect((await log.list({ limit: 3 })).map((x) => x.body.message)).toEqual(['20', '21', '22']);
    expect(reads).toHaveBeenCalledTimes(3);
    expect((await log.list({ unreadOnly: false, limit: 2 })).map((x) => x.body.message)).toEqual(['0', '1']);
    t += 100; // the read ones expire; unread ones never do
    expect((await log.list({ unreadOnly: false, limit: 100 })).map((x) => x.body.message)).toEqual(all.slice(20).map((x) => x.body.message));
    expect((await store.list('messages/')).length).toBe(10);
  });
});
