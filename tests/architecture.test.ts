// Regression tests for the mechanism-level fixes: one caching predicate, atomic pin + cache, one permit slot, one
// step-10 commit path, and KEL verification resumed from a verified prefix.
import { describe, expect, it, vi } from 'vitest';
import { ACEError, AdmissionBook, Inbox, MemoryStore, createPermit, verifyKel, type KelEvent, type ProfileRules } from './sdk.js';
import { Clock, FakeRelay, NOW, agent, identity } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';

describe('04 § Caching: one usability predicate', () => {
  it('a cached descriptor whose subject delegation passed notAfter is stale (01 rule 5: never send to an unusable identity)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock, { contact: 'open', listed: true });
    const B = bob.id.getACEId();
    clock.advance(10);
    await bob.id.delegate({ now: clock.t, notAfter: clock.t + 3600 });
    
    await bob.client.publish({ force: true });
    await alice.client.importAgent(await bob.client.publish());
    clock.advance(3601); // the descriptor is unexpired, the subject's signing key is not
    const sent = relay.sent.length;
    await expect(alice.client.agent(B)).rejects.toBeInstanceOf(ACEError);
    expect(relay.sent.length).toBe(sent);
  });
});

describe('05 § Flow step 3: accept a held request', () => {
  it('after its source descriptor expired, accept pins the source and refreshes it with the requester permit', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock); // private
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    const first = await bob.client.publish();
    clock.t = first.descriptor.expiresAt - 3601; // publish still reuses it (more than an hour left)
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    expect((await alice.client.requests())[0].source.descriptor.expiresAt).toBe(first.descriptor.expiresAt);
    clock.advance(7200); // the held request (24 h) outlived its source descriptor
    await bob.client.publish();
    await alice.client.accept(B);
    await bob.client.pull();
    expect((await bob.client.admission.get(A))!.status).toBe('admitted');
  });
});

describe('one permit slot per issuer', () => {
  it('keeps the newest permit by issuedAt, whatever path wrote it', async () => {
    const clock = new Clock();
    const issuer = await identity(clock), me = await identity(clock);
    const book = new AdmissionBook(new MemoryStore());
    const older = await createPermit(issuer, me.getACEId(), { now: NOW });
    const newer = await createPermit(issuer, me.getACEId(), { now: NOW + 10, ttl: 60 }); // expires earlier, issued later
    await book.holdPermit(newer);
    await book.holdPermit(older);
    expect((await book.heldPermit(issuer.getACEId()))!.id).toBe(newer.id);
  });

  it('a newer held permit that no longer verifies does not shadow a valid one (keep)', async () => {
    const clock = new Clock();
    const issuer = await identity(clock), me = await identity(clock);
    const book = new AdmissionBook(new MemoryStore());
    const stale = await createPermit(issuer, me.getACEId(), { now: NOW + 300 });
    const valid = await createPermit(issuer, me.getACEId(), { now: NOW });
    await book.holdPermit(stale);
    await book.holdPermit(valid, { keep: (held) => held.id !== stale.id }); // the caller found `stale` invalid
    expect((await book.heldPermit(issuer.getACEId()))!.id).toBe(valid.id);
  });

  it('a conditional hold checks the issuer record under the admission lock', async () => {
    const clock = new Clock();
    const issuer = await identity(clock), me = await identity(clock);
    const book = new AdmissionBook(new MemoryStore());
    await book.holdPermit(await createPermit(issuer, me.getACEId(), { now: NOW }), { when: (r) => r?.status === 'admitted' });
    expect(await book.heldPermit(issuer.getACEId())).toBeNull();
  });
});

describe('06 step 10: the journal entry is the commit point on every path', () => {
  it('a permanent commit failure aborts the step-10 transaction: rejected, nothing handed over or seen', async () => {
    let fail = true;
    const commit = vi.fn(() => { if (fail) throw new ACEError('wrong_role', 'no'); });
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check: () => {}, commit }];
    const w = await inboxWorld({ rules });
    const p = await w.pack(w.sender, msg('x'));
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'rejected', error: { code: 'wrong_role' } });
    expect(w.delivered).toEqual([]);
    expect(w.receipts.at(-1)![1]).toMatchObject({ outcome: 'rejected', code: 'wrong_role' });
    expect(await w.store.list('inbox/journal/')).toEqual([]);
    fail = false; // not seen: a later copy is processed anew
    expect((await w.inbox.receive(p)).kind).toBe('delivered');
  });

  it('an entry that keeps failing never blocks opening the Inbox', async () => {
    const onMessage = vi.fn(() => { throw new ACEError('invalid_argument', 'host refuses'); });
    const w = await inboxWorld({ onMessage });
    expect((await w.inbox.receive(await w.pack(w.sender, msg('x')))).kind).toBe('deferred');
    expect(await w.store.list('inbox/journal/')).toHaveLength(1);
    await w.inbox.close();
    const reopened = await Inbox.open(w.options);
    expect(onMessage).toHaveBeenCalledTimes(2);
    expect(await w.store.list('inbox/journal/')).toHaveLength(1); // still pending, retried by the redelivery
    await reopened.close();
  });

  it('a transient commit failure leaves the entry pending; the redelivered duplicate finishes it', async () => {
    let fail = true;
    const commit = vi.fn(() => { if (fail) throw new ACEError('storage_failed', 'down'); });
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check: () => {}, commit }];
    const w = await inboxWorld({ rules });
    const p = await w.pack(w.sender, msg('x'));
    expect((await w.inbox.receive(p)).kind).toBe('deferred');
    expect(w.delivered).toEqual([]);
    fail = false;
    expect((await w.inbox.receive(p)).kind).toBe('duplicate');
    expect(w.delivered).toHaveLength(1);
    expect(commit).toHaveBeenCalledTimes(2);
  });
});

describe('KEL verification resumed from a verified prefix', () => {
  it('still verifies every new event and every prefix signature', async () => {
    const clock = new Clock();
    const id = await identity(clock);
    const prefix = id.getKel();
    verifyKel(prefix, clock.t); // cached
    clock.advance(10);
    await id.delegate({ now: clock.t });
    const full = id.getKel();
    expect(verifyKel(full, clock.t).seq).toBe(full.length - 1);
    // a forged signature on the new event is rejected although its prefix is cached
    const sigOf = (e: KelEvent) => (e.sig as { value: string }).value;
    const forged = structuredClone(full) as KelEvent[];
    (forged.at(-1)!.sig as { value: string }).value = sigOf(full[0]);
    expect(() => verifyKel(forged, clock.t)).toThrow(ACEError);
    // a different signature on a cached prefix event is not that prefix: verified from scratch, and rejected
    const tampered = structuredClone(full) as KelEvent[];
    (tampered[0].sig as { value: string }).value = sigOf(full.at(-1)!);
    expect(() => verifyKel(tampered, clock.t)).toThrow(ACEError);
  });
});
