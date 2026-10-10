import { ACEError } from '../src/errors.js';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { SecureTransport, SECURE_DELIVERY_SCHEMA, SECURE_DELIVERY_TYPE, type SecureOutcome } from '../src/secure-transport.js';
import { MemoryStore } from '../src/store.js';
import { type MLSEngine } from '../src/session.js';
import { createMessage, parseMessage } from '../src/messages.js';
import { ReplayDetector } from '../src/replay.js';
import { type ACEMessage } from '../src/types.js';
import { Agent, Clock, CountingStore, json } from './pipeline.js';
const path = process.env.ACE_MLS_WASM;
describe.skipIf(!path)('authenticated forward secure delivery', () => {
  let engine: MLSEngine & { free(): void };
  beforeAll(async () => {
    const url = pathToFileURL(path!); const module = await import(/* @vite-ignore */ url.href);
    await module.default({ module_or_path: await readFile(new URL('./ace_session_core_bg.wasm', url)) });
    engine = new module.SessionEngine();
  });
  afterAll(() => engine?.free());
  async function setup() {
    const clock = new Clock(), writes = new CountingStore(new MemoryStore());
    const a = await Agent.create('a', 'ed25519', clock, writes), b = await Agent.create('b', 'secp256k1', clock);
    await a.pin(b); await b.pin(a);
    const pa = await b.peer(a), pb = await a.peer(b);
    const ta = new SecureTransport(a.identity, engine, a.store, clock.fn), tb = new SecureTransport(b.identity, engine, b.store, clock.fn);
    await SecureTransport.setPeerAllowed(a.store, b.id, true); await SecureTransport.setPeerAllowed(b.store, a.id, true);
    const inbox = await b.open();
    // The accept callback returns the Inbox verdict; only a retryable outcome throws (no receipt).
    const accept = async (bytes: Uint8Array): Promise<SecureOutcome> => { const result = await inbox.receive(bytes);
      if (result.kind === 'retryable') throw result.error;
      return result.kind === 'quarantined' ? { rejected: result.error.code } : result.kind; };
    const pending = await a.outbox.stage({ recipient: pb, type: 'text', body: { message: '秘密 hello' }, requestId: 'same-operation' });
    const close = async () => { await ta.close(); await tb.close(); await inbox.close(); };
    return { clock, a, b, pa, pb, ta, tb, inbox, accept, pending, writes, close };
  }
  it('runs original Inbox/Outbox exactly once, duplicate retries use fresh sessions, the sender journals nothing', async () => {
    const s = await setup();
    try {
      const exchange = (p: ACEMessage) => s.tb.respond(p, s.pa, s.accept);
      await s.ta.deliver(s.pending.message, s.pb, exchange);
      const [row] = await s.b.store.list('secure/in/');
      expect(json(await s.b.store.read(row))).toMatchObject({ version: 1, peer: s.a.id, outcome: 'delivered', envelope: null, response: expect.any(Object) });
      expect(Object.keys(json(await s.b.store.read(row))).sort()).toEqual(['envelope', 'expiresAt', 'generation', 'input', 'outcome', 'peer', 'response', 'version']);
      await s.a.outbox.deliver(s.pending.requestId, p => s.ta.deliver(p, s.pb, exchange)); // receipt outcome: duplicate
      expect(s.b.host.calls).toHaveLength(1); expect(await s.a.outbox.pending()).toHaveLength(0);
      expect(s.writes.writes.filter(k => k.startsWith('secure/'))).toEqual([expect.stringMatching(/^secure\/peers\//)]);
    } finally { await s.close(); }
  });
  it('a rejected inner envelope travels in the receipt: delivery_rejected with the Inbox code, journaled, replayed unchanged', async () => {
    const s = await setup(); const log: Array<[ACEMessage, ACEMessage]> = [];
    try {
      // a commerce message without a thread passes the handshake and is quarantined by the Inbox
      const bad = await createMessage({ sender: s.a.identity, recipient: s.pb, type: 'rfq', body: { need: 'x' }, timestamp: s.clock.t });
      await expect(s.ta.deliver(bad, s.pb, async p => { const r = await s.tb.respond(p, s.pa, s.accept); log.push([p, r]); return r; }))
        .rejects.toMatchObject({ name: 'ACEError', code: 'delivery_rejected', category: 'permanent', remoteCode: 'invalid_envelope' });
      expect(s.b.host.calls).toHaveLength(0); expect(await s.b.store.list('quarantine/')).toHaveLength(1);
      const [row] = await s.b.store.list('secure/in/');
      expect(json(await s.b.store.read(row))).toMatchObject({ outcome: 'rejected:invalid_envelope', envelope: null });
      // a replayed data frame re-sends the same receipt without touching the Inbox again
      const [data, ack] = log[1];
      expect(await s.tb.respond(data, s.pa, async () => { throw Error('must not run'); })).toEqual(ack);
      // the Outbox keeps a permanently rejected operation pending; the host decides to abandon
      const p = await s.a.outbox.stage({ recipient: s.pb, type: 'rfq', body: { need: 'y' }, threadId: 'rejected-by-policy' });
      await expect(s.a.outbox.deliver(p.requestId, async () => { throw new ACEError('delivery_rejected', 'x', { remoteCode: 'wrong_role' }); })).rejects.toMatchObject({ code: 'delivery_rejected' });
      expect((await s.a.outbox.pending()).map(x => x.status)).toEqual(['pending', 'pending']);
    } finally { await s.close(); }
  });
  it('an accept that throws leaves no receipt and the attempt dies with the process; a fresh attempt delivers once', async () => {
    const s = await setup(); let receiver = s.tb; let data: ACEMessage | undefined;
    try {
      await expect(s.ta.deliver(s.pending.message, s.pb, async p => {
        data = p; return receiver.respond(p, s.pa, async () => { throw Error('crash'); });
      })).rejects.toThrow('crash');
      const [row] = await s.b.store.list('secure/in/');
      expect(json(await s.b.store.read(row))).toMatchObject({ outcome: null, response: null, envelope: expect.any(Object) });
      await receiver.close(); receiver = new SecureTransport(s.b.identity, engine, s.b.store, s.clock.fn);
      await expect(receiver.respond(data!, s.pa, s.accept)).rejects.toMatchObject({ code: 'session_closed' });
      expect(s.b.host.calls).toHaveLength(0);
      await s.ta.deliver(s.pending.message, s.pb, p => receiver.respond(p, s.pa, s.accept));
      expect(s.b.host.calls).toHaveLength(1);
    } finally { await receiver.close(); await s.close(); }
  });
  it('rejects static application packets and peer disabled by default', async () => {
    const s = await setup();
    try {
      await expect(s.tb.respond(s.pending.message, s.pa, s.accept)).rejects.toMatchObject({ code: 'secure_delivery_required' });
      await SecureTransport.setPeerAllowed(s.b.store, s.a.id, false);
      await expect(s.ta.deliver(s.pending.message, s.pb, p => s.tb.respond(p, s.pa, s.accept))).rejects.toMatchObject({ code: 'delivery_peer_disabled' });
      expect(s.b.host.calls).toHaveLength(0);
    } finally { await s.close(); }
  });
  it('refuses a previously signed offer and sends no application ciphertext', async () => {
    const s = await setup(); let old: ACEMessage | undefined; let n = 0;
    try {
      await s.ta.deliver(s.pending.message, s.pb, async p => { const r = await s.tb.respond(p, s.pa, s.accept); old ??= r; return r; });
      await expect(s.ta.deliver(s.pending.message, s.pb, async () => { n++; return old!; })).rejects.toMatchObject({ code: 'invalid_delivery_frame' });
      expect(n).toBe(1);
    } finally { await s.close(); }
  });
  it('does not acknowledge a failed handler; revocation blocks prepared recovery', async () => {
    const s = await setup(); let data: ACEMessage | undefined;
    try {
      await expect(s.ta.deliver(s.pending.message, s.pb, async p => {
        data = p; return s.tb.respond(p, s.pa, async () => { throw Error('not committed'); });
      })).rejects.toThrow('not committed');
      await SecureTransport.setPeerAllowed(s.b.store, s.a.id, false);
      await expect(s.tb.respond(data!, s.pa, s.accept)).rejects.toMatchObject({ code: 'delivery_peer_disabled' });
      expect(s.b.host.calls).toHaveLength(0);
    } finally { await s.close(); }
  });
  it('detects a signed response with altered challenge and denies late receipts', async () => {
    const s = await setup();
    try {
      await expect(s.ta.deliver(s.pending.message, s.pb, async p => {
        const response = await s.tb.respond(p, s.pa, s.accept);
        const parsed = await parseMessage(response, s.a.identity, s.pb, { replay: new ReplayDetector({ clock: s.clock.fn }), clock: s.clock.fn });
        return createMessage({ sender: s.b.identity, recipient: s.pa, type: SECURE_DELIVERY_TYPE, schemaDigest: SECURE_DELIVERY_SCHEMA,
          body: { ...parsed.body, attempt: '0'.repeat(64) }, timestamp: s.clock.t });
      })).rejects.toMatchObject({ code: 'invalid_delivery_frame' });
      let calls = 0;
      await expect(s.ta.deliver(s.pending.message, s.pb, async p => { const response = await s.tb.respond(p, s.pa, s.accept);
        if (++calls === 2) s.clock.t += 121; return response; })).rejects.toMatchObject({ code: 'delivery_expired' });
    } finally { await s.close(); }
  });
  it('re-enabling a peer cannot revive a prepared receipt from its revoked policy generation', async () => {
    const s = await setup(); let data: ACEMessage | undefined;
    try {
      await expect(s.ta.deliver(s.pending.message, s.pb, async packet => {
        data = packet; return s.tb.respond(packet, s.pa, async () => { throw Error('crash before commit'); });
      })).rejects.toThrow('crash before commit');
      await SecureTransport.setPeerAllowed(s.b.store, s.a.id, false);
      await SecureTransport.setPeerAllowed(s.b.store, s.a.id, true);
      await expect(s.tb.respond(data!, s.pa, s.accept)).rejects.toMatchObject({ code: 'invalid_delivery_frame' });
      expect(s.b.host.calls).toHaveLength(0);
      await s.ta.deliver(s.pending.message, s.pb, p => s.tb.respond(p, s.pa, s.accept));
      expect(s.b.host.calls).toHaveLength(1);
    } finally { await s.close(); }
  });
  it('fails before sending oversized application envelopes or malformed admission records', async () => {
    const s = await setup(); let transmitted = false;
    try {
      const large = await createMessage({ sender: s.a.identity, recipient: s.pb, type: 'text', body: { message: 'x'.repeat(30_000) }, timestamp: s.clock.t });
      const exchange = async () => { transmitted = true; throw Error('must not send'); };
      await expect(s.ta.deliver(large, s.pb, exchange)).rejects.toMatchObject({ code: 'session_limit' });
      const [key] = await s.a.store.list('secure/peers/');
      expect(await SecureTransport.isPeerAllowed(s.a.store, s.b.id)).toBe(true);
      expect(await SecureTransport.isPeerAllowed(s.b.store, s.b.id)).toBe(false); // no row
      await s.a.store.write(key, new TextEncoder().encode('{"version":1,"allowed":true,"generation":1}'));
      expect(await SecureTransport.isPeerAllowed(s.a.store, s.b.id)).toBe(false); // malformed row, no throw
      await expect(s.ta.deliver(s.pending.message, s.pb, exchange)).rejects.toMatchObject({ code: 'delivery_peer_disabled' });
      await expect(SecureTransport.setPeerAllowed(s.a.store, s.b.id, true)).rejects.toMatchObject({ code: 'invalid_delivery_policy' });
      expect(transmitted).toBe(false);
    } finally { await s.close(); }
  });

  it('separates control expiry from an original application envelope requiring re-signing', async () => {
    const s = await setup();
    try {
      await expect(s.a.outbox.deliver(s.pending.requestId, packet => s.ta.deliver(packet, s.pb, async () => {
        throw new ACEError('envelope_expired', 'control packet rejected');
      }))).rejects.toMatchObject({ code: 'delivery_expired' });
      expect((await s.a.outbox.pending())[0].status).toBe('pending');
      s.clock.t += 604_801;
      await expect(s.a.outbox.deliver(s.pending.requestId, packet => s.ta.deliver(packet, s.pb, async () => {
        throw Error('must expire locally');
      }))).rejects.toMatchObject({ code: 'envelope_expired' });
      expect((await s.a.outbox.pending())[0].status).toBe('expired');
    } finally { await s.close(); }
  });

});
