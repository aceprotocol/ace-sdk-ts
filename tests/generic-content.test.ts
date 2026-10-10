import { isStreamId, isHttpsUrl } from "../src/encoding.js";
import { describe, expect, it } from 'vitest';
import { ACEError, createMessage, parseMessage, decodeEnvelope, Inbox, Outbox, MemoryStore, PeerStore, ReplayDetector, isMessageType, isACEId, isConversationId, isMessageId, type SchemaValidator } from '../src/index.js';
import { knownSchemaDigest } from '../src/messages.js';
import { agent, expectCode, peerOf, wire } from './helpers.js';

const alice = agent('alice'), bob = agent('bob');
const digest = 'ab'.repeat(32);
const type = 'https://example.org/schemas/task/1';

describe('private extensible content', () => {
  it('rejects trailing line terminators in identifiers and schema digests', async () => {
    for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
      expect(isMessageType(type + suffix)).toBe(false);
      expect(isACEId(alice.getACEId() + suffix)).toBe(false);
      expect(isConversationId(digest + suffix)).toBe(false);
      expect(isMessageId('550e8400-e29b-41d4-a716-446655440000' + suffix)).toBe(false);
      expect(isStreamId('123-0' + suffix)).toBe(false);
      expect(isHttpsUrl('https://example.com/' + suffix)).toBe(false);
      await expect(createMessage({ sender: alice, recipient: peerOf(bob), type, body: {}, schemaDigest: digest + suffix })).rejects.toMatchObject({ code: 'invalid_body' });
    }
  });

  it('quarantines missing private commerce threads once, without stalling delivery', async () => {
    const store = new MemoryStore(), peers = new PeerStore({ store });
    await peers.adopt(peerOf(alice));
    const inbox = await Inbox.open({ identity: bob, store, peers, commerce: true, onMessage: () => {} });
    const env = await createMessage({ sender: alice, recipient: peerOf(bob), type: 'rfq', body: { need: 'data' } });
    expect(await inbox.receive(wire(env))).toMatchObject({ kind: 'quarantined', error: { code: 'invalid_envelope' } });
    expect((await inbox.receive(wire(env))).kind).toBe('duplicate');
    await inbox.close();
  });

  it('round trips a custom schema without a commerce machine or account policy', async () => {
    const env = await createMessage({ sender: alice, recipient: peerOf(bob), type,
      schemaDigest: digest, threadId: 'secret workflow', body: { text: '你好', task: { amount: '10' } } });
    expect(Object.keys(env).sort()).toEqual(['ace', 'conversationId', 'encryption', 'from', 'messageId', 'signature', 'timestamp', 'to']);
    const decoded = await parseMessage(env, bob, peerOf(alice), { replay: new ReplayDetector() });
    expect(decoded).toMatchObject({ type, schemaDigest: digest, threadId: 'secret workflow', body: { text: '你好', task: { amount: '10' } } });
  });

  it('requires a custom schema pin and rejects substitution of a bundled pin', async () => {
    for (const input of [{ type, body: {} }, { type: 'text' as const, body: { message: 'hello' }, schemaDigest: digest }]) {
      await expect(createMessage({ sender: alice, recipient: peerOf(bob), ...input })).rejects.toMatchObject({ code: 'invalid_body' });
    }
    expect(knownSchemaDigest('text')).toBe('c82da8dde17338c28c42d2a6fad644961c3e7a8d1d008f9d2b18e8d624cf4a52');
  });

  it.each(['type', 'threadId', 'body', 'schemaDigest'])('rejects public %s even when the original signature is valid', async field => {
    const env = await createMessage({ sender: alice, recipient: peerOf(bob), type: 'text', body: { message: 'hello' } });
    expect(() => decodeEnvelope({ ...env, [field]: 'leak' })).toThrow(/invalid_envelope/);
  });

  it('installed schema validators: the Inbox quarantines with the validator\'s code, the Outbox refuses before persisting', async () => {
    const seen: unknown[] = [];
    const task: SchemaValidator = m => {
      seen.push(m);
      if (typeof m.body.amount !== 'string') throw new ACEError('limit_exceeded', 'task.amount must be a string');
      if (m.body.amount === 'boom') throw new Error('not an ACEError');
      (m.body as { amount: unknown }).amount = 'mutated'; // the validator sees a copy
    };
    const schemas = { [digest]: task };
    const store = new MemoryStore(), peers = new PeerStore({ store });
    await peers.adopt(peerOf(alice));
    const handed: unknown[] = [];
    const inbox = await Inbox.open({ identity: bob, store, peers, schemas, onMessage: m => { handed.push(m.body); } });
    const send = (body: Record<string, unknown>) => createMessage({ sender: alice, recipient: peerOf(bob), type, schemaDigest: digest, threadId: 't', body });
    expect(await inbox.receive(wire(await send({ amount: 5 })))).toMatchObject({ kind: 'quarantined', error: { code: 'limit_exceeded' }, fingerprint: expect.any(String) });
    expect(await inbox.receive(wire(await send({ amount: 'boom' })))).toMatchObject({ kind: 'quarantined', error: { code: 'invalid_body' } });
    expect(await store.list('quarantine/')).toHaveLength(2);
    expect(await inbox.receive(wire(await send({ amount: '10' })))).toMatchObject({ kind: 'delivered', message: { body: { amount: '10' } } });
    expect(handed).toEqual([{ amount: '10' }]);
    expect(seen[2]).toMatchObject({ type, schemaDigest: digest, threadId: 't', body: { amount: 'mutated' } });
    // without a validator the same digest is authenticated data; a bundled digest's validator runs in addition
    const other = await createMessage({ sender: alice, recipient: peerOf(bob), type: 'text', body: { message: 'hello' } });
    expect((await inbox.receive(wire(other))).kind).toBe('delivered');
    await inbox.close();
    const strict = await Inbox.open({ identity: bob, store, peers, onMessage: () => {}, schemas: { [knownSchemaDigest('text')!]: () => { throw new ACEError('wrong_party', 'no text here'); } } });
    expect(await strict.receive(wire(await createMessage({ sender: alice, recipient: peerOf(bob), type: 'text', body: { message: 'again' } })))).toMatchObject({ kind: 'quarantined', error: { code: 'wrong_party' } });
    await strict.close();
    // Outbox.stage runs the validator on the outgoing body; a rejection persists nothing
    const txStore = new MemoryStore();
    const outbox = await Outbox.open({ identity: alice, store: txStore, schemas });
    await expectCode(outbox.stage({ recipient: peerOf(bob), type, schemaDigest: digest, body: { amount: 7 }, requestId: 'bad' }), 'limit_exceeded');
    await expectCode(outbox.stage({ recipient: peerOf(bob), type, schemaDigest: digest, body: { amount: 'boom' }, requestId: 'bad' }), 'invalid_body');
    expect(await txStore.list('')).toEqual([]);
    expect(await outbox.pending()).toEqual([]);
    const ok = await outbox.stage({ recipient: peerOf(bob), type, schemaDigest: digest, body: { amount: '1' }, requestId: 'good' });
    expect((await outbox.pending()).map(p => p.requestId)).toEqual(['good']);
    expect(ok.message.messageId).toMatch(/^[0-9a-f-]{36}$/);
    // the map is checked at open: keys are 64 lowercase hex, values callable
    for (const bad of [null, { abc: task }, { [digest.toUpperCase()]: task }, { [digest]: 'nope' }] as never[]) {
      await expectCode(Inbox.open({ identity: bob, store, peers, onMessage: () => {}, schemas: bad }), 'invalid_argument');
      await expectCode(Outbox.open({ identity: alice, store: txStore, schemas: bad }), 'invalid_argument');
    }
    expect(await store.list('locks/')).toEqual([]); // a refused Inbox.open never took the receive lock
  });

  it('retains custom schema and private thread across restart and operation retries', async () => {
    const store = new MemoryStore(), rxStore = new MemoryStore();
    const outbox = await Outbox.open({ identity: alice, store });
    const input = { recipient: peerOf(bob), type, schemaDigest: digest, threadId: 'private', body: { data: 1 }, requestId: 'operation' };
    const p = await outbox.stage(input);
    const restarted = await Outbox.open({ identity: alice, store });
    expect(await restarted.stage(input)).toEqual(p);
    await expect(restarted.stage({ ...input, schemaDigest: 'cd'.repeat(32) })).rejects.toMatchObject({ code: 'pending_send_conflict' });
    const peers = new PeerStore({ store: rxStore });
    await peers.adopt(peerOf(alice));
    let handed = 0;
    const inbox = await Inbox.open({ identity: bob, store: rxStore, peers, onMessage: m => {
      expect(m.schemaDigest).toBe(digest); expect(m.threadId).toBe('private'); handed++;
    } });
    expect((await inbox.receive(wire(p.message))).kind).toBe('delivered');
    await inbox.close();
    const reopened = await Inbox.open({ identity: bob, store: rxStore, peers, onMessage: () => { handed++; } });
    expect((await reopened.receive(wire(p.message))).kind).toBe('duplicate');
    expect(handed).toBe(1);
    expect(await store.list('threads/')).toEqual([]);
    await reopened.close();
  });
});
