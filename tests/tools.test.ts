// The shared agent tool table (@ace-protocol/sdk/tools).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AGENT_TOOLS, checkArgs, requiredScope, type AgentTool } from '../src/tools.js';
import type { JSONObject } from './sdk.js';
import { Clock, FakeRelay, RELAY, agent, type TestAgent } from './helpers.js';

const T = Object.fromEntries(AGENT_TOOLS.map((t) => [t.name, t])) as Record<string, AgentTool>;
const run = async (a: TestAgent, name: string, args: JSONObject = {}) => (await T[name].run(a.client, args)).data as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe('AGENT_TOOLS', () => {
  it('uses the hosted vocabulary, JSON Schema inputs and no MCP or schema library', () => {
    expect(AGENT_TOOLS.map((t) => t.name)).toEqual(['ace_identity', 'ace_network', 'ace_send', 'ace_inbox', 'ace_outbox', 'ace_threads']);
    expect(Object.keys(T.ace_network.actions!).sort()).toEqual(
      ['accept', 'block', 'connect', 'discover', 'import', 'import_invitation', 'invite', 'lookup', 'peers', 'publish', 'reject', 'requests', 'unblock']);
    expect(Object.keys(T.ace_inbox.actions!)).toEqual(['read', 'ack']);
    expect(Object.keys(T.ace_outbox.actions!)).toEqual(['list', 'retry', 'abandon']);
    for (const t of AGENT_TOOLS) expect(t.inputSchema).toMatchObject({ type: 'object', additionalProperties: false });
    const src = readFileSync(new URL('../src/tools.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/from '(zod|@modelcontextprotocol\/[^']*)'/);
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(pkg.exports['./tools']).toEqual({ types: './dist/tools.d.ts', import: './dist/tools.js' });
  });

  it('scopes: admission-widening actions need ace:admission; an unknown action is refused', () => {
    expect(requiredScope(T.ace_network, { action: 'discover' })).toBe('ace:read');
    expect(requiredScope(T.ace_network, { action: 'connect' })).toBe('ace:connect');
    for (const a of ['accept', 'unblock', 'invite']) expect(requiredScope(T.ace_network, { action: a })).toBe('ace:admission');
    expect(requiredScope(T.ace_network, { action: 'configure' })).toBeNull();
    expect(requiredScope(T.ace_inbox, {})).toBe('ace:read'); // the default action
    expect(requiredScope(T.ace_inbox, { action: 'ack' })).toBe('ace:send');
    expect(requiredScope(T.ace_outbox, { action: 'retry' })).toBe('ace:send');
    expect(requiredScope(T.ace_send, {})).toBe('ace:send');
  });

  it('pins the scope of every tool and action (the hosted TOOL_SCOPES vocabulary)', () => {
    const scopes: Record<string, string> = {};
    for (const t of AGENT_TOOLS) {
      if (t.actions === undefined) scopes[t.name] = t.scope;
      else for (const [a, sc] of Object.entries(t.actions)) scopes[`${t.name}.${a}`] = sc;
    }
    expect(scopes).toEqual({
      ace_identity: 'ace:read',
      'ace_network.discover': 'ace:read', 'ace_network.lookup': 'ace:read', 'ace_network.requests': 'ace:read', 'ace_network.peers': 'ace:read',
      'ace_network.publish': 'ace:connect', 'ace_network.import': 'ace:connect', 'ace_network.import_invitation': 'ace:connect',
      'ace_network.connect': 'ace:connect', 'ace_network.reject': 'ace:connect', 'ace_network.block': 'ace:connect',
      'ace_network.invite': 'ace:admission', 'ace_network.accept': 'ace:admission', 'ace_network.unblock': 'ace:admission',
      ace_send: 'ace:send',
      'ace_inbox.read': 'ace:read', 'ace_inbox.ack': 'ace:send',
      'ace_outbox.list': 'ace:read', 'ace_outbox.retry': 'ace:send', 'ace_outbox.abandon': 'ace:send',
      ace_threads: 'ace:read',
    });
    for (const t of AGENT_TOOLS) expect(requiredScope(t, { action: 'nope' })).toBe(t.actions ? null : t.scope); // default deny
  });

  it('arguments are checked against the schema', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const a = await agent(relay, clock);
    await expect(T.ace_identity.run(a.client, { extra: 1 })).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(T.ace_network.run(a.client, { action: 'configure' })).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(T.ace_network.run(a.client, { action: 'lookup', peer: 7 })).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(T.ace_inbox.run(a.client, { action: 'ack', messages: [{ from: 'x', messageId: 'y' }] })).rejects.toMatchObject({ code: 'invalid_argument' });
    expect(() => checkArgs(T.ace_outbox.inputSchema, { action: 'list', status: 'gone' })).toThrow(/one of/);
    expect(() => checkArgs(T.ace_outbox.inputSchema, { status: 'pending' })).toThrow(/action is required/);
    const unique = { type: 'array', items: { type: 'object' }, uniqueItems: true } as const;
    expect(() => checkArgs(unique, [{ a: 1, b: 2 }, { b: 2, a: 1 }])).toThrow(/duplicate items/);
    expect(() => checkArgs(unique, [{ a: 1 }, { a: 2 }])).not.toThrow();
  });

  it('runs the hosted flows end to end and marks remote content untrusted', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true, handle: 'alice', card: { description: 'translation', tags: ['nlp'] }, profiles: ['text', 'commerce'] });
    const bob = await agent(relay, clock, { profiles: ['text', 'commerce'] });
    const A = alice.id.getACEId(), B = bob.id.getACEId();

    const me = await run(alice, 'ace_identity');
    expect(me).toMatchObject({ aceId: A, contact: 'open', listed: true, handle: 'alice', address: '@alice@relay.test', untrusted: [] });
    expect(me.profiles.map((p: { id: string }) => p.id)).toEqual(['ace:core:1', 'ace:text:1', 'ace:commerce:1']);

    const found = await run(bob, 'ace_network', { action: 'discover' });
    expect(found.cards).toEqual([{ aceId: A, home: RELAY, handle: 'alice', address: '@alice@relay.test', card: { description: 'translation', tags: ['nlp'] }, contact: 'open', listed: true }]);
    expect(found.untrusted).toEqual(['cards[].home', 'cards[].card', 'cards[].pay', 'cards[].erc8004']);
    expect((await run(bob, 'ace_network', { action: 'discover', tag: 'nlp' })).cards).toHaveLength(1);
    expect((await run(bob, 'ace_network', { action: 'discover', tag: 'absent' })).cards).toEqual([]);
    await expect(run(bob, 'ace_network', { action: 'discover', tag: 'NLP' })).rejects.toMatchObject({ code: 'invalid_argument' });
    const looked = await run(bob, 'ace_network', { action: 'lookup', peer: '@alice@relay.test' });
    expect(looked.card).toMatchObject({ aceId: A, handle: 'alice', card: { description: 'translation' }, contact: 'open' });
    expect(looked.untrusted).toContain('card');

    expect(await run(bob, 'ace_network', { action: 'connect', peer: '@alice@relay.test', note: 'hi, bob here' })).toMatchObject({ status: 'pending', aceId: A, profile: 'ace:text:1' });
    await alice.client.pull();
    const reqs = await run(alice, 'ace_network', { action: 'requests' });
    expect(reqs.requests.map((r: { from: string; note: string }) => [r.from, r.note])).toEqual([[B, 'hi, bob here']]);
    expect(reqs.untrusted).toContain('requests[].note');
    expect(await run(alice, 'ace_network', { action: 'accept', peer: B })).toMatchObject({ peer: B, status: 'admitted' });
    await bob.client.pull();
    expect((await run(bob, 'ace_network', { action: 'peers' })).peers).toEqual([{ aceId: A, status: 'admitted', profile: 'ace:text:1', canSend: true, permitExpiresAt: expect.any(Number) }]);

    const sent = await run(bob, 'ace_send', { to: '@alice@relay.test', type: 'ace:text:1', body: { message: 'hello' } });
    expect(sent).toMatchObject({ to: A, type: 'ace:text:1', status: 'pending', attempts: 1 });
    await alice.client.pull();
    const inbox = await run(alice, 'ace_inbox', {});
    expect(inbox.messages.map((m: { body: unknown }) => m.body)).toEqual([{ message: 'hello' }]);
    expect(inbox.untrusted).toEqual(['messages[].body', 'messages[].threadId']);
    expect(await run(alice, 'ace_inbox', { action: 'ack', messages: [{ from: B, messageId: sent.messageId }] })).toMatchObject({ acknowledged: 1 });
    expect((await run(alice, 'ace_inbox', { waitSeconds: 0 })).messages).toEqual([]);
    await bob.client.pull();
    expect((await run(bob, 'ace_outbox', { action: 'list' })).messages).toMatchObject([{ messageId: sent.messageId, status: 'delivered' }]);

    // commerce: thread state on send, in the inbox and in ace_threads
    const rfq = await run(bob, 'ace_send', { to: A, type: 'ace:commerce:rfq:1', body: { need: 'logo' }, threadId: 'job-1' });
    expect(rfq.threadState).toBeUndefined(); // committed only on the delivered receipt
    await alice.client.pull();
    expect((await run(alice, 'ace_inbox', { type: 'ace:commerce:rfq:1' })).messages[0]).toMatchObject({ threadId: 'job-1', threadState: 'requested' });
    const threads = await run(alice, 'ace_threads');
    expect(threads.threads).toMatchObject([{ threadId: 'job-1', peer: B, role: 'seller', state: 'requested' }]);
    expect((await run(alice, 'ace_threads', { threadId: 'job-1' })).allowedNextTypes).toEqual(['ace:commerce:offer:1', 'ace:commerce:reject:1']);

    // outbox retry and abandon
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    const later = await run(bob, 'ace_send', { to: A, type: 'ace:text:1', body: { message: 'later' } });
    expect(later).toMatchObject({ status: 'pending', code: 'relay_unavailable' });
    expect(await run(bob, 'ace_outbox', { action: 'retry', messageId: later.messageId })).toMatchObject({ attempts: 2 });
    expect(await run(bob, 'ace_outbox', { action: 'abandon', messageId: later.messageId })).toMatchObject({ status: 'expired' });

    // block and unblock are decisions by ACE ID
    expect(await run(alice, 'ace_network', { action: 'block', peer: B })).toMatchObject({ status: 'blocked' });
    expect(await run(alice, 'ace_network', { action: 'unblock', peer: B })).toMatchObject({ status: 'unblocked' });
    await expect(T.ace_network.run(alice.client, { action: 'accept', peer: '@bob@relay.test' })).rejects.toMatchObject({ code: 'invalid_argument' });
  });

  it('invitations: invite returns {agent, permit}; import_invitation never admits', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    const B = bob.id.getACEId();
    const shared = (await run(bob, 'ace_network', { action: 'publish' })).source;
    const inv = await run(alice, 'ace_network', { action: 'invite', source: shared });
    expect(inv).toMatchObject({ peer: B, profile: 'ace:text:1' });
    expect(await run(bob, 'ace_network', { action: 'import_invitation', invitation: inv.invitation })).toMatchObject({ permit: true, agent: { aceId: alice.id.getACEId() } });
    expect(await bob.client.admission.get(alice.id.getACEId())).toBeNull();
    expect(await run(bob, 'ace_network', { action: 'connect', peer: alice.id.getACEId() })).toMatchObject({ status: 'pending' });
    await alice.client.pull();
    await bob.client.pull();
    expect((await bob.client.admission.get(alice.id.getACEId()))?.status).toBe('admitted');
  });
});
