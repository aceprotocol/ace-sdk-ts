// Pre-release fixes: each case reproduces one defect.
import { describe, expect, it } from 'vitest';
import { chmodSync, mkdtempSync, realpathSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACEError, CONTACT_REQUEST_TTL_SECONDS, encodePrivateContent, FileStore, Inbox, createDescriptor, type PublishedAgent, OFFLINE_WINDOW_SECONDS, sha256Hex, decodePacket, MAX_SIGNING_KEY_LIFETIME, MemoryStore, SoftwareIdentity, isBlockedAddress, Outbox, ProfileSet, RelayClient, StorePrekeyVault, verifyPublishedAgent, type OutboxTransport,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, identity } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';

const deep = (n: number) => '['.repeat(n) + ']'.repeat(n);
const json = (body: string, type = 'application/json') => new Response(body, { status: 200, headers: { 'content-type': type } });

describe('received JSON depth (02 § JSON values: MAX_JSON_DEPTH)', () => {
  const aceId = `ace:sha256:${'a'.repeat(64)}`;

  it('a deeply nested relay response is relay_protocol_error, never a RangeError', async () => {
    const bodies = [
      `{"kel":[],"descriptor":${deep(200_000)}}`,
      `{"agents":[{"kel":[],"descriptor":${deep(200_000)}}],"cursor":null}`,
      `{"kel":[],"descriptor":${deep(40)}}`, // over the limit, far below the stack
    ];
    for (const body of bodies) {
      const relay = new RelayClient(RELAY, { fetch: async () => json(body), clock: () => NOW });
      const call = body.startsWith('{"agents"') ? relay.listDescriptors() : relay.getDescriptor(aceId);
      await expect(call).rejects.toMatchObject({ code: 'relay_protocol_error' });
    }
  });

  it('verifyPublishedAgent refuses a deep value with an ACEError', () => {
    let v: unknown = [];
    for (let i = 0; i < 200_000; i++) v = [v];
    const err = (() => { try { verifyPublishedAgent({ kel: [], descriptor: v }, NOW); } catch (e) { return e; } })();
    expect(err).toBeInstanceOf(ACEError);
  });

  it('a deeply nested SSE frame is relay_protocol_error', async () => {
    const id = await identity();
    const frame = `event: connected\ndata: {}\n\nid: 1-0\nevent: message\ndata: {"packet":${deep(200_000)}}\n\n`;
    const relay = new RelayClient(RELAY, { fetch: async () => json(frame, 'text/event-stream'), clock: () => NOW });
    const run = async () => { for await (const _ of relay.listen(id)) throw new Error('the frame was yielded'); };
    await expect(run()).rejects.toMatchObject({ code: 'relay_protocol_error' });
  });
});

describe('sent body depth: counted from the private content root (02 § JSON values)', () => {
  /** A body object whose deepest container is at depth `n` from the body (its root at 0): at `n + 1` in the content. */
  const bodyAt = (n: number) => { let v: unknown = []; for (let i = 1; i < n; i++) v = [v]; return { x: v }; };
  const content = (n: number) => ({ type: 'ace:text:1', schemaDigest: '0'.repeat(64), body: bodyAt(n) }) as never;

  it('a body at depth 31 is sent; 32 (content depth 33) is invalid_body at encode', () => {
    expect(() => encodePrivateContent(content(31))).not.toThrow();
    expect(() => encodePrivateContent(content(32))).toThrow(expect.objectContaining({ code: 'invalid_body' }));
  });
});

describe('response depth: MAX_JSON_DEPTH per contained object, + 3 for the wrapper (02 § JSON values)', () => {
  /** A JSON value whose deepest container is at depth `n` (its root at 0). */
  const nest = (n: number): unknown => (n === 0 ? {} : { a: nest(n - 1) });
  /** A public PublishedAgent within depth 32 exactly (ext.x:deep:1 at 3 holds 29 more levels); `over` adds one (unsigned). */
  const boundaryAgent = async (over = false): Promise<PublishedAgent> => {
    const id = await identity();
    const pk = await new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }).rotate(NOW);
    const a = await createDescriptor(id, {
      relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: [{ id: 'x:deep:1', digest: 'a'.repeat(64) }],
      visibility: 'public', ext: { 'x:deep:1': nest(29) as Record<string, never> }, now: NOW,
    });
    return over ? { ...a, descriptor: { ...a.descriptor, ext: { 'x:deep:1': nest(30) as Record<string, never> } } } : a;
  };
  const client = (body: string, type?: string) => new RelayClient(RELAY, { fetch: async () => json(body, type), clock: () => NOW });

  it('a PublishedAgent at depth 32 passes in a descriptor response and a directory page; 33 is relay_protocol_error', async () => {
    const ok = await boundaryAgent(), bad = await boundaryAgent(true);
    expect((await client(JSON.stringify(ok)).getDescriptor(ok.descriptor.aceId)).descriptor.aceId).toBe(ok.descriptor.aceId);
    expect((await client(JSON.stringify({ agents: [ok], cursor: null })).listDescriptors()).agents).toHaveLength(1);
    await expect(client(JSON.stringify(bad)).getDescriptor(bad.descriptor.aceId)).rejects.toMatchObject({ code: 'relay_protocol_error' });
    // never skipped: a conformant relay refused it on input
    await expect(client(JSON.stringify({ agents: [ok, bad], cursor: null })).listDescriptors()).rejects.toMatchObject({ code: 'relay_protocol_error' });
  });

  it('a packet at depth 32 passes in an inbox page and an SSE frame; 33 is relay_protocol_error', async () => {
    const id = await identity();
    const inbox = (n: number) => client(JSON.stringify({ messages: [{ streamId: '1-0', packet: nest(n) }], cursor: '1-0' })).fetchInbox(id);
    expect((await inbox(32)).messages[0].packet).toEqual(nest(32));
    await expect(inbox(33)).rejects.toMatchObject({ code: 'relay_protocol_error' });
    const listen = async (n: number) => {
      const frame = `event: connected\ndata: {}\n\nid: 1-0\nevent: message\ndata: ${JSON.stringify({ packet: nest(n) })}\n\n`;
      for await (const ev of client(frame, 'text/event-stream').listen(id)) return JSON.parse(ev.data) as unknown;
    };
    expect(await listen(32)).toEqual({ packet: nest(32) });
    await expect(listen(33)).rejects.toMatchObject({ code: 'relay_protocol_error' });
  });
});

describe('README names only what the package exports', () => {
  it('every symbol in "What is inside" is a public export, a type export or a NetworkClient member', async () => {
    const { readFileSync } = await import('node:fs');
    const sdk = await import('../src/index.js');
    const tools = await import('../src/tools.js');
    const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
    const inside = read('../README.md').split('## What is inside')[1].split('\n## ')[0];
    const exported = new Set([
      ...Object.keys(sdk), ...Object.keys(tools),
      ...[...(read('../src/index.ts') + read('../src/tools.ts')).matchAll(/export type \{([^}]*)\}/g)].flatMap((m) => m[1].split(',').map((n) => n.trim())),
      ...[...(read('../src/index.ts') + read('../src/tools.ts')).matchAll(/type ([A-Za-z]\w*)/g)].map((m) => m[1]),
      ...Object.getOwnPropertyNames(sdk.NetworkClient.prototype),
    ]);
    const fields = new Set(['relayUrl', 'onReceipt', 'messageId']); // option and wire field names
    const named = [...inside.matchAll(/`([A-Za-z]\w*)`/g)].map((m) => m[1]).filter((n) => /[A-Z]/.test(n) && !fields.has(n));
    expect(named.filter((n) => !exported.has(n))).toEqual([]);
  });
});

describe('sdk-py review findings, checked here', () => {
  it('two vaults over one FileStore (two processes) never lose each other\'s prekey', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ace-prekeys-'));
    const a = new StorePrekeyVault(new FileStore(dir), { clock: () => NOW });
    const b = new StorePrekeyVault(new FileStore(dir), { clock: () => NOW });
    const first = await a.rotate(NOW);
    expect((await b.current())!.id).toBe(first.id); // b holds no stale copy
    const [x, y] = await Promise.all([a.rotate(NOW + 1), b.rotate(NOW + 1)]);
    const cur = (await a.current())!.id;
    expect([x.id, y.id]).toContain(cur);
    for (const id of [first.id, x.id, y.id]) expect(await a.open(id)).not.toBeNull();
  });

  it('a delivered receipt that lands during an attempt is never overwritten by that attempt\'s outcome', async () => {
    const clock = new Clock();
    const me = await identity(clock), peer = await identity(clock);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const transport: OutboxTransport = async () => { await gate; throw new ACEError('unknown_prekey', 'refreshed descriptor still has it'); };
    const ob = new Outbox({ identity: me, store: new MemoryStore(), profiles: new ProfileSet(['text']), transport, clock: clock.now });
    const e = await ob.enqueue({ to: peer.getACEId(), type: 'ace:text:1', body: { message: 'x' } });
    const attempt = ob.attempt(e.messageId);
    await new Promise((r) => setTimeout(r, 10));
    expect(await ob.onReceipt(peer.getACEId(), { messageId: e.messageId, outcome: 'delivered' })).toMatchObject({ status: 'delivered' });
    release();
    expect(await attempt).toMatchObject({ status: 'delivered' });
    expect((await ob.get(e.messageId))!.status).toBe('delivered');
  });
});

describe('FileStore fails closed on loose permissions', () => {
  const enc = new TextEncoder();

  it('refuses a group/other-accessible root, directory or file; creates missing directories 0700', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ace-perm-'));
    const root = join(dir, 'a', 'b', 'store');
    const store = new FileStore(root);
    await store.write('x/y.json', enc.encode('{}'));
    for (const d of [join(dir, 'a'), join(dir, 'a', 'b'), root, join(root, 'x')]) expect(statSync(d).mode & 0o777).toBe(0o700);
    expect(statSync(join(root, 'x', 'y.json')).mode & 0o777).toBe(0o600);

    // the refusal names the offending path and the remedy
    const refused = (fix: string) => expect.objectContaining({ code: 'storage_failed', message: expect.stringContaining(fix) });
    chmodSync(join(root, 'x', 'y.json'), 0o644);
    await expect(store.read('x/y.json')).rejects.toEqual(refused(`chmod 600 ${join(realpathSync(root), 'x', 'y.json')}`));
    chmodSync(join(root, 'x', 'y.json'), 0o600);
    chmodSync(join(root, 'x'), 0o750);
    await expect(store.read('x/y.json')).rejects.toEqual(refused(`chmod 700 ${join(realpathSync(root), 'x')}`));
    chmodSync(join(root, 'x'), 0o700);
    expect(await store.read('x/y.json')).not.toBeNull();

    chmodSync(root, 0o755);
    await expect(new FileStore(root).read('x/y.json')).rejects.toEqual(refused(`chmod 700 ${root}`));
    await expect(new FileStore(root).lock('l')).rejects.toEqual(refused(`chmod 700 ${root}`));
    chmodSync(root, 0o700);
    await (await store.lock('l'))();
    chmodSync(join(root, 'locks', 'l.lock'), 0o644);
    await expect(new FileStore(root).lock('l')).rejects.toEqual(refused(`chmod 600 ${join(realpathSync(root), 'locks', 'l.lock')}`));
  });
});

describe('constants and the address blocklist (07 § Client rules)', () => {
  it('MAX_SIGNING_KEY_LIFETIME bounds a dlg notAfter', async () => {
    expect(MAX_SIGNING_KEY_LIFETIME).toBe(31_622_400);
    const id = await SoftwareIdentity.generate({ now: NOW });
    await expect(id.delegate({ now: NOW + 1, notAfter: NOW + 1 + MAX_SIGNING_KEY_LIFETIME + 1 })).rejects.toBeInstanceOf(ACEError);
    await id.delegate({ now: NOW + 1, notAfter: NOW + 1 + MAX_SIGNING_KEY_LIFETIME });
  });

  it('blocks 2001::/23, 3fff::/20, 5f00::/16 and fec0::/10, and only those', () => {
    for (const ip of ['2001::1', '2001:1ff:ffff::1', '3fff::1', '3fff:fff::1', '5f00::1', '5f00:ffff::1', 'fec0::1', 'feff::1']) expect(isBlockedAddress(ip), ip).toBe(true);
    for (const ip of ['2001:200::1', '2001:4860::8888', '3fff:1000::1', '5f01::1', '5eff::1', 'fe7f::1']) expect(isBlockedAddress(ip), ip).toBe(false);
  });
});

describe('06 § Outbox step 3: every attempt carries a live permit', () => {
  it('a retry without a permit valid under the pin fails not_permitted and is never posted on the stranger path', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { visibility: 'public', acceptProfiles: ['ace:text:1'] });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    await alice.client.pull();
    await bob.client.pull();
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    const e = await bob.client.send(A, 'ace:text:1', { message: 'retry me' });
    expect(e).toMatchObject({ status: 'pending', attempts: 1 });
    await bob.store.delete(`admission/permits/${sha256Hex(A)}.json`); // the permit is gone (lapsed, superseded)
    const before = relay.sent.length;
    clock.advance(60);
    const [r] = await bob.client.flush();
    expect(r).toMatchObject({ status: 'pending', attempts: 2, code: 'not_permitted' });
    expect(relay.sent.slice(before).filter((x) => decodePacket(x.packet).messageId === e.messageId)).toEqual([]);
  });
});

describe('05 § Flow step 4: an outgoing pending entry lives OFFLINE_WINDOW_SECONDS', () => {
  it('a pending entry outlives CONTACT_REQUEST_TTL_SECONDS and lapses at OFFLINE_WINDOW_SECONDS', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { visibility: 'public' });
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    await bob.client.connect(A, { profile: 'ace:text:1' });
    clock.advance(CONTACT_REQUEST_TTL_SECONDS + 1);
    expect(await bob.client.admission.get(A)).toMatchObject({ status: 'pending' });
    clock.advance(OFFLINE_WINDOW_SECONDS - CONTACT_REQUEST_TTL_SECONDS - 1);
    expect(await bob.client.admission.get(A)).toBeNull();
  });
});

describe('06 § Crash recovery: a delivered message leaves no plaintext in inbox state', () => {
  const MARKER = 'plaintext-marker-7f3a9c';
  const bytes = new TextEncoder().encode(MARKER);
  const holds = (v: Uint8Array) => Buffer.from(v).includes(bytes);
  const leaked = async (store: MemoryStore) => {
    const keys: string[] = [];
    for (const k of await store.list('')) if (holds((await store.read(k))!)) keys.push(k);
    return keys;
  };

  it('done journal entries hold only what dedup needs; dedup still works across a restart', async () => {
    const w = await inboxWorld();
    const packets = [];
    for (let i = 0; i < 5; i++) packets.push(await w.pack(w.sender, msg(`${MARKER} ${i}`)));
    for (const p of packets) expect((await w.inbox.receive(p)).kind).toBe('delivered');
    expect(await w.store.list('inbox/journal/')).toHaveLength(5);
    expect(await leaked(w.store)).toEqual([]);
    // a crash before the next snapshot: only the journal carries these seen entries
    const journal = await Promise.all((await w.store.list('inbox/journal/')).map(async (k) => [k, (await w.store.read(k))!] as const));
    const replay = (await w.store.read('inbox/replay.json'))!;
    await w.inbox.close();
    await w.store.write('inbox/replay.json', replay);
    for (const [k, v] of journal) await w.store.write(k, v);
    const reopened = await Inbox.open(w.options);
    for (const p of packets) expect((await reopened.receive(p)).kind).toBe('duplicate');
    expect(w.delivered).toHaveLength(5);
    await reopened.close();
  });

  it('a hand-over interrupted before the handler returned is re-delivered after restart, then its body is gone', async () => {
    let crash = true;
    const w = await inboxWorld({ onMessage: (m) => { if (crash) throw new Error('process died'); w.delivered.push(m); } });
    expect((await w.inbox.receive(await w.pack(w.sender, msg(MARKER)))).kind).toBe('deferred');
    expect(await leaked(w.store)).toHaveLength(1); // the pending entry: the only copy recovery can hand over
    await w.inbox.close();
    crash = false;
    const reopened = await Inbox.open(w.options);
    expect(w.delivered.map((m) => m.body.message)).toEqual([MARKER]);
    expect(await leaked(w.store)).toEqual([]);
    await reopened.close();
  });
});
