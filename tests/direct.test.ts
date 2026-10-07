// Direct delivery, sending side (08-relay § Direct Delivery, Sender): postDirect and the
// direct-or-relay transport. A plain HTTP server stands in for the HTTPS endpoint: the request
// module is injected, everything else (resolution, blocking, pinning, mapping) is the real code.
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ACEError, type ACEMessage } from '../src/index.js';
import { directOrRelayWith, postDirectWith, type DirectDeps } from '../src/direct.js';
import { postDirect } from '../src/node.js';
import { expectCode } from './helpers.js';
import { Agent, Clock } from './pipeline.js';

type Handler = (body: string, req: http.IncomingMessage, res: http.ServerResponse) => void;

let server: http.Server;
let port = 0;
let handler: Handler;
const seen: Array<{ method: string; path: string; host: string; body: string }> = [];

beforeEach(async () => {
  seen.length = 0;
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      seen.push({ method: req.method ?? '', path: req.url ?? '', host: req.headers.host ?? '', body });
      handler(body, req, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
});
afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

function reply(status: number, body: unknown, headers: Record<string, string> = {}): Handler {
  return (_b, _req, res) => {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    res.end(text);
  };
}

const lookups: string[] = [];
function deps(addrs = ['127.0.0.1'], extra: Partial<DirectDeps> = {}): DirectDeps {
  return {
    lookup: async (host) => {
      lookups.push(host);
      return addrs.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    },
    https: http as never,
    port,
    allowPrivateAddresses: true,
    ...extra,
  };
}

async function envelope(): Promise<{ alice: Agent; bob: Agent; env: ACEMessage }> {
  const clock = new Clock(Math.floor(Date.now() / 1000));
  const alice = await Agent.create('alice', 'ed25519', clock);
  const bob = await Agent.create('bob', 'secp256k1', clock);
  await alice.pin(bob);
  await bob.pin(alice);
  const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'hi' } });
  return { alice, bob, env: p.message };
}

describe('postDirect', () => {
  it('POSTs {"message": envelope} to the pinned address with the endpoint host; 2xx {ok:true} succeeds', async () => {
    const { env } = await envelope();
    handler = reply(200, { ok: true, messageId: env.messageId });
    lookups.length = 0;
    await postDirectWith('https://agent.example.com/ace/receive?x=1', env, {}, deps());
    expect(lookups).toEqual(['agent.example.com']);
    expect(seen).toHaveLength(1);
    expect(seen[0].method).toBe('POST');
    expect(seen[0].path).toBe('/ace/receive?x=1');
    expect(seen[0].host).toBe(`agent.example.com:${port}`);
    expect(JSON.parse(seen[0].body)).toEqual({ message: env });
  });

  it('an inbox answering through receiveDirect: delivered once, then a duplicate (both succeed)', async () => {
    const { bob, env } = await envelope();
    const inbox = await bob.open();
    handler = (body, _req, res) => {
      void inbox.receiveDirect(new TextEncoder().encode(body)).then((r) => {
        res.writeHead(r.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(r.body));
      });
    };
    await postDirectWith('https://bob.example.com/ace', env, {}, deps());
    await postDirectWith('https://bob.example.com/ace', env, {}, deps());
    expect(bob.host.calls).toHaveLength(1);
    await inbox.close();
  });

  it('400 / 413 are direct_rejected carrying the receiver error; everything else is direct_unavailable', async () => {
    const { env } = await envelope();
    for (const [status, body] of [[400, { ok: false, error: 'invalid_signature' }], [413, { ok: false, error: 'payload_too_large' }]] as const) {
      handler = reply(status, body);
      const e = await expectCode(postDirectWith('https://a.example.com/', env, {}, deps()), 'direct_rejected');
      expect([e.status, e.remoteCode, e.isTransient]).toEqual([status, body.error, false]);
    }
    handler = reply(400, 'not json');
    expect((await expectCode(postDirectWith('https://a.example.com/', env, {}, deps()), 'direct_rejected')).remoteCode).toBeUndefined();
    // remoteCode only when it matches ^[a-z0-9_]{1,64}$ (peer-controlled text otherwise)
    for (const [error, kept] of [
      ['Bad\u001b[31m', undefined], ['a'.repeat(65), undefined], ['', undefined], [5, undefined], ['a'.repeat(64), 'a'.repeat(64)],
    ] as const) {
      handler = reply(400, { ok: false, error });
      const e = await expectCode(postDirectWith('https://a.example.com/', env, {}, deps()), 'direct_rejected');
      expect(e.remoteCode).toBe(kept);
      expect(e.message).not.toContain('\u001b');
    }
    for (const [status, body] of [
      [429, { ok: false, error: 'rate_limited' }], [503, { ok: false, error: 'storage_failed' }], [500, 'oops'],
      [200, { ok: false }], [200, 'not json'], [204, ''], [302, ''], [404, { ok: false, error: 'nope' }],
    ] as const) {
      handler = reply(status, body, status === 302 ? { Location: 'https://elsewhere.example/' } : {});
      const e = await expectCode(postDirectWith('https://a.example.com/', env, {}, deps()), 'direct_unavailable');
      expect(e.isTransient).toBe(true);
    }
    expect(seen.every((s) => s.path === '/')).toBe(true); // the redirect was not followed
  });

  it('network failures and timeouts are direct_unavailable', async () => {
    const { env } = await envelope();
    handler = () => { /* never answers */ };
    await expectCode(postDirectWith('https://a.example.com/', env, { timeoutMs: 100 }, deps()), 'direct_unavailable');
    await expectCode(postDirectWith('https://a.example.com/', env, {}, deps(['127.0.0.1'], { port: 1 })), 'direct_unavailable');
    await expectCode(postDirectWith('https://a.example.com/', env, {}, deps([], {})), 'direct_unavailable');
    await expectCode(postDirectWith('https://a.example.com/', env, {}, {
      ...deps(), lookup: async () => { throw new Error('NXDOMAIN'); },
    }), 'direct_unavailable');
  });

  it('unsafe or malformed endpoints and envelopes are invalid_argument, before any request', async () => {
    const { env } = await envelope();
    handler = reply(200, { ok: true });
    const strict = deps(['93.184.216.34', '10.0.0.1'], { allowPrivateAddresses: false });
    await expectCode(postDirectWith('https://a.example.com/', env, {}, strict), 'invalid_argument'); // any blocked address
    await expectCode(postDirectWith('https://127.0.0.1/', env, {}, deps(['127.0.0.1'], { allowPrivateAddresses: false })), 'invalid_argument');
    for (const url of ['http://a.example.com/', 'ftp://a.example.com', 'https://user@a.example.com/', 'not a url']) {
      await expectCode(postDirectWith(url, env, {}, deps()), 'invalid_argument');
    }
    await expectCode(postDirectWith('https://a.example.com/', { ...env, ace: '2.0' } as never, {}, deps()), 'invalid_argument');
    await expectCode(postDirectWith('https://a.example.com/', env, { timeoutMs: 0 }, deps()), 'invalid_argument');
    expect(seen).toEqual([]);
    // the real (Node) entry point applies the same checks
    await expectCode(postDirect('https://127.0.0.1/', env), 'invalid_argument');
    await expectCode(postDirect('http://a.example.com/', env), 'invalid_argument');
  });
});

describe('direct-or-relay transport', () => {
  it('direct first; relay on direct_unavailable or an unsafe endpoint; never on direct_rejected', async () => {
    const { env } = await envelope();
    const relayed: ACEMessage[] = [];
    const relay = { send: async (e: ACEMessage) => { relayed.push(e); } };
    const post = (outcome: ACEError | null) => async () => { if (outcome) throw outcome; };
    expect(await directOrRelayWith(relay, 'https://a.example', post(null))(env)).toBe('direct');
    expect(await directOrRelayWith(relay, 'https://a.example', post(new ACEError('direct_unavailable')))(env)).toBe('relay');
    expect(await directOrRelayWith(relay, 'https://a.example', post(new ACEError('invalid_argument')))(env)).toBe('relay');
    expect(await directOrRelayWith(relay, null, post(new ACEError('direct_unavailable')))(env)).toBe('relay');
    expect(await directOrRelayWith(relay, undefined, post(null))(env)).toBe('relay');
    expect(relayed).toHaveLength(4);
    await expectCode(directOrRelayWith(relay, 'https://a.example', post(new ACEError('direct_rejected')))(env), 'direct_rejected');
    await expect(directOrRelayWith(relay, 'https://a.example', async () => { throw new Error('bug'); })(env)).rejects.toThrow('bug');
    expect(relayed).toHaveLength(4);
    expect(() => directOrRelayWith({} as never, null, post(null))).toThrow(ACEError);
  });

  it('works as an Outbox.deliver transport and reports the path', async () => {
    const { alice, bob } = await envelope();
    const p = await alice.outbox.stage({ recipient: await alice.peer(bob), type: 'text', body: { message: 'x' } });
    const relayed: ACEMessage[] = [];
    const transport = directOrRelayWith({ send: async (e) => { relayed.push(e); } }, 'https://bob.example',
      async () => { throw new ACEError('direct_unavailable'); });
    expect(await alice.outbox.deliver(p.requestId, transport)).toBe('relay');
    expect(relayed.map((e) => e.messageId)).toEqual([p.message.messageId]);
    expect((await alice.outbox.pending()).map((x) => x.requestId)).not.toContain(p.requestId); // acknowledged
  });
});
