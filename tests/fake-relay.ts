// A minimal in-process relay implementing enough of 08-relay.md for client tests.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  ACEError, decodeEnvelope, envelopeFingerprint, fromBase64, parseAuthHeaders, verifyAuthHeaders,
  verifyEnvelopeSignature, verifyRegistrationRequest, type PeerRecord, type RelayAuthRequest,
} from '../src/index.js';
import { canonicalStateBytes } from '../src/encoding.js';

class HTTPError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code);
  }
}

type Entry = [string, unknown];

/** An SSE frame whose `data` is sent verbatim (not JSON-encoded). */
export class RawFrame {
  constructor(readonly data: string) {}
}

export class FakeRelay {
  clock: () => number;
  identities = new Map<string, PeerRecord>();
  streams = new Map<string, Entry[]>();
  stored = new Map<string, string>();
  seenAuth = new Set<string>();
  intents: Record<string, unknown>[] = [];
  webhooks = new Map<string, { url: string; secret: string; updatedAt: number }>();
  extraAgents: unknown[] = [];
  /** One-shot responses for the next request to `path`: an error `code`, or a raw `body`. */
  inject: Array<{ path: string; status: number; headers?: Record<string, string> } & ({ code: string } | { body: unknown })> = [];
  drainAfter: number | null = null;
  /** Close the next N listen connections right after `connected` (no events). */
  dropListens = 0;
  /** Live-phase heartbeat interval for listen streams. */
  heartbeatMs = 200;
  requests: Array<[string, string]> = [];
  /** Request query strings and JSON bodies, by path. */
  queries: Array<[string, Record<string, string>]> = [];
  bodies: Array<[string, unknown]> = [];
  authTimestamps: number[] = [];
  url = '';
  #server: Server;
  #seq = 0;
  #waiters = new Set<() => void>();
  #open = new Set<ServerResponse>();

  constructor(clock?: () => number) {
    this.clock = clock ?? (() => Math.floor(Date.now() / 1000));
    this.#server = createServer((req, res) => {
      this.#dispatch(req, res).catch((e) => {
        if (!res.headersSent) this.#error(res, 500, String(e));
      });
    });
  }

  /** Listen responses the server still holds open (a client disconnect removes it). */
  get openListens(): number {
    return this.#open.size;
  }

  async start(): Promise<this> {
    await new Promise<void>((r) => this.#server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.#server.address() as AddressInfo).port}`;
    return this;
  }

  async close(): Promise<void> {
    for (const r of this.#open) r.end();
    this.#server.closeAllConnections();
    await new Promise<void>((r) => this.#server.close(() => r()));
  }

  enqueueRaw(to: string, message: unknown): string {
    const sid = `${1000 + ++this.#seq}-0`;
    const list = this.streams.get(to) ?? [];
    list.push([sid, message]);
    this.streams.set(to, list);
    for (const w of this.#waiters) w();
    return sid;
  }

  #after(aceId: string, since: string): Entry[] {
    const key = (s: string) => s.split('-').map(Number);
    const all = this.streams.get(aceId) ?? [];
    if (since === '-') return [...all];
    const [sm, ss] = key(since);
    return all.filter(([sid]) => {
      const [m, q] = key(sid);
      return m > sm || (m === sm && q > ss);
    });
  }

  #reply(res: ServerResponse, status: number, obj?: unknown, headers: Record<string, string> = {}): void {
    const body = obj === undefined ? '' : JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers });
    res.end(body);
  }

  #error(res: ServerResponse, status: number, code: string, headers?: Record<string, string>): void {
    this.#reply(res, status, { error: code, message: code }, headers);
  }

  #auth(req: IncomingMessage, r: RelayAuthRequest): string {
    const auth = parseAuthHeaders(req.headers as Record<string, string>);
    this.authTimestamps.push(auth.timestamp);
    const ident = this.identities.get(auth.aceId);
    if (ident === undefined) throw new HTTPError(403, 'not_registered');
    try {
      verifyAuthHeaders(auth, r, { aceId: auth.aceId, scheme: ident.scheme, signingPublicKey: fromBase64(ident.signingPublicKey) }, { clock: this.clock });
    } catch (e) {
      const code = (e as ACEError).code;
      throw new HTTPError(code === 'invalid_signature' ? 401 : 400, code);
    }
    const key = `${r.action}|${auth.aceId}|${auth.signature}`;
    if (this.seenAuth.has(key)) throw new HTTPError(409, 'replay');
    this.seenAuth.add(key);
    return auth.aceId;
  }

  async #dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const u = new URL(req.url ?? '/', 'http://x');
    const path = u.pathname;
    const query = Object.fromEntries(u.searchParams);
    this.requests.push([req.method ?? '', path]);
    this.queries.push([path, query]);
    const i = this.inject.findIndex((x) => x.path === path);
    if (i >= 0) {
      const [inj] = this.inject.splice(i, 1);
      return 'body' in inj ? this.#reply(res, inj.status, inj.body, inj.headers) : this.#error(res, inj.status, inj.code, inj.headers);
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString('utf8');
    try {
      const body = raw ? JSON.parse(raw) : undefined;
      if (body !== undefined) this.bodies.push([path, body]);
      const route = `${req.method} ${path}`;
      switch (route) {
        case 'POST /v1/register': return this.#register(res, body);
        case 'POST /v1/unregister': {
          const id = this.#auth(req, { action: 'unregister' });
          this.identities.delete(id);
          return this.#reply(res, 200, { ok: true });
        }
        case 'GET /v1/peer': {
          const rec = this.identities.get(query.aceId ?? '');
          if (!rec) throw new HTTPError(404, 'unknown_peer');
          return this.#reply(res, 200, rec);
        }
        case 'GET /v1/discover':
          return this.#reply(res, 200, { agents: [...this.identities.values(), ...this.extraAgents], cursor: null });
        case 'POST /v1/send': return this.#send(res, body);
        case 'GET /v1/inbox': {
          const since = query.since ?? '-';
          const limit = Number(query.limit ?? '100');
          const id = this.#auth(req, { action: 'inbox', since, limit });
          const entries = this.#after(id, since).slice(0, limit);
          return this.#reply(res, 200, {
            messages: entries.map(([streamId, message]) => ({ streamId, message })),
            cursor: entries.length ? entries[entries.length - 1][0] : null,
          });
        }
        case 'GET /v1/listen': return await this.#listen(req, res, query.since ?? '-');
        case 'POST /v1/intents': {
          const id = this.#auth(req, {
            action: 'intent', need: body.need, tags: body.tags ?? [], ext: body.ext ?? null, ttl: body.ttl,
          });
          const now = this.clock();
          const intent: Record<string, unknown> = {
            intentId: crypto.randomUUID(), from: id, need: body.need, tags: body.tags ?? [], ttl: body.ttl, createdAt: now, expiresAt: now + body.ttl,
          };
          // stored re-canonicalised, served as is, present only when non-empty
          if (body.ext !== undefined && body.ext !== null && Object.keys(body.ext).length > 0) intent.ext = JSON.parse(new TextDecoder().decode(canonicalStateBytes(body.ext)));
          this.intents.push(intent);
          return this.#reply(res, 201, { intentId: intent.intentId, expiresAt: intent.expiresAt });
        }
        case 'GET /v1/intents': return this.#reply(res, 200, { intents: this.intents, cursor: null });
        case 'PUT /v1/webhook': {
          if (typeof body?.url !== 'string' || typeof body?.secret !== 'string') return this.#error(res, 400, 'invalid_argument');
          const { url, secret } = body;
          const id = this.#auth(req, { action: 'webhook', method: 'PUT', url, secret });
          this.webhooks.set(id, { url, secret, updatedAt: this.clock() });
          return this.#reply(res, 200, { ok: true });
        }
        case 'GET /v1/webhook': {
          const id = this.#auth(req, { action: 'webhook', method: 'GET', url: '', secret: '' });
          const w = this.webhooks.get(id);
          return this.#reply(res, 200, { webhook: w ? { url: w.url, status: 'active', failures: 0, updatedAt: w.updatedAt } : null });
        }
        case 'DELETE /v1/webhook': {
          const id = this.#auth(req, { action: 'webhook', method: 'DELETE', url: '', secret: '' });
          this.webhooks.delete(id);
          return this.#reply(res, 200, { ok: true });
        }
        default: throw new HTTPError(404, 'not_found');
      }
    } catch (e) {
      if (e instanceof HTTPError) return this.#error(res, e.status, e.code);
      if (e instanceof ACEError) return this.#error(res, 400, e.code);
      throw e;
    }
  }

  #register(res: ServerResponse, body: unknown): void {
    const { request: r } = verifyRegistrationRequest(body, { clock: this.clock });
    const prev = this.identities.get(r.aceId);
    const rec: PeerRecord = {
      aceId: r.aceId, scheme: r.scheme, encryptionPublicKey: r.encryptionPublicKey, signingPublicKey: r.signingPublicKey,
      registrationSignature: r.signature, registeredAt: r.timestamp,
    };
    const profile = r.profile !== undefined ? r.profile : prev?.profile;
    if (profile) rec.profile = profile;
    let status: string;
    if (!prev) status = 'registered';
    else if (prev.registeredAt > r.timestamp) throw new HTTPError(409, 'identity_conflict');
    else if (prev.registeredAt === r.timestamp) status = 'idempotent';
    else status = prev.encryptionPublicKey === r.encryptionPublicKey ? 'refreshed' : 'rotated';
    this.identities.set(r.aceId, rec);
    this.#reply(res, 200, { ok: true, status });
  }

  #send(res: ServerResponse, body: any): void {
    if (typeof body?.message !== 'object' || body.message === null) throw new HTTPError(400, 'invalid_envelope');
    let env;
    try {
      env = decodeEnvelope(body.message);
    } catch {
      throw new HTTPError(400, 'invalid_envelope');
    }
    const sender = this.identities.get(env.from);
    if (!sender) throw new HTTPError(403, 'not_registered');
    if (!this.identities.has(env.to)) throw new HTTPError(404, 'unknown_peer');
    try {
      verifyEnvelopeSignature(env, { scheme: sender.scheme, signingPublicKey: fromBase64(sender.signingPublicKey) });
    } catch {
      throw new HTTPError(401, 'invalid_signature');
    }
    const fp = envelopeFingerprint(env);
    const key = `${env.from}|${env.messageId}`;
    const prev = this.stored.get(key);
    if (prev !== undefined) {
      if (prev === fp) return this.#reply(res, 200, { ok: true });
      throw new HTTPError(409, 'message_id_conflict');
    }
    if (Math.abs(this.clock() - env.timestamp) > 300) throw new HTTPError(400, 'envelope_expired');
    this.stored.set(key, fp);
    this.enqueueRaw(env.to, body.message);
    this.#reply(res, 200, { ok: true });
  }

  async #listen(req: IncomingMessage, res: ServerResponse, since: string): Promise<void> {
    const id = this.#auth(req, { action: 'listen', since });
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('event: connected\ndata: {}\n\n: heartbeat\n\n');
    if (this.dropListens > 0) {
      this.dropListens--;
      res.end();
      return;
    }
    this.#open.add(res);
    let closed = false;
    res.on('close', () => {
      closed = true;
      this.#open.delete(res);
    });
    let last = since;
    let catchup = true;
    let sent = 0;
    while (!closed) {
      const entries = this.#after(id, last);
      if (entries.length === 0) {
        catchup = false;
        await new Promise<void>((r) => {
          const w = () => {
            this.#waiters.delete(w);
            clearTimeout(t);
            r();
          };
          const t = setTimeout(w, this.heartbeatMs);
          this.#waiters.add(w);
        });
        if (!closed) res.write(': hb\n\n');
        continue;
      }
      for (const [sid, msg] of entries) {
        if (this.drainAfter !== null && sent >= this.drainAfter) {
          this.drainAfter = null;
          res.end('event: drain\ndata: {}\n\n');
          return;
        }
        const data = msg instanceof RawFrame ? msg.data : JSON.stringify(msg);
        res.write(`id: ${sid}\nevent: ${catchup ? 'catchup' : 'message'}\ndata: ${data}\n\n`);
        sent++;
        last = sid;
      }
      catchup = false;
    }
  }
}
