/**
 * Test support for hosts (`@ace-protocol/sdk/testing`): an in-memory relay. Never imported by the SDK itself.
 */
import { ACEError } from './errors.js';
import { verifyCardBundle, type CardBundle } from './card-record.js';
import { documentDigest, verifyPermit, verifyPublishedAgent, type PublishedAgent } from './descriptor.js';
import { parseAuthHeaders, verifyAuthHeaders, type RelayAuthRequest } from './auth.js';
import { lastEventHash, type KelState } from './kel.js';
import { decodePacket } from './packet.js';
import { verifyRegistrationRequest } from './registration.js';
import { compareStreamIds, RelayClient } from './relay.js';

export const RELAY = 'https://relay.test';

class HTTPError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}

interface Entry { streamId: string; packet: unknown; raw: string }

/**
 * An in-memory relay implementing the relay binding behind `fetch`, for host tests (`relay.fetch` into a RelayClient or
 * `NetworkClient.open`). Error statuses and codes follow the relay; packet signatures are not checked (the receiver
 * does that). Not for production.
 */
export class FakeRelay {
  readonly baseUrl: string;
  clock: () => number;
  kels = new Map<string, KelState>();
  descriptors = new Map<string, PublishedAgent>();
  /** Stored card records by ACE ID. */
  cards = new Map<string, CardBundle>();
  /** Handle bindings (permanent, set once per identity). */
  handles = new Map<string, string>();
  blocks = new Map<string, { blocked: boolean; revision: number }>();
  wakes = new Map<string, { gateway: string; token: string }>();
  queues = new Map<string, Entry[]>();
  nonces = new Set<string>();
  seq = 0;
  sent: Array<{ packet: unknown; permit?: unknown }> = [];
  /** Answer the next request to `path` with this error instead (consumed in order). */
  inject: Array<{ path: string; status: number; code: string }> = [];
  /** Loopback `http://` relays are accepted when this relay itself is one (local development). */
  readonly #verify: { allowLoopbackRelays: boolean };

  registrations = 0;
  listeners = new Map<string, Set<ReadableStreamDefaultController<Uint8Array>>>();

  constructor(clock: () => number = () => Math.floor(Date.now() / 1000), baseUrl = RELAY) {
    this.clock = clock;
    this.baseUrl = baseUrl;
    this.#verify = { allowLoopbackRelays: baseUrl.startsWith('http://') };
  }

  client(): RelayClient { return new RelayClient(this.baseUrl, { fetch: this.fetch, clock: this.clock, ...this.#verify }); }

  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const method = init?.method ?? 'GET';
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => { headers[k] = v; });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const json = (status: number, v: unknown) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
    const injected = this.inject.findIndex((x) => x.path === url.pathname);
    if (injected >= 0) {
      const [x] = this.inject.splice(injected, 1);
      return json(x.status, { error: x.code });
    }
    try {
      if (method === 'GET' && url.pathname === '/v1/listen') return this.#listen(url, headers, init?.signal ?? undefined);
      return json(200, await this.route(method, url, headers, body));
    } catch (e) {
      if (e instanceof HTTPError) return json(e.status, { error: e.code });
      if (e instanceof ACEError) return json(STATUS[e.code] ?? 400, { error: e.code });
      throw e;
    }
  };

  #auth(headers: Record<string, string>, req: RelayAuthRequest): string {
    const auth = parseAuthHeaders(headers);
    const state = this.kels.get(auth.aceId);
    if (!state) throw new HTTPError(403, 'not_registered');
    verifyAuthHeaders(auth, req, state, { audience: this.baseUrl, clock: this.clock });
    if (this.nonces.has(auth.nonce)) throw new HTTPError(409, 'replay');
    this.nonces.add(auth.nonce);
    return auth.aceId;
  }

  /** The authenticated SSE stream: catch-up after `since`, then each new packet as it arrives. */
  #listen(url: URL, headers: Record<string, string>, signal?: AbortSignal): Response {
    const since = url.searchParams.get('since') ?? '-';
    const owner = this.#auth(headers, { action: 'listen', since });
    const enc = new TextEncoder();
    let ctrl!: ReadableStreamDefaultController<Uint8Array>;
    const set = this.listeners.get(owner) ?? new Set();
    this.listeners.set(owner, set);
    const stream = new ReadableStream<Uint8Array>({
      start: (c) => {
        ctrl = c;
        set.add(c);
        c.enqueue(enc.encode(': connected\n\n'));
        for (const e of this.queues.get(owner) ?? []) {
          if (since === '-' || compareStreamIds(e.streamId, since) > 0) c.enqueue(enc.encode(frame('catchup', e)));
        }
      },
      cancel: () => { set.delete(ctrl); },
    });
    signal?.addEventListener('abort', () => { set.delete(ctrl); try { ctrl.close(); } catch { /* closed */ } }, { once: true });
    return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }

  /** The unexpired descriptor of a registered identity. */
  #live(id: string): PublishedAgent | undefined {
    const d = this.descriptors.get(id);
    return d && this.kels.has(id) && d.descriptor.expiresAt > this.clock() ? d : undefined;
  }

  #handleOf(id: string): string | undefined {
    for (const [h, owner] of this.handles) if (owner === id) return h;
    return undefined;
  }

  async route(method: string, url: URL, headers: Record<string, string>, body: any): Promise<unknown> {
    const path = url.pathname;
    const now = this.clock();
    if (method === 'POST' && path === '/v1/register') {
      const { state } = verifyRegistrationRequest(body, { audience: this.baseUrl, clock: this.clock });
      this.kels.set(state.aceId, state);
      this.registrations++;
      return { ok: true, status: 'registered' };
    }
    if (method === 'POST' && path === '/v1/descriptor') {
      const { agent, state } = verifyPublishedAgent(body, now, this.#verify);
      const reg = this.kels.get(state.aceId);
      if (!reg) throw new HTTPError(403, 'not_registered');
      if (reg.lastHash !== state.lastHash) throw new HTTPError(409, 'kel_conflict');
      if (!agent.descriptor.relays.includes(this.baseUrl)) throw new HTTPError(400, 'invalid_argument');
      this.descriptors.set(state.aceId, agent);
      return { ok: true };
    }
    let m = /^\/v1\/descriptor\/(.+)$/.exec(path);
    if (method === 'GET' && m) {
      const d = this.#live(decodeURIComponent(m[1]));
      if (!d) throw new HTTPError(404, 'unknown_peer');
      return d;
    }
    if (method === 'POST' && path === '/v1/card') {
      const { record, kelState } = verifyCardBundle(body, now, this.#verify);
      const reg = this.kels.get(record.aceId);
      if (!reg) throw new HTTPError(403, 'not_registered');
      if (reg.lastHash !== kelState.lastHash) throw new HTTPError(409, 'kel_conflict');
      // 07: a stored record under another KEL is absent, also here: it does not bound the new issuedAt.
      const old = this.cards.get(record.aceId);
      if (old && lastEventHash(old.kel) === reg.lastHash && (old.card.issuedAt > record.issuedAt || (old.card.issuedAt === record.issuedAt && documentDigest(old.card) !== documentDigest(record)))) {
        throw new HTTPError(409, 'stale_descriptor');
      }
      // 07 § Descriptors and cards: a handle is set once per identity and never reassigned.
      // A record naming another home claims nothing here (an existing binding stays).
      const bound = this.#handleOf(record.aceId);
      if (record.home === this.baseUrl) {
        if (bound !== undefined) {
          if (record.handle !== bound) throw new HTTPError(400, 'invalid_argument');
        } else if (record.handle !== undefined) {
          if (this.handles.has(record.handle)) throw new HTTPError(409, 'handle_taken');
          this.handles.set(record.handle, record.aceId);
        }
      }
      this.cards.set(record.aceId, body as CardBundle);
      return { ok: true };
    }
    m = /^\/v1\/card\/(.+)$/.exec(path);
    if (method === 'GET' && m) {
      const id = decodeURIComponent(m[1]);
      const c = this.kels.has(id) ? this.cards.get(id) : undefined;
      if (!c) throw new HTTPError(404, 'unknown_peer');
      return c;
    }
    m = /^\/v1\/handles\/(.+)$/.exec(path);
    if (method === 'GET' && m) {
      const owner = this.handles.get(m[1]);
      const c = owner !== undefined && this.kels.has(owner) ? this.cards.get(owner) : undefined;
      if (!c || c.card.home !== this.baseUrl) throw new HTTPError(404, 'unknown_peer');
      return c;
    }
    if (method === 'GET' && path === '/v1/cards') {
      // Listed records naming this relay as home whose descriptor is unexpired, by ACE ID; `profile` reads the descriptor.
      const tag = url.searchParams.get('tag'), profile = url.searchParams.get('profile');
      const cards = [...this.cards.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).filter(([id, c]) => {
        const d = c.card.listed === true && c.card.home === this.baseUrl ? this.#live(id) : undefined;
        return d !== undefined && (!tag || (c.card.card.tags ?? []).includes(tag)) && (!profile || d.descriptor.profiles.some((p) => p.id === profile));
      }).map(([, c]) => c);
      return { cards: cards.slice(0, Number(url.searchParams.get('limit') ?? 20)), cursor: null };
    }
    if (method === 'POST' && path === '/v1/blocks') {
      const owner = this.#auth(headers, { action: 'block', peer: body.peer, blocked: body.blocked, revision: body.revision });
      const k = `${owner}|${body.peer}`, old = this.blocks.get(k);
      if (old && body.revision <= old.revision) throw new HTTPError(409, 'stale_revision');
      this.blocks.set(k, { blocked: body.blocked, revision: body.revision });
      return { ok: true };
    }
    if (method === 'PUT' && path === '/v1/wake') {
      const owner = this.#auth(headers, { action: 'wake', gateway: body?.gateway, token: body?.token });
      this.wakes.set(owner, { gateway: body.gateway, token: body.token });
      return { ok: true };
    }
    if (method === 'DELETE' && path === '/v1/wake') {
      this.wakes.delete(this.#auth(headers, { action: 'wake' }));
      return { ok: true };
    }
    if (method === 'POST' && path === '/v1/send') {
      const packet = decodePacket(body.packet);
      if (packet.timestamp > now + 300 || packet.timestamp < now - 604800) throw new HTTPError(400, 'stale_timestamp');
      const reg = this.kels.get(packet.to);
      if (!reg) throw new HTTPError(404, 'unknown_peer');
      const raw = JSON.stringify(body.packet);
      const q = this.queues.get(packet.to) ?? [];
      if (q.some((e) => e.raw === raw)) return { ok: true };
      if (this.blocks.get(`${packet.to}|${packet.from}`)?.blocked) throw new HTTPError(403, 'not_permitted');
      if (body.permit) {
        try { verifyPermit(body.permit, reg, packet.from, now); if (body.permit.issuer !== packet.to) throw new Error(); }
        catch { throw new HTTPError(403, 'not_permitted'); }
      } else if (this.cards.get(packet.to)?.card.contact !== 'open' || !this.#live(packet.to)) {
        throw new HTTPError(403, 'not_permitted');
      }
      this.sent.push(body);
      const entry = { streamId: `${now * 1000}-${this.seq++}`, packet: body.packet, raw };
      q.push(entry);
      this.queues.set(packet.to, q);
      const enc = new TextEncoder();
      for (const c of this.listeners.get(packet.to) ?? []) { try { c.enqueue(enc.encode(frame('message', entry))); } catch { /* closed */ } }
      return { ok: true };
    }
    if (method === 'GET' && path === '/v1/inbox') {
      const since = url.searchParams.get('since') ?? '-', limit = Number(url.searchParams.get('limit') ?? 100);
      const owner = this.#auth(headers, { action: 'inbox', since, limit });
      const q = (this.queues.get(owner) ?? []).filter((e) => since === '-' || compareStreamIds(e.streamId, since) > 0).slice(0, limit);
      return { messages: q.map((e) => ({ streamId: e.streamId, packet: e.packet })), cursor: q.length ? q[q.length - 1].streamId : null };
    }
    if (method === 'POST' && path === '/v1/inbox/ack') {
      const through = url.searchParams.get('through')!;
      const owner = this.#auth(headers, { action: 'inbox-ack', through });
      this.queues.set(owner, (this.queues.get(owner) ?? []).filter((e) => compareStreamIds(e.streamId, through) > 0));
      return { ok: true };
    }
    throw new HTTPError(404, 'not_found');
  }

  pending(aceId: string): number { return this.queues.get(aceId)?.length ?? 0; }
}

/** 07 § Errors: the statuses of the verifier codes that are not 400. */
const STATUS: Partial<Record<string, number>> = {
  invalid_signature: 401, invalid_authorization: 401, stale_seq: 401, stale_peer_binding: 401, future_seq: 409, kel_conflict: 409,
};

const frame = (event: string, e: Entry) => `event: ${event}\nid: ${e.streamId}\ndata: ${JSON.stringify({ packet: e.packet })}\n\n`;
