/** Relay HTTP client (08-relay), including an SSE parser over `fetch`. */

import { ACEError, type ACEErrorCode } from './errors.js';
import { isACEId, wireInt } from './encoding.js';
import { createAuthHeaders, type RelayAuthRequest } from './auth.js';
import { readLimited, verifyPeerRecord, type VerifiedPeer } from './discovery.js';
import { MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE } from './limits.js';
import { createRegistrationRequest } from './registration.js';
import type { ACEIdentity, ACEMessage, AgentProfile, DiscoverQuery, Intent } from './types.js';

const STREAM_ID_RE = /^[0-9]+-[0-9]+$/;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const SSE_FRAME_LIMIT = MAX_ENVELOPE_BYTES + 512;
const MAX_FAILED_CONNECTS = 10;
const MAX_BACKOFF_MS = 30_000;
const LISTEN_IDLE_MS = 90_000;

export function isStreamId(v: unknown): v is string {
  return typeof v === 'string' && v.length <= 64 && STREAM_ID_RE.test(v);
}

/** Compare two stream IDs as integer pairs (ms, seq). */
export function compareStreamIds(a: string, b: string): number {
  const [am, as] = a.split('-').map(BigInt);
  const [bm, bs] = b.split('-').map(BigInt);
  return am !== bm ? (am < bm ? -1 : 1) : as !== bs ? (as < bs ? -1 : 1) : 0;
}

/** Normalize a relay base URL: lowercase scheme and host, no trailing '/'; no query or fragment. */
export function normalizeRelayUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new ACEError('invalid_argument', 'relay URL is not a valid URL');
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password || u.search || u.hash) {
    throw new ACEError('invalid_argument', 'relay URL must be http(s) without credentials, query or fragment');
  }
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

export interface RelayClientOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  clock?: () => number;
  /** First listen reconnect delay; doubles up to 30 s (default 1000). */
  reconnectBaseMs?: number;
}

export interface InboxPage {
  entries: Array<{ streamId: string; message: unknown }>;
  cursor: string | null;
}

export interface ListenEvent {
  streamId: string;
  message: unknown;
  catchup: boolean;
}

function retryAfter(res: Response): number | undefined {
  const v = res.headers.get('retry-after');
  if (v === null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.ceil(n) : undefined;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      resolve();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Map an HTTP error response to an ACEError (design §2.14). */
async function errorFor(res: Response): Promise<ACEError> {
  let relayCode: string | undefined;
  let message = '';
  try {
    const body = JSON.parse(new TextDecoder().decode(await readLimited(res, 64 * 1024)));
    if (typeof body?.error === 'string') relayCode = body.error.slice(0, 64);
    if (typeof body?.message === 'string') message = body.message.slice(0, 200);
  } catch {
    // body is informational only
  }
  const s = res.status;
  const opts = { status: s, relayCode, retryAfterSeconds: retryAfter(res) };
  const text = `HTTP ${s}${relayCode ? ` ${relayCode}` : ''}${message ? `: ${message}` : ''}`;
  if (s >= 500 || s === 408 || s === 429) return new ACEError('relay_unavailable', text, opts);
  let code: ACEErrorCode = 'relay_rejected';
  if (s === 400 && relayCode === 'envelope_expired') code = 'envelope_expired';
  else if (s === 404 && relayCode === 'unknown_peer') code = 'unknown_peer';
  else if (s === 403 && relayCode === 'not_registered') code = 'not_registered';
  else if (s < 400) return new ACEError('relay_protocol_error', `unexpected ${text}`, opts);
  return new ACEError(code, text, opts);
}

function protocolError(msg: string): ACEError {
  return new ACEError('relay_protocol_error', msg);
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** HTTP client for one relay. Every authenticated call uses a strictly increasing timestamp. */
export class RelayClient {
  readonly baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #clock?: () => number;
  readonly #reconnectBaseMs: number;
  #lastTs = -1;

  constructor(baseUrl: string, opts: RelayClientOptions = {}) {
    this.baseUrl = normalizeRelayUrl(baseUrl);
    this.#fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxResponseBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.#clock = opts.clock;
    this.#reconnectBaseMs = opts.reconnectBaseMs ?? 1000;
    if (!(this.#timeoutMs > 0) || !Number.isSafeInteger(this.#maxResponseBytes) || this.#maxResponseBytes < 1 || !(this.#reconnectBaseMs >= 0)) {
      throw new ACEError('invalid_argument', 'invalid RelayClient options');
    }
  }

  #nextTs(): number {
    const now = Math.floor(this.#clock ? this.#clock() : Date.now() / 1000);
    this.#lastTs = Math.max(now, this.#lastTs + 1);
    return this.#lastTs;
  }

  #url(path: string, params: Record<string, string | undefined> = {}): string {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, v);
    const s = q.toString();
    return `${this.baseUrl}${path}${s ? `?${s}` : ''}`;
  }

  /** One request with timeout; returns the parsed JSON body of a 2xx response. */
  async #request(method: string, url: string, init: { headers?: Record<string, string>; body?: unknown } = {}): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.#fetch(url, {
          method,
          headers: { Accept: 'application/json', ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
          body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
          signal: controller.signal,
          redirect: 'error',
        });
      } catch (e) {
        throw new ACEError('relay_unavailable', `request failed: ${e instanceof Error ? e.message : String(e)}`.slice(0, 300), { cause: e });
      }
      if (res.status < 200 || res.status >= 300) throw await errorFor(res);
      let raw: Uint8Array;
      try {
        raw = await readLimited(res, this.#maxResponseBytes + 1);
      } catch (e) {
        throw new ACEError('relay_unavailable', 'reading the response failed', { cause: e });
      }
      if (raw.length > this.#maxResponseBytes) throw protocolError('response exceeds maxResponseBytes');
      try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
      } catch {
        throw protocolError('response is not JSON');
      }
    } finally {
      clearTimeout(timer);
    }
  }

  /** An authenticated request; retried once with a fresh timestamp on 409 `replay`. */
  async #authed(identity: ACEIdentity, req: RelayAuthRequest, method: string, url: string, body?: unknown): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      const headers = await createAuthHeaders(identity, req, this.#nextTs());
      try {
        return await this.#request(method, url, { headers: { ...headers }, body });
      } catch (e) {
        if (attempt === 0 && e instanceof ACEError && e.status === 409 && e.relayCode === 'replay') continue;
        throw e;
      }
    }
  }

  async register(identity: ACEIdentity, profile?: AgentProfile | null): Promise<{ status: 'registered' | 'idempotent' | 'refreshed' | 'rotated' }> {
    const body = await createRegistrationRequest(identity, profile, this.#nextTs());
    const res = await this.#request('POST', this.#url('/v1/register'), { body });
    const status = isObj(res) ? res.status : undefined;
    if (status !== 'registered' && status !== 'idempotent' && status !== 'refreshed' && status !== 'rotated') {
      throw protocolError('unexpected register response');
    }
    return { status };
  }

  async unregister(identity: ACEIdentity): Promise<void> {
    await this.#authed(identity, { action: 'unregister' }, 'POST', this.#url('/v1/unregister'));
  }

  /** `GET /v1/peer`; the record must be for `aceId` and must verify (`invalid_peer`). */
  async lookupPeer(aceId: string): Promise<VerifiedPeer> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'aceId must be an ACE ID');
    const res = await this.#request('GET', this.#url('/v1/peer', { aceId }));
    if (!isObj(res)) throw protocolError('peer record must be an object');
    if (res.aceId !== aceId) throw new ACEError('invalid_peer', 'relay returned a record for another ACE ID');
    return verifyPeerRecord(res);
  }

  /** `GET /v1/discover`; unverifiable entries are dropped and counted in `rejected`. */
  async discover(q: DiscoverQuery = {}): Promise<{ agents: VerifiedPeer[]; rejected: number; cursor: string | null }> {
    const res = await this.#request('GET', this.#url('/v1/discover', {
      q: q.q, tags: q.tags, chain: q.chain, scheme: q.scheme,
      online: q.online === undefined ? undefined : String(q.online),
      limit: q.limit === undefined ? undefined : String(q.limit), cursor: q.cursor,
    }));
    if (!isObj(res) || !Array.isArray(res.agents)) throw protocolError('discover response must have agents');
    const agents: VerifiedPeer[] = [];
    let rejected = 0;
    for (const a of res.agents) {
      try {
        agents.push(verifyPeerRecord(a));
      } catch {
        rejected++;
      }
    }
    return { agents, rejected, cursor: typeof res.cursor === 'string' ? res.cursor : null };
  }

  /** `POST /v1/send`. A valid `Outbox.deliver` transport. */
  async send(env: ACEMessage): Promise<void> {
    await this.#request('POST', this.#url('/v1/send'), { body: { message: env } });
  }

  async fetchInbox(identity: ACEIdentity, o: { since?: string; limit?: number } = {}): Promise<InboxPage> {
    const since = o.since ?? '-';
    const limit = o.limit ?? MAX_INBOX_PAGE;
    const res = await this.#authed(identity, { action: 'inbox', since, limit }, 'GET',
      this.#url('/v1/inbox', { since: since === '-' ? undefined : since, limit: String(limit) }));
    if (!isObj(res) || !Array.isArray(res.messages)) throw protocolError('inbox response must have messages');
    const entries = res.messages.map((m) => {
      if (!isObj(m) || !isStreamId(m.streamId) || !('message' in m)) throw protocolError('invalid inbox entry');
      return { streamId: m.streamId, message: m.message };
    });
    if (entries.length > limit) throw protocolError('inbox page exceeds the limit');
    return { entries, cursor: isStreamId(res.cursor) ? res.cursor : null };
  }

  /**
   * `GET /v1/listen` as an async iterable (catchup, then live). Reconnects internally: at once
   * after a clean end or `drain`; after a failed connect or broken stream with backoff
   * min(30 s, max(1, 2, 4 … s, Retry-After)). Any received frame resets the failure count;
   * 10 consecutive failures → `relay_unavailable`; a non-retryable status → its mapped error;
   * a connection idle for 90 s counts as broken. Resumes after the last yielded stream ID.
   * Aborting `signal` ends the iteration.
   */
  async *listen(identity: ACEIdentity, o: { since?: string; signal?: AbortSignal } = {}): AsyncGenerator<ListenEvent, void, undefined> {
    let since = o.since ?? '-';
    if (since !== '-' && !isStreamId(since)) throw new ACEError('invalid_argument', "since must be '-' or '<ms>-<seq>'");
    const signal = o.signal;
    let failures = 0;
    while (!signal?.aborted) {
      try {
        for await (const ev of this.#listenOnce(identity, since, signal)) {
          failures = 0;
          if (ev === null) continue;
          yield ev;
          since = ev.streamId;
          if (signal?.aborted) return;
        }
        failures = 0;
        continue;
      } catch (e) {
        if (signal?.aborted) return;
        const err = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'listen failed', { cause: e });
        if (err.code !== 'relay_unavailable') throw err;
        failures++;
        if (failures >= MAX_FAILED_CONNECTS) throw err;
        let delay = Math.min(this.#reconnectBaseMs * 2 ** (failures - 1), MAX_BACKOFF_MS);
        if (err.retryAfterSeconds !== undefined) delay = Math.min(Math.max(delay, err.retryAfterSeconds * 1000), MAX_BACKOFF_MS);
        await sleep(delay, signal);
      }
    }
  }

  /** One listen connection: yields events, or null for frames that carry no message. */
  async *#listenOnce(identity: ACEIdentity, since: string, signal?: AbortSignal): AsyncGenerator<ListenEvent | null, void, undefined> {
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      let res: Response | null = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        const headers = await createAuthHeaders(identity, { action: 'listen', since }, this.#nextTs());
        const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
        try {
          res = await this.#fetch(this.#url('/v1/listen', { since: since === '-' ? undefined : since }), {
            headers: { Accept: 'text/event-stream', ...headers }, signal: controller.signal, redirect: 'error',
          });
        } catch (e) {
          throw new ACEError('relay_unavailable', `listen connect failed: ${e instanceof Error ? e.message : ''}`, { cause: e });
        } finally {
          clearTimeout(timer);
        }
        if (res.status === 200) break;
        const err = await errorFor(res);
        if (attempt === 0 && err.status === 409 && err.relayCode === 'replay') continue;
        throw err;
      }
      const media = (res!.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
      if (media !== 'text/event-stream' || res!.body === null) throw protocolError('listen response is not an event stream');
      try {
        for await (const ev of parseSSE(res!.body, LISTEN_IDLE_MS)) {
          if (ev.event === 'drain') return;
          if (ev.event !== 'catchup' && ev.event !== 'message') {
            yield null;
            continue;
          }
          if (!isStreamId(ev.id)) throw protocolError('SSE message without a valid id');
          let message: unknown;
          try {
            message = JSON.parse(ev.data);
          } catch {
            throw protocolError('SSE data is not JSON');
          }
          yield { streamId: ev.id, message, catchup: ev.event === 'catchup' };
        }
      } catch (e) {
        if (e instanceof ACEError) throw e;
        throw new ACEError('relay_unavailable', 'listen stream broke', { cause: e });
      }
    } finally {
      signal?.removeEventListener('abort', onAbort);
      controller.abort();
    }
  }

  async postIntent(
    identity: ACEIdentity, i: { need: string; tags?: string[]; maxPrice?: string; currency?: string; ttl: number },
  ): Promise<{ intentId: string; expiresAt: number }> {
    const req: RelayAuthRequest = {
      action: 'intent', need: i.need, tags: i.tags ?? [], maxPrice: i.maxPrice ?? null, currency: i.currency ?? null, ttl: i.ttl,
    };
    const body: Record<string, unknown> = { need: i.need, ttl: i.ttl };
    if (i.tags !== undefined) body.tags = i.tags;
    if (i.maxPrice !== undefined) body.maxPrice = i.maxPrice;
    if (i.currency !== undefined) body.currency = i.currency;
    const res = await this.#authed(identity, req, 'POST', this.#url('/v1/intents'), body);
    if (!isObj(res) || typeof res.intentId !== 'string' || wireInt(res.expiresAt) === null) throw protocolError('unexpected intent response');
    return { intentId: res.intentId, expiresAt: res.expiresAt as number };
  }

  async listIntents(q: { q?: string; tags?: string; limit?: number; cursor?: string } = {}): Promise<{ intents: Intent[]; cursor: string | null }> {
    const res = await this.#request('GET', this.#url('/v1/intents', {
      q: q.q, tags: q.tags, limit: q.limit === undefined ? undefined : String(q.limit), cursor: q.cursor,
    }));
    if (!isObj(res) || !Array.isArray(res.intents)) throw protocolError('intents response must have intents');
    const intents = res.intents.map((x): Intent => {
      if (
        !isObj(x) || typeof x.intentId !== 'string' || typeof x.from !== 'string' || typeof x.need !== 'string'
        || !Array.isArray(x.tags) || !x.tags.every((t) => typeof t === 'string') || wireInt(x.ttl) === null
        || wireInt(x.createdAt) === null || wireInt(x.expiresAt) === null
      ) {
        throw protocolError('invalid intent');
      }
      const out: Intent = {
        intentId: x.intentId, from: x.from, need: x.need, tags: x.tags as string[], ttl: x.ttl as number,
        createdAt: x.createdAt as number, expiresAt: x.expiresAt as number,
      };
      if (typeof x.maxPrice === 'string') out.maxPrice = x.maxPrice;
      if (typeof x.currency === 'string') out.currency = x.currency;
      return out;
    });
    return { intents, cursor: typeof res.cursor === 'string' ? res.cursor : null };
  }
}

// --- SSE -------------------------------------------------------------------------------

interface SSEEvent {
  id: string;
  event: string;
  data: string;
}

/**
 * Internal: a minimal Server-Sent Events parser (HTML Living Standard § 9.2.6) over a byte
 * stream. Lines end in LF, CRLF or CR; `:` lines are comments; an empty line dispatches.
 * A line or event larger than MAX_ENVELOPE_BYTES + 512 is `relay_protocol_error`.
 */
export async function* parseSSE(body: ReadableStream<Uint8Array>, idleMs?: number): AsyncGenerator<SSEEvent, void, undefined> {
  const decoder = new TextDecoder('utf-8');
  const reader = body.getReader();
  let buf = '';
  let id = '';
  let event = '';
  let data: string[] = [];
  let dataSize = 0;
  let first = true;
  try {
    for (;;) {
      const { done, value } = await readWithIdle(reader, idleMs);
      buf += done ? decoder.decode() : decoder.decode(value, { stream: true });
      if (first && buf.length > 0) {
        if (buf.charCodeAt(0) === 0xfeff) buf = buf.slice(1);
        first = false;
      }
      for (;;) {
        const m = /\r\n|\r|\n/.exec(buf);
        if (m === null) break;
        if (m[0] === '\r' && m.index === buf.length - 1 && !done) break; // CR may precede LF in the next chunk
        const line = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        if (line.length > SSE_FRAME_LIMIT) throw protocolError('SSE line exceeds the frame limit');
        if (line === '') {
          if (data.length > 0 || event !== '') yield { id, event: event || 'message', data: data.join('\n') };
          event = '';
          data = [];
          dataSize = 0;
          continue;
        }
        if (line.startsWith(':')) {
          yield { id, event: ':', data: '' }; // heartbeat: liveness only
          continue;
        }
        const colon = line.indexOf(':');
        const field = colon < 0 ? line : line.slice(0, colon);
        let val = colon < 0 ? '' : line.slice(colon + 1);
        if (val.startsWith(' ')) val = val.slice(1);
        if (field === 'data') {
          dataSize += val.length + 1;
          if (dataSize > SSE_FRAME_LIMIT) throw protocolError('SSE event exceeds the frame limit');
          data.push(val);
        } else if (field === 'event') {
          event = val;
        } else if (field === 'id') {
          if (!val.includes('\u0000')) id = val;
        }
      }
      if (buf.length > SSE_FRAME_LIMIT) throw protocolError('SSE line exceeds the frame limit');
      if (done) return;
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

async function readWithIdle(reader: ReadableStreamDefaultReader<Uint8Array>, idleMs?: number): Promise<{ done: boolean; value?: Uint8Array }> {
  if (idleMs === undefined) return reader.read();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const idle = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ACEError('relay_unavailable', 'listen connection idle')), idleMs);
  });
  try {
    return await Promise.race([reader.read(), idle]);
  } finally {
    clearTimeout(timer);
  }
}
