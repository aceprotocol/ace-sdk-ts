/** Relay HTTP client (08-relay), including an SSE parser over `fetch`. */

import { ACEError, categoryOf, type ACEErrorCode } from './errors.js';
import { isACEId, isObj, isStreamId, wireInt } from './encoding.js';
import { createAuthHeaders, type RelayAuthRequest } from './auth.js';
import { readLimited, verifyPeerRecord, type VerifiedPeer } from './discovery.js';
import { MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE } from './limits.js';
import { createRegistrationRequest } from './registration.js';
import { validateExt } from './ext.js';
import type { ACEIdentity, ACEMessage, AgentProfile, DiscoverQuery, ExtMap, Intent } from './types.js';

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const SSE_FRAME_LIMIT = MAX_ENVELOPE_BYTES + 512;
const MAX_FAILED_CONNECTS = 10;
const MAX_BACKOFF_MS = 30_000;
/** Yielded by #listenOnce once a connection is established (listen runs onOpen). */
const CONNECTED = Symbol('connected');
/** Yielded by #listenOnce for an SSE comment (heartbeat): liveness only, not an event. */
const HEARTBEAT = Symbol('heartbeat');
const LISTEN_IDLE_MS = 90_000;

/** Compare two stream IDs as integer pairs (ms, seq). */
export function compareStreamIds(a: string, b: string): number {
  const [am, as] = a.split('-').map(BigInt);
  const [bm, bs] = b.split('-').map(BigInt);
  return am !== bm ? (am < bm ? -1 : 1) : as !== bs ? (as < bs ? -1 : 1) : 0;
}

/**
 * Normalize a relay base URL (08-relay § Client Rules, Relay URL): scheme `http`/`https`
 * written lowercase; no `?`, `#`, userinfo, or character <= U+0020 or U+007F (nothing is
 * trimmed); host ASCII `[A-Za-z0-9.-]+` or a bracketed IPv6 literal, written lowercase; port
 * 1..65535 without leading zeros, the scheme's default port removed; path kept verbatim
 * except that all trailing `/` are removed. Anything else is `invalid_argument`.
 */
export function normalizeRelayUrl(url: string): string {
  const bad = (why: string) => new ACEError('invalid_argument', `relay URL ${why}`);
  if (typeof url !== 'string') throw bad('must be a string');
  if (/[\u0000-\u0020\u007f?#]/.test(url)) throw bad('must not contain whitespace, control characters, "?" or "#"');
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)(.*)$/s.exec(url);
  if (m === null) throw bad('must be an absolute http(s) URL');
  const scheme = m[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') throw bad('scheme must be http or https');
  const authority = m[2];
  if (authority.includes('@')) throw bad('must not contain userinfo');
  let host: string;
  let port: string | undefined;
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) throw bad('has an invalid IPv6 host');
    host = authority.slice(0, end + 1);
    const rest = authority.slice(end + 1);
    if (rest !== '') {
      if (!rest.startsWith(':')) throw bad('has an invalid authority');
      port = rest.slice(1);
    }
    // an IPv6 literal (the WHATWG parser rejects anything else, including a zone)
    if (!/^\[[0-9A-Fa-f:.]+\]$/.test(host)) throw bad('has an invalid IPv6 host');
    try {
      new URL(`http://${host}/`);
    } catch {
      throw bad('has an invalid IPv6 host');
    }
  } else {
    const colon = authority.indexOf(':');
    host = colon < 0 ? authority : authority.slice(0, colon);
    if (colon >= 0) port = authority.slice(colon + 1);
    if (!/^[A-Za-z0-9.-]+$/.test(host)) throw bad('host must be ASCII [A-Za-z0-9.-]');
  }
  host = host.toLowerCase();
  if (port !== undefined) {
    if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) throw bad('has an invalid port');
    if ((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80')) port = undefined;
  }
  return `${scheme}://${host}${port !== undefined ? `:${port}` : ''}${m[3].replace(/\/+$/, '')}`;
}

export interface RelayClientOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  clock?: () => number;
  /** First listen reconnect delay; doubles up to 30 s (default 1000). */
  reconnectBaseMs?: number;
}

/** Internal: SDK-side tags parameter (string array) to the comma-separated query value. */
function tagsParam(tags: unknown): string | undefined {
  if (tags === undefined) return undefined;
  if (!Array.isArray(tags) || !tags.every((t) => typeof t === 'string' && t.length > 0 && !t.includes(','))) {
    throw new ACEError('invalid_argument', 'tags must be an array of non-empty strings without ","');
  }
  return tags.length === 0 ? undefined : tags.join(',');
}

export interface InboxPage {
  entries: Array<{ streamId: string; message: unknown }>;
  cursor: string | null;
}

export interface Webhook {
  url: string;
  status: 'active' | 'disabled';
  failures: number;
  updatedAt: number;
  lastDeliveredAt?: number;
  lastError?: string;
}

/**
 * One SSE `catchup` / `message` frame. `data` is the raw frame data; the relay client does
 * not parse it (the Inbox decides: a frame that is not an envelope is quarantined).
 */
export interface ListenEvent {
  streamId: string;
  data: string;
  catchup: boolean;
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

/**
 * Internal: map a relay response other than the call's expected success to an ACEError
 * (08-relay § Client Rules, Responses; `test-vectors.json` → `relayErrors`). `retryAfter` is
 * the raw `Retry-After` header, attached only when the mapped code is transient.
 */
export function relayErrorFor(status: number, retryAfter: string | null, body: string): ACEError {
  let relayCode: string | undefined;
  let message = '';
  try {
    const parsed: unknown = JSON.parse(body);
    if (isObj(parsed)) {
      if (typeof parsed.error === 'string') relayCode = parsed.error;
      if (typeof parsed.message === 'string') message = parsed.message.slice(0, 200);
    }
  } catch {
    // no relay error code
  }
  const s = status;
  let code: ACEErrorCode;
  if (s < 400 || s >= 600) code = 'relay_protocol_error'; // 1xx, an unexpected 2xx, 3xx, out of range
  else if (s === 408 || s >= 500) code = 'relay_unavailable';
  else if (s === 429) code = relayCode === undefined || relayCode === 'rate_limited' ? 'relay_unavailable' : 'relay_rejected';
  else if (s === 400 && relayCode === 'envelope_expired') code = 'envelope_expired';
  else if (s === 403 && relayCode === 'not_registered') code = 'not_registered';
  else if (s === 404 && relayCode === 'unknown_peer') code = 'unknown_peer';
  else code = 'relay_rejected';
  const opts: { status: number; relayCode?: string; retryAfterSeconds?: number } = { status: s };
  if (relayCode !== undefined) opts.relayCode = relayCode;
  if (categoryOf(code) === 'transient' && retryAfter !== null && /^[0-9]+$/.test(retryAfter)) {
    const n = Number(retryAfter);
    if (Number.isSafeInteger(n)) opts.retryAfterSeconds = n;
  }
  const text = `HTTP ${s}${relayCode ? ` ${relayCode.slice(0, 64)}` : ''}${message ? `: ${message}` : ''}`;
  return new ACEError(code, text, opts);
}

async function errorFor(res: Response): Promise<ACEError> {
  // fetch with redirect: 'manual' in a browser yields an opaque redirect (status 0)
  if (res.type === 'opaqueredirect' || res.status === 0) {
    return new ACEError('relay_protocol_error', 'the relay answered with a redirect');
  }
  let body = '';
  try {
    body = new TextDecoder().decode(await readLimited(res, 64 * 1024));
  } catch {
    // the body is informational only
  }
  return relayErrorFor(res.status, res.headers.get('retry-after'), body);
}

function protocolError(msg: string): ACEError {
  return new ACEError('relay_protocol_error', msg);
}

/** A page's required `cursor`: a string or null. */
function pageCursor(res: Record<string, unknown>): string | null {
  if (!('cursor' in res) || (res.cursor !== null && typeof res.cursor !== 'string')) throw protocolError('cursor must be a string or null');
  return res.cursor;
}

/** HTTP client for one relay. Every authenticated call uses a strictly increasing timestamp. */
export class RelayClient {
  /** The normalized relay URL; also the key of this relay's persisted inbox cursor. */
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
          redirect: 'manual', // never followed: a 3xx is relay_protocol_error
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
      q: q.q, tags: tagsParam(q.tags), scheme: q.scheme, account: q.account,
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
    return { agents, rejected, cursor: pageCursor(res) };
  }

  /** `POST /v1/send`. A valid `Outbox.deliver` transport. */
  async send(env: ACEMessage): Promise<void> {
    await this.#request('POST', this.#url('/v1/send'), { body: { message: env } });
  }

  async fetchInbox(identity: ACEIdentity, o: { since?: string; limit?: number } = {}): Promise<InboxPage> {
    const since = o.since ?? '-';
    const limit = o.limit ?? MAX_INBOX_PAGE;
    if (wireInt(limit) === null || limit < 1 || limit > MAX_INBOX_PAGE) {
      throw new ACEError('invalid_argument', `limit must be an integer in 1..${MAX_INBOX_PAGE}`);
    }
    const res = await this.#authed(identity, { action: 'inbox', since, limit }, 'GET',
      this.#url('/v1/inbox', { since: since === '-' ? undefined : since, limit: String(limit) }));
    if (!isObj(res) || !Array.isArray(res.messages)) throw protocolError('inbox response must have messages');
    const entries = res.messages.map((m) => {
      if (!isObj(m) || !isStreamId(m.streamId) || !('message' in m)) throw protocolError('invalid inbox entry');
      return { streamId: m.streamId, message: m.message };
    });
    if (entries.length > limit) throw protocolError('inbox page exceeds the limit');
    if (!('cursor' in res) || (res.cursor !== null && !isStreamId(res.cursor))) throw protocolError('inbox cursor must be a stream ID or null');
    return { entries, cursor: res.cursor };
  }

  /**
   * `GET /v1/listen` as an async iterable (catchup, then live). Reconnects internally: at once
   * after a clean end or `drain` once that connection carried a `catchup`, `message` or `drain`
   * frame; after a failed connect, a broken stream, or a stream that ended without one (only
   * `connected`, heartbeats or nothing) with backoff min(30 s, max(1, 2, 4 … s, Retry-After)).
   * A `catchup`, `message` or `drain` frame resets the failure count (`connected`, other event
   * types and comments do not);
   * 10 consecutive failures → `relay_unavailable`; a non-retryable status → its mapped error;
   * a connection idle for 90 s counts as broken. Resumes after the last yielded stream ID.
   * Aborting `signal` ends the iteration promptly — during a stream (even one carrying only
   * heartbeats), a connect or a backoff sleep — and closes the connection; so does the
   * consumer leaving the loop early (`break` / `return()`). `onOpen` runs each time a
   * connection is established (the first and every reconnect).
   */
  async *listen(
    identity: ACEIdentity, o: { since?: string; signal?: AbortSignal; onOpen?: () => void } = {},
  ): AsyncGenerator<ListenEvent, void, undefined> {
    let since = o.since ?? '-';
    if (since !== '-' && !isStreamId(since)) throw new ACEError('invalid_argument', "since must be '-' or '<ms>-<seq>'");
    const signal = o.signal;
    let failures = 0;
    while (!signal?.aborted) {
      // Only reading the stream is inside the try: an error from onOpen, or one thrown in at
      // the yield (`.throw()`), is the caller's and propagates as is — never a reconnect.
      const stream = this.#listenOnce(identity, since, signal);
      let gotEvent = false; // a catchup / message / drain frame arrived on this connection
      try {
        while (true) {
          let next: IteratorResult<ListenEvent | null | typeof CONNECTED | typeof HEARTBEAT, void> | undefined;
          let failure: ACEError | undefined;
          try {
            next = await stream.next();
          } catch (e) {
            if (signal?.aborted) return;
            failure = e instanceof ACEError ? e : new ACEError('relay_unavailable', 'listen failed', { cause: e });
            if (failure.code !== 'relay_unavailable') throw failure;
          }
          if (signal?.aborted) return; // checked on every frame, heartbeats included
          if (next?.done === true) {
            if (gotEvent) { // clean end or drain after progress: reconnect at once
              failures = 0;
              break;
            }
            failure = new ACEError('relay_unavailable', 'listen stream ended without progress');
          }
          if (failure !== undefined || next === undefined || next.done === true) {
            const err = failure ?? new ACEError('relay_unavailable', 'listen failed');
            failures++;
            if (failures >= MAX_FAILED_CONNECTS) throw err;
            let delay = Math.min(this.#reconnectBaseMs * 2 ** (failures - 1), MAX_BACKOFF_MS);
            if (err.retryAfterSeconds !== undefined) delay = Math.min(Math.max(delay, err.retryAfterSeconds * 1000), MAX_BACKOFF_MS);
            await sleep(delay, signal);
            break;
          }
          const ev = next.value;
          if (ev === CONNECTED) {
            o.onOpen?.();
            continue;
          }
          if (ev === HEARTBEAT) continue;
          failures = 0;
          gotEvent = true;
          if (ev === null) continue;
          yield ev;
          since = ev.streamId;
        }
      } finally {
        await stream.return();
      }
    }
  }

  /** One listen connection: yields CONNECTED once established, then events, HEARTBEAT for
   * comments, or null for events that carry no message. */
  async *#listenOnce(
    identity: ACEIdentity, since: string, signal?: AbortSignal,
  ): AsyncGenerator<ListenEvent | null | typeof CONNECTED | typeof HEARTBEAT, void, undefined> {
    // Linked controller: aborts the fetch (and its body) on caller abort, connect timeout, or
    // generator exit. parseSSE also watches it and cancels the body reader itself, because
    // undici does not always cancel a body that is already streaming.
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    if (signal?.aborted) return;
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      let res: Response | null = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        const headers = await createAuthHeaders(identity, { action: 'listen', since }, this.#nextTs());
        const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
        try {
          res = await this.#fetch(this.#url('/v1/listen', { since: since === '-' ? undefined : since }), {
            headers: { Accept: 'text/event-stream', ...headers }, signal: controller.signal, redirect: 'manual',
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
      yield CONNECTED;
      try {
        for await (const ev of parseSSE(res!.body, LISTEN_IDLE_MS, controller.signal)) {
          if (controller.signal.aborted) return;
          if (ev.event === ':') {
            yield HEARTBEAT;
            continue;
          }
          if (ev.event === 'drain') {
            yield null; // progress: the relay asked for a reconnect, which is immediate
            return;
          }
          // connected and unknown types are not progress (08 § Client Rules, Listen)
          if (ev.event !== 'catchup' && ev.event !== 'message') continue;
          if (!isStreamId(ev.id)) throw protocolError('SSE message without a valid id');
          yield { streamId: ev.id, data: ev.data, catchup: ev.event === 'catchup' };
        }
      } catch (e) {
        if (signal?.aborted) return;
        if (e instanceof ACEError) throw e;
        throw new ACEError('relay_unavailable', 'listen stream broke', { cause: e });
      }
    } finally {
      signal?.removeEventListener('abort', onAbort);
      controller.abort();
    }
  }

  /**
   * `POST /v1/intents`. `ext` follows the profile `ext` rules (`invalid_argument`); put `maxPrice` / `currency` under
   * `ext['urn:ace:commerce:1']`. An empty `ext` is not sent.
   */
  async postIntent(
    identity: ACEIdentity, i: { need: string; tags?: string[]; ext?: ExtMap | null; ttl: number },
  ): Promise<{ intentId: string; expiresAt: number }> {
    const tags = i.tags ?? [];
    const ext = validateExt(i.ext, 'intent');
    const req: RelayAuthRequest = { action: 'intent', need: i.need, tags, ext: ext ?? null, ttl: i.ttl };
    // the body mirrors the signed payload: tags is always sent (possibly empty), ext only when non-empty
    const body: Record<string, unknown> = { need: i.need, tags, ttl: i.ttl };
    if (ext !== undefined) body.ext = ext;
    const res = await this.#authed(identity, req, 'POST', this.#url('/v1/intents'), body);
    if (!isObj(res) || typeof res.intentId !== 'string' || wireInt(res.expiresAt) === null) throw protocolError('unexpected intent response');
    return { intentId: res.intentId, expiresAt: res.expiresAt as number };
  }

  async listIntents(q: { q?: string; tags?: string[]; limit?: number; cursor?: string } = {}): Promise<{ intents: Intent[]; cursor: string | null }> {
    const res = await this.#request('GET', this.#url('/v1/intents', {
      q: q.q, tags: tagsParam(q.tags), limit: q.limit === undefined ? undefined : String(q.limit), cursor: q.cursor,
    }));
    if (!isObj(res) || !Array.isArray(res.intents)) throw protocolError('intents response must have intents');
    const intents = res.intents.map((x): Intent => {
      if (
        !isObj(x) || typeof x.intentId !== 'string' || !isACEId(x.from) || typeof x.need !== 'string'
        || !Array.isArray(x.tags) || !x.tags.every((t) => typeof t === 'string') || wireInt(x.ttl) === null
        || wireInt(x.createdAt) === null || wireInt(x.expiresAt) === null
      ) {
        throw protocolError('invalid intent');
      }
      const out: Intent = {
        intentId: x.intentId, from: x.from, need: x.need, tags: x.tags as string[], ttl: x.ttl as number,
        createdAt: x.createdAt as number, expiresAt: x.expiresAt as number,
      };
      // optional ext: absent is fine; present but malformed (02 § Profile Fields rules) is a protocol error
      if (x.ext !== undefined) {
        let ext: ExtMap | undefined;
        try {
          ext = validateExt(x.ext, 'intent');
        } catch (e) {
          throw protocolError(`invalid intent ext: ${e instanceof ACEError ? e.message : 'malformed'}`);
        }
        if (ext !== undefined) out.ext = ext;
      }
      return out;
    });
    return { intents, cursor: pageCursor(res) };
  }

  /** `PUT /v1/webhook`: set or replace this identity's webhook. */
  async setWebhook(identity: ACEIdentity, { url, secret }: { url: string; secret: string }): Promise<void> {
    await this.#authed(identity, { action: 'webhook', method: 'PUT', url, secret }, 'PUT', this.#url('/v1/webhook'), { url, secret });
  }

  /** `GET /v1/webhook`; null when none is set. */
  async getWebhook(identity: ACEIdentity): Promise<Webhook | null> {
    const res = await this.#authed(identity, { action: 'webhook', method: 'GET', url: '', secret: '' }, 'GET', this.#url('/v1/webhook'));
    if (!isObj(res) || !('webhook' in res)) throw protocolError('webhook response must have webhook');
    const w = res.webhook;
    if (w === null) return null;
    if (
      !isObj(w) || typeof w.url !== 'string' || (w.status !== 'active' && w.status !== 'disabled')
      || wireInt(w.failures) === null || wireInt(w.updatedAt) === null
    ) {
      throw protocolError('invalid webhook');
    }
    const out: Webhook = { url: w.url, status: w.status, failures: w.failures as number, updatedAt: w.updatedAt as number };
    // Optional fields: absent is fine; present but malformed is a protocol error.
    if (w.lastDeliveredAt !== undefined) {
      if (wireInt(w.lastDeliveredAt) === null) throw protocolError('invalid webhook lastDeliveredAt');
      out.lastDeliveredAt = w.lastDeliveredAt as number;
    }
    if (w.lastError !== undefined) {
      if (typeof w.lastError !== 'string') throw protocolError('invalid webhook lastError');
      out.lastError = w.lastError;
    }
    return out;
  }

  /** `DELETE /v1/webhook` (idempotent). */
  async clearWebhook(identity: ACEIdentity): Promise<void> {
    await this.#authed(identity, { action: 'webhook', method: 'DELETE', url: '', secret: '' }, 'DELETE', this.#url('/v1/webhook'));
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
 * stream. Lines end in LF, CRLF or CR; `:` lines are comments; an empty line dispatches the
 * event if it has a `data` field (08-relay § Client Rules, Listen); `id` and `event` apply only
 * to the event they appear in.
 * A line or event larger than MAX_ENVELOPE_BYTES + 512 is `relay_protocol_error`.
 * Aborting `signal` ends the iteration at once (pending reads included) and cancels the body;
 * so does closing the generator early.
 */
export async function* parseSSE(
  body: ReadableStream<Uint8Array>, idleMs?: number, signal?: AbortSignal,
): AsyncGenerator<SSEEvent, void, undefined> {
  const decoder = new TextDecoder('utf-8');
  const reader = body.getReader();
  let buf = '';
  let id = '';
  let event = '';
  let data: string[] = [];
  let dataSize = 0;
  let first = true;
  const onAbort = () => {
    reader.cancel().catch(() => {});
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    for (;;) {
      if (signal?.aborted) return;
      const { done, value } = await readWithIdle(reader, idleMs, signal);
      if (signal?.aborted) return;
      buf += done ? decoder.decode() : decoder.decode(value, { stream: true });
      if (first && buf.length > 0) {
        if (buf.charCodeAt(0) === 0xfeff) buf = buf.slice(1);
        first = false;
      }
      for (;;) {
        if (signal?.aborted) return;
        const m = /\r\n|\r|\n/.exec(buf);
        if (m === null) break;
        if (m[0] === '\r' && m.index === buf.length - 1 && !done) break; // CR may precede LF in the next chunk
        const line = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        if (line.length > SSE_FRAME_LIMIT) throw protocolError('SSE line exceeds the frame limit');
        if (line === '') {
          // dispatch only an event with a data field; id and event are per event
          if (data.length > 0) yield { id, event: event || 'message', data: data.join('\n') };
          id = '';
          event = '';
          data = [];
          dataSize = 0;
          continue;
        }
        if (line.startsWith(':')) {
          yield { id: '', event: ':', data: '' }; // heartbeat: liveness only
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
    signal?.removeEventListener('abort', onAbort);
    // Do not await: a misbehaving body must not be able to hold up the caller's exit.
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {
      /* a pending read on an old runtime */
    }
  }
}

/** One read, raced against the idle timeout and the abort signal (abort reads as end of stream). */
async function readWithIdle(
  reader: ReadableStreamDefaultReader<Uint8Array>, idleMs?: number, signal?: AbortSignal,
): Promise<{ done: boolean; value?: Uint8Array }> {
  if (idleMs === undefined && signal === undefined) return reader.read();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const racers: Array<Promise<{ done: boolean; value?: Uint8Array }>> = [reader.read()];
  if (idleMs !== undefined) {
    racers.push(new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new ACEError('relay_unavailable', 'listen connection idle')), idleMs);
    }));
  }
  if (signal !== undefined) {
    racers.push(new Promise((resolve) => {
      onAbort = () => resolve({ done: true });
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }));
  }
  try {
    return await Promise.race(racers);
  } finally {
    clearTimeout(timer);
    if (onAbort !== undefined) signal?.removeEventListener('abort', onAbort);
  }
}
