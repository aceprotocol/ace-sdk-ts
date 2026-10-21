/** Relay HTTP client for the minimal relay binding (opaque packets, descriptors, card records, blocks, inbox), with an SSE parser over `fetch`. */

import { ACEError, categoryOf, type ACEErrorCode } from './errors.js';
import { canonicalStateBytes, checkJsonValue, closedKeys, isACEId, isHandle, isObj, isStreamId, nowOf, pairKey, parseJSONBytes, parseStateBytes, utf8, wireInt } from './encoding.js';
import { withLock, type ACEStore } from './store.js';
import { createAuthHeaders, type AuthHeaders, type RelayAuthRequest } from './auth.js';
import { verifyCardBundle, type CardBundle } from './card-record.js';
import { verifyPublishedAgent, type DeliveryPermit, type PublishedAgent } from './descriptor.js';
import type { ACEIdentity } from './identity.js';
import { DEFAULT_PAGE_LIMIT, MAX_INBOX_PAGE, MAX_JSON_DEPTH, MAX_PACKET_BYTES, MAX_PAGE_BYTES } from './limits.js';
import type { Packet } from './packet.js';
import { readLimited } from './pinned-https.js';
import { createRegistrationRequest } from './registration.js';
import { normalizeRelayUrl } from './relay-url.js';

/** Internal: the RelayClient request timeout (also the transport limit of `publicRelay`). */
export const DEFAULT_TIMEOUT_MS = 10_000;
const SSE_FRAME_LIMIT = MAX_PACKET_BYTES + 512;
/** A response or SSE `data` as a whole: its deepest wrapper, an inbox page, holds packets at depth 3 (02 § JSON values). */
const RESPONSE_DEPTH = MAX_JSON_DEPTH + 3;
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

export interface RelayClientOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  clock?: () => number;
  /** First listen reconnect delay; doubles up to 30 s (default 1000). */
  reconnectBaseMs?: number;
  /** Development only: accept loopback `http://` relays inside descriptors. */
  allowLoopbackRelays?: boolean;
  /**
   * Where requests go when that differs from `baseUrl` (e.g. an internal address of the same relay). `baseUrl` stays
   * the signed audience, the inbox cursor key and the route this client stands for.
   */
  connectUrl?: string;
  /**
   * Persist the last registration/unregister timestamp per (relay, identity) in this store under the lock
   * `relay-registration`, so several processes sharing an identity keep it strictly increasing (07 § Registration).
   * Without it the ordering is per RelayClient instance.
   */
  store?: ACEStore;
}

/** One inbox page: opaque packets (decoded by the Inbox), each with its stream ID. */
export interface InboxPage {
  messages: Array<{ streamId: string; packet: unknown }>;
  cursor: string | null;
}

/** One SSE `catchup` / `message` frame. `data` is the raw frame data, `{"packet": …}`; the Inbox decodes it. */
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

/** A relay-supplied string without control characters (C0, DEL, C1), so it cannot forge lines in a host's logs. */
const printable = (s: string) => s.replace(/\p{Cc}/gu, '');

/**
 * Internal: map a relay response other than the call's expected success to an ACEError. `retryAfter` is
 * the raw `Retry-After` header, attached only when the mapped code is transient. The body's `error` and `message`
 * lose their control characters before they enter the error.
 */
export function relayErrorFor(status: number, retryAfter: string | null, body: string): ACEError {
  let relayCode: string | undefined;
  let message = '';
  try {
    const parsed: unknown = JSON.parse(body);
    if (isObj(parsed)) {
      if (typeof parsed.error === 'string') relayCode = printable(parsed.error);
      if (typeof parsed.message === 'string') message = printable(parsed.message).slice(0, 200);
    }
  } catch {
    // no relay error code
  }
  let code: ACEErrorCode;
  if (status < 400 || status >= 600) code = 'relay_protocol_error'; // 1xx, an unexpected 2xx, 3xx, out of range
  else if (status === 408 || status === 429 || status >= 500) code = 'relay_unavailable'; // any 429 is transient (07 § Client rules)
  else if (status === 403 && relayCode === 'not_registered') code = 'not_registered';
  else if (status === 403 && relayCode === 'not_permitted') code = 'not_permitted';
  else if (status === 404 && relayCode === 'unknown_peer') code = 'unknown_peer';
  else code = 'relay_rejected';
  const opts: { status: number; relayCode?: string; retryAfterSeconds?: number } = { status };
  if (relayCode !== undefined) opts.relayCode = relayCode;
  if (categoryOf(code) === 'transient' && retryAfter !== null && /^[0-9]+$/.test(retryAfter)) {
    const n = Number(retryAfter);
    if (Number.isSafeInteger(n)) opts.retryAfterSeconds = n;
  }
  const text = `HTTP ${status}${relayCode ? ` ${relayCode.slice(0, 64)}` : ''}${message ? `: ${message}` : ''}`;
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

/** A packet, PublishedAgent or CardBundle inside a response is within MAX_JSON_DEPTH on its own (02 § JSON values). */
function contained(value: unknown): void {
  checkJsonValue(value, 'relay_protocol_error');
}

/**
 * HTTP client for one relay. Every authenticated call uses a fresh nonce and wall-clock timestamp and is retried once on
 * 409 `replay`; `X-ACE-Seq` names the signing delegation. Relay records are verified at this client's clock.
 */
export class RelayClient {
  /** The normalized relay URL; also the key of this relay's persisted inbox cursor. */
  readonly baseUrl: string;
  /** Request origin: `connectUrl`, else `baseUrl`. */
  readonly #origin: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #clock?: () => number;
  readonly #reconnectBaseMs: number;
  readonly #verify: { allowLoopbackRelays?: boolean };
  #lastRegistrationTs = -1;
  readonly #store?: ACEStore;

  constructor(baseUrl: string, opts: RelayClientOptions = {}) {
    this.baseUrl = normalizeRelayUrl(baseUrl);
    this.#origin = opts.connectUrl === undefined ? this.baseUrl : normalizeRelayUrl(opts.connectUrl);
    this.#fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxResponseBytes = opts.maxResponseBytes ?? MAX_PAGE_BYTES;
    this.#clock = opts.clock;
    this.#reconnectBaseMs = opts.reconnectBaseMs ?? 1000;
    this.#verify = { allowLoopbackRelays: opts.allowLoopbackRelays };
    this.#store = opts.store;
    if (!(this.#timeoutMs > 0) || !Number.isSafeInteger(this.#maxResponseBytes) || this.#maxResponseBytes < 1 || !(this.#reconnectBaseMs >= 0)) {
      throw new ACEError('invalid_argument', 'invalid RelayClient options');
    }
  }

  #url(path: string, params: Record<string, string | undefined> = {}): string {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, v);
    const s = q.toString();
    return `${this.#origin}${path}${s ? `?${s}` : ''}`;
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
        if (e instanceof ACEError) throw e;
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
      return parseJSONBytes(raw, 'relay_protocol_error', 'response', RESPONSE_DEPTH);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Run `send` with fresh auth headers; retried once with a fresh timestamp on 409 `replay`. */
  async #withFreshAuth<T>(identity: ACEIdentity, req: RelayAuthRequest, send: (headers: AuthHeaders) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const now = nowOf(this.#clock);
      const ts = req.action === 'unregister' ? await this.#nextRegistrationTs(identity, now) : now;
      const headers = await createAuthHeaders(identity, req, ts, { audience: this.baseUrl });
      try {
        return await send(headers);
      } catch (e) {
        if (attempt === 0 && e instanceof ACEError && e.status === 409 && e.relayCode === 'replay') continue;
        throw e;
      }
    }
  }

  /** An authenticated request (see #withFreshAuth). */
  #authed(identity: ACEIdentity, req: RelayAuthRequest, method: string, url: string, body?: unknown): Promise<unknown> {
    return this.#withFreshAuth(identity, req, (headers) => this.#request(method, url, { headers: { ...headers }, body }));
  }

  /** The next strictly increasing registration-ordering timestamp (persisted when a store is configured). */
  async #nextRegistrationTs(identity: ACEIdentity, floor: number): Promise<number> {
    const next = (stored: number) => Math.max(floor, stored + 1, this.#lastRegistrationTs + 1);
    if (this.#store === undefined) return (this.#lastRegistrationTs = next(-1));
    const store = this.#store;
    const k = `relay/registration/${pairKey(this.baseUrl, identity.getACEId())}.json`;
    return withLock(store, 'relay-registration', async () => {
      const raw = await store.read(k);
      let stored = -1;
      if (raw !== null) {
        const d = parseStateBytes(raw, k);
        if (!isObj(d) || wireInt(d.timestamp) === null) throw new ACEError('storage_failed', `${k} is invalid`);
        stored = d.timestamp as number;
      }
      const ts = next(stored);
      await store.write(k, canonicalStateBytes({ version: 1, timestamp: ts }));
      return (this.#lastRegistrationTs = ts);
    });
  }

  async register(identity: ACEIdentity): Promise<{ status: 'registered' | 'idempotent' | 'refreshed' | 'rotated' }> {
    // Inbox/contact reads must not push publication ordering ahead of another local process.
    const body = await createRegistrationRequest(identity, { audience: this.baseUrl, timestamp: await this.#nextRegistrationTs(identity, nowOf(this.#clock)) });
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

  /** `POST /v1/descriptor`: publish this identity's PublishedAgent (its KEL must equal the registered KEL). */
  async publishDescriptor(agent: PublishedAgent): Promise<void> {
    verifyPublishedAgent(agent, nowOf(this.#clock), this.#verify);
    await this.#request('POST', this.#url('/v1/descriptor'), { body: agent });
  }

  /**
   * A relay response verified by `verify`, of identity `aceId` when given. Any failure is `relay_protocol_error`: a
   * conformant relay refused the document on input, so serving it is the relay's fault, never a verdict on the peer
   * (a permanent code would let one bad route end a lookup the next route serves).
   */
  #verified<T>(res: unknown, verify: (v: unknown) => T, idOf: (t: T) => string, what: string, aceId?: string): T {
    contained(res); // never a skipped entry
    let doc: T;
    try {
      doc = verify(res);
    } catch (e) {
      throw new ACEError('relay_protocol_error', `relay served an invalid ${what}${e instanceof ACEError ? `: ${e.message}` : ''}`, { cause: e });
    }
    if (aceId !== undefined && idOf(doc) !== aceId) throw protocolError(`${what} identity mismatch`);
    return doc;
  }

  #agent(res: unknown, aceId?: string): PublishedAgent {
    return this.#verified(res, (v) => verifyPublishedAgent(v, nowOf(this.#clock), this.#verify).agent, (a) => a.descriptor.aceId, 'descriptor', aceId);
  }

  /** `GET /v1/descriptor/{aceId}`: anonymous; the unexpired descriptor of any registered identity. */
  async getDescriptor(aceId: string): Promise<PublishedAgent> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'invalid ACE ID');
    return this.#agent(await this.#request('GET', this.#url(`/v1/descriptor/${encodeURIComponent(aceId)}`)), aceId);
  }

  /** `POST /v1/card`: publish this identity's CardBundle (its KEL must equal the registered KEL; the handle is set once). */
  async publishCard(bundle: CardBundle): Promise<void> {
    verifyCardBundle(bundle, nowOf(this.#clock), this.#verify);
    await this.#request('POST', this.#url('/v1/card'), { body: bundle });
  }

  #card(res: unknown, aceId?: string): CardBundle {
    return this.#verified(res, (v) => verifyCardBundle(v, nowOf(this.#clock), this.#verify).bundle, (b) => b.card.aceId, 'card record', aceId);
  }

  /** `GET /v1/card/{aceId}`: anonymous; the stored card record of a registered identity. */
  async card(aceId: string): Promise<CardBundle> {
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'invalid ACE ID');
    return this.#card(await this.#request('GET', this.#url(`/v1/card/${encodeURIComponent(aceId)}`)), aceId);
  }

  /**
   * `GET /v1/handles/{handle}`: the card record of the identity the handle is bound to at this relay. A record whose
   * `home` is not this relay or whose `handle` differs is `unknown_peer` (04 § Card record).
   */
  async handle(handle: string): Promise<CardBundle> {
    if (!isHandle(handle)) throw new ACEError('invalid_argument', 'invalid handle');
    const bundle = this.#card(await this.#request('GET', this.#url(`/v1/handles/${handle}`)));
    if (bundle.card.home !== this.baseUrl || bundle.card.handle !== handle) throw new ACEError('unknown_peer', 'the record does not hold this handle at this relay');
    return bundle;
  }

  /**
   * `GET /v1/descriptors?profile=&cursor=&limit=`: the public directory (identities whose card record is listed). Every
   * entry is verified; one that fails permanently or does not list the requested profile is skipped.
   */
  async listDescriptors(o: { profile?: string; cursor?: string; limit?: number } = {}): Promise<{ agents: PublishedAgent[]; cursor: string | null }> {
    const limit = o.limit ?? DEFAULT_PAGE_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_INBOX_PAGE) throw new ACEError('invalid_argument', 'invalid page limit');
    const res = await this.#request('GET', this.#url('/v1/descriptors', { profile: o.profile, cursor: o.cursor, limit: String(limit) }));
    if (!isObj(res) || !Array.isArray(res.agents) || res.agents.length > limit || !(res.cursor === null || typeof res.cursor === 'string')) throw protocolError('invalid descriptor page');
    const agents: PublishedAgent[] = [];
    for (const a of res.agents) {
      let agent: PublishedAgent;
      try { agent = this.#agent(a); } catch (e) { if (!(e instanceof ACEError) || e.isTransient) throw e; continue; }
      // Filtered by the exact profile ID when one was requested.
      if (o.profile !== undefined && !agent.descriptor.profiles.some((p) => p.id === o.profile)) continue;
      agents.push(agent);
    }
    return { agents, cursor: res.cursor };
  }

  /** `POST /v1/blocks`: a signed block or unblock of `peer`; `revision` must increase. */
  async setBlock(identity: ACEIdentity, peer: string, blocked: boolean, revision: number): Promise<void> {
    const req: RelayAuthRequest = { action: 'block', peer, blocked, revision };
    await this.#authed(identity, req, 'POST', this.#url('/v1/blocks'), { peer, blocked, revision });
  }

  /**
   * `PUT /v1/wake`: register (or replace) the gateway this relay wakes when entries are queued for `identity` (07 §
   * Wake hints); `token` is the gateway's opaque token. A relay without wake hints answers `relay_rejected` with relay
   * code `not_found`.
   */
  async setWake(identity: ACEIdentity, gateway: string, token: string): Promise<void> {
    // The auth payload checks gateway and token; a loopback http gateway is this client's development policy.
    if (this.#verify.allowLoopbackRelays !== true && typeof gateway === 'string' && gateway.startsWith('http://')) {
      throw new ACEError('invalid_argument', 'wake gateway must be https');
    }
    await this.#authed(identity, { action: 'wake', gateway, token }, 'PUT', this.#url('/v1/wake'), { gateway, token });
  }

  /** `DELETE /v1/wake`: remove the wake registration (idempotent). */
  async clearWake(identity: ACEIdentity): Promise<void> {
    await this.#authed(identity, { action: 'wake' }, 'DELETE', this.#url('/v1/wake'));
  }

  /**
   * `POST /v1/send {packet, permit?}`. `{ok: true}` means the relay stored it, not that it was delivered (only a
   * receipt says that). Without a permit the recipient's card record must be `open` (stranger quota).
   */
  async send(packet: Packet, permit?: DeliveryPermit): Promise<void> {
    // A permit is a bearer credential: attach it only to a packet it authorizes.
    if (permit !== undefined && (!isObj(permit) || !isObj(packet) || permit.issuer !== packet.to || permit.subject !== packet.from)) {
      throw new ACEError('invalid_argument', 'the permit must be issued by packet.to to packet.from');
    }
    const res = await this.#request('POST', this.#url('/v1/send'), { body: { packet, ...(permit ? { permit } : {}) } });
    if (!isObj(res) || res.ok !== true) throw protocolError('unexpected send response');
  }

  /** `GET /v1/inbox?since=&limit=`: non-destructive read. */
  async fetchInbox(identity: ACEIdentity, o: { since?: string; limit?: number } = {}): Promise<InboxPage> {
    const since = o.since ?? '-';
    const limit = o.limit ?? MAX_INBOX_PAGE;
    if (wireInt(limit) === null || limit < 1 || limit > MAX_INBOX_PAGE) throw new ACEError('invalid_argument', `limit must be an integer in 1..${MAX_INBOX_PAGE}`);
    const res = await this.#authed(identity, { action: 'inbox', since, limit }, 'GET',
      this.#url('/v1/inbox', { since: since === '-' ? undefined : since, limit: String(limit) }));
    if (!isObj(res) || !Array.isArray(res.messages) || res.messages.length > limit) throw protocolError('inbox response must have messages');
    const messages = res.messages.map((m) => {
      if (!closedKeys(m, ['streamId', 'packet']) || !isStreamId(m.streamId)) throw protocolError('invalid inbox entry');
      contained(m.packet);
      return { streamId: m.streamId, packet: m.packet };
    });
    if (!('cursor' in res) || (res.cursor !== null && !isStreamId(res.cursor))) throw protocolError('inbox cursor must be a stream ID or null');
    return { messages, cursor: res.cursor as string | null };
  }

  /** `POST /v1/inbox/ack?through=`: delete inbox entries up to and including `through`. */
  async ackInbox(identity: ACEIdentity, through: string): Promise<void> {
    await this.#authed(identity, { action: 'inbox-ack', through }, 'POST', this.#url('/v1/inbox/ack', { through }));
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
      const res = await this.#withFreshAuth(identity, { action: 'listen', since }, async (headers) => {
        const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
        let r: Response;
        try {
          r = await this.#fetch(this.#url('/v1/listen', { since: since === '-' ? undefined : since }), {
            headers: { Accept: 'text/event-stream', ...headers }, signal: controller.signal, redirect: 'manual',
          });
        } catch (e) {
          throw new ACEError('relay_unavailable', `listen connect failed: ${e instanceof Error ? e.message : ''}`, { cause: e });
        } finally {
          clearTimeout(timer);
        }
        if (r.status !== 200) throw await errorFor(r);
        return r;
      });
      const media = (res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
      if (media !== 'text/event-stream' || res.body === null) throw protocolError('listen response is not an event stream');
      yield CONNECTED;
      try {
        for await (const ev of parseSSE(res.body, LISTEN_IDLE_MS, controller.signal)) {
          if (controller.signal.aborted) return;
          if (ev.event === ':') {
            yield HEARTBEAT;
            continue;
          }
          if (ev.event === 'drain') {
            yield null; // progress: the relay asked for a reconnect, which is immediate
            return;
          }
          // connected and unknown types are not progress (07 § Client rules, Listen)
          if (ev.event !== 'catchup' && ev.event !== 'message') continue;
          if (!isStreamId(ev.id)) throw protocolError('SSE message without a valid id');
          const frame = parseJSONBytes(utf8(ev.data), 'relay_protocol_error', 'SSE data', RESPONSE_DEPTH);
          if (!isObj(frame) || !Object.hasOwn(frame, 'packet')) throw protocolError('SSE data must be {"packet": …}');
          contained(frame.packet);
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
 * event if it has a `data` field (07 § Client rules, Listen); `id` and `event` apply only
 * to the event they appear in.
 * A line or event larger than MAX_PACKET_BYTES + 512 is `relay_protocol_error`.
 * Aborting `signal` ends the iteration at once (pending reads included) and cancels the body;
 * so does closing the generator early.
 */
export async function* parseSSE(
  body: ReadableStream<Uint8Array>, idleMs?: number, signal?: AbortSignal,
): AsyncGenerator<SSEEvent, void, undefined> {
  const decoder = new TextDecoder('utf-8');
  const reader = body.getReader();
  let buf = '';
  let scanned = 0; // buf[0, scanned) holds no line ending: a long line is not rescanned per chunk
  const eol = /\r\n|\r|\n/g;
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
        eol.lastIndex = scanned;
        const m = eol.exec(buf);
        if (m === null) {
          scanned = buf.length;
          break;
        }
        if (m[0] === '\r' && m.index === buf.length - 1 && !done) { // CR may precede LF in the next chunk
          scanned = m.index;
          break;
        }
        const line = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        scanned = 0;
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
