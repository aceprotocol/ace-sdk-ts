/**
 * Internal: the sending side of direct delivery (08-relay § Direct Delivery, Sender). The
 * public entry points (`postDirect`, `deliverDirectOrRelay`) live in the `./node` entry, which
 * supplies the Node network modules.
 */

import { ACEError } from './errors.js';
import { isHttpsUrl, isObj, utf8 } from './encoding.js';
import { decodeEnvelope } from './envelope.js';
import { isBlockedAddress } from './discovery.js';
import { pinnedRequest, type HttpsModule, type LookupFn } from './pinned-https.js';
import type { ACEMessage } from './types.js';

export const DEFAULT_DIRECT_TIMEOUT_MS = 5000;
const MAX_REPLY_BYTES = 64 * 1024;
/** A receiver `error` string kept as `remoteCode` (08-relay § Direct Delivery, Sender). */
const REMOTE_CODE_RE = /^[a-z0-9_]{1,64}$/;

export interface PostDirectOptions {
  /** Whole-request timeout (default 5000 ms). */
  timeoutMs?: number;
}

export interface DirectDeps {
  lookup: LookupFn;
  https: HttpsModule;
  /** Tests only: TCP port override and private addresses allowed. */
  port?: number;
  allowPrivateAddresses?: boolean;
}

/** `postDirect` with injected network modules. */
export async function postDirectWith(endpoint: string, envelope: ACEMessage, opts: PostDirectOptions, deps: DirectDeps): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_DIRECT_TIMEOUT_MS;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ACEError('invalid_argument', 'timeoutMs must be positive');
  }
  if (!isHttpsUrl(endpoint)) throw new ACEError('invalid_argument', 'endpoint must be an ACE HTTPS URL');
  let message: ACEMessage;
  try {
    message = decodeEnvelope(envelope);
  } catch (e) {
    throw new ACEError('invalid_argument', `envelope is invalid (${e instanceof ACEError ? e.code : 'error'})`, { cause: e });
  }
  const url = new URL(endpoint);
  const host = url.hostname;
  let addrs: Array<{ address: string; family: number }>;
  if (/^[0-9.]+$/.test(host)) {
    addrs = [{ address: host, family: 4 }];
  } else {
    try {
      addrs = await deps.lookup(host, { all: true, verbatim: true });
    } catch (e) {
      throw new ACEError('direct_unavailable', `DNS resolution failed: ${e instanceof Error ? e.message : ''}`.slice(0, 300), { cause: e });
    }
    if (addrs.length === 0) throw new ACEError('direct_unavailable', 'no addresses resolved');
  }
  if (deps.allowPrivateAddresses !== true && addrs.some((a) => isBlockedAddress(a.address))) {
    throw new ACEError('invalid_argument', 'endpoint resolves to a blocked address');
  }
  const body = utf8(JSON.stringify({ message }));
  const res = await pinnedRequest(deps.https, {
    host, addr: addrs[0], port: url.port !== '' ? Number(url.port) : deps.port ?? 443, path: `${url.pathname}${url.search}`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Content-Length': String(body.length) },
    body, timeoutMs, limit: MAX_REPLY_BYTES, readBody: () => true,
    fail: (msg) => new ACEError('direct_unavailable', msg),
  });
  const raw = await res.body();
  let reply: unknown = null;
  try {
    reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    // not JSON: decided by the status below
  }
  const s = res.status;
  if (s >= 200 && s < 300 && isObj(reply) && reply.ok === true) return;
  if (s === 400 || s === 413) {
    // peer-controlled text: kept only when it looks like an error code
    const error = isObj(reply) ? reply.error : undefined;
    const remoteCode = typeof error === 'string' && REMOTE_CODE_RE.test(error) ? error : undefined;
    const opts2: { status: number; remoteCode?: string } = { status: s };
    if (remoteCode !== undefined) opts2.remoteCode = remoteCode;
    throw new ACEError('direct_rejected', `HTTP ${s}${remoteCode !== undefined ? ` ${remoteCode}` : ''}`, opts2);
  }
  throw new ACEError('direct_unavailable', `HTTP ${s}`, { status: s });
}

/** Which path delivered an envelope. */
export type DeliveryPath = 'direct' | 'relay';

/** `deliverDirectOrRelay` with an injected direct sender. */
export function directOrRelayWith(
  relay: { send(env: ACEMessage): Promise<void> },
  endpoint: string | null | undefined,
  post: (endpoint: string, env: ACEMessage) => Promise<void>,
): (env: ACEMessage) => Promise<DeliveryPath> {
  if (typeof relay !== 'object' || relay === null || typeof relay.send !== 'function') {
    throw new ACEError('invalid_argument', 'relay must have send()');
  }
  return async (env) => {
    if (endpoint !== undefined && endpoint !== null) {
      try {
        await post(endpoint, env);
        return 'direct';
      } catch (e) {
        // direct_rejected: the recipient rejected this envelope; never re-sent through the relay
        if (!(e instanceof ACEError) || (e.code !== 'direct_unavailable' && e.code !== 'invalid_argument')) throw e;
      }
    }
    await relay.send(env);
    return 'relay';
  };
}
