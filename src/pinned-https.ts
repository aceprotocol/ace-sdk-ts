/**
 * Internal: one HTTPS request connected only to an already validated address (DNS pinning),
 * shared by `fetchRegistrationFile` and `postDirect`. Node only, but this module imports no
 * `node:` module itself: the caller passes the `https` module in, so the main entry stays free
 * of static Node imports.
 */

import { ACEError } from './errors.js';

export type HttpsModule = Pick<typeof import('node:https'), 'request'>;

export type LookupFn = (host: string, opts: { all: true; verbatim: true }) => Promise<Array<{ address: string; family: number }>>;

export interface PinnedResponse {
  status: number;
  contentType: string;
  /** At most `limit` bytes of the body. */
  body: () => Promise<Uint8Array>;
}

export interface PinnedRequest {
  /** Host name for the Host header, SNI and certificate validation. */
  host: string;
  /** The validated address the connection goes to. */
  addr: { address: string; family: number };
  port: number;
  path: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: Uint8Array;
  timeoutMs: number;
  limit: number;
  /** Whether the body of a response with this status will be read (otherwise it is discarded). */
  readBody: (status: number) => boolean;
  /** The error for a network failure, timeout or read failure. */
  fail: (message: string) => ACEError;
}

const IP_LITERAL = /^(?:[0-9.]+|.*:.*)$/;

/** One request pinned to `o.addr`; redirects are never followed (Node's https does not). */
export function pinnedRequest(https: HttpsModule, o: PinnedRequest): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    const fail = (e: unknown) => reject(e instanceof ACEError ? e : o.fail(`request failed: ${e instanceof Error ? e.message : String(e)}`));
    const pinned = (_host: string, opts: unknown, cb: (...args: unknown[]) => void) => {
      const all = typeof opts === 'object' && opts !== null && (opts as { all?: boolean }).all === true;
      if (all) cb(null, [{ address: o.addr.address, family: o.addr.family }]);
      else cb(null, o.addr.address, o.addr.family);
    };
    const timer = setTimeout(() => {
      req.destroy(o.fail(`timed out after ${o.timeoutMs} ms`));
    }, o.timeoutMs);
    (timer as { unref?: () => void }).unref?.();
    const req = https.request({
      host: o.host, ...(IP_LITERAL.test(o.host) ? {} : { servername: o.host }), port: o.port, path: o.path, method: o.method,
      headers: o.headers, lookup: pinned as never, agent: false,
    }, (msg) => {
      const status = msg.statusCode ?? 0;
      const contentType = String(msg.headers['content-type'] ?? '');
      const body = () => new Promise<Uint8Array>((res2, rej2) => {
        const chunks: Buffer[] = [];
        let total = 0;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          res2(new Uint8Array(Buffer.concat(chunks).subarray(0, o.limit)));
        };
        msg.on('data', (c: Buffer) => {
          chunks.push(c);
          total += c.length;
          if (total >= o.limit) {
            finish();
            msg.destroy();
          }
        });
        msg.on('end', finish);
        msg.on('error', (e) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          rej2(o.fail(`read failed: ${e.message}`));
        });
      });
      if (!o.readBody(status)) {
        clearTimeout(timer);
        msg.resume();
      }
      resolve({ status, contentType, body });
    });
    req.on('error', (e) => {
      clearTimeout(timer);
      fail(e);
    });
    req.end(o.body);
  });
}

/** The `node:https` module, or null outside Node. */
export async function loadHttps(): Promise<HttpsModule | null> {
  try {
    return await import('node:https');
  } catch {
    return null;
  }
}

/** `node:dns` lookup, or null outside Node. */
export async function loadLookup(): Promise<LookupFn | null> {
  try {
    const dns = await import('node:dns');
    return dns.promises.lookup as unknown as LookupFn;
  } catch {
    return null;
  }
}
