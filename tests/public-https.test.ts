// The outbound policy for untrusted public URLs (publicHttpsFetch, also behind publicRelay), at the socket boundary.
import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ lookup: vi.fn(), request: vi.fn() }));
vi.mock('node:dns', () => ({ promises: { lookup: mocks.lookup } }));
vi.mock('node:https', () => ({ request: mocks.request }));
import { publicHttpsFetch } from '../src/node.js';

const URL_ = 'https://client.example/doc.json';
function respond(body: string, status = 200, contentType = 'application/json') {
  mocks.request.mockImplementation((_options, callback) => {
    const req = new EventEmitter() as EventEmitter & { end(): void; destroy(): void };
    req.destroy = vi.fn();
    req.end = () => {
      const res = new EventEmitter() as EventEmitter & { statusCode: number; headers: object; destroy(): void; resume(): void };
      res.statusCode = status; res.headers = { 'content-type': contentType }; res.destroy = vi.fn(); res.resume = vi.fn();
      callback(res);
      setImmediate(() => { res.emit('data', Buffer.from(body)); res.emit('end'); }); // after the body reader attaches
    };
    return req;
  });
}
beforeEach(() => { vi.resetAllMocks(); mocks.lookup.mockResolvedValue([{ address: '8.8.8.8', family: 4 }]); respond('{"ok":true}'); });
afterEach(() => vi.useRealTimers());

describe('publicHttpsFetch', () => {
  it('connects only to the checked public answer while keeping the HTTPS hostname', async () => {
    const res = await publicHttpsFetch()(URL_, { headers: { accept: 'application/json', authorization: 'Bearer x' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    const [options] = mocks.request.mock.calls[0];
    expect(options).toMatchObject({ host: 'client.example', servername: 'client.example', port: 443, path: '/doc.json', method: 'GET' });
    expect(options.headers).toEqual({ accept: 'application/json' }); // credentials are never forwarded
    const callback = vi.fn(); options.lookup('client.example', { all: true }, callback);
    expect(callback).toHaveBeenCalledWith(null, [{ address: '8.8.8.8', family: 4 }]);
  });

  it.each(['http://client.example/x', 'https://user:secret@client.example/x', URL_ + '#fragment', 'file:///etc/passwd'])('refuses %s before DNS', async (url) => {
    await expect(publicHttpsFetch()(url)).rejects.toMatchObject({ code: 'invalid_argument' });
    expect(mocks.lookup).not.toHaveBeenCalled();
  });

  it.each(['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:127.0.0.1'])('refuses any private answer, even beside a public one: %s', async (address) => {
    mocks.lookup.mockResolvedValue([{ address: '8.8.8.8', family: 4 }, { address, family: address.includes(':') ? 6 : 4 }]);
    await expect(publicHttpsFetch()(URL_)).rejects.toMatchObject({ code: 'blocked_address' });
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it('returns a redirect as is (never follows it) and refuses an oversized body', async () => {
    respond('', 302);
    expect((await publicHttpsFetch()(URL_)).status).toBe(302);
    expect(mocks.request).toHaveBeenCalledTimes(1);
    respond(' '.repeat(33));
    await expect(publicHttpsFetch({ maxResponseBytes: 32 })(URL_)).rejects.toMatchObject({ code: 'relay_unavailable' });
  });

  it('bounds DNS resolution', async () => {
    vi.useFakeTimers(); mocks.lookup.mockReturnValue(new Promise(() => {}));
    const result = publicHttpsFetch({ timeoutMs: 5000 })(URL_).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5000);
    expect(await result).toMatchObject({ code: 'relay_unavailable' });
    expect(mocks.request).not.toHaveBeenCalled();
  });
});
