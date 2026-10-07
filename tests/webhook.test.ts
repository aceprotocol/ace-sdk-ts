import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ACEError, SoftwareIdentity, verifyWebhookNotification, signWebhookNotification } from '../src/index.js';
import { authPayload } from '../src/auth.js';
import { encodePayload } from '../src/signing.js';

const SECRET = '0123456789abcdef0123456789abcdef';
const TS = 1741000000;
const ACE = 'ace:sha256:' + 'a'.repeat(64);
const BODY = JSON.stringify({ event: 'message', aceId: ACE, streamId: '1741000000000-0' });
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const sig = (o: { secret?: string; ts?: number; body?: string; prefix?: string } = {}) =>
  (o.prefix ?? 'sha256=') + createHmac('sha256', o.secret ?? SECRET).update(`${o.ts ?? TS}.`).update(o.body ?? BODY).digest('hex');

function expectCode(fn: () => unknown, code: string) {
  try { fn(); } catch (e) { expect((e as ACEError).code).toBe(code); return; }
  throw new Error(`expected ${code}`);
}

describe('webhook auth payload', () => {
  it('binds method, url and secret', () => {
    expect(hex(authPayload({ action: 'webhook', method: 'PUT', url: 'https://example.com/h', secret: SECRET })))
      .toBe(hex(encodePayload('PUT', 'https://example.com/h', SECRET)));
    expect(hex(authPayload({ action: 'webhook', method: 'GET', url: '', secret: '' }))).toBe(hex(encodePayload('GET', '', '')));
    expect(hex(authPayload({ action: 'webhook', method: 'DELETE', url: '', secret: '' }))).toBe(hex(encodePayload('DELETE', '', '')));
  });
  it.each([
    { method: 'PATCH', url: '', secret: '' },
    { method: 'PUT', url: 'http://example.com', secret: SECRET },
    { method: 'PUT', url: 'https://example.com', secret: 'short' },
    { method: 'PUT', url: 'https://example.com', secret: 'x'.repeat(129) },
    { method: 'PUT', url: 'https://example.com', secret: 'bad\u0000' + 'a'.repeat(16) },
    { method: 'GET', url: 'https://example.com', secret: '' },
    { method: 'DELETE', url: '', secret: SECRET },
  ])('rejects %o', (req) => {
    expectCode(() => authPayload({ action: 'webhook', ...req } as never), 'invalid_argument');
  });
});

describe('verifyWebhookNotification', () => {
  const ok = { secret: SECRET, timestamp: String(TS), signature: sig(), body: BODY, clock: () => TS + 10 };
  it('accepts a good notification (string and bytes body)', () => {
    expect(verifyWebhookNotification(ok)).toEqual({ aceId: ACE, streamId: '1741000000000-0' });
    expect(verifyWebhookNotification({ ...ok, body: new TextEncoder().encode(BODY) })).toEqual({ aceId: ACE, streamId: '1741000000000-0' });
  });
  it('signWebhookNotification produces what verify accepts', () => {
    expect(signWebhookNotification(SECRET, TS, BODY)).toBe(sig());
  });
  it.each([
    [{ signature: sig({ secret: 'wrong-secret-wrong-secret' }) }, 'invalid_signature'],
    [{ signature: sig({ prefix: 'sha1=' }) }, 'invalid_signature'],
    [{ signature: sig().toUpperCase() }, 'invalid_signature'],
    [{ body: BODY.replace('-0"', '-1"') }, 'invalid_signature'],
    [{ clock: () => TS + 301 }, 'stale_timestamp'],
    [{ timestamp: 'nope' }, 'invalid_argument'],
    [{ body: '{"event":"message","aceId":"' + ACE + '"}', signature: sig({ body: '{"event":"message","aceId":"' + ACE + '"}' }) }, 'invalid_argument'],
  ])('rejects %o → %s', (patch, code) => {
    expectCode(() => verifyWebhookNotification({ ...ok, ...patch } as never), code);
  });
});

describe('RelayAuthRequest webhook over headers', () => {
  it('a PUT signature does not verify as GET', async () => {
    const id = await SoftwareIdentity.generate('ed25519');
    const { createAuthHeaders, parseAuthHeaders, verifyAuthHeaders } = await import('../src/auth.js');
    const h = await createAuthHeaders(id, { action: 'webhook', method: 'PUT', url: 'https://example.com/h', secret: SECRET }, TS);
    const signer = { aceId: id.getACEId(), scheme: id.getSigningScheme(), signingPublicKey: id.getSigningPublicKey() };
    verifyAuthHeaders(parseAuthHeaders(h), { action: 'webhook', method: 'PUT', url: 'https://example.com/h', secret: SECRET }, signer, { clock: () => TS });
    expectCode(() => verifyAuthHeaders(parseAuthHeaders(h), { action: 'webhook', method: 'GET', url: '', secret: '' }, signer, { clock: () => TS }), 'invalid_signature');
  });
});
