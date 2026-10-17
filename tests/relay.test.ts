import { describe, expect, it } from 'vitest';
import {
  createAuthHeaders, createRegistrationRequest, encodePayload, parseAuthHeaders, verifyAuthHeaders, verifyRegistrationRequest, parseSSE,
} from './sdk.js';
import { authPayload } from '../src/auth.js';
import { relayErrorFor } from '../src/relay.js';
import { NOW, RELAY, identity, stateOf } from './helpers.js';

describe('relay binding', () => {
  it('auth payloads for block and inbox-ack', () => {
    const peer = `ace:sha256:${'c'.repeat(64)}`;
    expect(authPayload({ action: 'block', peer, blocked: true, revision: 3 })).toEqual(encodePayload(peer, 'block', '3'));
    expect(authPayload({ action: 'block', peer, blocked: false, revision: 4 })).toEqual(encodePayload(peer, 'unblock', '4'));
    expect(authPayload({ action: 'inbox-ack', through: '5-1' })).toEqual(encodePayload('5-1'));
  });

  it('auth headers and registration verify', async () => {
    const id = await identity();
    const h = await createAuthHeaders(id, { action: 'inbox', since: '-', limit: 10 }, NOW, { audience: RELAY });
    expect(Object.keys(h).sort()).toEqual(['X-ACE-Audience', 'X-ACE-Id', 'X-ACE-Nonce', 'X-ACE-Seq', 'X-ACE-Signature', 'X-ACE-Timestamp']);
    expect(h['X-ACE-Signature']).toHaveLength(4412);
    expect(() => verifyAuthHeaders(parseAuthHeaders({ ...h }), { action: 'inbox', since: '-', limit: 10 }, stateOf(id), { audience: RELAY, clock: () => NOW })).not.toThrow();
    // 07 order: the seq is compared before the audience and the clock
    const old = await createAuthHeaders(id, { action: 'listen', since: '-' }, NOW, { audience: 'https://other.example' });
    expect(() => verifyAuthHeaders(parseAuthHeaders({ ...old, 'X-ACE-Seq': '0' }), { action: 'listen', since: '-' }, stateOf(id), { audience: RELAY, clock: () => NOW + 999 }))
      .toThrow(expect.objectContaining({ code: 'stale_seq' }));
    expect(() => verifyAuthHeaders(parseAuthHeaders({ ...old, 'X-ACE-Seq': '7' }), { action: 'listen', since: '-' }, stateOf(id), { audience: RELAY, clock: () => NOW + 999 }))
      .toThrow(expect.objectContaining({ code: 'future_seq' }));
    const reg = await createRegistrationRequest(id, { audience: RELAY, timestamp: NOW });
    expect(verifyRegistrationRequest(reg, { audience: RELAY, clock: () => NOW }).state.aceId).toBe(id.getACEId());
    // L2: bound to its relay; another relay refuses it, and retargeting breaks the signature
    expect(() => verifyRegistrationRequest(reg, { audience: 'https://other.example', clock: () => NOW })).toThrow(expect.objectContaining({ code: 'invalid_signature' }));
    expect(() => verifyRegistrationRequest({ ...reg, audience: 'https://other.example' }, { audience: 'https://other.example', clock: () => NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_authorization' }));
  });

  it('an audience is https, or http to a loopback host (02 § Relay URL)', async () => {
    const nonce = 'a'.repeat(64), req = { action: 'unregister' } as const;
    const id = await identity();
    for (const ok of ['https://relay.example', 'http://127.0.0.1:8080', 'http://[::1]:8080']) {
      await expect(createAuthHeaders(id, req, NOW, { audience: ok, nonce })).resolves.toBeDefined();
    }
    await expect(createAuthHeaders(id, req, NOW, { audience: 'http://relay.example', nonce })).rejects.toMatchObject({ code: 'invalid_argument' });
    const reg = await createRegistrationRequest(id, { audience: 'http://relay.example', timestamp: NOW });
    expect(() => verifyRegistrationRequest(reg, { audience: 'http://relay.example', clock: () => NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_registration' }));
  });

  it('maps relay errors', () => {
    expect(relayErrorFor(403, null, '{"error":"not_permitted"}').code).toBe('not_permitted');
    expect(relayErrorFor(404, null, '{"error":"unknown_peer"}').code).toBe('unknown_peer');
    expect(relayErrorFor(429, '7', '{"error":"rate_limited"}')).toMatchObject({ code: 'relay_unavailable', retryAfterSeconds: 7 });
    expect(relayErrorFor(409, null, '{"error":"stale_descriptor"}')).toMatchObject({ code: 'relay_rejected', relayCode: 'stale_descriptor' });
  });

  it('SSE frames', async () => {
    const stream = new Response('event: connected\ndata: {}\n\nid: 1-0\nevent: message\ndata: {"packet":{}}\n\n').body!;
    const events = [];
    for await (const e of parseSSE(stream)) events.push(e);
    expect(events.at(-1)).toEqual({ id: '1-0', event: 'message', data: '{"packet":{}}' });
  });
});
