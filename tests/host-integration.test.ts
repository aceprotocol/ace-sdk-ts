// Host-facing knobs used by the hosted MCP: transport address, live delegations, the presented permit, public fetch.
import { describe, expect, it } from 'vitest';
import { RelayClient, createDelegationCredential, publicHttpsFetch } from './sdk.js';
import { Clock, FakeRelay, RELAY, agent } from './helpers.js';

describe('host integration', () => {
  it('connectUrl moves requests only; baseUrl stays the relay this client stands for', async () => {
    const seen: string[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      seen.push(String(input));
      return new Response(JSON.stringify({ cards: [], cursor: null }), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const relay = new RelayClient(RELAY, { connectUrl: 'http://relay-internal:8080/', fetch });
    expect(relay.baseUrl).toBe(RELAY);
    await relay.directory({ limit: 5 });
    expect(seen).toEqual(['http://relay-internal:8080/v1/cards?limit=5']);
  });

  it('an expired configured delegation drops out of the next descriptor', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const issuer = await agent(relay, clock, { contact: 'open', listed: true });
    const subject = await agent(relay, clock, { contact: 'open', listed: true });
    const credential = await createDelegationCredential(issuer.id, subject.id.getACEId(), { now: clock.t, ttl: 60 });
    subject.client.options.delegations = [{ kel: issuer.id.getKel(), credential }];
    expect((await subject.client.publish()).descriptor.delegations).toHaveLength(1);
    clock.advance(61);
    expect((await subject.client.publish()).descriptor.delegations).toBeUndefined();
  });

  it('permitFrom is the permit send presents: held and live, else undefined', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    const bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    expect(await bob.client.permitFrom(A)).toBeUndefined();
    const invitation = await alice.client.createInvitation(await bob.client.publish());
    await bob.client.importInvitation(invitation);
    expect((await bob.client.permitFrom(A))?.id).toBe(invitation.permit.id);
    clock.advance(invitation.permit.expiresAt - clock.t + 1);
    expect(await bob.client.permitFrom(A)).toBeUndefined();
  });

  it('publicHttpsFetch refuses non-https, foreign origins and blocked addresses before connecting', async () => {
    const f = publicHttpsFetch({ origin: 'https://example.com' });
    await expect(f('http://example.com/x')).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(f('https://other.example/x')).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(publicHttpsFetch()('https://127.0.0.1/x')).rejects.toMatchObject({ code: 'blocked_address' });
  });
});
