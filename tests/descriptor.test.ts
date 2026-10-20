import { describe, expect, it } from 'vitest';
import {
  MemoryStore, StorePrekeyVault, ProfileSet, createDelegationCredential, createDescriptor, createPermit, verifyErc8004Registration,
  verifyPermit, verifyPublishedAgent, MAX_PERMIT_LIFETIME, type DescriptorOptions, type SoftwareIdentity,
} from './sdk.js';
import { NOW, RELAY, identity, stateOf } from './helpers.js';

async function opts(extra: Partial<DescriptorOptions> = {}): Promise<DescriptorOptions> {
  const pk = await new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }).rotate(NOW);
  return { relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: new ProfileSet(['text', 'commerce']).descriptors(), now: NOW, ...extra };
}
const code = (c: string) => expect.objectContaining({ code: c });

describe('descriptor', () => {
  it('signs and verifies; any tampering invalidates', async () => {
    const a = await identity();
    const agent = await createDescriptor(a, await opts());
    expect(verifyPublishedAgent(agent, NOW).state.aceId).toBe(a.getACEId());
    expect(() => verifyPublishedAgent({ ...agent, descriptor: { ...agent.descriptor, relays: ['https://other.test'] } }, NOW)).toThrow(code('invalid_authorization'));
    // visibility, handle and card left the descriptor for the card record (04 § Card record): unknown members now
    for (const extra of [{ visibility: 'public' }, { handle: 'alice' }, { card: {} }]) {
      expect(() => verifyPublishedAgent({ ...agent, descriptor: { ...agent.descriptor, ...extra } }, NOW)).toThrow(code('invalid_authorization'));
    }
    expect(() => verifyPublishedAgent(agent, NOW + 86_400)).toThrow(code('invalid_authorization')); // default lifetime 86400
  });

  it('field rules: lifetime, prekey id, loopback relays, ext', async () => {
    const a = await identity();
    const week = await createDescriptor(a, await opts({ ttl: 604_800 }));
    expect(verifyPublishedAgent(week, NOW + 604_799).state.aceId).toBe(a.getACEId());
    await expect(createDescriptor(a, await opts({ ttl: 604_801 }))).rejects.toThrow(code('invalid_argument'));
    const o = await opts();
    await expect(createDescriptor(a, { ...o, prekey: { ...o.prekey, id: 'f'.repeat(64) } })).rejects.toThrow(code('invalid_authorization'));
    await expect(createDescriptor(a, await opts({ relays: ['http://localhost:8080'] }))).rejects.toThrow(code('invalid_authorization'));
    expect((await createDescriptor(a, await opts({ relays: ['http://localhost:8080'], allowLoopbackRelays: true }))).descriptor.relays).toEqual(['http://localhost:8080']);
    await expect(createDescriptor(a, await opts({ ext: { 'ace:text:1': {} } }))).rejects.toThrow(/defines no ext/);
    await expect(createDescriptor(a, await opts({ ext: { 'ace:commerce:1': { settlement: [{ method: 'paypal' }] } } }))).rejects.toThrow(code('invalid_authorization'));
    await expect(createDescriptor(a, await opts({ ext: { 'x:other:1': {} } }))).rejects.toThrow(/not a listed profile/);
    const ok = await createDescriptor(a, await opts({ ext: { 'ace:commerce:1': { settlement: [{ method: 'stablecoin', asset: 'eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' }, { method: 'stripe-link' }] } } }));
    expect(ok.descriptor.ext).toBeDefined();
  });

  it('delegations: valid kept, expired dropped, forged rejected', async () => {
    const issuer = await identity(), subject = await identity(), other = await identity();
    const credential = await createDelegationCredential(issuer, subject.getACEId(), { now: NOW, ttl: 3600 });
    const entry = { kel: issuer.getKel(), credential };
    const agent = await createDescriptor(subject, await opts({ delegations: [entry] }));
    expect(verifyPublishedAgent(agent, NOW).delegations.map((d) => d.issuer)).toEqual([issuer.getACEId()]);
    const later = await createDescriptor(subject, await opts({ delegations: [entry], now: NOW + 4000 }));
    expect(verifyPublishedAgent(later, NOW + 4000).delegations).toEqual([]);
    await expect(createDescriptor(subject, await opts({ delegations: [{ kel: other.getKel(), credential }] }))).rejects.toThrow(code('invalid_authorization'));
    const foreign = await createDelegationCredential(issuer, other.getACEId(), { now: NOW });
    await expect(createDescriptor(subject, await opts({ delegations: [{ kel: issuer.getKel(), credential: foreign }] }))).rejects.toThrow(code('invalid_authorization'));
    await expect(createDelegationCredential(issuer, subject.getACEId(), { now: NOW, ttl: 604_801 })).rejects.toThrow(code('invalid_argument'));
  });

  it('erc8004: shape in the descriptor, reverse binding via the registration file', async () => {
    const a = await identity();
    const binding = { agentRegistry: 'eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432', agentId: '42' };
    expect((await createDescriptor(a, await opts({ erc8004: [binding] }))).descriptor.erc8004).toEqual([binding]);
    await expect(createDescriptor(a, await opts({ erc8004: [{ ...binding, agentId: '042' }] }))).rejects.toThrow(code('invalid_authorization'));
    await expect(createDescriptor(a, await opts({ erc8004: [binding, binding] }))).rejects.toThrow(/distinct/);
    const reg = { type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1', services: [{ name: 'A2A', endpoint: 'https://x' }, { name: 'ACE', endpoint: a.getACEId() }] };
    expect(verifyErc8004Registration(reg, a.getACEId())).toBe(true);
    expect(verifyErc8004Registration(JSON.stringify({ services: [{ name: 'ACE', endpoint: a.getACEId() }] }), a.getACEId())).toBe(true);
    expect(verifyErc8004Registration({ endpoints: [{ name: 'ACE', endpoint: a.getACEId() }] }, a.getACEId())).toBe(false); // services only
    expect(verifyErc8004Registration({ services: [{ name: 'ace', endpoint: a.getACEId() }] }, a.getACEId())).toBe(false);
    expect(verifyErc8004Registration('not json', a.getACEId())).toBe(false);
  });
});

describe('permits', () => {
  it('30 days at most, bound to issuer and subject, die with the signing key', async () => {
    const issuer: SoftwareIdentity = await identity(), subject = await identity();
    const p = await createPermit(issuer, subject.getACEId(), { now: NOW });
    expect(p.expiresAt - p.issuedAt).toBe(MAX_PERMIT_LIFETIME);
    expect(Object.keys(p).sort()).toEqual(['expiresAt', 'issuedAt', 'issuer', 'signature', 'subject']);
    expect(verifyPermit(p, stateOf(issuer), subject.getACEId(), NOW)).toEqual(p);
    expect(() => verifyPermit(p, stateOf(issuer), issuer.getACEId(), NOW)).toThrow(code('invalid_authorization'));
    expect(() => verifyPermit(p, stateOf(issuer), subject.getACEId(), NOW + MAX_PERMIT_LIFETIME)).toThrow(code('invalid_authorization'));
    await expect(createPermit(issuer, subject.getACEId(), { now: NOW, ttl: MAX_PERMIT_LIFETIME + 1 })).rejects.toThrow(code('invalid_argument'));
    await issuer.delegate({ now: NOW + 1 });
    expect(() => verifyPermit(p, stateOf(issuer, NOW + 1), subject.getACEId(), NOW + 1)).toThrow(code('stale_peer_binding'));
  });
});
