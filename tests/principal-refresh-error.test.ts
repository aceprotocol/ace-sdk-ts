// A permanent error from the R-P20 usable-check is quarantined, not retried (only transient errors are retryable).
import { describe, expect, it, vi } from 'vitest';
import {
  ACEError, Inbox, MemoryStore, PeerStore, SoftwareIdentity, createPrincipalRecord, createRegistrationRequest,
  principalSignerFromIdentity, toBase64, verifyPeerRecord,
} from '../src/index.js';
import { Agent, Clock } from './pipeline.js';
import { wire } from './helpers.js';

const flags = vi.hoisted(() => ({ throwPermanent: false }));
vi.mock('../src/principal.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../src/principal.js')>();
  const { ACEError: E } = await import('../src/errors.js');
  return {
    ...orig,
    senderPrincipalUsable: (...args: Parameters<typeof orig.senderPrincipalUsable>) => {
      if (flags.throwPermanent) throw new E('invalid_principal', 'unusable');
      return orig.senderPrincipalUsable(...args);
    },
  };
});

const NOW = 1_800_000_000;
const ACC = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';

describe('principal refresh errors', () => {
  it('a permanent error from the usable-check is quarantined (one-shot)', async () => {
    const clock = new Clock(NOW);
    const owner = await SoftwareIdentity.generate('ed25519');
    const relay = { calls: 0, async lookupPeer() { this.calls++; throw new ACEError('relay_unavailable', 'x'); } };
    const a = await Agent.create('a', 'ed25519', clock, new MemoryStore(), relay as any);
    const b = await Agent.create('b', 'ed25519', clock);
    const pin = async (peers: PeerStore, who: SoftwareIdentity, principal?: unknown) => {
      const req = await createRegistrationRequest(who, principal === undefined ? {} : { principal } as any, NOW);
      await peers.adopt(verifyPeerRecord({
        aceId: req.aceId, scheme: req.scheme, encryptionPublicKey: req.encryptionPublicKey, signingPublicKey: req.signingPublicKey,
        registrationSignature: req.signature, registeredAt: NOW, profile: req.profile,
      }, { clock: () => NOW }));
    };
    await pin(a.peers, b.identity);
    await pin(b.peers, a.identity, await createPrincipalRecord(principalSignerFromIdentity(owner), {
      subjectSigningPublicKey: a.identity.getSigningPublicKey(), account: ACC, roles: ['delegate'], expiresAt: NOW + 3600, issuedAt: NOW - 10,
    }));
    const ia = await Inbox.open({ commerce: true,
      identity: a.identity, store: a.store, peers: new PeerStore({ store: a.store, relay: relay as any, clock: clock.fn }),
      onMessage: a.host.fn, clock: clock.fn,
      principal: { account: ACC, selfSigner: { scheme: owner.getSigningScheme(), publicKey: toBase64(owner.getSigningPublicKey()) } },
    });
    const p = await b.outbox.stage({ recipient: (await b.peers.get(a.id))!, type: 'request', body: { action: 'pay', summary: 's' } });
    flags.throwPermanent = true;
    try {
      const r = await ia.receive(wire(p.message));
      expect(r.kind).toBe('quarantined');
      expect('error' in r && r.error.code).toBe('invalid_principal');
      expect(relay.calls).toBe(0);
    } finally {
      flags.throwPermanent = false;
    }
    // Authenticated permanent policy rejection is one-shot; replay never triggers refresh.
    const r2 = await ia.receive(wire(p.message));
    expect(r2.kind).toBe('duplicate');
    expect(relay.calls).toBe(0);
  });
});
