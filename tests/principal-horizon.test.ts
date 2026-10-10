import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  MemoryStore, PeerStore, SoftwareIdentity, createRegistrationFile, createRegistrationRequest, verifyPeerRecord,
} from '../src/index.js';
import { createPrincipalRecord, principalSignerFromIdentity } from '../src/principal.js';
import { toBase64 } from '../src/encoding.js';

const NOW = 1_800_000_000;
const ACC = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
const ACC2 = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:9xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';

const rec = (owner: SoftwareIdentity, subject: SoftwareIdentity, o: { issuedAt?: number; roles?: any; account?: string } = {}) =>
  createPrincipalRecord(principalSignerFromIdentity(owner), {
    subjectSigningPublicKey: subject.getSigningPublicKey(), account: o.account ?? ACC, roles: o.roles ?? ['controller'],
    expiresAt: NOW + 3600, issuedAt: o.issuedAt ?? NOW - 10,
  });

async function relayRecord(id: SoftwareIdentity, profile: any, ts = NOW) {
  const req = await createRegistrationRequest(id, profile, ts);
  return verifyPeerRecord({
    aceId: req.aceId, scheme: req.scheme, encryptionPublicKey: req.encryptionPublicKey, signingPublicKey: req.signingPublicKey,
    registrationSignature: req.signature, registeredAt: ts, profile: req.profile,
  }, { clock: () => NOW });
}

describe('principal horizon', () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(NOW * 1000); });
  afterEach(() => { vi.useRealTimers(); });

  it('a pin cached before horizons existed gets one on the next adopt, so strip-then-replay cannot roll back', async () => {
    const owner = await SoftwareIdentity.generate('ed25519'), subject = await SoftwareIdentity.generate('ed25519');
    const store = new MemoryStore();
    const older = await rec(owner, subject, { issuedAt: NOW - 100, roles: ['controller'] });
    const newer = await rec(owner, subject, { issuedAt: NOW - 10, roles: ['delegate'] });
    await new PeerStore({ store, clock: () => NOW }).adopt(await relayRecord(subject, { principal: newer }));
    for (const k of await store.list('principal-horizons/')) await store.delete(k); // a store from before horizons
    const peers = new PeerStore({ store, clock: () => NOW });
    await peers.adopt(await relayRecord(subject, { name: 'n' })); // relay strips the principal
    await expect(peers.adopt(await relayRecord(subject, { principal: older }))).rejects.toMatchObject({ code: 'invalid_principal' });
  });

  it('a registration file that rotates the encryption key keeps the cached principal', async () => {
    const owner = await SoftwareIdentity.generate('ed25519'), subject = await SoftwareIdentity.generate('ed25519');
    const peers = new PeerStore({ store: new MemoryStore(), clock: () => NOW });
    const principal = await rec(owner, subject);
    await peers.adopt(await relayRecord(subject, { principal }, NOW - 50));
    const rotated = SoftwareIdentity.fromExport({ ...subject.exportPrivateKey(), encryptionPrivateKey: toBase64(new Uint8Array(32).fill(42)) });
    const file = await createRegistrationFile(rotated, { name: 'n', endpoint: 'https://a.example/ace', timestamp: NOW });
    const peer = await peers.pinRegistrationFile(file);
    expect(toBase64(peer.encryptionPublicKey)).toBe(toBase64(rotated.getEncryptionPublicKey()));
    expect(peer.principal).toEqual(principal);
  });

  it('a registration file never moves an unexpired principal to another authority domain', async () => {
    const x = await SoftwareIdentity.generate('ed25519'), y = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('ed25519');
    const peers = new PeerStore({ store: new MemoryStore(), clock: () => NOW });
    const inX = await rec(x, subject, { issuedAt: NOW - 100 });
    const inY = await rec(y, subject, { issuedAt: NOW - 10, account: ACC2, roles: ['delegate'] });
    await peers.adopt(await relayRecord(subject, { principal: inX }, NOW - 60));
    await peers.adopt(await relayRecord(subject, { principal: inY }, NOW - 50)); // the relay may move it
    const file = await createRegistrationFile(subject, { name: 'n', endpoint: 'https://a.example/ace', timestamp: NOW - 50 });
    (file as any).principal = inX; // an endpoint re-attaches the older account's principal
    expect((await peers.pinRegistrationFile(file)).principal).toEqual(inY);
  });

  it('a registration file cannot swap in a principal signed by someone else', async () => {
    const owner = await SoftwareIdentity.generate('ed25519'), attacker = await SoftwareIdentity.generate('ed25519');
    const subject = await SoftwareIdentity.generate('ed25519');
    const peers = new PeerStore({ store: new MemoryStore(), clock: () => NOW });
    const legit = await rec(owner, subject);
    await peers.adopt(await relayRecord(subject, { principal: legit }, NOW - 50));
    const file = await createRegistrationFile(subject, { name: 'n', endpoint: 'https://a.example/ace', timestamp: NOW - 50 });
    (file as any).principal = await rec(attacker, subject, { issuedAt: NOW - 5 });
    expect((await peers.pinRegistrationFile(file)).principal).toEqual(legit);
  });
});
