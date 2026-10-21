// Security review 2026-10-21 (docs/review-2026-10-21-security.md): one regression per decision.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  FileStore, MemoryStore, SoftwareIdentity, SoftwareKey, canonicalStateBytes, createDelegation, generateSoftwareKey, keyDigest, relayErrorFor,
  validateNetworkRelay, verifiedCacheUsage, verifyCardBundle, verifyKel, verifyPublishedAgent,
} from './sdk.js';
import { Clock, FakeRelay, NOW, agent, stateOf } from './helpers.js';

const code = (c: string) => expect.objectContaining({ code: c });
const rootOf = (id: SoftwareIdentity) => new SoftwareKey(Buffer.from(id.exportPrivateKey().rootSeed, 'base64'));

describe('C1: relay URL host grammar (02 § Relay URLs)', () => {
  it.each(['https://[::1]', 'https://a..b', 'https://-a.example', 'https://a-.example', 'https://example.com.'])('%s is not a canonical relay URL', (url) => {
    expect(() => validateNetworkRelay(url)).toThrow(code('invalid_authorization'));
  });

  it('hosts in the ACE HTTPS URL grammar stay valid', () => {
    for (const url of ['https://relay.test', 'https://a-b.example:8443/ace', 'https://127.0.0.1']) expect(validateNetworkRelay(url)).toBe(url);
    expect(validateNetworkRelay('http://[::1]:8080', { allowLoopbackRelays: true })).toBe('http://[::1]:8080');
  });
});

describe('C4: relay error strings', () => {
  it('lose their control characters before they enter the error', () => {
    const e = relayErrorFor(400, null, JSON.stringify({ error: 'bad\u0007code\n', message: 'line\r\nFORGED\u009b\u0000 entry' }));
    expect(e.relayCode).toBe('badcode');
    expect(e.message).toBe('relay_rejected: HTTP 400 badcode: lineFORGED entry');
    expect(e.message).not.toMatch(/\p{Cc}/u);
  });
});

describe('C6: signer refusals (01 § Rotation and recovery)', () => {
  it('a next root committing to a revealed signing key is refused', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const signing = keyDigest('ml-dsa-65', id.getSigningPublicKey());
    await expect(id.rotate({ now: NOW, nextRootDigest: signing })).rejects.toThrow(code('invalid_argument'));
    expect(id.getKel()).toHaveLength(2);
  });

  it('a dlg key equal to the current root is refused', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const root = rootOf(id);
    await expect(createDelegation(stateOf(id), root, root.publicKey(), NOW)).rejects.toThrow(code('invalid_argument'));
  });

  it('a dlg key committed as the next root is refused', async () => {
    const next = generateSoftwareKey();
    const id = await SoftwareIdentity.generate({ now: NOW, nextRootDigest: keyDigest(next.scheme, next.publicKey()) });
    await expect(createDelegation(stateOf(id), rootOf(id), next.publicKey(), NOW)).rejects.toThrow(code('invalid_argument'));
  });
});

describe('C7: shape before KEL work (04 § Verification, § Card record)', () => {
  it('a malformed signature or delegation entry is invalid_authorization even when the KEL is invalid too', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' });
    const published = await alice.client.publish();
    const d = published.descriptor, short = { ...d.signature, value: 'AAAA' };
    expect(() => verifyPublishedAgent({ kel: [], descriptor: { ...d, signature: short } }, clock.t)).toThrow(code('invalid_authorization'));
    expect(() => verifyPublishedAgent({ kel: [], descriptor: { ...d, delegations: [{ kel: [] }] } }, clock.t)).toThrow(code('invalid_authorization'));
    const card = relay.cards.get(alice.id.getACEId())!;
    expect(() => verifyCardBundle({ kel: [], card: { ...card.card, signature: { ...card.card.signature, value: 'AAAA' } } }, clock.t))
      .toThrow(code('invalid_authorization'));
  });
});

describe('C10: verified-KEL cache', () => {
  it('never caches an unusable log', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const before = verifiedCacheUsage();
    verifyKel(id.getKel().slice(0, 1), NOW); // icp only: no signing delegation
    expect(verifiedCacheUsage()).toEqual(before);
  });

  it('holds at most 16 MiB of logs', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    for (let i = 0; i < 90; i++) await id.delegate({ now: NOW });
    const kel = id.getKel();
    let total = 0;
    for (let n = 2; n <= kel.length; n++) {
      verifyKel(kel.slice(0, n), NOW);
      total += kel.slice(0, n).reduce((sum, ev) => sum + canonicalStateBytes(ev).length, 0);
    }
    expect(total).toBeGreaterThan(16 * 1024 * 1024);
    expect(verifiedCacheUsage().bytes).toBeLessThanOrEqual(16 * 1024 * 1024);
  }, 60_000); // 90 root signatures
});

describe('C11: list prefixes are validated like keys', () => {
  const stores = [['MemoryStore', () => new MemoryStore()], ['FileStore', () => new FileStore(join(mkdtempSync(join(tmpdir(), 'ace-')), 's'))]] as const;
  it.each(stores)('%s', async (_, make) => {
    const store = make();
    await store.write('inbox/journal/a.json', new Uint8Array([1]));
    for (const bad of ['../', 'inbox/../', '/inbox', 'inbox//', 'Inbox/', 'inbox/journal/.x']) {
      await expect(store.list(bad)).rejects.toThrow(code('invalid_argument'));
    }
    expect(await store.list('inbox/journal/')).toEqual(['inbox/journal/a.json']);
    expect(await store.list('inbox/jo')).toEqual(['inbox/journal/a.json']);
    expect(await store.list('')).toEqual(['inbox/journal/a.json']);
  });
});
