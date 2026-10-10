// The integration glue every host needs once: inboxPrincipalFromOwnRecord, openSecureMailbox, deliverSecure.
import { describe, expect, it, vi } from 'vitest';
import {
  MemoryStore, PeerStore, SoftwareIdentity, checkKey, checkLockName, createPrincipalRecord, inboxPrincipalFromOwnRecord,
  principalSignerFromIdentity, type RelayClient,
} from '../src/index.js';
import { SecureTransport } from '../src/secure-transport.js';
import { deliverSecure, openSecureMailbox, secureTransportFor } from '../src/secure-mailbox.js';
import type { MLSEngine } from '../src/session.js';
import { sha256Hex, utf8 } from '../src/encoding.js';
import { Agent, Clock } from './pipeline.js';
import { expectCode } from './helpers.js';

const ACC = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
const NOW = 1_800_000_000;

/** An engine that is never reached by these tests (no handshake completes). */
function stubEngine(): MLSEngine & { free: ReturnType<typeof vi.fn> } {
  return { execute: () => { throw new Error('engine must not run'); }, free: vi.fn() };
}

describe('inboxPrincipalFromOwnRecord', () => {
  it('no record is no principal, without a warning', async () => {
    const me = await SoftwareIdentity.generate('ed25519');
    expect(inboxPrincipalFromOwnRecord(undefined, me)).toEqual({ principal: undefined });
    expect(inboxPrincipalFromOwnRecord(null, me)).toEqual({ principal: undefined });
  });

  it('a valid own record binds its account with the record signer as selfSigner (and the given trusted signers)', async () => {
    const owner = await SoftwareIdentity.generate('secp256k1'), me = await SoftwareIdentity.generate('ed25519');
    const record = await createPrincipalRecord(principalSignerFromIdentity(owner), {
      subjectSigningPublicKey: me.getSigningPublicKey(), account: ACC, roles: ['controller', 'delegate'], issuedAt: NOW - 10, expiresAt: NOW + 3600,
    });
    const other = { scheme: 'ed25519' as const, publicKey: 'x' };
    expect(inboxPrincipalFromOwnRecord(record, me, { now: NOW })).toEqual({ principal: { account: ACC, selfSigner: record.signer, trustedSigners: [] } });
    expect(inboxPrincipalFromOwnRecord(record, me, { now: NOW, trustedSigners: [other] }).principal?.trustedSigners).toEqual([other]);
  });

  it('an expired record, or one bound to another key, is no principal with a "<code>: <detail>" warning and never throws', async () => {
    const owner = await SoftwareIdentity.generate('ed25519'), me = await SoftwareIdentity.generate('ed25519'), someone = await SoftwareIdentity.generate('ed25519');
    const expired = await createPrincipalRecord(principalSignerFromIdentity(owner), {
      subjectSigningPublicKey: me.getSigningPublicKey(), account: ACC, roles: ['delegate'], issuedAt: NOW - 100, expiresAt: NOW - 50,
    });
    const r = inboxPrincipalFromOwnRecord(expired, me, { now: NOW });
    expect(r.principal).toBeUndefined();
    expect(r.warning).toMatch(/^invalid_principal: .*expired/);
    const foreign = inboxPrincipalFromOwnRecord(expired, someone, { now: NOW - 75 });
    expect(foreign.principal).toBeUndefined();
    expect(foreign.warning).toMatch(/^invalid_principal: /);
    // The wall clock is the default: the expired record is expired now too.
    expect(inboxPrincipalFromOwnRecord(expired, me).warning).toMatch(/^invalid_principal: /);
  });
});

describe('openSecureMailbox', () => {
  it('one close() releases the receive lock and frees the engine', async () => {
    const clock = new Clock(NOW), a = await Agent.create('a', 'ed25519', clock);
    const relay = { baseUrl: 'https://relay.example' } as RelayClient, engine = stubEngine();
    const mailbox = await openSecureMailbox({ identity: a.identity, store: a.store, peers: a.peers, relay, engine, clock: clock.fn,
      inbox: { commerce: true, onMessage: a.host.fn, clock: clock.fn } });
    await expectCode(a.store.lock('receive', { timeoutMs: 0 }), 'receiver_busy');
    await expectCode(a.store.lock('secure-mailbox', { timeoutMs: 0 }), 'lock_busy');
    expect(engine.free).not.toHaveBeenCalled();
    await mailbox.close();
    expect(engine.free).toHaveBeenCalledTimes(1);
    await (await a.store.lock('receive', { timeoutMs: 0 }))();
    await (await a.store.lock('secure-mailbox', { timeoutMs: 0 }))();
  });

  it('a failure after the Inbox opened closes it (no leaked receive lock) and leaves the engine to the caller', async () => {
    const clock = new Clock(NOW), a = await Agent.create('a', 'ed25519', clock);
    const relay = { baseUrl: 'https://relay.example' } as RelayClient, engine = stubEngine();
    // SecureMailbox.open refuses a corrupt persisted cursor: the failure comes after Inbox.open took `receive`.
    await a.store.write(`secure/cursors/${sha256Hex(relay.baseUrl)}.json`, utf8(JSON.stringify({ version: 1, identity: a.id, cursor: 'nope' })));
    await expectCode(openSecureMailbox({ identity: a.identity, store: a.store, peers: a.peers, relay, engine, inbox: { onMessage: a.host.fn } }), 'storage_failed');
    expect(engine.free).not.toHaveBeenCalled();
    await (await a.store.lock('receive', { timeoutMs: 0 }))();
    await (await a.store.lock('secure-mailbox', { timeoutMs: 0 }))();
  });
});

describe('deliverSecure / secureTransportFor', () => {
  async function staged() {
    const clock = new Clock(NOW), a = await Agent.create('a', 'ed25519', clock), b = await Agent.create('b', 'secp256k1', clock);
    const peer = await a.pin(b);
    await SecureTransport.setPeerAllowed(a.store, b.id, true);
    const secure = new SecureTransport(a.identity, stubEngine(), a.store, clock.fn);
    const pending = await a.outbox.stage({ recipient: peer, type: 'text', body: { message: 'hi' } });
    return { a, b, peer, secure, pending };
  }

  it('sends every handshake frame through the given send (the relay is not used for frames)', async () => {
    const { a, b, peer, secure, pending } = await staged();
    const relay = { baseUrl: 'https://relay.example', send: vi.fn(), fetchInbox: vi.fn() } as unknown as RelayClient;
    const sent: unknown[] = [];
    const send = vi.fn(async (packet: unknown) => { sent.push(packet); throw new Error('frame transport stopped'); });
    await expect(deliverSecure(a.outbox, pending.requestId, { identity: a.identity, secure, relay, peer, send })).rejects.toThrow('frame transport stopped');
    expect(send).toHaveBeenCalledTimes(1);
    expect(sent[0]).toMatchObject({ from: a.id, to: b.id });
    expect((sent[0] as { messageId: string }).messageId).not.toBe(pending.message.messageId); // a frame, not the application envelope
    expect(relay.send).not.toHaveBeenCalled();
    expect(relay.fetchInbox).not.toHaveBeenCalled();
    // The operation stays pending under its requestId.
    expect((await a.outbox.pending()).map((p) => p.requestId)).toEqual([pending.requestId]);
    await secure.close();
  });

  it('defaults to relay.send and resolves only through outbox.deliver', async () => {
    const { a, b, peer, secure, pending } = await staged();
    const relay = { baseUrl: 'https://relay.example', send: vi.fn(async () => { throw new Error('relay stopped'); }), fetchInbox: vi.fn() } as unknown as RelayClient;
    const transport = secureTransportFor({ identity: a.identity, secure, relay, peer });
    await expect(transport(pending.message)).rejects.toThrow('relay stopped');
    expect(relay.send).toHaveBeenCalledTimes(1);
    expect((relay.send as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({ from: a.id, to: b.id });
    await expectCode(deliverSecure(a.outbox, '', { identity: a.identity, secure, relay, peer }), 'invalid_argument');
    await secure.close();
  });
});

describe('public store-key validators', () => {
  it('checkKey / checkLockName are the store contract', () => {
    expect(checkKey('secure/in/a.json')).toBe('secure/in/a.json');
    expect(checkLockName('receive')).toBe('receive');
    for (const bad of ['', '/x', 'A', 'a//b', 'a/', 'a'.repeat(201)]) expect(() => checkKey(bad)).toThrow('invalid store key');
    for (const bad of ['', 'a/b', 'A', 'a'.repeat(65)]) expect(() => checkLockName(bad)).toThrow('invalid lock name');
  });
});
