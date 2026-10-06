# @ace-protocol/sdk

TypeScript SDK for the **ACE Protocol** (Agent Commerce Engine) — a secure, end-to-end encrypted messaging protocol for agent-to-agent commerce.

## Features

- **Identity** — Ed25519 / secp256k1 signing keys, X-Wing encryption keys, ACE IDs, registration files
- **End-to-end encryption** — X-Wing (X25519 + ML-KEM-768) → HKDF-SHA256 → AES-256-GCM, bound to the conversation
- **Strict wire encodings** — canonical Base64, strict hex signatures, strict ed25519 (no malleable or small-order encodings), low-S secp256k1
- **Economic state machine** — parties, buyer/seller roles and fixed reference positions
- **Replay protection** — seen store with horizons, per-sender quota and canonical persistence
- **Pipeline** — `PeerStore` (rollback barrier), `Outbox` (durable send), `Inbox` (exactly-once receive with crash recovery), `RelayClient` (HTTP + SSE), over any `ACEStore` (`MemoryStore`, or `FileStore` from `@ace-protocol/sdk/node`)

Every failure is an `ACEError` with a stable `code` and a `category` (`permanent`, `transient` or `local`; `isTransient` means retry).

## Encryption

Every message body is encrypted for its recipient with:

1. **X-Wing KEM** ([draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)) — a hybrid of ML-KEM-768 (FIPS 203) and X25519. The recipient's static encryption public key is 1216 bytes; each message carries a 1120-byte `kemCiphertext`; the private key is a 32-byte seed.
2. **HKDF-SHA256** — `ikm = X-Wing shared secret`, `salt = SHA-256("ace.protocol.kem.v1")`, `info = conversationId`, 32-byte output.
3. **AES-256-GCM** — random 12-byte nonce, 16-byte tag, `aad = conversationId`; `payload = nonce || ciphertext || tag`.

The `kemCiphertext` is part of the signed message payload, so a relay cannot swap it without breaking the sender's signature. Signatures (Ed25519 / secp256k1) remain classical; the hybrid KEM protects message confidentiality against harvest-now-decrypt-later attacks.

**Forward secrecy — honest statement:** the sender holds no long-term secret for encryption, so compromising a sender reveals nothing about past messages. The recipient's static X-Wing seed, however, decrypts every message ever sent to that key, past and future. Rotate the encryption key by publishing a newer relay registration if that is a concern (peers adopt it under the rollback barrier).

## Installation

```bash
npm install @ace-protocol/sdk
```

Requires Node.js >= 20.19.0. `FileStore` is Node-only (`import { FileStore } from '@ace-protocol/sdk/node'`); everything else also runs in browsers and edge runtimes.

## Quick Start

```typescript
import {
  SoftwareIdentity, createMessage, parseMessage, verifyRegistrationFile,
  ThreadStateMachine, ReplayDetector, MemoryStore, RelayClient, PeerStore, Outbox, Inbox,
  type ParsedMessage,
} from '@ace-protocol/sdk';

// 1. Pure local: two in-process identities, no relay, no storage.
export async function local(): Promise<ParsedMessage> {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  // Peers are verified bindings; here from each other's registration files.
  const alicePeer = verifyRegistrationFile(alice.toRegistrationFile({ name: 'Alice', endpoint: 'https://alice.example/ace' }));
  const bobPeer = verifyRegistrationFile(bob.toRegistrationFile({ name: 'Bob', endpoint: 'https://bob.example/ace' }));

  const message = await createMessage({
    sender: alice, recipient: bobPeer, type: 'rfq', threadId: 'translation-1',
    body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
    threads: new ThreadStateMachine({ localAceId: alice.getACEId() }),
  });
  return parseMessage(message, bob, alicePeer, {
    threads: new ThreadStateMachine({ localAceId: bob.getACEId() }),
    replay: new ReplayDetector(),
  });
}

// 2. Over a relay: durable send (Outbox) and exactly-once receive (Inbox).
//    Use FileStore from '@ace-protocol/sdk/node' instead of MemoryStore to persist state.
export async function overRelay(relayUrl: string): Promise<ParsedMessage[]> {
  const relay = new RelayClient(relayUrl);
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  await relay.register(alice, { name: 'Alice', tags: ['buyer'] });
  await relay.register(bob, { name: 'Bob', tags: ['translation'] });

  // Alice resolves Bob through the relay (binding verified, pinned under the rollback barrier).
  const aliceStore = new MemoryStore();
  const alicePeers = new PeerStore({ store: aliceStore, relay });
  const outbox = new Outbox({ identity: alice, store: aliceStore });
  const pending = await outbox.stage({
    recipient: await alicePeers.resolve(bob.getACEId()), type: 'rfq', threadId: 'translation-1',
    body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  });
  await outbox.deliver(pending.requestId, (env) => relay.send(env));

  // Bob drains his relay inbox; onMessage must persist its effect idempotently.
  const received: ParsedMessage[] = [];
  const bobStore = new MemoryStore();
  const inbox = await Inbox.open({
    identity: bob, store: bobStore, peers: new PeerStore({ store: bobStore, relay }),
    onMessage: (m) => { received.push(m); },
  });
  try {
    const result = await inbox.pull(relay);
    if (result.blocked) throw result.blocked;
    // For live delivery: for await (const outcome of inbox.follow(relay, { signal })) { ... }
  } finally {
    await inbox.close();
  }
  return received;
}

export const parsed = await local();
console.log(parsed.body);
if (process.env.ACE_RELAY_URL) console.log((await overRelay(process.env.ACE_RELAY_URL)).map((m) => m.body));
```

## Message Types

| Category | Types |
|----------|-------|
| Economic | `rfq`, `offer`, `accept`, `reject`, `invoice`, `receipt`, `deliver`, `confirm` |
| System   | `info` |
| Social   | `text` |

Economic messages require a `threadId` and follow the transition table of the spec (04-messages): the `rfq` sender is the buyer; each transition requires a sender role; `accept`, `invoice`, `receipt` and `confirm` must reference fixed history positions.

## API

### Identity and keys

- `SoftwareIdentity.generate(scheme)`, `SoftwareIdentity.fromExport(data)`, `identity.exportPrivateKey()`, `identity.toRegistrationFile({ name, endpoint, tier?, ... })`
- `ACEIdentity` — implement it for hardware keys; `decrypt` may use `decryptWithSeed(kemCiphertext, payload, seed, conversationId)`. A non-`ACEError` thrown by `decrypt` is reported as `identity_unavailable` (retryable).
- `computeACEId`, `computeConversationId`, `kemPublicKeyFromSeed`, `generateKemSeed`, `toBase64`, `fromBase64`

### Envelopes and messages

- `decodeEnvelope(json)` — the exact 04 decoding rules (`invalid_envelope` / `unsupported_version`)
- `verifyEnvelopeSignature(env, { scheme, signingPublicKey })`, `envelopeFingerprint(env)`
- `createMessage({ sender, recipient, type, body, threads, threadId?, timestamp? })`
- `parseMessage(env, receiver, sender, { threads, replay, floor?, clock? })` — the 06 pipeline; the first failure determines the error code
- `validateBody(type, body)`; predicates `isACEId`, `isMessageId`, `isThreadId`, `isConversationId`

### Peers, registration, relay auth

- `VerifiedPeer` — only obtainable from `verifyPeerRecord`, `verifyRegistrationFile`, `verifyRegistrationRequest`, `PeerStore` or `RelayClient`. Its `profile` is unverified relay metadata.
- `fetchRegistrationFile(domain, { timeoutMs?, maxBytes?, allowPrivateAddresses? })` — SSRF-checked (the DNS check needs Node), no redirects
- `validateProfile`, `createRegistrationRequest`, `verifyRegistrationRequest` (returns `{ request, peer, requestDigest }`)
- `createAuthHeaders`, `parseAuthHeaders`, `verifyAuthHeaders` for `listen` / `inbox` / `unregister` / `intent`

### State

- `ThreadStateMachine({ localAceId })` — `check`, `apply`, `getState`, `getSnapshot`, `allowedTypes`, `exportState`, `ThreadStateMachine.fromState`
- `ReplayDetector({ capacity?, horizon?, clock? })` — `accepts`, `commit`, `clone`, `exportState`, `ReplayDetector.fromState`

### Pipeline

- `ACEStore` — `read` / `write` (atomic) / `delete` / `list` / `lock`; `MemoryStore`, `FileStore(root)`
- `PeerStore({ store, relay?, ttlSeconds?, clock? })` — `get`, `resolve`, `adopt`, `pinRegistrationFile`, `remove`. A registration file never rotates a pinned encryption key; rotation needs a newer signed relay binding.
- `Outbox({ identity, store })` — `stage`, `deliver(requestId, transport)`, `resign` (after `envelope_expired`), `abandon`, `pending`
- `Inbox.open({ identity, store, peers, onMessage })` — `receive(envelope, source)`, `pull(relay)`, `follow(relay)`, `cursor(relayUrl)`, `close`. `onMessage` must persist its effect idempotently keyed by `(from, messageId)`.
- `ThreadStore({ store, localAceId })` — read access to persisted threads
- `RelayClient(baseUrl)` — `register`, `unregister`, `lookupPeer`, `discover`, `send`, `fetchInbox`, `listen`, `postIntent`, `listIntents`

Persisted files follow ace-spec 06 Appendix A (compact JSON, sorted keys), so the Python and Swift SDKs read the same state.

## License

Apache-2.0 — see [LICENSE](./LICENSE) for details.

## Validate unpublished SDK changes in a consumer

Run `npm ci` in this SDK, then:

```sh
node scripts/install-local.mjs --update-locks /absolute/path/to/ace-cli /absolute/path/to/relay
```

The script builds and packs this source, records the actual tarball integrity in consumer
lockfiles, seeds npm's content-addressed cache, and runs `npm ci`. Omit `--update-locks`
to verify that the current source exactly matches the locked artifact. No package is
published. Release the same SDK artifact before relying on registry-only installation.
The SDK tests execute `examples/quickstart.ts`; interoperability fixtures are included
in `tests/fixtures` with a source revision and SHA-256 digest.
