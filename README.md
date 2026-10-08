# @ace-protocol/sdk

TypeScript SDK for the **ACE Protocol** (Agent Commerce Engine) — a secure, end-to-end encrypted messaging protocol for agent-to-agent commerce.

## Features

- **Identity** — Ed25519 / secp256k1 signing keys, X-Wing encryption keys, ACE IDs, registration files
- **End-to-end encryption** — X-Wing (X25519 + ML-KEM-768) → HKDF-SHA256 → AES-256-GCM, bound to the conversation
- **Strict wire encodings** — canonical Base64, strict hex signatures, strict ed25519 (no malleable or small-order encodings), low-S secp256k1
- **Economic state machine** — parties, buyer/seller roles and fixed reference positions
- **Replay protection** — seen store with horizons, per-sender quota and canonical persistence
- **Pipeline** — `PeerStore` (rollback barrier), `Outbox` (durable send), `Inbox` (exactly-once receive with crash recovery), `RelayClient` (HTTP + SSE), over any `ACEStore` (`MemoryStore`, or `FileStore` from `@ace-protocol/sdk/node`)

Every failure is an `ACEError` with a stable `code` and a `category` (`permanent`, `transient` or `local`; `isTransient` means retry). The codes and categories are those of ace-spec 06-security § SDK Error Codes.

**Signatures may be non-deterministic.** secp256k1 signatures use RFC 6979 with extra randomness, so signing the same data twice can give different (equally valid) signatures. Treat signatures as verify-only: never compare signature bytes, deduplicate on them, or expect them to match a fixture.

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

Requires Node.js >= 20.19.0. `FileStore`, `postDirect` and `deliverDirectOrRelay` are Node-only (`import { FileStore, postDirect, deliverDirectOrRelay } from '@ace-protocol/sdk/node'`); the main entry has no static Node imports and also runs in browsers and edge runtimes.

## Quick Start

```typescript
import {
  SoftwareIdentity, createMessage, createRegistrationFile, parseMessage, verifyRegistrationFile,
  ThreadStateMachine, ReplayDetector, MemoryStore, RelayClient, PeerStore, Outbox, Inbox,
  type ParsedMessage,
} from '@ace-protocol/sdk';

// 1. Pure local: two in-process identities, no relay, no storage.
export async function local(): Promise<ParsedMessage> {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  // Peers are verified bindings; here from each other's registration files
  // (createRegistrationFile works for any ACEIdentity, hardware-backed ones included).
  const alicePeer = verifyRegistrationFile(createRegistrationFile(alice, { name: 'Alice', endpoint: 'https://alice.example/ace' }));
  const bobPeer = verifyRegistrationFile(createRegistrationFile(bob, { name: 'Bob', endpoint: 'https://bob.example/ace' }));

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

// 2. Over a relay (e.g. https://relay.aceprotocol.org): durable send (Outbox) and exactly-once
//    receive (Inbox). Use FileStore from '@ace-protocol/sdk/node' instead of MemoryStore to persist state.
export async function overRelay(relayUrl: string): Promise<ParsedMessage[]> {
  const relay = new RelayClient(relayUrl);
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('ed25519');
  await relay.register(alice, { name: 'Alice', tags: ['buyer'] });
  await relay.register(bob, { name: 'Bob', tags: ['translation'] });

  // Alice resolves Bob through the relay (binding verified, pinned under the rollback barrier).
  const aliceStore = new MemoryStore();
  const alicePeers = new PeerStore({ store: aliceStore, relay });
  const outbox = await Outbox.open({ identity: alice, store: aliceStore });
  const pending = await outbox.stage({
    recipient: await alicePeers.resolve(bob.getACEId()), type: 'rfq', threadId: 'translation-1',
    body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  });
  await outbox.deliver(pending.requestId, (env) => relay.send(env));

  // Bob drains his relay inbox; onMessage must persist its effect idempotently.
  const bobStore = new MemoryStore();
  const inbox = await Inbox.open({
    identity: bob, store: bobStore, peers: new PeerStore({ store: bobStore, relay }),
    onMessage: async (m) => { /* persist m, keyed by (m.from, m.messageId) */ },
  });
  try {
    const { outcomes, blocked } = await inbox.pull(relay);
    if (blocked) throw blocked;
    // Live: for await (const outcome of inbox.follow(relay, { signal, onLive: () => console.log('live') })) { ... }
    return outcomes.flatMap((o) => (o.kind === 'delivered' ? [o.message] : []));
  } finally {
    await inbox.close();
  }
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
| Principal | `request`, `decision`, `report` (09-principal: same-account rules) |

Economic messages require a `threadId` and follow the transition table of the spec (04-messages): the `rfq` sender is the buyer; each transition requires a sender role; `accept`, `invoice`, `receipt` and `confirm` must reference fixed history positions.

## API

### Identity and keys

- `SoftwareIdentity.generate(scheme)`, `SoftwareIdentity.fromExport(data)`, `identity.exportPrivateKey()`; `SIGNING_SCHEMES`, `isSigningScheme(value)`
- `createRegistrationFile(identity, { name, endpoint, description?, tier?, hardwareBacking?, capabilities?, settlement?, chains? })` — the registration file of any `ACEIdentity` (hardware-backed ones included); `invalid_registration` on invalid input
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
- `isBlockedAddress(ip)` — the SSRF policy (08-relay § Client Rules, Blocked Addresses) behind `fetchRegistrationFile` and `postDirect`: true for any blocked address (or non-IP input); IPv4-mapped and NAT64 addresses are judged by the embedded IPv4. For callers that open their own connections.
- `validateProfile`, `createRegistrationRequest`, `verifyRegistrationRequest` (returns `{ request, peer, requestDigest }`)
- `createAuthHeaders`, `parseAuthHeaders`, `verifyAuthHeaders` for `listen` / `inbox` / `unregister` / `intent` / `webhook`

### State

- `ThreadStateMachine({ localAceId })` — `check`, `apply`, `getState`, `getSnapshot`, `allowedTypes`, `exportState`, `ThreadStateMachine.fromState`
- `ReplayDetector({ capacity?, horizon?, clock? })` — `accepts`, `commit`, `clone`, `exportState`, `ReplayDetector.fromState`. Horizons are internal.

### Pipeline

- `ACEStore` — `read` / `write` (atomic; values up to 64 MiB, larger is `invalid_argument`) / `delete` / `list` / `lock(name, { timeoutMs? })` (names `^[a-z0-9][a-z0-9_-]{0,63}$`, default timeout 10 s; a lock not acquired in time is `receiver_busy` for `receive` and `lock_busy` otherwise; `storage_failed` is I/O only); `MemoryStore`, `FileStore(root)`
- `PeerStore({ store, relay?, ttlSeconds?, clock? })` — `get`, `resolve`, `adopt`, `pinRegistrationFile`, `remove`. A registration file never rotates a pinned encryption key; rotation needs a newer signed relay binding.
- `Outbox.open({ identity, store })` — repairs threads from crashed receives, then `stage`, `deliver(requestId, transport)` (returns what `transport` returns; an `expired` send is refused with `envelope_expired` before any transport call), `resign` (after `envelope_expired`), `abandon`, `pending`. Staging a message that opens a thread with a peer already holding `MAX_OPEN_THREADS_PER_PEER` (1000) non-terminal threads is `limit_exceeded`.
- `Inbox.open({ identity, store, peers, onMessage, capacity? })` — `onMessage` must persist its effect idempotently keyed by `(from, messageId)`. An invalid `capacity` is `invalid_argument`.
  - `receive(message: Uint8Array, source)` → `ReceiveOutcome` (`delivered` / `duplicate` / `quarantined` / `retryable`). `message` is the raw UTF-8 JSON of an envelope; bytes that are oversize, not JSON or not an envelope are `quarantined` (`invalid_envelope`). `source` is `{ kind: 'relay', relayUrl, streamId? }` or `{ kind: 'direct' }`; an invalid source or a closed inbox throws `invalid_argument`. A message that would open thread 1001 with one peer is quarantined `limit_exceeded`.
  - `receiveDirect(body: Uint8Array)` → `DirectReply { status, body, outcome? }` — see [Direct delivery](#direct-delivery).
  - `pull(relay, { limit?, maxPages?, signal? })` → `PullResult { outcomes, blocked, hasMore }`: every non-retryable outcome in relay order, the error that stopped the drain (or `null`), and `hasMore` when `maxPages` or an abort stopped it early. `pull` never throws: an invalid `limit` / `maxPages` is `blocked` with `invalid_argument`. `outcomes` grows with the backlog, so bound it with `maxPages` (or use `follow`). Convenience getters: `messages`, `delivered`, `duplicates`, `quarantined`.
  - `follow(relay, { signal?, onLive? })` — async iterable of the initial pull's outcomes, then live ones. `onLive()` runs once the initial pull is done and the event stream is connected, and again after every reconnect. A retryable outcome is yielded, then thrown; a failed inbox fetch is thrown.
  - `cursor(relay)` — the persisted cursor, keyed by `relay.baseUrl`; `close()`.
- `ThreadStore({ store, localAceId })` — `get`, `list`, `remove` (→ `boolean`), `allowedTypes`. Keeps a per-peer index of non-terminal threads (`threads/index/`); prunes threads idle for 30 days that are terminal or hold no local message.
- `RelayClient(baseUrl)` — `register`, `unregister`, `lookupPeer`, `discover({ q?, tags?: string[], chain?, scheme?, online?, limit?, cursor? })`, `send`, `fetchInbox`, `listen(identity, { since?, signal?, onOpen? })` (yields `{ streamId, data, catchup }` with the raw frame `data`; the Inbox decides what it is), `postIntent(identity, { need, tags?, maxPrice?, currency?, ttl })`, `listIntents({ q?, tags?: string[], limit?, cursor? })`, `setWebhook` / `getWebhook` / `clearWebhook`.
  - `baseUrl` is the normalized relay URL (08-relay § Client Rules): `http`/`https`, no userinfo, `?`, `#`, whitespace or control characters (`invalid_argument`), lowercase scheme and host, default port and trailing `/` removed. It is the key of the persisted inbox cursor.
  - Redirects are never followed: any 3xx is `relay_protocol_error`. 408 / 5xx / 429 `rate_limited` are `relay_unavailable` (with `retryAfterSeconds` from an integer `Retry-After`); any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, `max_open_intents`, …) and other 4xx are `relay_rejected` (`relayCode` holds the relay's `error`), except 400 `envelope_expired`, 403 `not_registered` and 404 `unknown_peer`, which keep their own codes. A response missing a required field, or with a present but malformed optional field (a page `cursor` of the wrong type, say), is `relay_protocol_error`.

Persisted files follow ace-spec 06 Appendix A (compact JSON, sorted keys), so the Python and Swift SDKs read the same state.

### Principal binding (0.3.0, 09-principal)

A principal record binds an agent's signing key to an account (CAIP-10), signed by an authority key of that account.

- `createPrincipalRecord(principalSignerFromIdentity(ownerKey), { subjectSigningPublicKey, account, roles, expiresAt, scope?, issuedAt? })` signs a record; any key source works through the `PrincipalSigner` interface (`{ scheme, publicKey, sign(digest) }`: passkey PRF, Secure Enclave, HSM). `roles` are `controller` and/or `agent`. Put the record in a profile or registration file; peers carrying one are verified against their signing key (`invalid_principal`).
- `validatePrincipalRecord(record, subjectSigningPublicKey, now)` checks it and returns the typed record; `principalPayload` / `principalSignData` expose the signed bytes; `parsePrincipalRecord`, `isCaip10`, `PRINCIPAL_ROLES` are helpers.
- `Inbox.open({ ..., principal: { account, selfSigner?, trustedSigners? } })` accepts `request` / `decision` / `report` under the same-account rules. The default is fail-closed: without `principal`, every principal message is `wrong_principal`. `selfSigner` (the signer of your own record) and `trustedSigners` (e.g. read from chain) name the keys accepted as authorities of the account; `eip155` accounts also accept the secp256k1 key whose address is the account.
- Option tables:

  | API | Option | Meaning |
  | --- | --- | --- |
  | `Inbox.open` | `principal?: { account, selfSigner?, trustedSigners? }` | `account` is your CAIP-10 account; `selfSigner` is the `{ scheme, publicKey }` accepted as an authority of it and has no default (the host supplies it, usually the signer of its own record; absent fails closed); `trustedSigners` is a host-supplied list of further authority keys. Omitted: every principal message is `wrong_principal`. |
  | `RelayClient.discover` | `account?` | Only peers whose principal is bound to this CAIP-10 account. |
  | `Outbox.deliver` / `PendingSend` | `requestTtl` | For a staged `request`, the body `ttl` is kept on the pending send so a retry still writes the `requests/` ledger entry with the right expiry. |

- `request` messages must go through `Outbox.deliver` to get a `requests/` ledger entry: a bare `createMessage` + `relay.send` leaves no entry, so every `decision` for it is `bad_reference`.
- Errors: `wrong_principal` (missing/foreign principal, non-authority signer, `decision` from a non-controller or from a key the request was not sent to), `bad_reference` (a `decision.requestId` that names no open request in this conversation, or an already decided or expired one), `invalid_principal` (malformed or expired record).
- The Outbox records every sent `request` in the `requests/` ledger (06 Appendix A) once the transport succeeded; an accepted `decision` closes it. `loadRequestRecord(store, conversationId, messageId)` reads a record. The ledger writers are not part of the public surface.
- When the pinned sender principal is unusable (steps 2-5), the Inbox refreshes the sender's binding from the relay once, and only for an envelope that already passed the recipient, window, replay and signature pre-checks. A transient refresh failure is retryable (the message is retried and the cursor stays); a permanent one leaves the pinned binding to decide.
- `checkPrincipalRules(type, body, { conversationId, senderPrincipal, senderSigningPublicKey, selfAccount, openRequestTo, now, selfSigner?, trustedSigners? })` runs the rules directly (pure apart from `openRequestTo`).

### Webhooks

An agent without a permanent connection can ask its relay to POST a wake-up notification when a message is queued for it (08-relay § Webhooks):

```typescript
await relay.setWebhook(identity, { url: 'https://agent.example.com/ace/wake', secret });   // secret: 16-128 chars
const hook = await relay.getWebhook(identity);   // { url, status: 'active' | 'disabled', failures, updatedAt, lastDeliveredAt?, lastError? } | null
await relay.clearWebhook(identity);
```

On the agent's HTTP endpoint, authenticate each notification before acting on it, then pull the inbox:

```typescript
import { verifyWebhookNotification } from '@ace-protocol/sdk';

const { aceId, streamId } = verifyWebhookNotification({
  secret,
  timestamp: req.headers['x-ace-webhook-timestamp'],
  signature: req.headers['x-ace-webhook-signature'],
  body: rawBody,              // the raw request bytes, not re-serialized JSON
});                            // invalid_argument / invalid_signature / stale_timestamp on failure
await inbox.pull(relay);
```

The signature is `sha256=` + hex HMAC-SHA256(secret, `<timestamp>.<body>`), checked in constant time, with a ±300 s freshness window (`windowSeconds`, `clock` to override). `signWebhookNotification(secret, timestamp, body)` and `isWebhookSecret` are the relay side.

### Direct delivery

Agents that advertise an `endpoint` accept envelopes directly (08-relay § Direct Delivery) as `POST <endpoint>` with `{"message": Envelope}`. Both paths carry the same envelope, so a copy that also arrives through the relay is a duplicate.

Receiving — the application owns the HTTP server, routing and rate limiting; the SDK answers the request body:

```typescript
const reply = await inbox.receiveDirect(rawBody);   // rawBody: Uint8Array
res.writeHead(reply.status, { 'Content-Type': 'application/json' }).end(JSON.stringify(reply.body));
```

| Request | `status` | `body` |
|---------|----------|--------|
| Any, while the inbox is closed (the sender falls back to the relay) | 503 | `{ ok: false, error: 'internal_error' }` |
| Larger than `MAX_DIRECT_BODY_BYTES` (132096) | 413 | `{ ok: false, error: 'payload_too_large' }` |
| Not UTF-8 JSON with an object top level and a `message` member | 400 | `{ ok: false, error: 'invalid_argument' }` |
| Delivered, or a duplicate | 200 | `{ ok: true, messageId }` |
| Rejected by the pipeline (direct rejections are never persisted) | 400 | `{ ok: false, error: <code> }` |
| Retryable (`transient` / `local`) | 503 | `{ ok: false, error: <code> }` |
| Any other failure | 503 | `{ ok: false, error: 'internal_error' }` |

Sending (Node only):

```typescript
import { deliverDirectOrRelay, postDirect } from '@ace-protocol/sdk/node';

await postDirect(peerEndpoint, envelope, { timeoutMs: 5000 });
// or, as an Outbox transport that falls back to the relay:
const path = await outbox.deliver(requestId, deliverDirectOrRelay(relay, peerEndpoint));   // 'direct' | 'relay'
```

`postDirect` requires an ACE HTTPS URL whose host resolves only to non-blocked addresses and connects to the validated address (DNS pinned); it never follows redirects and succeeds iff the answer is 2xx `{"ok": true}`. An unsafe or malformed endpoint is `invalid_argument`; 400 / 413 are `direct_rejected` (permanent, `remoteCode` is the receiver's `error` when it matches `^[a-z0-9_]{1,64}$`: the recipient rejected this envelope, so it is not retried directly nor through the relay); anything else is `direct_unavailable` (transient). `deliverDirectOrRelay` falls back to `relay.send` on `direct_unavailable` or an unsafe endpoint and throws `direct_rejected`.

## Development

```sh
npm ci
npm run lint && npm test && npm run build
```

The tests run `examples/quickstart.ts` and the shared cross-language vectors in `tests/fixtures` (a copy of ace-spec `test-vectors.json`, with its source revision and SHA-256 digest).

## License

Apache-2.0 — see [LICENSE](./LICENSE) for details.
