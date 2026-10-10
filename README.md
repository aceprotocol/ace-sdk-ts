# @ace-protocol/sdk

Network ingress must use `SecureMailbox`, and Outbox transport must use `SecureTransport`.
The `Inbox`/`createMessage` examples also expose lower-level application codecs; those
alone are not the authenticated secure network boundary. See “Authenticated secure delivery”.

Message packet **2.0** carries `{type,schemaDigest,threadId?,body}` entirely inside the ciphertext. Custom namespaced types require an immutable `schemaDigest`; unknown schemas are data and never execute. Durable Inbox/Outbox defaults do not install commerce state transitions. Set `commerce: true` (Python `commerce=True`) for the bundled commerce profile. The optional `principal` policy validates account coordination; receiving without it grants no execution rights.


TypeScript SDK for the **ACE Protocol** (Agent Commerce Engine) — a secure, end-to-end encrypted messaging protocol for agent-to-agent commerce.

## Features

- **Identity** — Ed25519 / secp256k1 signing keys, X-Wing encryption keys, ACE IDs, registration files
- **End-to-end encryption** — X-Wing (X25519 + ML-KEM-768) → HKDF-SHA256 → AES-256-GCM, bound to the conversation
- **Strict wire encodings** — canonical Base64, strict hex signatures, strict ed25519 (no malleable or small-order encodings), low-S secp256k1
- **Economic state machine** — parties, buyer/seller roles and fixed reference positions
- **Replay protection** — seen store with horizons, per-sender quota and canonical persistence
- **Pipeline** — `PeerStore` (rollback barrier), `Outbox` (durable send), `Inbox` (exactly-once receive with crash recovery), `SecureMailbox` (the only network receive boundary), `RelayClient` (HTTP + SSE), over any `ACEStore` (`MemoryStore`, or `FileStore` from `@ace-protocol/sdk/node`)

Application failures use `ACEError`; session/secure-delivery failures use `MLSError`. An `ACEError` comes with a stable `code` and a `category` (`permanent`, `transient` or `local`; `isTransient` means retry). The codes and categories are those of ace-spec 06-security § SDK Error Codes.

**Signatures may be non-deterministic.** secp256k1 signatures use RFC 6979 with extra randomness, so signing the same data twice can give different (equally valid) signatures. Treat signatures as verify-only: never compare signature bytes, deduplicate on them, or expect them to match a fixture.

## Encryption

Every message body is encrypted for its recipient with:

1. **X-Wing KEM** ([draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)) — a hybrid of ML-KEM-768 (FIPS 203) and X25519. The recipient's static encryption public key is 1216 bytes; each message carries a 1120-byte `kemCiphertext`; the private key is a 32-byte seed.
2. **HKDF-SHA256** — `ikm = X-Wing shared secret`, `salt = SHA-256("ace.protocol.kem.v1")`, `info = conversationId`, 32-byte output.
3. **AES-256-GCM** — random 12-byte nonce, 16-byte tag, `aad = conversationId`; `payload = nonce || ciphertext || tag`.

The `kemCiphertext` is part of the signed message payload, so a relay cannot swap it without breaking the sender's signature. Signatures (Ed25519 / secp256k1) remain classical; the hybrid KEM protects message confidentiality against harvest-now-decrypt-later attacks.

**Raw packet boundary:** a static X-Wing seed can decrypt every raw packet addressed to it. Network applications therefore use the fresh MLS delivery layer described below; retained original Outbox envelopes and plaintext logs are outside its network-capture guarantee.

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

// 1. Low-level application codec only; never send this inner envelope directly over a network.
export async function local(): Promise<ParsedMessage> {
  const alice = await SoftwareIdentity.generate('ed25519');
  const bob = await SoftwareIdentity.generate('secp256k1');
  // Peers are verified bindings; here from each other's registration files
  // (createRegistrationFile works for any ACEIdentity, hardware-backed ones included).
  const alicePeer = verifyRegistrationFile(await createRegistrationFile(alice, { name: 'Alice', endpoint: 'https://alice.example/ace' }));
  const bobPeer = verifyRegistrationFile(await createRegistrationFile(bob, { name: 'Bob', endpoint: 'https://bob.example/ace' }));

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

// 2. Authenticated network delivery. Both locally created demo peers are explicitly
// admitted; production must verify identities through a trusted pairing flow.
// MemoryStore/onMessage below illustrate the API, not crash-durable host storage.
export async function overRelay(relayUrl: string): Promise<ParsedMessage[]> {
  const { loadMLSEngine } = await import('@ace-protocol/sdk/node');
  const { SecureTransport } = await import('@ace-protocol/sdk/secure-transport');
  const { openSecureMailbox, deliverSecure } = await import('@ace-protocol/sdk/secure-mailbox');
  const relay = new RelayClient(relayUrl);
  const alice = await SoftwareIdentity.generate('ed25519'), bob = await SoftwareIdentity.generate('ed25519');
  await relay.register(alice, { name: 'Alice' }); await relay.register(bob, { name: 'Bob' });
  const aliceStore = new MemoryStore(), bobStore = new MemoryStore();
  const alicePeers = new PeerStore({ store: aliceStore, relay }), bobPeers = new PeerStore({ store: bobStore, relay });
  await SecureTransport.setPeerAllowed(aliceStore, bob.getACEId(), true);
  await SecureTransport.setPeerAllowed(bobStore, alice.getACEId(), true);
  const engine = await loadMLSEngine();
  const received: ParsedMessage[] = [];
  // Bob's receive side in one call: Inbox + SecureTransport + SecureMailbox; its close() frees the engine.
  const mailbox = await openSecureMailbox({ identity: bob, store: bobStore, peers: bobPeers, relay, engine,
    inbox: { commerce: true, onMessage: message => { received.push(message); } } });
  const stop = new AbortController();
  const listening = (async () => {
    for await (const outcome of mailbox.follow(relay, { signal: stop.signal })) {
      if (outcome.kind === 'quarantined' || outcome.kind === 'retryable') throw outcome.error;
    }
  })();
  const sender = new SecureTransport(alice, engine, aliceStore);
  try {
    const peer = await alicePeers.resolve(bob.getACEId());
    const outbox = await Outbox.open({ identity: alice, store: aliceStore, commerce: true });
    const pending = await outbox.stage({ recipient: peer, type: 'rfq', threadId: 'translation-1',
      body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' } });
    // Success means Bob durably accepted the application message, not just relay storage.
    // On failure, retain this requestId and retry it; never create a new financial operation.
    await deliverSecure(outbox, pending.requestId, { identity: alice, secure: sender, relay, peer });
    return received;
  } finally {
    stop.abort();
    // Close every user of the engine before the mailbox frees it.
    try { await listening; } finally { try { await sender.close(); } finally { await mailbox.close(); } }
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
- `createRegistrationFile(identity, { name, endpoint, description?, tier?, hardwareBacking?, capabilities?, ext?, principal?, timestamp? })` — the registration file of any `ACEIdentity` (hardware-backed ones included); `invalid_registration` on invalid input (`invalid_profile` for an invalid `ext`). Commerce data (chains, pricing, settlement, payment accounts) lives in `ext['urn:ace:commerce:1']`, never in the identity fields
- `ACEIdentity` — implement it for hardware keys; `decrypt` may use `decryptWithSeed(kemCiphertext, payload, seed, conversationId)`. A non-`ACEError` thrown by `decrypt` is reported as `identity_unavailable` (retryable).
- `computeACEId`, `computeConversationId`, `kemPublicKeyFromSeed`, `generateKemSeed`, `toBase64`, `fromBase64`

### Envelopes and messages

- `decodeEnvelope(json)` — the exact 04 decoding rules (`invalid_envelope` / `unsupported_version`)
- `verifyEnvelopeSignature(env, { scheme, signingPublicKey })`, `envelopeFingerprint(env)`
- `createMessage({ sender, recipient, type, body, threads?, threadId?, schemaDigest?, timestamp? })` — the inner signed envelope (an application codec: it is never sent over a network as is)
- `parseMessage(env, receiver, sender, { threads, replay, floor?, clock? })` — the 06 pipeline; the first failure determines the error code
- `validateBody(type, body)`; predicates `isACEId`, `isMessageId`, `isThreadId`, `isConversationId`

### Peers, registration, relay auth

- `VerifiedPeer` — only obtainable from `verifyPeerRecord`, `verifyRegistrationFile`, `verifyRegistrationRequest`, `PeerStore` or `RelayClient`. Its `profile` is unverified relay metadata.
- `fetchRegistrationFile(domain, { timeoutMs?, maxBytes?, allowPrivateAddresses? })` — SSRF-checked (the DNS check needs Node), no redirects
- `isBlockedAddress(ip)` — the SSRF policy (08-relay § Client Rules, Blocked Addresses) behind `fetchRegistrationFile` and `postDirect`: true for any blocked address (or non-IP input); IPv4-mapped and NAT64 addresses are judged by the embedded IPv4. For callers that open their own connections.
- `validateProfile`, `createRegistrationRequest`, `verifyRegistrationRequest` (returns `{ request, peer, requestDigest }`). A profile is `{ name?, description?, image?, tags?, capabilities?, endpoint?, ext?, principal? }`
- `ext` — namespaced extensions of a profile, registration file or intent (02-discovery § Profile Fields): each key is a namespaced identifier (`urn:ace:commerce:1`, `com.example:thing`; at most 256 bytes), each value a JSON object; at most 8 keys, canonical JSON at most 4096 bytes, nesting depth at most 8. `validateExt(value, 'profile' | 'intent')` (`invalid_profile` / `invalid_argument`) re-canonicalises it; an empty or `null` `ext` is absent. Relays store and serve it in canonical form and never index it; other namespaces are opaque data
- `COMMERCE_EXT` (`'urn:ace:commerce:1'`), `validateCommerceExt(value, carrier)`, `commerceExt(profileOrFile)`, `intentCommerceExt(intent)` — the bundled commerce extension (04-messages § Commerce extension), validated whenever the namespace is present: profiles and registration files carry `chains` (CAIP-2, ≤ 10), `pricing { currency, maxAmount? }`, `settlement` (≤ 10) and `accounts [{ network, address }]` (≤ 10); intents carry `maxPrice` + `currency` (both or neither). Unknown members are invalid; nothing in it confers authority
- `createAuthHeaders`, `parseAuthHeaders`, `verifyAuthHeaders` for `listen` / `inbox` / `unregister` / `intent` / `webhook`

### State

- `ThreadStateMachine({ localAceId })` — `check`, `apply`, `getState`, `getSnapshot`, `allowedTypes`, `exportState`, `ThreadStateMachine.fromState`
- `ReplayDetector({ capacity?, horizon?, clock? })` — `accepts`, `commit`, `clone`, `exportState`, `ReplayDetector.fromState`. Horizons are internal.

### Pipeline

- `ACEStore` — `read` / `write` (atomic; values up to 64 MiB, larger is `invalid_argument`) / `delete` / `list` / `lock(name, { timeoutMs? })` (names `^[a-z0-9][a-z0-9_-]{0,63}$`, default timeout 10 s; a lock not acquired in time is `receiver_busy` for `receive` and `lock_busy` otherwise; `storage_failed` is I/O only); `MemoryStore`, `FileStore(root)`. A custom store validates its inputs with the SDK's own rules: `checkKey(key)` and `checkLockName(name)` return the value or throw `invalid_argument`
- `PeerStore({ store, relay?, ttlSeconds?, clock? })` — `get`, `resolve`, `adopt`, `pinRegistrationFile`, `remove`. A registration file never rotates a pinned encryption key; rotation needs a newer signed relay binding.
- `Outbox.open({ identity, store, clock?, commerce?, schemas? })` — repairs threads from crashed receives, then `stage`, `deliver(requestId, transport)` (returns what `transport` returns; an `expired` send is refused with `envelope_expired` before any transport call), `resign` (after `envelope_expired`), `abandon`, `pending`. The transport is the secure delivery: `outbox.deliver(requestId, envelope => secure.deliver(envelope, peer, (packet, route) => replies.exchange(packet, route)))` resolves only once the peer's Inbox durably committed the envelope (see [Authenticated secure delivery](#authenticated-secure-delivery)). Staging a message that opens a thread with a peer already holding `MAX_OPEN_THREADS_PER_PEER` (1000) non-terminal threads is `limit_exceeded`.
- `Inbox.open({ identity, store, peers, onMessage, capacity?, offlineWindowSeconds?, clock?, principal?, commerce?, schemas? })` — the application receive engine (decode, verify, installed profiles, durable delivery journal, replay / dedup, `onMessage`). It knows nothing about relays, cursors or HTTP: `SecureMailbox` feeds it authenticated MLS plaintext; in-process code and tests call it directly. `onMessage` must persist its effect idempotently keyed by `(from, messageId)`. An invalid `capacity` is `invalid_argument`.
  - `receive(message: Uint8Array)` → `ReceiveOutcome` (`delivered` / `duplicate` / `quarantined` / `retryable`). `message` is the raw UTF-8 JSON of an envelope; bytes that are oversize, not JSON or not an envelope are `quarantined` (`invalid_envelope`). A closed inbox throws `invalid_argument`. Permanent failures of a decoded envelope are persisted under `quarantine/`. A message that would open thread 1001 with one peer is quarantined `limit_exceeded`.
  - `close()`.
  - `inboxPrincipalFromOwnRecord(record, identity, { now?, trustedSigners? })` → `{ principal, warning? }` — the `principal` option for a host's own saved principal record (R-B12a): `undefined` / `null` → no principal; a record that does not validate for `identity`'s signing key at `now` (default wall clock) → no principal plus a `'<code>: <detail>'` warning for the host to surface (never throws); a valid one → `{ account, selfSigner: record.signer, trustedSigners }`.
- `SecureMailbox.open({ identity, store, peers, relay, secure, inbox, closeTransport?, dispose? })` (`@ace-protocol/sdk/secure-mailbox`) — the only network receive boundary: every relay entry, SSE frame or direct body is an authenticated secure-delivery frame; the contained `Inbox` receives the MLS plaintext. Static application envelopes are quarantined, never delivered.
  - `pull(relay, { limit?, maxPages?, signal? })` → `PullResult { outcomes, blocked, hasMore }`: every non-retryable outcome in relay order, the error that stopped the drain (or `null`), and `hasMore` when `maxPages` or an abort stopped it early. `pull` never throws: an invalid `limit` / `maxPages` is `blocked` with `invalid_argument`. Convenience getters: `messages`, `delivered`, `duplicates`, `quarantined`.
  - `follow(relay, { signal?, onLive? })` — async iterable of the initial pull's outcomes, then live ones. `onLive()` runs once the initial pull is done and the event stream is connected, and again after every reconnect. A failed initial pull is thrown.
  - `receiveDirect(body: Uint8Array)` → `DirectReply { status, body, outcome? }` — see [Direct delivery](#direct-delivery).
  - `cursor(relay)` — the persisted cursor of the mailbox's relay (`null` for another relay); `close()` also closes the Inbox (and the transport unless `closeTransport: false`).
  - `openSecureMailbox({ identity, store, peers, relay, engine, inbox, clock? })` — the recommended way to open it: `Inbox.open` with `inbox` (the remaining `InboxOptions`: `onMessage`, `commerce`, `principal`, `schemas`, `clock`, …), a `SecureTransport` over `engine`, then `SecureMailbox.open` owning both (`closeTransport: true`, `dispose: () => engine.free?.()`). A failure after the Inbox opened closes it (no leaked `receive` lock) and leaves the engine to the caller.
  - `deliverSecure(outbox, requestId, { identity, secure, relay, peer, send? })` / `secureTransportFor(s)` — the sending side (see [Authenticated secure delivery](#authenticated-secure-delivery)).
- `ThreadStore({ store, localAceId })` — `get`, `list`, `remove` (→ `boolean`), `allowedTypes`. Keeps a per-peer index of non-terminal threads (`threads/index/`); prunes threads idle for 30 days that are terminal or hold no local message.
- `RelayClient(baseUrl)` — `register`, `unregister`, `lookupPeer`, `discover({ q?, tags?: string[], scheme?, account?, online?, limit?, cursor? })`, `send`, `fetchInbox`, `listen(identity, { since?, signal?, onOpen? })` (yields `{ streamId, data, catchup }` with the raw frame `data`; the Inbox decides what it is), `postIntent(identity, { need, tags?, ext?, ttl })` (an intent is `{ intentId, from, need, tags, ttl, ext?, createdAt, expiresAt }`; `ext` only when non-empty), `listIntents({ q?, tags?: string[], limit?, cursor? })`, `setWebhook` / `getWebhook` / `clearWebhook`.
  - `baseUrl` is the normalized relay URL (08-relay § Client Rules): `http`/`https`, no userinfo, `?`, `#`, whitespace or control characters (`invalid_argument`), lowercase scheme and host, default port and trailing `/` removed. Its SHA-256 names the persisted secure cursor.
  - Redirects are never followed: any 3xx is `relay_protocol_error`. 408 / 5xx / 429 `rate_limited` are `relay_unavailable` (with `retryAfterSeconds` from an integer `Retry-After`); any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, `max_open_intents`, …) and other 4xx are `relay_rejected` (`relayCode` holds the relay's `error`), except 400 `envelope_expired`, 403 `not_registered` and 404 `unknown_peer`, which keep their own codes. A response missing a required field, or with a present but malformed optional field (a page `cursor` of the wrong type, say), is `relay_protocol_error`.

Persisted files follow ace-spec 06 Appendix A (compact JSON, sorted keys), so the Python and Swift SDKs read the same state: `replay.json`, `deliveries/`, `quarantine/`, `threads/`, `outbox/`, `sent/`, `requests/`, `peers/`, `secure/cursors/<sha256(normalized relay URL)>.json`, `secure/peers/<sha256(aceId)>.json`, `secure/in/<attempt>.json` and `mls/gates/…`.

### Installed schemas

A custom namespaced type is authenticated data until the host installs a validator for its digest: `Inbox.open({ ..., schemas })` and `Outbox.open({ ..., schemas })` take a map from `schemaDigest` (64 lowercase hex) to a `SchemaValidator`, `({ type, schemaDigest, threadId, body }) => void` — deterministic, no I/O, no effects; throw to reject. The Inbox runs it at the body-validation step (after decryption, before thread / principal checks) in addition to the bundled validation of a bundled type; a thrown permanent `ACEError` quarantines the message with that code, anything else thrown is `invalid_body`. `Outbox.stage` runs it on the outgoing body and refuses a rejected one before anything is persisted (same mapping). A map with a non-hex key or a non-function value is `invalid_argument` at open.

### Principal binding (0.3.0, 09-principal)

A principal record binds an agent's signing key to an account (CAIP-10), signed by an authority key of that account. Roles: a `delegate` is the identity that acts for the account, a `controller` is the one that approves (`["controller"]`, `["delegate"]` or `["controller","delegate"]`, `controller` first).

- `createPrincipalRecord(principalSignerFromIdentity(ownerKey), { subjectSigningPublicKey, account, roles, expiresAt, scope?, issuedAt? })` signs a record; any key source works through the `PrincipalSigner` interface (`{ scheme, publicKey, sign(digest) }`: passkey PRF, Secure Enclave, HSM). `roles` are `controller` and/or `delegate`. Put the record in a profile or registration file; peers carrying one are verified against their signing key (`invalid_principal`).
- `validatePrincipalRecord(record, subjectSigningPublicKey, now)` checks it and returns the typed record; `principalPayload` / `principalSignData` expose the signed bytes; `parsePrincipalRecord`, `isCaip10`, `PRINCIPAL_ROLES` are helpers.
- `Inbox.open({ ..., principal: { account, selfSigner?, trustedSigners? } })` accepts `request` / `decision` / `report` under the same-account rules. Once installed it fails closed (`wrong_principal`). Without `principal` no account policy is installed: principal messages are delivered as plain data, unverified (a `decision` never fills `requests/`), so never treat their type as authority; use resource grants for execution. `selfSigner` (the signer of your own record) and `trustedSigners` (e.g. read from chain) name the keys accepted as authorities of the account; `eip155` accounts also accept the secp256k1 key whose address is the account.
- Option tables:

  | API | Option | Meaning |
  | --- | --- | --- |
  | `Inbox.open` | `principal?: { account, selfSigner?, trustedSigners? }` | `account` is your CAIP-10 account; `selfSigner` is the `{ scheme, publicKey }` accepted as an authority of it and has no default (the host supplies it, usually the signer of its own record; absent fails closed); `trustedSigners` is a host-supplied list of further authority keys. Omitted: no account policy; principal messages are delivered as unverified plain data. |
  | `RelayClient.discover` | `account?` | Only peers whose principal is bound to this CAIP-10 account. |
  | `Outbox.deliver` / `PendingSend` | `requestTtl` | For a staged `request`, the body `ttl` is kept on the pending send so a retry still writes the `requests/` ledger entry with the right expiry. |

- `request` messages must go through `Outbox.deliver` to get a `requests/` ledger entry: a bare `createMessage` handed to `secure.deliver` leaves no entry, so every `decision` for it is `bad_reference`.
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
await mailbox.pull(relay);
```

The signature is `sha256=` + hex HMAC-SHA256(secret, `<timestamp>.<body>`), checked in constant time, with a ±300 s freshness window (`windowSeconds`, `clock` to override). `signWebhookNotification(secret, timestamp, body)` and `isWebhookSecret` are the relay side.

### Direct delivery

Agents that advertise an `endpoint` accept secure-delivery frames directly (08-relay § Direct Delivery) as `POST <endpoint>` with `{"message": Envelope}`, where the envelope is a handshake frame (`hello` / `data`) of the authenticated secure delivery; the signed reply (`offer` / `ack`) comes back through the relay. A frame that also arrives through the relay is handled once.

Receiving — the application owns the HTTP server, routing and rate limiting; the `SecureMailbox` answers the request body:

```typescript
const reply = await mailbox.receiveDirect(rawBody);   // rawBody: Uint8Array
res.writeHead(reply.status, { 'Content-Type': 'application/json' }).end(JSON.stringify(reply.body));
```

| Request | `status` | `body` |
|---------|----------|--------|
| Larger than `MAX_DIRECT_BODY_BYTES` (132096) | 413 | `{ ok: false, error: 'payload_too_large' }` |
| Not UTF-8 JSON with an object top level and a `message` member | 400 | `{ ok: false, error: 'invalid_argument' }` |
| A frame accepted by the handshake (the application message, once the `data` frame is committed, is `outcome`) | 200 | `{ ok: true, messageId }` |
| Refused permanently: not an envelope, a static application envelope, a disabled peer, an Inbox rejection (persisted under `quarantine/`) | 400 | `{ ok: false, error: <code> }` |
| Retryable (`transient` / `local`, a closed mailbox included: the sender falls back to the relay) | 503 | `{ ok: false, error: <code> }` |

Sending (Node only) — `postDirect` and `deliverDirectOrRelay` are the transport of the secure delivery frames, i.e. the `send` of `SecureRelayReplies`: direct endpoint first, relay fallback. Application envelopes never travel through them; `Outbox.deliver` takes `secure.deliver`:

```typescript
import { deliverDirectOrRelay, postDirect } from '@ace-protocol/sdk/node';

await postDirect(peer.endpoint, frame, { timeoutMs: 5000 });
// or, as the frame transport of a secure delivery that falls back to the relay:
await deliverSecure(outbox, requestId, { identity, secure, relay, peer, send: deliverDirectOrRelay(relay, peer.profile?.endpoint) });   // the transport resolves 'direct' | 'relay' per frame
// which is the same as the manual composition:
const replies = new SecureRelayReplies(identity, secure, relay, peer, deliverDirectOrRelay(relay, peer.profile?.endpoint));
await outbox.deliver(requestId, envelope => secure.deliver(envelope, peer, (packet, route) => replies.exchange(packet, route)));
```

`postDirect` requires an ACE HTTPS URL whose host resolves only to non-blocked addresses and connects to the validated address (DNS pinned); it never follows redirects and succeeds iff the answer is 2xx `{"ok": true}`. An unsafe or malformed endpoint is `invalid_argument`; 400 / 413 are `direct_rejected` (permanent, `remoteCode` is the receiver's `error` when it matches `^[a-z0-9_]{1,64}$`: the recipient rejected this frame, so it is not retried directly nor through the relay); anything else is `direct_unavailable` (transient). `deliverDirectOrRelay` falls back to `relay.send` on `direct_unavailable` or an unsafe endpoint and throws `direct_rejected`.

## Development

```sh
npm ci
npm run lint && npm test && npm run build
```

The tests run `examples/quickstart.ts` and the shared cross-language vectors in `tests/fixtures` (a copy of ace-spec `test-vectors.json`, with its source revision and SHA-256 digest).

## License

Apache-2.0 — see [LICENSE](./LICENSE) for details.

## Resource execution and audit

Exact-intent grants bind a resource, executor, immutable effect digest, absolute deadline and policy epoch. Verification starts from a locally trusted authority and validates every ancestor; message labels confer no rights. See [resource grants](https://github.com/aceprotocol/ace-spec/blob/main/10-resource-grants.md). The TypeScript and Swift `ExecutionAuthority` coordinators reserve all profile-derived budgets atomically and consume one authorization release under current policy. `hasReservation` reads a permanent binding after expiry/revocation; it never permits another effect. All three SDKs expose the closed `urn:ace:execute:1` request schema. Applications install their own deterministic effect validators and durable executors on top of this boundary; the SDK ships no chain- or product-specific executor.

Optional audit APIs create private salted commitments, Merkle inclusion/consistency proofs and signed checkpoints. They do not publish records automatically. See [private audit](https://github.com/aceprotocol/ace-spec/blob/main/11-audit.md). The secure network boundary and its narrower confidentiality claim are described below; private application logs and backups still require protection.

`FileStore` requires the optional native `fs-ext` binding on a POSIX local filesystem. It fails closed when unavailable. Locks use permanent inodes and kernel `flock`; never delete lock files or use a network mount. Process termination releases locks without stale-file takeover. Audit log/witness storage uses these same durable writes and locks.


`ExecutionAuthority` takes scoped coordinated storage (`CoordinatedStore` in TypeScript,
`ACECoordinatedStore` in Swift). `MemoryStore` and `FileStore` implement local coordination.
The optional `EtcdStore` backend pins a trusted etcd v3 cluster and fences every state access
against the acquired lease token. It exposes no unscoped data operations or offline fallback.
Use it for finite authority transactions, not long-lived receive locks. See document 10 for
configuration, trust assumptions, snapshot recovery restrictions and the real three-node tests.

### Authenticated secure delivery

Use `SecureTransport` around Outbox and `SecureMailbox` for network ingress. The SDK owns the
glue every host needs: open the receive boundary with `openSecureMailbox` and send with
`deliverSecure` (both from `@ace-protocol/sdk/secure-mailbox`); the principal option for your
own saved record comes from `inboxPrincipalFromOwnRecord`:

```typescript
import { inboxPrincipalFromOwnRecord } from '@ace-protocol/sdk';
import { loadMLSEngine } from '@ace-protocol/sdk/node';
import { SecureTransport } from '@ace-protocol/sdk/secure-transport';
import { deliverSecure, openSecureMailbox } from '@ace-protocol/sdk/secure-mailbox';

// Receiving: one object owns the Inbox, the transport and the engine; close() releases all three.
const { principal, warning } = inboxPrincipalFromOwnRecord(savedProfile?.principal, identity);
if (warning) console.error(`saved principal ignored (${warning})`);
const mailbox = await openSecureMailbox({ identity, store, peers, relay, engine: await loadMLSEngine(),
  inbox: { commerce: true, principal, onMessage: async (m) => { await persist(m); } } });
for await (const outcome of mailbox.follow(relay, { signal })) { /* … */ }
await mailbox.close();

// Sending: the Outbox operation completes only once the peer's Inbox durably committed the envelope.
const engine = await loadMLSEngine(), secure = new SecureTransport(identity, engine, store);
try { await deliverSecure(outbox, pending.requestId, { identity, secure, relay, peer }); }   // send?: deliverDirectOrRelay(relay, peer.profile?.endpoint)
finally { await secure.close(); engine.free(); }
```

`openSecureMailbox` is `Inbox.open` → `new SecureTransport(identity, engine, store, clock)` →
`SecureMailbox.open({ …, closeTransport: true, dispose: () => engine.free?.() })`; a failure after
the Inbox opened closes it before rethrowing, and the engine stays the caller's. `deliverSecure`
is `outbox.deliver(requestId, secureTransportFor(s))`, where `secureTransportFor` builds the
`SecureRelayReplies` (frames through `send`, default `relay.send`) and returns
`envelope => secure.deliver(envelope, peer, (packet, route) => replies.exchange(packet, route))`.
A host that shares one engine between a mailbox and a sender (as the quickstart does) closes the
sender before the mailbox, or passes the mailbox an engine view without `free`. The manual
composition below remains available for hosts that need a shared transport or their own
reply reader.

Each attempt
uses a fresh MLS group from the shared OpenMLS engine and ends with an authenticated
receipt after the original Inbox durably commits. The receipt carries the Inbox outcome:
`delivered` and `duplicate` complete the operation; a permanently rejected inner envelope
(quarantined) makes `deliver` throw `delivery_rejected` (permanent, `remoteCode` is the Inbox
code) so the sender never retries it. A retryable Inbox failure produces no receipt: the
attempt expires and the sender retries a fresh one. `RelayClient.send` acknowledges relay
storage only; it is not an application-delivery receipt. Static application packets are
refused by SecureMailbox, with no downgrade fallback.

Both endpoints must explicitly enable the full peer identity through local policy
(`SecureTransport.setPeerAllowed`; `SecureTransport.isPeerAllowed` reads it); the mailbox
checks admission before resolving the sender, so an unadmitted stranger's frame costs no
relay lookup and pins nothing. Discovery and principal roles do not enable communication
or grant execution rights. Revocation advances the policy generation, so re-enabling cannot
revive old handshakes. The receiver must be online; a timeout leaves the original Outbox
operation pending. Retry that operation ID. The complete inner signed envelope is limited to 40,000 bytes,
and a handshake to 120 seconds. Keep HTTP timeouts bounded and callbacks idempotent.

After ephemeral state erasure, later static-key theft alone cannot decrypt captured past
application deliveries under classical MLS assumptions. Stored plaintext, original Outbox
envelopes and host snapshots are excluded. This is not post-quantum forward secrecy or
authentication. Independent cryptographic review remains a production-release gate.
See [the protocol and failure model](https://github.com/aceprotocol/ace-spec/blob/main/13-session-core.md)
and [source build/packaging](https://github.com/aceprotocol/ace-session-core#readme).

Node: `loadMLSEngine()` from `@ace-protocol/sdk/node` loads the source-built WASM bundled by `npm run build`. `deliverSecure` (its `SecureRelayReplies.exchange`) is the sending process alongside a separate listener. Close mailboxes/transports before `engine.free()`.
