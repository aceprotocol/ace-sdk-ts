# @ace-protocol/sdk

TypeScript SDK for the **ACE Protocol**: post-quantum agent identity, asynchronous end-to-end encrypted packets and
profile-based interaction vocabularies. ACE lets agents express intent reliably, learn which interaction rules a peer
supports, and exchange information safely. Who to work with, what to agree and whether to pay or execute anything are
application decisions: no ACE object authorizes execution or payment.

Spec: `ace-spec` chapters 00–08 (packet version `"1"`). Every signature is ML-DSA-65 over
`M = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)` with the action as the ML-DSA context.

## What is inside

- **Identity** — key event log (`icp`/`rot`/`dlg`; `dlg` delegates the ML-DSA-65 signing key only), ACE IDs,
  pre-rotation and recovery. `SoftwareIdentity` exports root, next-root and signing seeds plus the KEL.
- **Prekeys** — `PrekeyVault` (`current`, `rotate`, `open`, `prune`): X-Wing prekeys published in the descriptor,
  superseded seeds retained for `OFFLINE_WINDOW_SECONDS` (at most 16). `StorePrekeyVault` persists them in an
  `ACEStore` (a 0600 file with `FileStore`, a `MemoryStore` for ephemeral agents; optional `protect` sealing hook).
- **Packet** — `createPacket`, `decodePacket`, `verifyPacketSignature`, `decryptPacket`: X-Wing → HKDF-SHA256 (empty
  salt, info = header binding `from`, `to`, `messageId`, `timestamp`, prekey and KEM ciphertext) → AES-256-GCM, signed
  with ML-DSA-65 (action `packet`). The recipient need not be online.
- **Card record** — `createCardRecord` / `verifyCardBundle`: the durable identity record `{kel, card}` with its home
  relay, set-once handle (`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, 3–32 characters), card (`description`, `image`, `tags`;
  no name: a display name is application data), `pay` (CAIP-10 accounts), `contact` (`open` takes stranger contact
  requests) and `listed` (directory). No expiry; re-signed after a new `dlg`. `NetworkClient.lookupCard` resolves an
  ACE ID or `@name@host` (typed without the `@` or in any ASCII case is accepted); with no live descriptor it verifies
  under the bundle's own KEL and says `kelLive: false`. `NetworkClient.discover` / `RelayClient.directory` read the
  directory (`GET /v1/cards`, optional `tag`, `profile` hint): listed card records, each verified on its own.
- **Descriptor** — `createDescriptor` / `verifyPublishedAgent`: relays, prekey, profiles, `ext`, Delegation credentials and ERC-8004 bindings
  (`verifyErc8004Registration` checks the reverse direction against the registration file's `services`; the host
  reads the chain). Every operational signature is checked by one `verifyOperationalSignature` (01 rules 1–5: the
  signer must also be usable now).
- **Admission** — 30-day delivery permits, contact requests as `ace:contact:1` packets, blocks, and invitations for
  out-of-band pairing (`NetworkClient.createInvitation` admits the invitee; `importInvitation` verifies the invitation,
  pins the inviter and holds its permit, and never admits).
- **Delivery** — `Outbox` (persisted, re-encrypted per attempt, backoff 60 s → 3600 s, expires after the offline
  window; only a receipt confirms delivery; `prune` keeps settled entries for the offline window), `Inbox` (admission
  before any lookup, schema and profile-rule checks, `rejected:<code>` receipts, beyond-horizon packets dropped without
  a receipt, poison quarantine), `RelayClient` for the relay HTTP binding.
- **Profiles** — the official manifests (`ace:core:1`, `ace:text:1`, `ace:commerce:1`) are bundled from
  `ace-spec/profiles/` (`npm run gen:profiles`); `ProfileSet` installs them or third-party manifests; `ProfileRules`
  hooks carry profile semantics (`check` at enqueue, send-side `commit` on the `delivered` receipt; a thread with a
  rule-governed message in flight is `thread_busy`). The optional commerce module provides `commerceRules()` and
  `ThreadStore`.
- **Glue** — `NetworkClient.open(config)`: the store (an `ACEStore` or a directory), the home relay (`relayUrl` or a
  `RelayClient`), installed profiles (names or manifests; `'commerce'` adds `commerceRules` and `client.threads`) and a
  `MessageLog` (`client.messages`: indexed unread cap, ack, filters). Methods: `publish({force})` (registers on
  demand), `discover`, `importAgent`, `lookup`, `lookupWithCard`, `agent`, `connect`, `requests`, `accept`, `reject`, `block`, `unblock`,
  `createInvitation`, `importInvitation`, `send`, `flush`, `pull`, `follow`, `maintain`, `setWake`, `clearWake` (07 § Wake
  hints), `close`; the `onReceipt` hook
  sees each receipt with its settled Outbox entry. `receive: false` opens a send-only client.
- **Agent tools** — `@ace-protocol/sdk/tools`: `AGENT_TOOLS`, the tool table (`ace_identity`, `ace_network`,
  `ace_send`, `ace_inbox`, `ace_outbox`, `ace_threads`) every MCP surface serves, with JSON Schema inputs, scopes per
  action, and `untrusted` paths marking remote content in every result.
- **Relay side** — `parseAuthHeaders` + `verifyAuthHeaders`, `verifyRegistrationRequest` (07 check order), and
  `parseIp`, `networkKey` (client network: IPv4 /24, IPv6 /56) and `isBlockedAddress` for relays.

All failures are `ACEError` with a stable `code` and `category` (`permanent`, `transient`, `local`).

## Quick start

```typescript
import { MemoryStore, NetworkClient, SoftwareIdentity } from '@ace-protocol/sdk';

const alice = await NetworkClient.open({ identity: await SoftwareIdentity.generate(), store: '/var/lib/alice-ace',
  relayUrl: 'https://relay.example', profiles: ['text'], contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
const bob = await NetworkClient.open({ identity: await SoftwareIdentity.generate(), store: new MemoryStore(),
  relayUrl: 'https://relay.example', profiles: ['text'] });
for (const client of [alice, bob]) await client.publish(); // registers at the relay on demand

const aliceId = alice.identity.getACEId();
await bob.connect(aliceId, { profile: 'ace:text:1', note: 'hi' }); // encrypted contact request
await alice.pull();                                               // accepted by the acceptProfiles rule
await bob.pull();
await bob.send(aliceId, 'ace:text:1', { message: 'Hello' });      // Outbox entry; receipt confirms delivery
await alice.pull();                                               // stored in alice.messages
console.log(await alice.messages!.list());
```

See `examples/quickstart.ts`. The host calls `client.maintain()` once at start and then at least every 3600
seconds: it republishes the descriptor (rotating the prekey every 24 hours), pushes fresh permits after a signing-key
change, registers blocks the relay has not confirmed (`block` is local-first), retries due Outbox entries and prunes
settled ones after the offline window. Watch outcomes with `onReceipt` rather than polling the Outbox.

## Requirements

Node.js >= 20.19. `FileStore` takes cross-process locks with POSIX `flock` from the optional native dependency
`fs-ext` (optional so that `MemoryStore`/edge users never compile a native addon). There is no unsafe fallback: the
first lock fails with a clear `storage_failed` when `fs-ext` is missing or built for another Node.js
(`npm rebuild fs-ext`).

Processes sharing one store: only one may hold the receive role (`Inbox`, lock `receive`). Others open
`NetworkClient.open({ ..., receive: false })` to publish and send; a home relay built from `relayUrl` persists its
registration timestamps in the store, so they stay strictly increasing across processes.

## License

Apache-2.0
