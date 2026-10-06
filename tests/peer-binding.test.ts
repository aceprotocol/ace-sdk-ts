import { describe, it, expect } from 'vitest';
import {
  SoftwareIdentity,
  verifyEncryptionKeyBinding,
  verifyPeerResponse,
  parseMessageFromPeer,
  createMessage,
  buildSignData,
  encodePayload,
  encodeSignature,
  toBase64,
  ThreadStateMachine,
  ReplayDetector,
  type RelayPeerResponse,
  type SigningScheme,
} from '../src/index.js';

// Reproduce exactly what the relay stores/serves for GET /v1/peer.
async function relayPeerResponse(
  identity: SoftwareIdentity,
  registeredAt = 1741000000,
): Promise<RelayPeerResponse> {
  const encB64 = toBase64(identity.getEncryptionPublicKey());
  const signB64 = toBase64(identity.getSigningPublicKey());
  const signData = buildSignData('register', identity.getACEId(), registeredAt, encodePayload(encB64, signB64));
  const { signature, scheme } = await identity.sign(signData);
  return {
    aceId: identity.getACEId(),
    scheme,
    encryptionPublicKey: encB64,
    signingPublicKey: signB64,
    registrationSignature: encodeSignature(signature, scheme),
    registeredAt,
  };
}

const SCHEMES: SigningScheme[] = ['ed25519', 'secp256k1'];

describe('encryption-key binding (relay MITM defense)', () => {
  it.each(SCHEMES)('accepts a genuine %s binding', async (scheme) => {
    const identity = await SoftwareIdentity.generate(scheme);
    const peer = verifyPeerResponse(await relayPeerResponse(identity));
    expect(peer.aceId).toBe(identity.getACEId());
    expect(peer.encryptionPublicKey).toEqual(identity.getEncryptionPublicKey());
    expect(peer.signingPublicKey).toEqual(identity.getSigningPublicKey());
  });

  it.each(SCHEMES)('rejects a substituted %s encryption key', async (scheme) => {
    const victim = await SoftwareIdentity.generate(scheme);
    const attacker = await SoftwareIdentity.generate(scheme);

    const poisoned = await relayPeerResponse(victim);
    poisoned.encryptionPublicKey = toBase64(attacker.getEncryptionPublicKey());

    // aceId still matches the (untouched) signing key — only the binding catches it.
    expect(
      verifyEncryptionKeyBinding(
        poisoned.aceId, poisoned.scheme,
        poisoned.encryptionPublicKey, poisoned.signingPublicKey,
        poisoned.registeredAt!, poisoned.registrationSignature!,
      ),
    ).toBe(false);
    expect(() => verifyPeerResponse(poisoned)).toThrow(/binding failed verification/);
  });

  it('rejects a 32-byte (non-X-Wing) encryption key even with a signature over it', async () => {
    const identity = await SoftwareIdentity.generate('ed25519');
    const encB64 = toBase64(new Uint8Array(32));
    const signB64 = toBase64(identity.getSigningPublicKey());
    const registeredAt = 1741000000;
    const signData = buildSignData('register', identity.getACEId(), registeredAt, encodePayload(encB64, signB64));
    const { signature, scheme } = await identity.sign(signData);
    const resp: RelayPeerResponse = {
      aceId: identity.getACEId(),
      scheme,
      encryptionPublicKey: encB64,
      signingPublicKey: signB64,
      registrationSignature: encodeSignature(signature, scheme),
      registeredAt,
    };
    expect(verifyEncryptionKeyBinding(
      resp.aceId, resp.scheme, resp.encryptionPublicKey, resp.signingPublicKey,
      registeredAt, resp.registrationSignature!,
    )).toBe(false);
    expect(() => verifyPeerResponse(resp)).toThrow(/binding failed verification/);
  });

  it('rejects a missing binding signature', async () => {
    const identity = await SoftwareIdentity.generate('secp256k1');
    const resp = await relayPeerResponse(identity);
    delete resp.registrationSignature;
    expect(() => verifyPeerResponse(resp)).toThrow(/missing the encryption-key binding/);
  });

  it('rejects an aceId that does not match the signing key', async () => {
    const identity = await SoftwareIdentity.generate('ed25519');
    const other = await SoftwareIdentity.generate('ed25519');
    const resp = await relayPeerResponse(identity);
    resp.aceId = other.getACEId();
    expect(() => verifyPeerResponse(resp)).toThrow();
  });

  it('rejects a tampered registeredAt (timestamp is signed)', async () => {
    const identity = await SoftwareIdentity.generate('secp256k1');
    const resp = await relayPeerResponse(identity, 1741000000);
    expect(
      verifyEncryptionKeyBinding(
        resp.aceId, resp.scheme, resp.encryptionPublicKey,
        resp.signingPublicKey, 1741000001, resp.registrationSignature!,
      ),
    ).toBe(false);
  });

  it.each(SCHEMES)('parseMessageFromPeer round-trips for %s', async (scheme) => {
    const sender = await SoftwareIdentity.generate(scheme);
    const receiver = await SoftwareIdentity.generate('ed25519');

    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'text',
      body: { message: 'hello' },
      stateMachine: new ThreadStateMachine(),
    });

    const senderPeer = verifyPeerResponse(await relayPeerResponse(sender));
    const parsed = await parseMessageFromPeer(msg, receiver, senderPeer, {
      stateMachine: new ThreadStateMachine(),
      replayDetector: new ReplayDetector(),
    });

    expect(parsed.body).toEqual({ message: 'hello' });
    expect(parsed.from).toBe(sender.getACEId());
  });
});
