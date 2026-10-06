import { describe, it, expect } from 'vitest';
import { SoftwareIdentity, toBase64, fromBase64 } from '../src/identity.js';
import { ReplayDetector } from '../src/security.js';
import { MAX_PAYLOAD_SIZE } from '../src/encryption.js';
import { encrypt } from '../src/encryption.js';
import { buildSignData, encodePayload, encodeSignature } from '../src/signing.js';
import { ThreadStateMachine } from '../src/state-machine.js';
import { MESSAGE_TYPES, isMessageType, type ACEMessage, type MessageType } from '../src/index.js';
import {
  createMessage,
  validateBody,
  parseMessage,
  parseMessageFromRegistration,
} from '../src/messages.js';

function makeSM(): ThreadStateMachine {
  return new ThreadStateMachine();
}

describe('Messages', () => {
  describe('validateBody', () => {
    it('validates rfq body', () => {
      expect(() => validateBody('rfq', { need: 'GPU rental' })).not.toThrow();
      expect(() => validateBody('rfq', {})).toThrow(/need/);
    });

    it('validates offer body', () => {
      expect(() => validateBody('offer', { price: '10', currency: 'USD' })).not.toThrow();
      expect(() => validateBody('offer', { price: '10' })).toThrow(/currency/);
    });

    it('validates accept body', () => {
      expect(() => validateBody('accept', { offerId: 'abc' })).not.toThrow();
      expect(() => validateBody('accept', {})).toThrow(/offerId/);
    });

    it('validates invoice body', () => {
      expect(() => validateBody('invoice', {
        offerId: 'abc',
        amount: '10',
        currency: 'USD',
        settlementMethod: 'crypto/instant',
      })).not.toThrow();
      expect(() => validateBody('invoice', { amount: '10' })).toThrow(/offerId/);
    });

    it('validates receipt body', () => {
      expect(() => validateBody('receipt', {
        referenceId: 'abc',
        amount: '10',
        currency: 'USD',
        settlementMethod: 'crypto/instant',
        proof: { txHash: '0x123' },
      })).not.toThrow();
    });

    it('validates deliver body (inline)', () => {
      expect(() => validateBody('deliver', {
        type: 'inline',
        content: 'data here',
      })).not.toThrow();
      expect(() => validateBody('deliver', {
        type: 'inline',
      })).toThrow(/content/);
    });

    it('validates deliver body (reference)', () => {
      expect(() => validateBody('deliver', {
        type: 'reference',
        uri: 'https://example.com/file',
      })).not.toThrow();
      expect(() => validateBody('deliver', {
        type: 'reference',
      })).toThrow(/uri/);
    });

    it('validates confirm body', () => {
      expect(() => validateBody('confirm', { deliverId: 'abc' })).not.toThrow();
      expect(() => validateBody('confirm', {})).toThrow(/deliverId/);
    });

    it('validates text body', () => {
      expect(() => validateBody('text', { message: 'hello' })).not.toThrow();
      expect(() => validateBody('text', {})).toThrow(/message/);
    });

    it('validates info body', () => {
      expect(() => validateBody('info', { message: 'status ok' })).not.toThrow();
      expect(() => validateBody('info', {})).toThrow(/message/);
    });

    it('validates reject body (no required fields)', () => {
      expect(() => validateBody('reject', {})).not.toThrow();
      expect(() => validateBody('reject', { reason: 'not interested' })).not.toThrow();
    });

    it('rejects invalid deliver.type with sanitized error', () => {
      expect(() => validateBody('deliver', {
        type: '<script>alert("xss")</script>'.repeat(10),
      })).toThrow(/deliver\.type must be/);
    });

    it('rejects wrong required field types', () => {
      expect(() => validateBody('invoice', {
        offerId: '550e8400-e29b-41d4-a716-446655440000',
        amount: ['3.50'],
        currency: 'USD',
        settlementMethod: 'crypto/instant',
      } as any)).toThrow(/amount must be a string/);
    });

    it('rejects wrong optional field types', () => {
      expect(() => validateBody('offer', {
        price: '3.50',
        currency: 'USD',
        ttl: true,
      } as any)).toThrow(/ttl must be a number/);
    });

    it('rejects wrong system message type', () => {
      expect(() => validateBody('text', {
        message: { hello: 'world' },
      } as any)).toThrow(/message must be a string/);
    });
  });

  describe('createMessage', () => {
    it('creates a full ACE message envelope', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'GPU rental', maxPrice: '50', currency: 'USD' },
        stateMachine: makeSM(),
        threadId: 'deal-001',
      });

      expect(msg.ace).toBe('1.0');
      expect(msg.type).toBe('rfq');
      expect(msg.from).toBe(sender.getACEId());
      expect(msg.to).toBe(receiver.getACEId());
      expect(msg.messageId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect('body' in msg).toBe(false);
      expect(msg.encryption.kemCiphertext).toBeTruthy();
      expect(fromBase64(msg.encryption.kemCiphertext)).toHaveLength(1120);
      expect(msg.encryption.payload).toBeTruthy();
      expect(msg.signature.scheme).toBe('ed25519');
      expect(msg.signature.value).toBeTruthy();
    });

    it('includes threadId when provided', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'test' },
        stateMachine: makeSM(),
        threadId: 'deal-001',
      });

      expect(msg.threadId).toBe('deal-001');
    });

    it('rejects economic message without threadId', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      await expect(createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'test' },
        stateMachine: makeSM(),
      })).rejects.toThrow(/requires a threadId/);
    });

    it('allows non-economic message without threadId', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'hello' },
        stateMachine: makeSM(),
      });

      expect(msg.type).toBe('text');
    });

    it('enforces state machine on create', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const sm = makeSM();

      // Can't send offer without rfq first
      await expect(createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'offer',
        body: { price: '10', currency: 'USD' },
        stateMachine: sm,
        threadId: 'deal-001',
      })).rejects.toThrow(/Invalid transition/);
    });
  });

  describe('parseMessage (decrypt + verify)', () => {
    it('round-trips a message: create → parse', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'Hello from ACE!' },
        stateMachine: makeSM(),
      });

      const parsed = await parseMessage(
        msg,
        receiver,
        sender.getSigningPublicKey(),
        { replayDetector: new ReplayDetector(), stateMachine: makeSM() },
      );

      expect(parsed.type).toBe('text');
      expect(parsed.body).toEqual({ message: 'Hello from ACE!' });
      expect(parsed.from).toBe(sender.getACEId());
    });

    it('rejects message addressed to a different recipient', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const intended = await SoftwareIdentity.generate('ed25519');
      const eavesdropper = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: intended.getEncryptionPublicKey(),
        recipientACEId: intended.getACEId(),
        type: 'text',
        body: { message: 'private' },
        stateMachine: makeSM(),
      });

      await expect(
        parseMessage(msg, eavesdropper, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/not addressed/);
    });

    it('rejects message with stale timestamp', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'old msg' },
        stateMachine: makeSM(),
        timestamp: Math.floor(Date.now() / 1000) - 400,
      });

      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/fresh/i);
    });

    it('rejects message with missing encryption fields', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'test' },
        stateMachine: makeSM(),
      });

      const broken = { ...msg, encryption: undefined } as any;
      await expect(
        parseMessage(broken, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/encryption/i);
    });

    it('rejects message with missing signature fields', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'test' },
        stateMachine: makeSM(),
      });

      const broken = { ...msg, signature: undefined } as any;
      await expect(
        parseMessage(broken, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/signature/i);
    });

    it('rejects message with mismatched signature scheme', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'test' },
        stateMachine: makeSM(),
      });

      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), {
          replayDetector: new ReplayDetector(),
          stateMachine: makeSM(),
          expectedScheme: 'secp256k1',
        }),
      ).rejects.toThrow(/scheme mismatch/i);
    });

    it('validates msg.from matches sender signing public key', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const other = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'test' },
        stateMachine: makeSM(),
      });

      await expect(
        parseMessage(msg, receiver, other.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/does not match/);
    });

    it('integrates replay detection when provided', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const detector = new ReplayDetector();
      const sm = makeSM();

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'hello' },
        stateMachine: makeSM(),
      });

      // First parse succeeds
      const parsed = await parseMessage(msg, receiver, sender.getSigningPublicKey(), {
        stateMachine: sm,
        replayDetector: detector,
      });
      expect(parsed.body).toEqual({ message: 'hello' });

      // Second parse of same message is rejected as replay
      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), {
          stateMachine: sm,
          replayDetector: detector,
        }),
      ).rejects.toThrow(/Replay detected/);
    });

    it('rejects oversized payload before Base64 decode', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const oversizedPayload = 'A'.repeat(Math.ceil((MAX_PAYLOAD_SIZE + 1) / 3) * 4);

      await expect(
        parseMessage({
          ace: '1.0',
          messageId: '550e8400-e29b-41d4-a716-446655440000',
          from: sender.getACEId(),
          to: receiver.getACEId(),
          conversationId: 'a'.repeat(64),
          type: 'text',
          timestamp: Math.floor(Date.now() / 1000),
          encryption: {
            kemCiphertext: toBase64(new Uint8Array(1120)),
            payload: oversizedPayload,
          },
          signature: {
            scheme: 'ed25519',
            value: 'AQ==',
          },
        }, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/Payload too large/);
    });

    it.each([1119, 1121])('rejects kemCiphertext of %i bytes before signature check or decapsulation', async (len) => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'hello' },
        stateMachine: makeSM(),
      });
      msg.encryption.kemCiphertext = toBase64(new Uint8Array(len).fill(0xaa));
      const detector = new ReplayDetector();
      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), { stateMachine: makeSM(), replayDetector: detector }),
      ).rejects.toThrow(new RegExp(`X-Wing KEM ciphertext (must be exactly 1120 bytes, got|too large:) ${len}`));
      // Nothing enters the seen store before the signature verifies.
      expect(detector.accepts(msg.messageId, msg.from, msg.timestamp)).toBe(true);
    });

    it('rejects missing kemCiphertext', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'hello' },
        stateMachine: makeSM(),
      });
      delete (msg.encryption as Partial<typeof msg.encryption>).kemCiphertext;
      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/Missing required encryption fields/);
    });

    it('rejects conversationId that is not bound to sender and recipient encryption keys', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const bogusConversationId = 'b'.repeat(64);
      const bodyBytes = new TextEncoder().encode(JSON.stringify({ message: 'bound check' }));
      const { kemCiphertext, payload } = await encrypt(
        bodyBytes,
        receiver.getEncryptionPublicKey(),
        bogusConversationId,
      );
      const messageId = '550e8400-e29b-41d4-a716-446655440000';
      const timestamp = Math.floor(Date.now() / 1000);
      const messagePayload = encodePayload('text', receiver.getACEId(), bogusConversationId, messageId, '', payload);
      const signData = buildSignData('message', sender.getACEId(), timestamp, messagePayload);
      const { signature, scheme } = await sender.sign(signData);

      const msg = {
        ace: '1.0' as const,
        messageId,
        from: sender.getACEId(),
        to: receiver.getACEId(),
        conversationId: bogusConversationId,
        type: 'text' as const,
        timestamp,
        encryption: {
          kemCiphertext: toBase64(kemCiphertext),
          payload: toBase64(payload),
        },
        signature: {
          scheme,
          value: encodeSignature(signature, scheme),
        },
      };

      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), {
          replayDetector: new ReplayDetector(),
          stateMachine: makeSM(),
          senderEncryptionPubKey: sender.getEncryptionPublicKey(),
        }),
      ).rejects.toThrow(/conversationId does not match/);
    });

    it('parses strictly from sender registration', async () => {
      const sender = await SoftwareIdentity.generate('secp256k1');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const reg = sender.toRegistrationFile({
        name: 'Seller',
        endpoint: 'https://seller.example.com/ace',
      });

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'strict registration path' },
        stateMachine: makeSM(),
      });

      const parsed = await parseMessageFromRegistration(msg, receiver, reg, {
        replayDetector: new ReplayDetector(),
        stateMachine: makeSM(),
      });
      expect(parsed.body).toEqual({ message: 'strict registration path' });
    });

    it('enforces state machine on parse — rejects invalid sequence', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      // Create an offer message (valid body) but with no prior rfq in state machine
      const smSend = makeSM();
      // Manually advance sender's state machine
      const { computeConversationId: _cc } = await import('../src/encryption.js');
      const convId = _cc(sender.getEncryptionPublicKey(), receiver.getEncryptionPublicKey());
      smSend.transition(convId, 'deal-x', 'rfq', crypto.randomUUID(), Math.floor(Date.now() / 1000));

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'offer',
        body: { price: '10', currency: 'USD' },
        stateMachine: smSend,
        threadId: 'deal-x',
      });

      // Receiver has a fresh state machine — no rfq seen, so offer is invalid
      const smRecv = makeSM();
      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), { stateMachine: smRecv, replayDetector: new ReplayDetector() }),
      ).rejects.toThrow(/Invalid transition/);
    });

    it('rejects economic message without threadId on parse', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      // Create a text message (no threadId required), then tamper type to economic
      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: { message: 'hello' },
        stateMachine: makeSM(),
      });

      // Tamper: change type to economic without threadId
      const tampered = { ...msg, type: 'rfq' as const };

      await expect(
        parseMessage(tampered, receiver, sender.getSigningPublicKey(), { stateMachine: makeSM(), replayDetector: new ReplayDetector() }),
      ).rejects.toThrow(/requires a threadId/);
    });

    it('rejects tampered threadId because it is signed', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'gpu rental' },
        stateMachine: makeSM(),
        threadId: 'deal-a',
      });

      const tampered = { ...msg, threadId: 'deal-b' };
      await expect(
        parseMessage(tampered, receiver, sender.getSigningPublicKey(), { stateMachine: makeSM(), replayDetector: new ReplayDetector() }),
      ).rejects.toThrow(/signature verification failed/i);
    });

    it('rejects cross-thread references on create', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');
      const sm = makeSM();

      await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'gpu rental' },
        stateMachine: sm,
        threadId: 'deal-a',
      });
      const offerA = await createMessage({
        sender: receiver,
        recipientPubKey: sender.getEncryptionPublicKey(),
        recipientACEId: sender.getACEId(),
        type: 'offer',
        body: { price: '10', currency: 'USD' },
        stateMachine: sm,
        threadId: 'deal-a',
      });
      await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'accept',
        body: { offerId: offerA.messageId },
        stateMachine: sm,
        threadId: 'deal-a',
      });

      await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'rfq',
        body: { need: 'design review' },
        stateMachine: sm,
        threadId: 'deal-b',
      });
      const offerB = await createMessage({
        sender: receiver,
        recipientPubKey: sender.getEncryptionPublicKey(),
        recipientACEId: sender.getACEId(),
        type: 'offer',
        body: { price: '20', currency: 'USD' },
        stateMachine: sm,
        threadId: 'deal-b',
      });
      await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'accept',
        body: { offerId: offerB.messageId },
        stateMachine: sm,
        threadId: 'deal-b',
      });

      await expect(createMessage({
        sender: receiver,
        recipientPubKey: sender.getEncryptionPublicKey(),
        recipientACEId: sender.getACEId(),
        type: 'invoice',
        body: {
          offerId: offerA.messageId,
          amount: '20',
          currency: 'USD',
          settlementMethod: 'crypto/instant',
        },
        stateMachine: sm,
        threadId: 'deal-b',
      })).rejects.toThrow(/same thread/i);
    });

    it('rejects deeply nested JSON body', async () => {
      const sender = await SoftwareIdentity.generate('ed25519');
      const receiver = await SoftwareIdentity.generate('ed25519');

      // Build a deeply nested object (depth > 32)
      let nested: Record<string, unknown> = { message: 'deep' };
      for (let i = 0; i < 40; i++) {
        nested = { inner: nested };
      }

      // Create a text message with deeply nested body
      // The body validation for 'text' only checks 'message' field,
      // but additional fields are allowed. We need to bypass createMessage's
      // validation by crafting a raw message that parseMessage will decode.
      // Simpler approach: use 'text' type which allows extra keys in body
      const deepBody = { message: 'hello', extra: nested };

      const msg = await createMessage({
        sender,
        recipientPubKey: receiver.getEncryptionPublicKey(),
        recipientACEId: receiver.getACEId(),
        type: 'text',
        body: deepBody,
        stateMachine: makeSM(),
      });

      await expect(
        parseMessage(msg, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() }),
      ).rejects.toThrow(/maximum nesting depth/);
    });
  });

  describe('cross-SDK envelope and reference rules', () => {
    async function pair() {
      const buyer = await SoftwareIdentity.generate('ed25519');
      const seller = await SoftwareIdentity.generate('ed25519');
      const send = (from: SoftwareIdentity, to: SoftwareIdentity, sm: ThreadStateMachine, type: MessageType, body: Record<string, unknown>, threadId?: string) =>
        createMessage({
          sender: from,
          recipientPubKey: to.getEncryptionPublicKey(),
          recipientACEId: to.getACEId(),
          type, body, stateMachine: sm, threadId,
        });
      return { buyer, seller, send };
    }
    const parse = (msg: ACEMessage, receiver: SoftwareIdentity, sender: SoftwareIdentity) =>
      parseMessage(msg, receiver, sender.getSigningPublicKey(), { replayDetector: new ReplayDetector(), stateMachine: makeSM() });
    const receiptBody = (referenceId: string) => ({
      referenceId, amount: '10', currency: 'USD', settlementMethod: 'crypto/instant', proof: { txHash: '0x1' },
    });

    it('exports the full set of message types', () => {
      expect([...MESSAGE_TYPES]).toEqual(['rfq', 'offer', 'accept', 'reject', 'invoice', 'receipt', 'deliver', 'confirm', 'info', 'text']);
      expect(isMessageType('text')).toBe(true);
      expect(isMessageType('bogus')).toBe(false);
    });

    it('rejects unknown message types in validateBody, createMessage and parseMessage', async () => {
      expect(() => validateBody('bogus' as MessageType, {})).toThrow("Unknown message type: 'bogus'");
      const { buyer, seller, send } = await pair();
      await expect(send(buyer, seller, makeSM(), 'x'.repeat(100) as MessageType, {}))
        .rejects.toThrow(`Unknown message type: '${'x'.repeat(32)}'`);
      const msg = await send(buyer, seller, makeSM(), 'text', { message: 'hi' });
      await expect(parse({ ...msg, type: 'bogus' as MessageType }, seller, buyer)).rejects.toThrow(/Unknown message type/);
    });

    it('validates threadId whenever it is present', async () => {
      const { buyer, seller, send } = await pair();
      await expect(send(buyer, seller, makeSM(), 'text', { message: 'hi' }, '')).rejects.toThrow(/must not be empty/);
      const msg = await send(buyer, seller, makeSM(), 'text', { message: 'hi' }, 't');
      await expect(parse({ ...msg, threadId: 'a\nb' }, seller, buyer)).rejects.toThrow(/control characters/);
      await expect(parse({ ...msg, threadId: 'x'.repeat(257) }, seller, buyer)).rejects.toThrow(/exceeds max length/);
    });

    it('requires conversationId to be 64 lowercase hex characters', async () => {
      const { buyer, seller, send } = await pair();
      const msg = await send(buyer, seller, makeSM(), 'text', { message: 'hi' });
      for (const conversationId of [msg.conversationId.toUpperCase(), msg.conversationId.slice(1), 'z'.repeat(64)]) {
        await expect(parse({ ...msg, conversationId }, seller, buyer))
          .rejects.toThrow('Invalid conversationId: expected 64 lowercase hex characters');
      }
    });

    it('has no per-field string length caps', () => {
      expect(() => validateBody('text', { message: 'x'.repeat(100_000) })).not.toThrow();
      expect(() => validateBody('rfq', { need: 'x'.repeat(10_000) })).not.toThrow();
    });

    it('receipt references the accept on the pre-paid path and the invoice otherwise', async () => {
      const { buyer, seller, send } = await pair();
      const sm = makeSM();
      await send(buyer, seller, sm, 'rfq', { need: 'gpu' }, 'pre');
      const offer = await send(seller, buyer, sm, 'offer', { price: '10', currency: 'USD' }, 'pre');
      const accept = await send(buyer, seller, sm, 'accept', { offerId: offer.messageId }, 'pre');
      await expect(send(buyer, seller, sm, 'receipt', receiptBody(offer.messageId), 'pre'))
        .rejects.toThrow('receipt.referenceId must reference the invoice (or, when pre-paid, the accept) in the same thread');
      await send(buyer, seller, sm, 'receipt', receiptBody(accept.messageId), 'pre');
      expect(sm.getState(accept.conversationId, 'pre')).toBe('paid');

      await send(buyer, seller, sm, 'rfq', { need: 'gpu' }, 'std');
      const offer2 = await send(seller, buyer, sm, 'offer', { price: '10', currency: 'USD' }, 'std');
      const accept2 = await send(buyer, seller, sm, 'accept', { offerId: offer2.messageId }, 'std');
      const invoice = await send(seller, buyer, sm, 'invoice', {
        offerId: offer2.messageId, amount: '10', currency: 'USD', settlementMethod: 'crypto/instant',
      }, 'std');
      await expect(send(buyer, seller, sm, 'receipt', receiptBody(accept2.messageId), 'std')).rejects.toThrow(/must reference the invoice/);
      await send(buyer, seller, sm, 'receipt', receiptBody(invoice.messageId), 'std');
    });

    it('stops sending once the thread limit is reached', async () => {
      const { buyer, seller, send } = await pair();
      const sm = new ThreadStateMachine({ maxThreads: 1 });
      await send(buyer, seller, sm, 'rfq', { need: 'gpu' }, 't1');
      await expect(send(buyer, seller, sm, 'rfq', { need: 'gpu' }, 't2')).rejects.toThrow('Thread limit reached (1)');
    });
  });
});

