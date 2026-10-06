import { describe, it, expect } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { computeACEId, secp256k1Address } from '../src/identity.js';
import { computeConversationId } from '../src/encryption.js';
import { buildSignData, encodePayload } from '../src/signing.js';

describe('Protocol Vectors', () => {
  it('matches ACE ID golden vector', () => {
    const signingPub = Uint8Array.from(Array.from({ length: 33 }, (_, i) => i));
    expect(computeACEId(signingPub)).toBe(
      'ace:sha256:5d8fcfefa9aeeb711fb8ed1e4b7d5c8a9bafa46e8e76e68aa18adce5a10df6ab',
    );
  });

  it('matches conversationId golden vector', () => {
    // X-Wing public keys are 1216 bytes; patterns wrap mod 256.
    const pubA = Uint8Array.from(Array.from({ length: 1216 }, (_, i) => (i + 1) & 0xff));
    const pubB = Uint8Array.from(Array.from({ length: 1216 }, (_, i) => (255 - i) & 0xff));
    expect(computeConversationId(pubA, pubB)).toBe(
      'cd42dbed37b97cd015b5b02119ecd6b27eceabb740e238c29075cdc17a558474',
    );
    expect(computeConversationId(pubB, pubA)).toBe(
      'cd42dbed37b97cd015b5b02119ecd6b27eceabb740e238c29075cdc17a558474',
    );
  });

  it('matches signData golden vector', () => {
    const payload = Uint8Array.from([1, 2, 3, 4, 5, 6]);
    const messagePayload = encodePayload('offer', 'ace:sha256:bbb', 'conv123', '550e8400-e29b-41d4-a716-446655440000', 'thread-1', payload);
    expect(bytesToHex(buildSignData('message', 'ace:sha256:aaa', 1741000000, messagePayload)))
      .toBe('34bc0519278ebfd7ed8c97cbb348eac253a016c97710d69c8feb01afa2405c47');
  });

  it('matches secp256k1 address golden vector', () => {
    const compressedPub = hexToBytes(
      '0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0',
    );
    expect(secp256k1Address(compressedPub)).toBe(
      '0x6370eF2f4Db3611D657b90667De398a2Cc2a370C',
    );
  });
});
