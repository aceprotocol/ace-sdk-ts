import { describe, it, expect } from 'vitest';
import { validateProfile } from '../src/discovery.js';
import type { AgentProfile } from '../src/types.js';

describe('validateProfile', () => {
  // ─── empty profile ────────────────────────────────────────────────────────

  it('accepts an empty profile', () => {
    expect(() => validateProfile({})).not.toThrow();
  });

  // ─── name ─────────────────────────────────────────────────────────────────

  describe('name', () => {
    it('accepts a 1-character name', () => {
      expect(() => validateProfile({ name: 'A' })).not.toThrow();
    });

    it('accepts a 64-character name', () => {
      expect(() => validateProfile({ name: 'A'.repeat(64) })).not.toThrow();
    });

    it('rejects an empty name', () => {
      expect(() => validateProfile({ name: '' })).toThrow(/name/);
    });

    it('rejects a name longer than 64 characters', () => {
      expect(() => validateProfile({ name: 'A'.repeat(65) })).toThrow(/name/);
    });
  });

  // ─── description ──────────────────────────────────────────────────────────

  describe('description', () => {
    it('accepts a description of exactly 256 characters', () => {
      expect(() => validateProfile({ description: 'x'.repeat(256) })).not.toThrow();
    });

    it('accepts an empty description', () => {
      expect(() => validateProfile({ description: '' })).not.toThrow();
    });

    it('rejects a description longer than 256 characters', () => {
      expect(() => validateProfile({ description: 'x'.repeat(257) })).toThrow(/description/);
    });

    it('rejects a description containing a newline (control character)', () => {
      expect(() => validateProfile({ description: 'hello\nworld' })).toThrow(/control/);
    });

    it('rejects a description containing a tab (control character)', () => {
      expect(() => validateProfile({ description: 'hello\tworld' })).toThrow(/control/);
    });

    it('rejects a description containing a null byte', () => {
      expect(() => validateProfile({ description: 'hello\x00world' })).toThrow(/control/);
    });

    it('rejects a description containing DEL (U+007F)', () => {
      expect(() => validateProfile({ description: 'hello\x7Fworld' })).toThrow(/control/);
    });

    it('accepts a description with printable ASCII and Unicode', () => {
      expect(() => validateProfile({ description: 'Hello, 世界! 🚀' })).not.toThrow();
    });
  });

  // ─── tags ─────────────────────────────────────────────────────────────────

  describe('tags', () => {
    it('accepts an empty tags array', () => {
      expect(() => validateProfile({ tags: [] })).not.toThrow();
    });

    it('accepts 10 valid tags', () => {
      const tags = Array.from({ length: 10 }, (_, i) => `tag${i}`);
      expect(() => validateProfile({ tags })).not.toThrow();
    });

    it('rejects more than 10 tags', () => {
      const tags = Array.from({ length: 11 }, (_, i) => `tag${i}`);
      expect(() => validateProfile({ tags })).toThrow(/tags/);
    });

    it('accepts a tag of exactly 32 characters', () => {
      expect(() => validateProfile({ tags: ['a'.repeat(32)] })).not.toThrow();
    });

    it('rejects a tag longer than 32 characters', () => {
      expect(() => validateProfile({ tags: ['a'.repeat(33)] })).toThrow(/tags/);
    });

    it('accepts lowercase alphanumeric tags', () => {
      expect(() => validateProfile({ tags: ['abc123', 'foo-bar', 'a1b2'] })).not.toThrow();
    });

    it('accepts a tag with hyphens in the middle', () => {
      expect(() => validateProfile({ tags: ['foo-bar-baz'] })).not.toThrow();
    });

    it('rejects a tag starting with a hyphen', () => {
      expect(() => validateProfile({ tags: ['-invalid'] })).toThrow(/tags/);
    });

    it('rejects a tag with uppercase letters', () => {
      expect(() => validateProfile({ tags: ['FooBar'] })).toThrow(/tags/);
    });

    it('rejects a tag with spaces', () => {
      expect(() => validateProfile({ tags: ['foo bar'] })).toThrow(/tags/);
    });

    it('rejects a tag with special characters', () => {
      expect(() => validateProfile({ tags: ['foo_bar'] })).toThrow(/tags/);
    });

    it('rejects an empty tag string', () => {
      expect(() => validateProfile({ tags: [''] })).toThrow(/tags/);
    });
  });

  // ─── capabilities ─────────────────────────────────────────────────────────

  describe('capabilities', () => {
    it('accepts an empty capabilities array', () => {
      expect(() => validateProfile({ capabilities: [] })).not.toThrow();
    });

    it('accepts 20 valid capabilities', () => {
      const capabilities = Array.from({ length: 20 }, (_, i) => `cap${i}`);
      expect(() => validateProfile({ capabilities })).not.toThrow();
    });

    it('rejects more than 20 capabilities', () => {
      const capabilities = Array.from({ length: 21 }, (_, i) => `cap${i}`);
      expect(() => validateProfile({ capabilities })).toThrow(/capabilities/);
    });

    it('accepts a capability of exactly 32 characters', () => {
      expect(() => validateProfile({ capabilities: ['a'.repeat(32)] })).not.toThrow();
    });

    it('rejects a capability longer than 32 characters', () => {
      expect(() => validateProfile({ capabilities: ['a'.repeat(33)] })).toThrow(/capabilities/);
    });

    it('rejects a capability starting with a hyphen', () => {
      expect(() => validateProfile({ capabilities: ['-invalid'] })).toThrow(/capabilities/);
    });

    it('rejects a capability with uppercase letters', () => {
      expect(() => validateProfile({ capabilities: ['SendMessage'] })).toThrow(/capabilities/);
    });

    it('accepts capabilities with hyphens', () => {
      expect(() => validateProfile({ capabilities: ['send-message', 'read-data'] })).not.toThrow();
    });
  });

  // ─── chains ───────────────────────────────────────────────────────────────

  describe('chains', () => {
    it('accepts an empty chains array', () => {
      expect(() => validateProfile({ chains: [] })).not.toThrow();
    });

    it('accepts valid CAIP-2 chain identifiers', () => {
      expect(() => validateProfile({
        chains: ['eip155:1', 'eip155:8453', 'cosmos:cosmoshub-4'],
      })).not.toThrow();
    });

    it('accepts 10 chains', () => {
      const chains = Array.from({ length: 10 }, (_, i) => `eip155:${i}`);
      expect(() => validateProfile({ chains })).not.toThrow();
    });

    it('rejects more than 10 chains', () => {
      const chains = Array.from({ length: 11 }, (_, i) => `eip155:${i}`);
      expect(() => validateProfile({ chains })).toThrow(/chains/);
    });

    it('rejects a chain without a colon', () => {
      expect(() => validateProfile({ chains: ['ethereum'] })).toThrow(/chains/);
    });

    it('rejects an empty chain string', () => {
      expect(() => validateProfile({ chains: [''] })).toThrow(/chains/);
    });
  });

  // ─── endpoint ─────────────────────────────────────────────────────────────

  describe('endpoint', () => {
    it('accepts a valid HTTPS URL', () => {
      expect(() => validateProfile({ endpoint: 'https://example.com/ace' })).not.toThrow();
    });

    it('accepts a valid HTTPS URL with port', () => {
      expect(() => validateProfile({ endpoint: 'https://example.com:8443/ace' })).not.toThrow();
    });

    it('rejects an HTTP URL', () => {
      expect(() => validateProfile({ endpoint: 'http://example.com/ace' })).toThrow(/https/i);
    });

    it('rejects a non-URL string', () => {
      expect(() => validateProfile({ endpoint: 'not-a-url' })).toThrow(/endpoint/);
    });

    it('rejects a URL with an unsupported scheme', () => {
      expect(() => validateProfile({ endpoint: 'ftp://example.com/ace' })).toThrow(/https/i);
    });
  });

  // ─── pricing ──────────────────────────────────────────────────────────────

  describe('pricing', () => {
    it('accepts valid pricing with only currency', () => {
      expect(() => validateProfile({ pricing: { currency: 'USD' } })).not.toThrow();
    });

    it('accepts valid pricing with currency and maxAmount', () => {
      expect(() => validateProfile({
        pricing: { currency: 'USD', maxAmount: '100.00' },
      })).not.toThrow();
    });

    it('rejects pricing with empty currency', () => {
      expect(() => validateProfile({ pricing: { currency: '' } })).toThrow(/currency/);
    });
  });

  // ─── combined valid profile ────────────────────────────────────────────────

  describe('full valid profile', () => {
    it('accepts a fully populated valid profile', () => {
      const profile: AgentProfile = {
        name: 'My Agent',
        description: 'An agent that does things.',
        tags: ['ai', 'finance', 'defi'],
        capabilities: ['swap', 'bridge', 'lend'],
        chains: ['eip155:1', 'eip155:8453'],
        endpoint: 'https://agent.example.com/ace',
        pricing: { currency: 'USDC', maxAmount: '50' },
      };
      expect(() => validateProfile(profile)).not.toThrow();
    });
  });
});
