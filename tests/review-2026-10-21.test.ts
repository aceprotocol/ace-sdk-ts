// Security review 2026-10-21 (docs/review-2026-10-21-security.md): one regression per decision.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  FileStore, MemoryStore, relayErrorFor, validateNetworkRelay,
} from './sdk.js';

const code = (c: string) => expect.objectContaining({ code: c });

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
