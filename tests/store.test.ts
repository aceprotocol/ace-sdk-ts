// ACEStore: MemoryStore and FileStore semantics, lock protocol.
import { mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MemoryStore, type ACEStore } from '../src/index.js';
import { FileStore } from '../src/node.js';
import { expectCode } from './helpers.js';

const temps: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'ace-store-'));
  temps.push(d);
  return d;
}
afterEach(() => {
  for (const t of temps.splice(0)) rmSync(t, { recursive: true, force: true });
});

const enc = (s: string) => new TextEncoder().encode(s);

const backends: Array<[string, () => ACEStore]> = [
  ['memory', () => new MemoryStore()],
  ['file', () => new FileStore(join(tmp(), 'root'))],
];

describe.each(backends)('%s store', (_name, make) => {
  it('read / write / delete / list', async () => {
    const s = make();
    expect(await s.read('a.json')).toBeNull();
    await s.write('a.json', enc('1'));
    await s.write('threads/x.json', enc('2'));
    await s.write('threads/y.json', enc('3'));
    await s.write('deliveries/z.json', enc('4'));
    await s.write('a.json', enc('5'));
    expect(new TextDecoder().decode((await s.read('a.json'))!)).toBe('5');
    expect(await s.list('threads/')).toEqual(['threads/x.json', 'threads/y.json']);
    expect(await s.list('')).toEqual(['a.json', 'deliveries/z.json', 'threads/x.json', 'threads/y.json']);
    expect(await s.list('thr')).toEqual(['threads/x.json', 'threads/y.json']);
    expect(await s.list('nope/')).toEqual([]);
    await s.delete('threads/x.json');
    await s.delete('threads/x.json');
    expect(await s.list('threads/')).toEqual(['threads/y.json']);
  });

  it('rejects invalid keys', async () => {
    const s = make();
    for (const k of ['', '/a', 'a/', 'A.json', '../x', 'a//b', '.hidden', 'x'.repeat(201), 'a b']) {
      await expectCode(s.write(k, enc('x')), 'invalid_argument');
      await expectCode(s.read(k), 'invalid_argument');
    }
  });

  it('rejects values over 64 MiB and lock names outside ^[a-z0-9][a-z0-9_-]{0,63}$', async () => {
    const s = make();
    await expectCode(s.write('big.json', new Uint8Array(64 * 1024 * 1024 + 1)), 'invalid_argument');
    expect(await s.read('big.json')).toBeNull();
    for (const name of ['', 'a.b', 'a/b', 'A', '-a', '_a', 'a'.repeat(65), 'a b']) await expectCode(s.lock(name), 'invalid_argument');
    for (const name of ['a', 'a-b_c', '0', 'a'.repeat(64)]) await (await s.lock(name, { timeoutMs: 0 }))();
  });

  it('locks are exclusive; timeout is receiver_busy for receive, lock_busy otherwise', async () => {
    const s = make();
    const release = await s.lock('receive', { timeoutMs: 0 });
    await expectCode(s.lock('receive', { timeoutMs: 0 }), 'receiver_busy');
    const r2 = await s.lock('threads');
    const busy = await expectCode(s.lock('threads', { timeoutMs: 60 }), 'lock_busy');
    expect(busy.category).toBe('local');
    const waiting = s.lock('threads', { timeoutMs: 2000 });
    setTimeout(() => { void r2(); }, 30);
    const r3 = await waiting;
    await r3();
    await release();
    await release(); // idempotent
    await (await s.lock('receive', { timeoutMs: 0 }))();
  });
});

describe('FileStore', () => {
  it('modes, atomic temp files and symlink refusal', async () => {
    const root = join(tmp(), 'root');
    const s = new FileStore(root);
    await s.write('threads/x.json', enc('{}'));
    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(join(root, 'threads')).mode & 0o777).toBe(0o700);
    expect(statSync(join(root, 'threads/x.json')).mode & 0o777).toBe(0o600);
    writeFileSync(join(root, 'target'), 'secret');
    symlinkSync(join(root, 'target'), join(root, 'link.json'));
    await expectCode(s.read('link.json'), 'storage_failed');
    mkdirSync(join(root, 'real'));
    symlinkSync(join(root, 'real'), join(root, 'dirlink'));
    await expectCode(s.write('dirlink/x.json', enc('1')), 'storage_failed');
    await expectCode(s.write('locks/x.lock', enc('1')), 'invalid_argument');
    expect((await s.list('')).filter((k) => k.includes('.tmp-'))).toEqual([]);
  });

  it('lock files: content, release, stale takeover, cross-instance exclusion', async () => {
    const root = join(tmp(), 'root');
    const a = new FileStore(root);
    const b = new FileStore(root);
    const release = await a.lock('peers');
    const info = JSON.parse(readFileSync(join(root, 'locks/peers.lock'), 'utf8'));
    expect(Object.keys(info).sort()).toEqual(['createdAt', 'host', 'pid']);
    expect(info.pid).toBe(process.pid);
    await expectCode(b.lock('peers', { timeoutMs: 80 }), 'lock_busy');
    await release();
    expect(() => statSync(join(root, 'locks/peers.lock'))).toThrow();
    // a lock left by a dead process on this host is taken over
    writeFileSync(join(root, 'locks/receive.lock'), JSON.stringify({ createdAt: 1, host: hostname(), pid: 2 ** 22 + 12345 }));
    await (await b.lock('receive', { timeoutMs: 0 }))();
    // a live foreign lock is respected
    writeFileSync(join(root, 'locks/receive.lock'), JSON.stringify({ createdAt: 1, host: 'other-host', pid: 1 }));
    await expectCode(b.lock('receive', { timeoutMs: 0 }), 'receiver_busy');
  });

  it('persisted files are portable across instances', async () => {
    const root = join(tmp(), 'root');
    await new FileStore(root).write('replay.json', enc('{"version":1}'));
    expect(new TextDecoder().decode((await new FileStore(root).read('replay.json'))!)).toBe('{"version":1}');
  });
});
