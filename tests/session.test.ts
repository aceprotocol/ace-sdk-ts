import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { PairwiseMLS, type MLSEngine, MLSError } from '../src/session.js';
import { MemoryStore, type CoordinatedStore, type StoreData } from '../src/store.js';
import { canonicalStateBytes } from '../src/encoding.js';

// The explicit integration job builds this artifact first. Ordinary SDK tests never fetch it.
const path = process.env.ACE_MLS_WASM;
describe.skipIf(!path)('common MLS engine and durable generation gate', () => {
  let engine: MLSEngine & { free(): void };
  beforeAll(async () => {
    const url = pathToFileURL(path!);
    const module = await import(/* @vite-ignore */ url.href);
    await module.default({ module_or_path: await readFile(new URL('./ace_session_core_bg.wasm', url)) });
    engine = new module.SessionEngine();
  });
  afterAll(() => engine?.free());
  const alice = `ace:sha256:${'a'.repeat(64)}`, bob = `ace:sha256:${'b'.repeat(64)}`;
  async function pair(store: CoordinatedStore = new MemoryStore()) {
    const a = await PairwiseMLS.open(engine, store, alice, bob);
    const b = await PairwiseMLS.open(engine, new MemoryStore(), bob, alice);
    await b.join((await a.create(b.state.keyPackage)).message!);
    return { a, b };
  }
  it('round trips, reorders, updates, and rejects replay', async () => {
    const { a, b } = await pair();
    const first = (await a.send(new TextEncoder().encode('one'))).message!;
    const second = (await a.send(new TextEncoder().encode('two'))).message!;
    expect(new TextDecoder().decode(PairwiseMLS.plaintext(await b.receive(second)))).toBe('two');
    expect(new TextDecoder().decode(PairwiseMLS.plaintext(await b.receive(first)))).toBe('one');
    await expect(b.receive(first)).rejects.toMatchObject({ code: 'invalid_session_message' });
    await a.receive((await b.update()).message!);
    expect(PairwiseMLS.plaintext(await a.receive((await b.send(new Uint8Array([1, 2, 3]))).message!))).toEqual(new Uint8Array([1, 2, 3]));
    await a.close(); await b.close();
  });
  it('a rejected message advances the durable gate without losing the valid ratchet', async () => {
    const { a, b } = await pair();
    const packet = (await a.send(new Uint8Array([42]))).message!;
    const generation = b.state.generation;
    await expect(b.receive('garbage')).rejects.toBeInstanceOf(MLSError);
    expect(b.state.generation).toBe(generation + 1);
    expect(PairwiseMLS.plaintext(await b.receive(packet))).toEqual(new Uint8Array([42]));
    await a.close(); await b.close();
  });
  it('old or missing gate state closes the context rather than resetting it', async () => {
    const store = new MemoryStore();
    const { a, b } = await pair(store);
    const [key] = await store.list('mls/gates/');
    const old = await store.read(key);
    await a.send(new Uint8Array([1]));
    await store.write(key, old!);
    await expect(a.send(new Uint8Array([2]))).rejects.toMatchObject({ code: 'session_generation_mismatch' });
    await expect(a.update()).rejects.toMatchObject({ code: 'session_closed' });
    await b.close();
  });
  it('detects engine state changes outside the SDK gate', async () => {
    const { a, b } = await pair();
    engine.execute(new TextEncoder().encode(JSON.stringify({ op: 'update', handle: a.state.handle, generation: a.state.generation })));
    await expect(a.send(new Uint8Array([2]))).rejects.toMatchObject({ code: 'invalid_engine_state' });
    await expect(a.update()).rejects.toMatchObject({ code: 'session_closed' });
    await b.close();
  });
  it('lost acknowledgement after ratchet mutation returns no output and never resumes', async () => {
    const data = new MemoryStore(); let fail = false;
    const store: CoordinatedStore = { async coordinate<T>(name: string, fn: (data: StoreData) => Promise<T>): Promise<T> {
      return data.coordinate(name, async scoped => {
        const result = await fn(scoped);
        if (fail) throw Error('lost acknowledgement');
        return result;
      });
    } };
    const { a, b } = await pair(store); fail = true;
    await expect(a.send(new Uint8Array([1]))).rejects.toThrow('lost acknowledgement');
    fail = false;
    await expect(a.send(new Uint8Array([1]))).rejects.toMatchObject({ code: 'session_closed' });
    await b.close();
  });
  it('commits the generation before invoking the engine and stores no secrets', async () => {
    const data = new MemoryStore(); let persisted = -1;
    const store: CoordinatedStore = { async coordinate<T>(name: string, fn: (data: StoreData) => Promise<T>): Promise<T> {
      return data.coordinate(name, scoped => fn({
        read: key => scoped.read(key), delete: key => scoped.delete(key), list: prefix => scoped.list(prefix),
        async write(key, bytes) { await scoped.write(key, bytes); persisted = JSON.parse(new TextDecoder().decode(bytes)).generation; },
      }));
    } };
    const guarded: MLSEngine = { execute(bytes) {
      const command = JSON.parse(new TextDecoder().decode(bytes));
      if ('generation' in command) expect(persisted).toBe(command.generation + 1);
      return engine.execute(bytes);
    } };
    const a = await PairwiseMLS.open(guarded, store, alice, bob);
    const b = await PairwiseMLS.open(engine, new MemoryStore(), bob, alice);
    await b.join((await a.create(b.state.keyPackage)).message!);
    await a.send(new Uint8Array([1]));
    const [key] = await data.list('mls/gates/');
    const row = JSON.parse(new TextDecoder().decode((await data.read(key))!));
    expect(Object.keys(row).sort()).toEqual(['closed', 'context', 'generation', 'local', 'peer', 'signatureKey', 'version']);
    expect(await data.read(key)).toEqual(canonicalStateBytes(row));
    await a.close(); await b.close();
  });
  it('serializes concurrent sends and does not reencrypt a replay', async () => {
    const { a, b } = await pair();
    const messages = await Promise.all(Array.from({ length: 20 }, (_, i) => a.send(new Uint8Array([i]))));
    for (let i = 19; i >= 0; i--) expect(PairwiseMLS.plaintext(await b.receive(messages[i].message!))[0]).toBe(i);
    await a.close(); await b.close();
  });
  it('unexpected core failure destroys the context', async () => {
    const faulty: MLSEngine = { execute(input) {
      const command = JSON.parse(new TextDecoder().decode(input));
      const result = engine.execute(input);
      return command.op === 'send'
        ? new TextEncoder().encode(JSON.stringify({ ok: false, result: null, error: 'session_failed' }))
        : result;
    } };
    const a = await PairwiseMLS.open(faulty, new MemoryStore(), alice, bob);
    const b = await PairwiseMLS.open(engine, new MemoryStore(), bob, alice);
    await b.join((await a.create(b.state.keyPackage)).message!);
    await expect(a.send(new Uint8Array([1]))).rejects.toMatchObject({ code: 'session_failed' });
    await expect(a.update()).rejects.toMatchObject({ code: 'session_closed' });
    await b.close();
  });
});
