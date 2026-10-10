import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createServer as httpServer } from 'node:http';
import { createServer } from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { EtcdStore } from '../src/node.js';
import { ExecutionAuthority, createExecutionGrant, executionIntentDigest, type ExecutionIntent, type StoreData } from '../src/index.js';
import { V, agent, peerOf } from './helpers.js';

const binary = process.env.ACE_ETCD_BIN;
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array | null) => b === null ? null : new TextDecoder().decode(b);
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
function signal() { let resolve!: () => void; return { promise: new Promise<void>(r => { resolve = r; }), done: () => resolve() }; }
async function port(): Promise<number> {
  const s = createServer(); await new Promise<void>(r => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as { port: number }).port; await new Promise<void>(r => s.close(() => r())); return p;
}
async function post(endpoint: string, path: string, body: unknown): Promise<any> {
  const response = await fetch(endpoint + path, { method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(1000) });
  if (!response.ok) throw Error('etcd unavailable'); return response.json();
}

async function command(binary: string, args: string[], env?: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(Error('test child timed out')); }, 90_000);
    const collect = (data: Buffer) => { output = (output + data.toString()).slice(-100_000); };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); code === 0 ? resolve(output) : reject(Error(output)); });
  });
}

describe.skipIf(!binary)('real three-member replicated authority store', () => {
  let directory: string, endpoints: string[], peers: string[], clusterId: string, cluster: string;
  const processes: ChildProcess[] = [];
  function start(i: number) {
    const child = spawn(binary!, ['--name', `n${i}`, '--data-dir', join(directory, `n${i}`),
      '--listen-client-urls', endpoints[i], '--advertise-client-urls', endpoints[i], '--listen-peer-urls', peers[i],
      '--initial-advertise-peer-urls', peers[i], '--initial-cluster', cluster, '--initial-cluster-token', directory,
      '--log-level', 'error'], { stdio: 'ignore' });
    processes[i] = child; return child;
  }
  async function ready(endpoint: string) {
    for (let i = 0; i < 100; i++) {
      try { return await post(endpoint, '/v3/kv/range', { key: 'aGVhbHRo' }); } catch { await pause(100); }
    }
    throw Error('local etcd did not become ready');
  }
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'ace-etcd-'));
    endpoints = await Promise.all([0, 1, 2].map(async () => `http://127.0.0.1:${await port()}`));
    peers = await Promise.all([0, 1, 2].map(async () => `http://127.0.0.1:${await port()}`));
    cluster = peers.map((u, i) => `n${i}=${u}`).join(','); [0, 1, 2].forEach(start);
    clusterId = (await ready(endpoints[0])).header.cluster_id;
  }, 30_000);
  afterAll(async () => {
    await Promise.all(processes.map(p => new Promise<void>(resolve => {
      if (p.exitCode !== null || p.signalCode !== null) { resolve(); return; }
      p.once('exit', () => resolve()); p.kill('SIGTERM');
    })));
    if (directory) await rm(directory, { recursive: true, force: true });
  });
  function store(namespace = randomUUID(), member = 0) {
    return new EtcdStore({ endpoint: endpoints[member], clusterId, namespace, timeoutMs: 1500 });
  }

  it('uses scoped handles, exact bytes and a pinned revision for paginated lists', async () => {
    const s = store(); let escaped!: StoreData;
    await s.coordinate('state', async data => {
      escaped = data;
      expect(await data.read('missing')).toBeNull();
      await data.write('one', enc('value')); await data.write('empty', new Uint8Array());
      expect(dec(await data.read('one'))).toBe('value'); expect(await data.read('empty')).toEqual(new Uint8Array());
      // Actual pagination: keys cannot disappear or be duplicated between pages.
      for (let i = 0; i < 1030; i++) await data.write(`items/${String(i).padStart(4, '0')}`, enc('x'));
      expect(await data.list('items/')).toHaveLength(1030);
      await data.delete('one'); await data.delete('one'); expect(await data.read('one')).toBeNull();
    });
    await expect(escaped.write('after-release', enc('bad'))).rejects.toThrow(/storage_failed/);
  }, 30_000);

  it('does not confuse concurrent lock scopes on one client', async () => {
    const s = store(), started = signal(), complete = signal();
    const first = s.coordinate('first', async data => { started.done(); await complete.promise; await data.write('first', enc('1')); });
    await started.promise;
    await s.coordinate('second', async data => data.write('second', enc('2')));
    complete.done(); await first;
    await s.coordinate('read', async data => expect(await data.list('')).toEqual(['first', 'second']));
  });

  it('prevents overspend and duplicate release across independent quorum members', async () => {
    const a = agent('alice'), b = agent('bob'), base = V.grants.cases[0], ns = randomUUID();
    const config = { resource: base.intent.resource, authority: peerOf(a), executor: b.getACEId(),
      schemaDigest: base.intent.schemaDigest, actions: [base.intent.action], clock: () => 150,
      validateIntent: (i: Readonly<ExecutionIntent>) => ({ 'asset:token': i.details.amount as string }) };
    const instances = Array.from({ length: 12 }, (_, i) => new ExecutionAuthority(config, store(ns, i % 3)));
    await instances[0].provision(1, { 'asset:token': '10' });
    const intent: ExecutionIntent = { ...base.intent, details: { ...base.intent.details, amount: '6' } };
    const grant = await createExecutionGrant(a, { ...base.chain[0].claims, subject: b.getACEId(), delegationDepth: 0, intentDigest: executionIntentDigest(intent) });
    const reserved = await Promise.all(instances.map(x => x.reserve([grant], intent, b.getACEId())));
    expect(reserved.filter(x => x.status === 'reserved')).toHaveLength(1);
    const released = await Promise.allSettled(instances.map(x => x.release([grant], intent, b.getACEId())));
    expect(released.filter(x => x.status === 'fulfilled')).toHaveLength(1);
    expect(await instances[11].inspect()).toEqual({ epoch: 1, remaining: { 'asset:token': '4' }, reserved: 1 });
    await instances[0].advanceEpoch(2);
    await expect(instances[11].release([grant], intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
  }, 30_000);

  it('fences a stalled owner and cannot delete its replacement lock', async () => {
    const ns = randomUUID(), a = store(ns), b = store(ns, 1), acquired = signal(), resume = signal(), replacement = signal(), finish = signal();
    const stale = a.coordinate('state', async data => { acquired.done(); await resume.promise; await data.write('value', enc('stale')); });
    const rejection = expect(stale).rejects.toThrow(/storage_failed/);
    await acquired.promise;
    const key = Buffer.from(`/ace/${ns}/locks/state`).toString('base64');
    const row = await post(endpoints[0], '/v3/kv/range', { key });
    await post(endpoints[0], '/v3/lease/revoke', { ID: row.kvs[0].lease });
    const fresh = b.coordinate('state', async data => {
      await data.write('value', enc('fresh')); replacement.done(); await finish.promise;
      expect(dec(await data.read('value'))).toBe('fresh');
    });
    await replacement.promise; resume.done(); await rejection;
    const held = await post(endpoints[1], '/v3/kv/range', { key }); expect(held.kvs).toHaveLength(1);
    finish.done(); await fresh;
    await expect(a.coordinate('again', async () => undefined)).rejects.toThrow(/storage_failed/);
    await store(ns, 2).coordinate('read', async data => expect(dec(await data.read('value'))).toBe('fresh'));
  });

  it('refuses a different cluster pin before running the state callback', async () => {
    const s = new EtcdStore({ endpoint: endpoints[0], clusterId: clusterId === '1' ? '2' : '1', namespace: randomUUID() });
    let ran = false;
    await expect(s.coordinate('state', async () => { ran = true; })).rejects.toThrow(/storage_failed/); expect(ran).toBe(false);
  });

  it('never re-releases an authorization whose committed response was lost', async () => {
    const ns = randomUUID(), a = agent('alice'), b = agent('bob'), base = V.grants.cases[0];
    let drop = false, committed = false, lease: string | undefined;
    const proxy = httpServer(async (req, res) => {
      try {
        const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(chunk);
        const raw = Buffer.concat(chunks).toString(), body = JSON.parse(raw);
        const upstream = await fetch(endpoints[0] + req.url, { method: 'POST', body: raw });
        const result = await upstream.text();
        if (req.url === '/v3/lease/grant') lease = JSON.parse(result).ID;
        const put = body.success?.[0]?.request_put;
        if (drop && put?.value && Buffer.from(put.key, 'base64').toString().includes('/operations/') && JSON.parse(Buffer.from(put.value, 'base64').toString()).released === true) {
          committed = true; res.destroy(); return;
        }
        res.writeHead(upstream.status, { 'content-type': 'application/json' }); res.end(result);
      } catch { res.destroy(); }
    });
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r));
    const endpoint = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
    const config = { resource: base.intent.resource, authority: peerOf(a), executor: b.getACEId(), schemaDigest: base.intent.schemaDigest,
      actions: [base.intent.action], clock: () => 150, validateIntent: () => ({ 'asset:token': '6' }) };
    const grant = await createExecutionGrant(a, { ...base.chain[0].claims, subject: b.getACEId(), delegationDepth: 0 });
    const authority = new ExecutionAuthority(config, new EtcdStore({ endpoint, namespace: ns, clusterId }));
    try {
      await authority.provision(1, { 'asset:token': '10' }); await authority.reserve([grant], base.intent, b.getACEId());
      drop = true;
      await expect(authority.release([grant], base.intent, b.getACEId())).rejects.toThrow(/storage_failed/);
      expect(committed).toBe(true);
      await post(endpoints[0], '/v3/lease/revoke', { ID: lease }); // Simulate eventual expiry, not a client retry.
      const reopened = new ExecutionAuthority(config, store(ns, 2));
      await expect(reopened.release([grant], base.intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
      expect((await reopened.inspect()).remaining).toEqual({ 'asset:token': '4' });
    } finally { proxy.closeAllConnections(); await new Promise<void>(r => proxy.close(() => r())); }
  });

  it('rejects an actual old snapshot restored as another cluster', async () => {
    const ns = randomUUID(), snapshot = join(directory, 'snapshot.db');
    await store(ns).coordinate('state', data => data.write('value', enc('old')));
    await command(join(dirname(binary!), 'etcdctl'), [`--endpoints=${endpoints[0]}`, 'snapshot', 'save', snapshot]);
    await store(ns).coordinate('state', data => data.write('value', enc('new')));
    const client = `http://127.0.0.1:${await port()}`, peer = `http://127.0.0.1:${await port()}`, dataDir = join(directory, 'restored');
    await command(join(dirname(binary!), 'etcdutl'), ['snapshot', 'restore', snapshot, '--name', 'restored', '--data-dir', dataDir,
      '--initial-cluster', `restored=${peer}`, '--initial-advertise-peer-urls', peer, '--initial-cluster-token', randomUUID()]);
    const restored = spawn(binary!, ['--name', 'restored', '--data-dir', dataDir, '--listen-client-urls', client,
      '--advertise-client-urls', client, '--listen-peer-urls', peer, '--initial-advertise-peer-urls', peer, '--log-level', 'error'], { stdio: 'ignore' });
    processes.push(restored);
    const header = (await ready(client)).header; expect(header.cluster_id).not.toBe(clusterId);
    const old = await post(client, '/v3/kv/range', { key: Buffer.from(`/ace/${ns}/data/value`).toString('base64') });
    expect(Buffer.from(old.kvs[0].value, 'base64').toString()).toBe('old');
    const pinned = new EtcdStore({ endpoint: client, clusterId, namespace: ns }); let ran = false;
    await expect(pinned.coordinate('state', async () => { ran = true; })).rejects.toThrow(/storage_failed/); expect(ran).toBe(false);
    await store(ns).coordinate('state', async data => expect(dec(await data.read('value'))).toBe('new'));
  }, 30_000);

  it.skipIf(!process.env.ACE_SWIFT_INTEROP)('shares reservations and one-time release with the Swift SDK', async () => {
    const ns = randomUUID(), a = agent('alice'), b = agent('bob'), base = V.grants.cases[0], s = store(ns);
    const intent: ExecutionIntent = { ...base.intent, details: { ...base.intent.details, amount: '6' } };
    const config = { resource: intent.resource, authority: peerOf(a), executor: b.getACEId(), schemaDigest: intent.schemaDigest,
      actions: [intent.action], clock: () => 150, validateIntent: () => ({ 'asset:token': '6' }) };
    const grant = await createExecutionGrant(a, { ...base.chain[0].claims, subject: b.getACEId(), delegationDepth: 0, intentDigest: executionIntentDigest(intent) });
    const authority = new ExecutionAuthority(config, s);
    await authority.provision(1, { 'asset:token': '10' }); await authority.reserve([grant], intent, b.getACEId());
    await s.coordinate('bridge', async data => {
      await data.write('request', enc(JSON.stringify({ intent, grants: [grant] }))); await data.write('empty', new Uint8Array());
      for (let i = 0; i < 1030; i++) await data.write(`items/${String(i).padStart(4, '0')}`, enc('x'));
    });
    const result = await command('swift', ['test', '--package-path', '../sdk-swift', '--filter', 'EtcdStoreIntegrationTests'], {
      ...process.env, ACE_ETCD_ENDPOINT: endpoints[1], ACE_ETCD_CLUSTER_ID: clusterId, ACE_ETCD_NAMESPACE: ns,
    });
    expect(result).toMatch(/passed/);
    await s.coordinate('bridge', async data => expect(dec(await data.read('swift'))).toBe('released'));
    await expect(authority.release([grant], intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
    expect((await authority.inspect()).remaining).toEqual({ 'asset:token': '4' });
  }, 120_000);

  it('fails closed without a quorum, and a fresh client recovers the same state after restart', async () => {
    const ns = randomUUID();
    await store(ns).coordinate('state', data => data.write('value', enc('committed')));
    for (const i of [1, 2]) await new Promise<void>(resolve => { processes[i].once('exit', () => resolve()); processes[i].kill('SIGTERM'); });
    const isolated = store(ns);
    try { await expect(isolated.coordinate('state', data => data.write('value', enc('partitioned')))).rejects.toThrow(/storage_failed/); }
    finally { start(1); start(2); await ready(endpoints[0]); }
    await expect(isolated.coordinate('state', async () => undefined)).rejects.toThrow(/storage_failed/);
    await store(ns, 2).coordinate('state', async data => expect(dec(await data.read('value'))).toBe('committed'));
  }, 30_000);
});
