import { describe, it, expect } from 'vitest';
import { createExecutionGrant, executionGrantDigest, executionIntentDigest, verifyExecutionGrantChain, ExecutionAuthority,
  MemoryStore, ACEError, isExecutionUnits, parseExecutionRequest, EXECUTION_REQUEST_SCHEMA_DIGEST, type ExecutionIntent, type ExecutionGrant, type StoreData } from '../src/index.js';
import { V, agent, peerOf } from './helpers.js';
const v = V.grants, base = v.cases[0];
const a = agent('alice'), b = agent('bob');
const config = { resource: base.intent.resource, authority: peerOf(a), executor: b.getACEId(), schemaDigest: base.intent.schemaDigest,
  actions: [base.intent.action], clock: () => 150,
  validateIntent: (i: Readonly<ExecutionIntent>) => {
    if (Object.keys(i.details).sort().join(',') !== 'amount,recipient' || !isExecutionUnits(i.details.amount)) throw new ACEError('invalid_authorization', 'invalid profile');
    return { 'asset:token': i.details.amount as string };
  } };
async function operation(n: number, units = '5'): Promise<{ intent: ExecutionIntent; chain: ExecutionGrant[] }> {
  const intent: ExecutionIntent = { ...base.intent, details: { ...base.intent.details, amount: units },
    operationId: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}` };
  const grant = await createExecutionGrant(a, { ...base.chain[0].claims, subject: b.getACEId(), delegationDepth: 0, intentDigest: executionIntentDigest(intent) });
  return { intent, chain: [grant] };
}

describe('resource grants and atomic authority', () => {
  it('parses the generic execution wrapper as data, rejecting unknown constraints', async () => {
    const op = await operation(1), body = { intent: op.intent, grants: op.chain };
    expect(parseExecutionRequest(body)).toEqual(body);
    expect(EXECUTION_REQUEST_SCHEMA_DIGEST).toBe('5acd227e6886b0d327ed34be5ff2a89debbc08a1cbcd87ba582f9eed6e42cf32');
    for (const invalid of [{ ...body, condition: 'hidden' }, { ...body, grants: [] }, { ...body, grants: new Array(9).fill(op.chain[0]) }]) {
      expect(() => parseExecutionRequest(invalid)).toThrow();
    }
  });
  it.each(['revoke', 'epoch', 'expire'])('rechecks %s before releasing a prepared authorization', async change => {
    const store = new MemoryStore(), authority = new ExecutionAuthority(config, store), op = await operation(1);
    await authority.provision(1, { 'asset:token': '10' }); await authority.reserve(op.chain, op.intent, b.getACEId());
    if (change === 'revoke') await authority.revoke(op.chain[0].claims.grantId);
    if (change === 'epoch') await authority.advanceEpoch(2);
    const reopened = new ExecutionAuthority({ ...config, clock: () => change === 'expire' ? 1000 : 150 }, store);
    expect(await reopened.hasReservation(op.intent, b.getACEId())).toBe(true);
    await expect(reopened.hasReservation(op.intent, a.getACEId())).rejects.toThrow(/already bound/);
    await expect(reopened.release(op.chain, op.intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
    expect((await reopened.inspect()).remaining).toEqual({ 'asset:token': '5' });
  });
  it('retains a consumed release but refuses disclosure when storage waits cross the deadline', async () => {
    let now = 150;
    class Slow extends MemoryStore {
      armed = false;
      override async coordinate<T>(name: string, body: (data: StoreData) => Promise<T>): Promise<T> {
        const result = await super.coordinate(name, body);
        if (this.armed) now = 1000;
        return result;
      }
    }
    const store = new Slow(), authority = new ExecutionAuthority({ ...config, clock: () => now }, store), op = await operation(1);
    await authority.provision(1, { 'asset:token': '10' }); await authority.reserve(op.chain, op.intent, b.getACEId());
    store.armed = true;
    await expect(authority.release(op.chain, op.intent, b.getACEId())).rejects.toThrow(/expired during release/);
    await expect(new ExecutionAuthority(config, store).release(op.chain, op.intent, b.getACEId())).rejects.toThrow(/already released/);
    expect((await authority.inspect()).remaining).toEqual({ 'asset:token': '5' });
  });
  it('consumes release exactly once across concurrent executors and lost write acknowledgements', async () => {
    class Fault extends MemoryStore {
      fail = false;
      override async write(k: string, v: Uint8Array) {
        await super.write(k, v); if (this.fail) { this.fail = false; throw new ACEError('storage_failed'); }
      }
    }
    for (const lostAck of [false, true]) {
      const store = new Fault(), a = new ExecutionAuthority(config, store), c = new ExecutionAuthority(config, store), op = await operation(1);
      await a.provision(1, { 'asset:token': '10' }); await a.reserve(op.chain, op.intent, b.getACEId()); store.fail = lostAck;
      const results = await Promise.allSettled([a, c].map(x => x.release(op.chain, op.intent, b.getACEId())));
      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(lostAck ? 0 : 1);
      await expect(c.release(op.chain, op.intent, b.getACEId())).rejects.toThrow(/already released/);
    }
  });
  it.each(v.cases)('shared vector: $name', c => {
    const check = () => verifyExecutionGrantChain(c.chain, c.intent, c.sender, c.executor,
      { resource: base.intent.resource, authority: peerOf(a), epoch: c.epoch, revoked: c.revoked }, c.now);
    if (c.expected === 'ok') expect(check()).toBe(v.intentDigest);
    else expect(check).toThrow(/invalid_authorization/);
  });
  it('pins canonical claims independently of signature randomness', () => {
    expect(executionGrantDigest(base.chain[0])).toBe(v.rootDigest);
    expect(executionIntentDigest(base.intent)).toBe(v.intentDigest);
  });
  it('reserves once across concurrent agents and restarted instances', async () => {
    const store = new MemoryStore(), one = new ExecutionAuthority(config, store), two = new ExecutionAuthority(config, store);
    await one.provision(1, { 'asset:token': '10' });
    const op = await operation(1, '6');
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? one : two).reserve(op.chain, op.intent, b.getACEId())));
    expect(results.filter(r => r.status === 'reserved')).toHaveLength(1);
    expect(results.filter(r => r.status === 'existing')).toHaveLength(7);
    expect(await two.inspect()).toEqual({ epoch: 1, remaining: { 'asset:token': '4' }, reserved: 1 });
    const next = await operation(2, '6');
    await expect(two.reserve(next.chain, next.intent, b.getACEId())).rejects.toThrow(/budget/);
    const changed = await operation(1, '4');
    await expect(two.reserve(changed.chain, changed.intent, b.getACEId())).rejects.toThrow(/already bound/);
    await expect(two.provision(1, { 'asset:token': '999' })).rejects.toThrow(/already provisioned/);
  });
  it('cannot overspend with different simultaneous operations', async () => {
    const store = new MemoryStore(), authority = new ExecutionAuthority(config, store);
    await authority.provision(1, { 'asset:token': '10' });
    const ops = await Promise.all([operation(1, '6'), operation(2, '6')]);
    const results = await Promise.allSettled(ops.map(o => authority.reserve(o.chain, o.intent, b.getACEId())));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(await authority.inspect()).toEqual({ epoch: 1, remaining: { 'asset:token': '4' }, reserved: 1 });
  });
  it('checks revocation, epoch and the installed profile in the reservation transaction', async () => {
    const authority = new ExecutionAuthority(config, new MemoryStore());
    await authority.provision(1, { 'asset:token': '10' });
    const op = await operation(1);
    await authority.revoke(op.chain[0].claims.grantId);
    await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
    await authority.advanceEpoch(2);
    await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
    await expect(authority.advanceEpoch(1)).rejects.toThrow();
    const bad = { ...op.intent, details: { ...op.intent.details, fee: '100' } };
    const g = await createExecutionGrant(a, { ...op.chain[0].claims, epoch: 2, intentDigest: executionIntentDigest(bad) });
    await expect(authority.reserve([g], bad, b.getACEId())).rejects.toThrow(/invalid profile/);
    expect(await authority.inspect()).toEqual({ epoch: 2, remaining: { 'asset:token': '10' }, reserved: 0 });
  });
  it('handles a durable write with a lost acknowledgement without granting twice', async () => {
    class LostAckStore extends MemoryStore {
      fail = false;
      override async write(key: string, bytes: Uint8Array) { await super.write(key, bytes); if (this.fail) { this.fail = false; throw new ACEError('storage_failed'); } }
    }
    const store = new LostAckStore(), authority = new ExecutionAuthority(config, store), op = await operation(1);
    await authority.provision(1, { 'asset:token': '10' }); store.fail = true;
    await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/storage_failed/);
    expect((await new ExecutionAuthority(config, store).reserve(op.chain, op.intent, b.getACEId())).status).toBe('existing');
    expect((await authority.inspect()).remaining).toEqual({ 'asset:token': '5' });
  });
  it('fails closed on unavailable state and never accepts an async profile validator', async () => {
    const store = new MemoryStore(), authority = new ExecutionAuthority(config, store), op = await operation(1);
    await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/storage_failed/);
    await authority.provision(1, { 'asset:token': '10' });
    const asyncValidator = new ExecutionAuthority({ ...config, validateIntent: (async () => { throw new Error('asynchronous failure'); }) as never }, store);
    await expect(asyncValidator.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/synchronously/);
    for (const key of await store.list('authority/')) await store.write(key, new TextEncoder().encode('{}'));
    await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/storage_failed/);
  });
  it('reserves principal and fee budgets atomically, deriving costs from the installed profile', async () => {
    const validateIntent = (i: Readonly<ExecutionIntent>) => {
      if (Object.keys(i.details).sort().join(',') !== 'amount,fee,recipient'
        || !isExecutionUnits(i.details.amount) || !isExecutionUnits(i.details.fee)) throw new ACEError('invalid_authorization');
      return { 'asset:token': i.details.amount, 'asset:gas': i.details.fee };
    };
    const authority = new ExecutionAuthority({ ...config, validateIntent }, new MemoryStore());
    await authority.provision(1, { 'asset:token': '100', 'asset:gas': '3' });
    const ops = await Promise.all([1, 2].map(async n => {
      const o = await operation(n, '40'); o.intent.details.fee = '2';
      o.chain = [await createExecutionGrant(a, { ...o.chain[0].claims, intentDigest: executionIntentDigest(o.intent) })];
      return o;
    }));
    const results = await Promise.allSettled(ops.map(o => authority.reserve(o.chain, o.intent, b.getACEId())));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(await authority.inspect()).toEqual({ epoch: 1, remaining: { 'asset:token': '60', 'asset:gas': '1' }, reserved: 1 });
    // The failed fee reservation did not subtract the second principal amount.
    const accepted = ops[results.findIndex(r => r.status === 'fulfilled')];
    expect((await authority.reserve(accepted.chain, accepted.intent, b.getACEId())).status).toBe('existing');
  });
  it('rejects unknown accounting dimensions, malformed costs, and redundant caller accounting fields', async () => {
    const store = new MemoryStore(), authority = new ExecutionAuthority(config, store), op = await operation(1);
    await authority.provision(1, { 'asset:token': '10' });
    for (const cost of [{}, { 'asset:token': '01' }, { 'asset:token': -1 }, { 'asset:other': '1' }]) {
      const invalid = new ExecutionAuthority({ ...config, validateIntent: () => cost as never }, store);
      await expect(invalid.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/invalid_authorization/);
    }
    expect((await authority.inspect()).remaining).toEqual({ 'asset:token': '10' });
    expect(() => executionIntentDigest({ ...op.intent, units: '0' } as ExecutionIntent)).toThrow();
    expect(() => executionIntentDigest({ ...op.intent, charges: { 'asset:token': '0' } } as ExecutionIntent)).toThrow();
  });
  it.each([false, true])('recovers every reservation write boundary without double charging (after=%s)', async after => {
    class FailingStore extends MemoryStore {
      remaining = Infinity;
      override async write(k: string, v: Uint8Array) {
        if (--this.remaining === 0 && !after) throw new ACEError('storage_failed');
        await super.write(k, v); if (this.remaining === 0 && after) throw new ACEError('storage_failed');
      }
      override async delete(k: string) {
        if (--this.remaining === 0 && !after) throw new ACEError('storage_failed');
        await super.delete(k); if (this.remaining === 0 && after) throw new ACEError('storage_failed');
      }
    }
    for (let step = 1; step <= 4; step++) {
      const store = new FailingStore(), authority = new ExecutionAuthority(config, store), op = await operation(1);
      await authority.provision(1, { 'asset:token': '10' }); store.remaining = step;
      await expect(authority.reserve(op.chain, op.intent, b.getACEId())).rejects.toThrow(/storage_failed/);
      store.remaining = Infinity;
      const reopened = new ExecutionAuthority(config, store);
      const retry = await reopened.reserve(op.chain, op.intent, b.getACEId());
      expect(retry.status).toBe(step === 1 && !after ? 'reserved' : 'existing');
      expect(await reopened.inspect()).toEqual({ epoch: 1, remaining: { 'asset:token': '5' }, reserved: 1 });
    }
  });
});
