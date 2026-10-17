// Test helpers: identities and agents over the in-memory relay of src/testing.ts.
import {
  ACEError, MemoryStore, NetworkClient, SoftwareIdentity, verifyKel, type KelState, type NetworkClientOptions, type ParsedMessage,
} from './sdk.js';
import { FakeRelay } from '../src/testing.js';

export { FakeRelay, RELAY } from '../src/testing.js';
export const NOW = 1_760_140_800;

export class Clock {
  t = NOW;
  now = () => this.t;
  advance(s: number) { this.t += s; }
}

export async function identity(clock: Clock = new Clock()): Promise<SoftwareIdentity> {
  return SoftwareIdentity.generate({ now: clock.t });
}

export interface TestAgent {
  id: SoftwareIdentity;
  client: NetworkClient;
  store: MemoryStore;
  received: ParsedMessage[];
}

export async function agent(relay: FakeRelay, clock: Clock, o: Partial<NetworkClientOptions> = {}): Promise<TestAgent> {
  const id = await identity(clock);
  const store = new MemoryStore();
  const received: ParsedMessage[] = [];
  const client = await NetworkClient.open({
    identity: id, store, relay: relay.client(), clock: clock.now,
    onMessage: (m) => { received.push(m); }, foreignRelay: () => { throw new ACEError('blocked_address', 'no foreign relays in tests'); },
    ...o,
  });
  await client.publish(); // registers on demand
  return { id, client, store, received };
}

export function stateOf(id: SoftwareIdentity, now = NOW): KelState {
  return verifyKel(id.getKel(), now);
}
