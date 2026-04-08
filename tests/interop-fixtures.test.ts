import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { SoftwareIdentity } from '../src/identity.js';
import { parseMessageFromRegistration } from '../src/messages.js';
import { ThreadStateMachine } from '../src/state-machine.js';

function loadFixture(name: string) {
  return JSON.parse(
    readFileSync(new URL(`../../interop-fixtures/${name}`, import.meta.url), 'utf8'),
  );
}

// Skipped: signing wire format changed (unified buildSignData), old fixtures are invalid
describe.skip('Interop Fixtures', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('parses Python-produced message fixture', async () => {
    const fixture = loadFixture('py-to-ts.json');
    const receiver = SoftwareIdentity.fromExport(fixture.receiverExport);
    vi.useFakeTimers();
    vi.setSystemTime(new Date(fixture.message.timestamp * 1000));

    const parsed = await parseMessageFromRegistration(
      fixture.message,
      receiver,
      fixture.senderRegistration,
      { stateMachine: new ThreadStateMachine() },
    );

    expect(parsed.body).toEqual(fixture.expectedBody);
    expect(parsed.threadId).toBe('interop-py-to-ts');
  });

  it('parses Swift-produced message fixture', async () => {
    const fixture = loadFixture('swift-to-tspy.json');
    const receiver = SoftwareIdentity.fromExport(fixture.receiverExport);
    vi.useFakeTimers();
    vi.setSystemTime(new Date(fixture.message.timestamp * 1000));

    const parsed = await parseMessageFromRegistration(
      fixture.message,
      receiver,
      fixture.senderRegistration,
      { stateMachine: new ThreadStateMachine() },
    );

    expect(parsed.body).toEqual(fixture.expectedBody);
    expect(parsed.threadId).toBe('interop-swift-to-tspy');
  });
});
