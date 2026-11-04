/**
 * Invitations (05 § Invitations): the out-of-band pairing path (e.g. for a `closed` agent). The inviter hands one peer, out of band, its own
 * PublishedAgent and a delivery permit issued to that peer. Creating one is an explicit local admission of the peer;
 * importing one verifies the agent and holds the permit, and never admits the inviter.
 */
import { createPermit, verifyPermit, verifyPublishedAgent, type DeliveryPermit, type PublishedAgent, type VerifiedAgent, type VerifyOptions } from './descriptor.js';
import { ACEError } from './errors.js';
import { closedKeys, nowOf } from './encoding.js';
import type { ACEIdentity } from './identity.js';
import { MAX_PERMIT_LIFETIME } from './limits.js';

export interface Invitation { agent: PublishedAgent; permit: DeliveryPermit }

/** `{agent, permit}`: `agent` must be the issuer's own PublishedAgent; the permit is issued to `peer`. */
export async function createInvitation(identity: ACEIdentity, agent: PublishedAgent, peer: string, o: { now?: number; ttl?: number } = {}): Promise<Invitation> {
  if (agent?.descriptor?.aceId !== identity.getACEId()) throw new ACEError('invalid_argument', 'agent must be the inviter\'s own PublishedAgent');
  const permit = await createPermit(identity, peer, { now: o.now ?? nowOf(), ttl: o.ttl ?? MAX_PERMIT_LIFETIME });
  return { agent, permit };
}

/**
 * Verify an invitation addressed to `subject`: the closed object `{agent, permit}`, `agent` a valid PublishedAgent and
 * `permit` valid under its KEL with `issuer = agent.aceId` and `subject = subject` (`invalid_authorization`).
 */
export function verifyInvitation(value: unknown, subject: string, now: number = nowOf(), o: VerifyOptions = {}): { agent: VerifiedAgent; permit: DeliveryPermit } {
  if (!closedKeys(value, ['agent', 'permit'])) throw new ACEError('invalid_authorization', 'invitation must be {agent, permit}');
  const agent = verifyPublishedAgent(value.agent, now, o);
  if (agent.agent.descriptor.aceId === subject) throw new ACEError('invalid_authorization', 'an invitation from this identity to itself');
  return { agent, permit: verifyPermit(value.permit, agent.state, subject, now) };
}
