/** Optional application schema; neither parsing nor its message label grants execution rights. */
import { sha256Hex, hasExactKeys, isObj } from './encoding.js';
import { ACEError } from './errors.js';
import { executionIntentDigest, type ExecutionGrant, type ExecutionIntent } from './grants.js';

export const EXECUTION_REQUEST_TYPE = 'urn:ace:execute:1';
export const EXECUTION_REQUEST_SCHEMA = '{"fields":["intent","grants"],"type":"urn:ace:execute:1","version":1}';
export const EXECUTION_REQUEST_SCHEMA_DIGEST = sha256Hex(EXECUTION_REQUEST_SCHEMA);
export interface ExecutionRequest { intent: ExecutionIntent; grants: ExecutionGrant[] }
/** Only parses the closed wrapper. Use the authoritative executor to validate grants and execute. */
export function parseExecutionRequest(body: unknown): ExecutionRequest {
  try {
    if (!isObj(body) || !hasExactKeys(body, ['grants', 'intent']) || !Array.isArray(body.grants)
      || body.grants.length < 1 || body.grants.length > 8 || !body.grants.every(isObj)) throw new Error();
    executionIntentDigest(body.intent as ExecutionIntent);
    const bytes = JSON.stringify(body);
    if (new TextEncoder().encode(bytes).length > 60_000) throw new Error();
    return JSON.parse(bytes) as ExecutionRequest;
  } catch { throw new ACEError('invalid_authorization', 'invalid execution request'); }
}
