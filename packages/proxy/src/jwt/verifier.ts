import { jwtVerify, importSPKI, type JWTPayload } from 'jose';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { AgentSessionClaims } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_KEY_PATH = process.env.JWT_PUBLIC_KEY_PATH ?? join(__dirname, '../../keys/public.pem');

const ISSUER = 'guardian-mcp';
const AUDIENCE = 'mcp-server';

// ─── Tool → Required Scope Mapping ───────────────────────────────────────────
// This is the single source of truth for tool authorization
export const TOOL_SCOPE_MAP: Record<string, string> = {
  'list_documents':  'docs:list',
  'read_document':   'docs:read',
  'delete_document': 'docs:delete',
  'write_document':  'docs:write',   // future tool
};

export interface VerifyResult {
  authorized: boolean;
  reason?: string;
  type?: 'TOKEN_MISSING' | 'TOKEN_EXPIRED' | 'TOKEN_INVALID' | 'SCOPE_DENIED' | 'UNKNOWN_TOOL';
  claims?: AgentSessionClaims;
}

export async function verifyAndAuthorize(
  rawToken: string | undefined,
  toolName: string
): Promise<VerifyResult> {

  // 1. Token presence check
  if (!rawToken || rawToken.trim() === '') {
    return {
      authorized: false,
      type: 'TOKEN_MISSING',
      reason: 'No Authorization token provided. Include "Authorization: Bearer <token>" header.',
    };
  }

  // 2. Cryptographic verification
  let claims: AgentSessionClaims;
  try {
    const publicKeyPEM = readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const publicKey = await importSPKI(publicKeyPEM, 'RS256');

    const { payload } = await jwtVerify(rawToken, publicKey, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['RS256'],
    });

    claims = payload as unknown as AgentSessionClaims;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';

    if (message.includes('exp')) {
      return { authorized: false, type: 'TOKEN_EXPIRED', reason: 'Session token has expired. Request a new token.' };
    }
    if (message.includes('signature')) {
      return { authorized: false, type: 'TOKEN_INVALID', reason: 'Token signature verification failed. Token may be tampered.' };
    }
    if (message.includes('iss') || message.includes('aud')) {
      return { authorized: false, type: 'TOKEN_INVALID', reason: 'Token issuer or audience mismatch.' };
    }
    return { authorized: false, type: 'TOKEN_INVALID', reason: `Token validation failed: ${message}` };
  }

  // 3. Tool scope check
  const requiredScope = TOOL_SCOPE_MAP[toolName];
  if (!requiredScope) {
    return {
      authorized: false,
      type: 'UNKNOWN_TOOL',
      reason: `Unknown tool: "${toolName}". Tool is not registered in the scope map.`,
    };
  }

  const grantedScopes: string[] = claims.scopes ?? [];
  if (!grantedScopes.includes(requiredScope)) {
    return {
      authorized: false,
      type: 'SCOPE_DENIED',
      reason: `Scope "${requiredScope}" required for tool "${toolName}". ` +
              `Token grants: [${grantedScopes.join(', ')}]`,
      claims,
    };
  }

  return { authorized: true, claims };
}
