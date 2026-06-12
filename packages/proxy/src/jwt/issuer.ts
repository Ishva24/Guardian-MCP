import { SignJWT, importPKCS8 } from 'jose';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { AgentSessionClaims } from '../types.js';
import { randomUUID } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PRIVATE_KEY_PATH = process.env.JWT_PRIVATE_KEY_PATH ?? join(__dirname, '../../keys/private.pem');

const ISSUER = 'guardian-mcp';
const AUDIENCE = 'mcp-server';
const DEFAULT_TTL = '15m'; // Short-lived by design

export async function issueSessionToken(
  claims: Omit<AgentSessionClaims, 'iat' | 'exp' | 'iss' | 'aud'>,
  ttl: string = DEFAULT_TTL
): Promise<string> {
  const privateKeyPEM = readFileSync(PRIVATE_KEY_PATH, 'utf8');
  const privateKey = await importPKCS8(privateKeyPEM, 'RS256');

  return new SignJWT({
    sub: claims.sub,
    role: claims.role,
    scopes: claims.scopes,
    sessionId: claims.sessionId,
    constraints: claims.constraints,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(ttl)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setJti(randomUUID()) // Unique token ID to prevent replay
    .sign(privateKey);
}

// ─── Predefined Session Profiles ─────────────────────────────────────────────

export const SESSION_PROFILES = {
  /** Read-only support agent — can list and read, cannot delete */
  supportAgent: (userId: string) => ({
    sub: userId,
    role: 'support_agent',
    scopes: ['docs:read', 'docs:list'],
    sessionId: `sess_${randomUUID().slice(0, 8)}`,
  }),

  /** Manager — full read/write/delete access */
  manager: (userId: string) => ({
    sub: userId,
    role: 'manager',
    scopes: ['docs:read', 'docs:list', 'docs:delete'],
    sessionId: `sess_${randomUUID().slice(0, 8)}`,
    constraints: { allowedResourcePrefix: 'project_alpha/' },
  }),

  /** Unprivileged guest — list only */
  guest: (userId: string) => ({
    sub: userId,
    role: 'guest',
    scopes: ['docs:list'],
    sessionId: `sess_${randomUUID().slice(0, 8)}`,
  }),
};
