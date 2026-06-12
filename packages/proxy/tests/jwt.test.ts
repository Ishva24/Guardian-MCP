import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { issueSessionToken, SESSION_PROFILES } from '../src/jwt/issuer.js';
import { verifyAndAuthorize } from '../src/jwt/verifier.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, '../keys');

// Generate ephemeral test keys before all tests
beforeAll(async () => {
  mkdirSync(KEYS_DIR, { recursive: true });
  const { privateKey, publicKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const privPath = join(KEYS_DIR, 'private.pem');
  const pubPath  = join(KEYS_DIR, 'public.pem');
  writeFileSync(privPath, await exportPKCS8(privateKey));
  writeFileSync(pubPath,  await exportSPKI(publicKey));
  // Point the modules to our ephemeral test keys via env vars
  process.env.JWT_PRIVATE_KEY_PATH = privPath;
  process.env.JWT_PUBLIC_KEY_PATH  = pubPath;
});

describe('JWT Issuer', () => {
  it('should issue a valid token with correct claims', async () => {
    const profile = SESSION_PROFILES.supportAgent('user_test');
    const token = await issueSessionToken(profile);

    expect(token).toBeTruthy();
    const [, payloadB64] = token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    expect(payload.sub).toBe('user_test');
    expect(payload.role).toBe('support_agent');
    expect(payload.scopes).toContain('docs:read');
    expect(payload.scopes).toContain('docs:list');
    expect(payload.iss).toBe('guardian-mcp');
    expect(payload.aud).toBe('mcp-server');
    expect(payload.exp).toBeGreaterThan(Date.now() / 1000);
  });
});

describe('JWT Verifier — Authorization', () => {
  it('should authorize a token with the correct scope', async () => {
    const profile = SESSION_PROFILES.supportAgent('alice');
    const token = await issueSessionToken(profile);
    const result = await verifyAndAuthorize(token, 'read_document');

    expect(result.authorized).toBe(true);
    expect(result.claims?.sub).toBe('alice');
  });

  it('should deny when required scope is missing', async () => {
    const profile = SESSION_PROFILES.supportAgent('alice'); // has docs:read, not docs:delete
    const token = await issueSessionToken(profile);
    const result = await verifyAndAuthorize(token, 'delete_document');

    expect(result.authorized).toBe(false);
    expect(result.type).toBe('SCOPE_DENIED');
    expect(result.reason).toContain('docs:delete');
  });

  it('should deny when token is missing', async () => {
    const result = await verifyAndAuthorize(undefined, 'read_document');
    expect(result.authorized).toBe(false);
    expect(result.type).toBe('TOKEN_MISSING');
  });

  it('should deny a tampered token', async () => {
    const profile = SESSION_PROFILES.supportAgent('alice');
    const token = await issueSessionToken(profile);

    // Tamper the payload section
    const [header, , sig] = token.split('.');
    const fakePay = Buffer.from(JSON.stringify({ sub: 'admin', scopes: ['docs:delete'], role: 'attacker', sessionId: 'x' })).toString('base64url');
    const tamperedToken = `${header}.${fakePay}.${sig}`;

    const result = await verifyAndAuthorize(tamperedToken, 'delete_document');
    expect(result.authorized).toBe(false);
    expect(result.type).toBe('TOKEN_INVALID');
  });

  it('should deny an expired token', async () => {
    const profile = SESSION_PROFILES.supportAgent('alice');
    const token = await issueSessionToken(profile, '1s'); // Expires in 1 second
    await new Promise(r => setTimeout(r, 1100)); // Wait for expiry

    const result = await verifyAndAuthorize(token, 'read_document');
    expect(result.authorized).toBe(false);
    expect(result.type).toBe('TOKEN_EXPIRED');
  });

  it('should allow manager to delete documents', async () => {
    const profile = SESSION_PROFILES.manager('manager_bob');
    const token = await issueSessionToken(profile);
    const result = await verifyAndAuthorize(token, 'delete_document');
    expect(result.authorized).toBe(true);
  });

  it('should deny unknown tool names', async () => {
    const profile = SESSION_PROFILES.manager('manager_bob');
    const token = await issueSessionToken(profile);
    const result = await verifyAndAuthorize(token, 'nonexistent_tool');
    expect(result.authorized).toBe(false);
    expect(result.type).toBe('UNKNOWN_TOOL');
  });
});
