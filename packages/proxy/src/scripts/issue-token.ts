import { issueSessionToken, SESSION_PROFILES } from '../jwt/issuer.js';

const [,, role = 'supportAgent', userId = 'user_alice', ttl = '15m'] = process.argv;

const validRoles = ['supportAgent', 'manager', 'guest'] as const;
type Role = typeof validRoles[number];

if (!validRoles.includes(role as Role)) {
  console.error(`❌ Invalid role: "${role}". Valid: ${validRoles.join(', ')}`);
  process.exit(1);
}

const profile = SESSION_PROFILES[role as Role](userId);
const token = await issueSessionToken(profile, ttl);
const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());

console.log('\n🎟️  Guardian-MCP Session Token');
console.log('─'.repeat(50));
console.log(`User ID   : ${decoded.sub}`);
console.log(`Role      : ${decoded.role}`);
console.log(`Session   : ${decoded.sessionId}`);
console.log(`Scopes    : ${decoded.scopes.join(', ')}`);
console.log(`Issued    : ${new Date(decoded.iat * 1000).toISOString()}`);
console.log(`Expires   : ${new Date(decoded.exp * 1000).toISOString()}`);
console.log('─'.repeat(50));
console.log('\nToken (copy this for Authorization header):');
console.log(`Bearer ${token}`);
console.log('');
