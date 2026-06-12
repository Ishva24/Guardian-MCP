import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const keysDir = join(__dirname, '../../keys');

console.log('\n🔑 Guardian-MCP Key Generator');
console.log('─'.repeat(40));

mkdirSync(keysDir, { recursive: true });

console.log('Generating RSA-2048 key pair...');
const { privateKey, publicKey } = await generateKeyPair('RS256', {
  modulusLength: 2048,
  extractable: true,
});

const privateKeyPEM = await exportPKCS8(privateKey);
const publicKeyPEM = await exportSPKI(publicKey);

const privatePath = join(keysDir, 'private.pem');
const publicPath = join(keysDir, 'public.pem');

writeFileSync(privatePath, privateKeyPEM, 'utf8');
writeFileSync(publicPath, publicKeyPEM, 'utf8');

console.log(`✅ Private key → ${privatePath}`);
console.log(`✅ Public key  → ${publicPath}`);
console.log('\n⚠️  Add keys/ to .gitignore — never commit private keys!');
console.log('─'.repeat(40));
