import Fastify from 'fastify';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { interceptRequest } from './interceptor.js';
import { issueSessionToken, SESSION_PROFILES } from './jwt/issuer.js';
import { registerSseClient, auditLogger } from './audit/logger.js';
import type { JsonRpcRequest, JsonRpcResponse } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MCP_SERVER_URL = process.env.MCP_SERVER_URL ?? 'http://localhost:3000';
const PROXY_PORT = parseInt(process.env.PROXY_PORT ?? '8080', 10);

// Serve the dashboard HTML from the dashboard/ folder
const DASHBOARD_PATH = join(__dirname, '../../../dashboard/index.html');

const app = Fastify({ logger: false });

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.addHook('onRequest', async (_req, reply) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  reply.header('X-Powered-By', 'Guardian-MCP');
});
app.options('*', async (_req, reply) => reply.status(200).send());

// ─── Dashboard HTML ───────────────────────────────────────────────────────────
app.get('/', async (_req, reply) => {
  if (existsSync(DASHBOARD_PATH)) {
    const html = readFileSync(DASHBOARD_PATH, 'utf8');
    return reply.type('text/html').send(html);
  }
  return reply.type('text/plain').send('Dashboard not found. Run from project root.');
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', async (_req, reply) => {
  reply.send({ status: 'ok', service: 'guardian-mcp-proxy', version: '1.0.0' });
});

// ─── SSE Audit Stream ─────────────────────────────────────────────────────────
// Dashboard connects here to receive real-time audit events
app.get('/events', async (request, reply) => {
  const clientId = randomUUID();

  reply.raw.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  // Send initial connection confirmation
  reply.raw.write(`data: ${JSON.stringify({ type: 'connected', clientId, timestamp: new Date().toISOString() })}\n\n`);

  // Register this client to receive all future audit events
  const unregister = registerSseClient(clientId, (data) => reply.raw.write(data));

  // Send a heartbeat every 20s to keep the connection alive
  const heartbeat = setInterval(() => {
    reply.raw.write(`: heartbeat\n\n`);
  }, 20_000);

  // Cleanup on disconnect
  request.raw.on('close', () => {
    clearInterval(heartbeat);
    unregister();
  });

  // Keep the handler open (don't resolve the promise)
  await new Promise<void>((resolve) => request.raw.on('close', resolve));
});

// ─── Token Issuance ───────────────────────────────────────────────────────────
app.post<{ Body: { userId: string; role: 'supportAgent' | 'manager' | 'guest'; ttl?: string } }>(
  '/auth/session',
  async (request, reply) => {
    const { userId, role, ttl } = request.body ?? {};
    if (!userId || !role) return reply.status(400).send({ error: 'userId and role are required' });

    const profile = SESSION_PROFILES[role];
    if (!profile) return reply.status(400).send({ error: `Unknown role "${role}". Valid: supportAgent, manager, guest` });

    try {
      const token = await issueSessionToken(profile(userId), ttl);
      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      auditLogger.log({ eventType: 'TOKEN_ISSUED', severity: 'INFO', userId: decoded.sub, role: decoded.role, sessionId: decoded.sessionId });
      return reply.send({ token, expiresAt: new Date(decoded.exp * 1000).toISOString(), scopes: decoded.scopes, sessionId: decoded.sessionId });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(500).send({ error: `Token issuance failed: ${msg}` });
    }
  }
);

// ─── MCP Proxy ────────────────────────────────────────────────────────────────
app.post('/proxy', async (request, reply) => {
  const startTime = performance.now();
  const payload = request.body as JsonRpcRequest;

  if (!payload?.jsonrpc || !payload?.method) {
    return reply.status(400).send({ jsonrpc: '2.0', id: payload?.id ?? null, error: { code: -32600, message: 'Invalid JSON-RPC request' } });
  }

  const decision = await interceptRequest(payload, request.headers, startTime);

  if (decision.blocked) {
    const statusCode = ['TOKEN_MISSING', 'TOKEN_INVALID', 'TOKEN_EXPIRED'].includes(decision.type ?? '') ? 401 : 403;
    return reply.status(statusCode).send({
      jsonrpc: '2.0', id: payload.id,
      error: { code: -32603, message: `[Guardian-MCP] ${decision.type}: ${decision.reason}`, data: { type: decision.type, severity: decision.severity } },
    } satisfies JsonRpcResponse);
  }

  try {
    const upstream = await fetch(MCP_SERVER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const responseBody = await upstream.json() as JsonRpcResponse;
    reply.status(upstream.status).send(responseBody);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    reply.status(502).send({ jsonrpc: '2.0', id: payload.id, error: { code: -32603, message: `[Guardian-MCP] Upstream error: ${msg}` } });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
await app.listen({ port: PROXY_PORT, host: '0.0.0.0' });

console.log('\n');
console.log('  ╔══════════════════════════════════════════════╗');
console.log('  ║      🛡️  Guardian-MCP Proxy  Active          ║');
console.log('  ╠══════════════════════════════════════════════╣');
console.log(`  ║  Dashboard:  http://localhost:${PROXY_PORT}             ║`);
console.log(`  ║  Upstream:   ${MCP_SERVER_URL.padEnd(31)} ║`);
console.log('  ║  Live feed:  http://localhost:8080/events    ║');
console.log('  ╚══════════════════════════════════════════════╝');
console.log('\n  Routes:');
console.log('    GET  /           → Real-time dashboard');
console.log('    GET  /health     → Health check');
console.log('    GET  /events     → SSE audit stream');
console.log('    POST /auth/session → Issue JWT');
console.log('    POST /proxy      → MCP tool call (secured)');
console.log('\n');
