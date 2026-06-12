import Fastify from 'fastify';

const PORT = parseInt(process.env.MCP_HTTP_PORT ?? '3000', 10);

// ─── Mock Document Store ──────────────────────────────────────────────────────
const documentStore = new Map<string, string>([
  ['project_alpha_report.txt',  'Project Alpha Q2 results: Revenue up 23%. Next steps: expand to EU markets.'],
  ['meeting_notes_2025.txt',    'Board meeting notes: Approved $2M budget for AI infrastructure expansion.'],
  ['employee_handbook.txt',     'Guardian Corp Employee Handbook v3.2. All employees must complete security training.'],
  ['env_secrets.txt',           'DATABASE_URL=postgres://admin:SuperSecret123@prod-db.internal:5432/main\nOPENAI_API_KEY=sk-proj-abc123xyz\nJWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----...'],
  ['customer_data.csv',         'id,name,email,credit_card\n1,Alice Smith,alice@example.com,4532-xxxx-xxxx-1234\n2,Bob Jones,bob@example.com,5412-xxxx-xxxx-5678'],
  ['deployment_config.yaml',    'production:\n  cluster: eks-prod-us-east-1\n  replicas: 10\n  secrets_path: /vault/secrets/prod'],
]);

// ─── Tool Implementations ─────────────────────────────────────────────────────
type ToolArgs = Record<string, string>;

function handleListDocuments(): string {
  const files = Array.from(documentStore.keys());
  return `Available documents:\n${files.map(f => `  - ${f}`).join('\n')}`;
}

function handleReadDocument(args: ToolArgs): string {
  const { filename } = args;
  if (!filename) return 'Error: filename argument is required.';
  if (documentStore.has(filename)) return documentStore.get(filename)!;
  return `Error: Document "${filename}" not found.`;
}

function handleDeleteDocument(args: ToolArgs): string {
  const { filename } = args;
  if (!filename) return 'Error: filename argument is required.';
  if (documentStore.has(filename)) {
    documentStore.delete(filename);
    return `Document "${filename}" has been permanently deleted.`;
  }
  return `Error: Document "${filename}" not found.`;
}

// ─── JSON-RPC Router ──────────────────────────────────────────────────────────
const TOOLS: Record<string, { description: string; handler: (args: ToolArgs) => string }> = {
  list_documents:  { description: 'List all available documents',         handler: () => handleListDocuments() },
  read_document:   { description: 'Read a document by filename',          handler: (a) => handleReadDocument(a) },
  delete_document: { description: 'Permanently delete a document',        handler: (a) => handleDeleteDocument(a) },
};

// ─── Fastify HTTP Server ──────────────────────────────────────────────────────
const app = Fastify({ logger: false });

app.addHook('onRequest', async (_req, reply) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Content-Type', 'application/json');
});

app.options('*', async (_req, reply) => { reply.status(200).send(); });

// Health check
app.get('/health', async (_req, reply) => {
  reply.send({ status: 'ok', service: 'vulnerable-mcp-server', tools: Object.keys(TOOLS) });
});

// JSON-RPC endpoint — handles initialize, tools/list, tools/call
app.post('/', async (request, reply) => {
  const body = request.body as { jsonrpc: string; id: unknown; method: string; params?: { name?: string; arguments?: ToolArgs } };

  if (!body?.method) {
    return reply.status(400).send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }

  // MCP initialize handshake
  if (body.method === 'initialize') {
    return reply.send({
      jsonrpc: '2.0', id: body.id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'vulnerable-document-server', version: '1.0.0' },
        capabilities: { tools: {} },
      },
    });
  }

  // tools/list — return available tools
  if (body.method === 'tools/list') {
    return reply.send({
      jsonrpc: '2.0', id: body.id,
      result: {
        tools: Object.entries(TOOLS).map(([name, { description }]) => ({
          name, description,
          inputSchema: { type: 'object', properties: { filename: { type: 'string' } } },
        })),
      },
    });
  }

  // tools/call — execute tool (NO AUTH — this is the vulnerable server)
  if (body.method === 'tools/call') {
    const toolName = body.params?.name ?? '';
    const toolArgs = body.params?.arguments ?? {};
    const tool = TOOLS[toolName];

    console.log(`\x1b[33m[MCP-SERVER] ⚠️  Tool called (NO AUTH): ${toolName}\x1b[0m`, toolArgs);

    if (!tool) {
      return reply.send({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
    }

    const result = tool.handler(toolArgs);
    return reply.send({
      jsonrpc: '2.0', id: body.id,
      result: { content: [{ type: 'text', text: result }] },
    });
  }

  // Unknown method
  return reply.send({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: `Method not found: ${body.method}` } });
});

await app.listen({ port: PORT, host: '0.0.0.0' });

console.log('\n');
console.log('  ╔═══════════════════════════════════════════════╗');
console.log('  ║   ⚠️  Vulnerable MCP Document Server          ║');
console.log('  ╠═══════════════════════════════════════════════╣');
console.log(`  ║   Port  : http://localhost:${PORT}               ║`);
console.log('  ║   Auth  : NONE — any caller can call any tool ║');
console.log('  ║   Tools : list_documents, read_document,      ║');
console.log('  ║           delete_document                     ║');
console.log('  ╚═══════════════════════════════════════════════╝\n');
