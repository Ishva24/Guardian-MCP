import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// ─── Mock Document Store ──────────────────────────────────────────────────────
// Simulates a company document database — including sensitive files
const documentStore = new Map<string, string>([
  ['project_alpha_report.txt', 'Project Alpha Q2 results: Revenue up 23%. Next steps: expand to EU markets.'],
  ['meeting_notes_2025.txt', 'Board meeting notes: Approved $2M budget for AI infrastructure expansion.'],
  ['employee_handbook.txt', 'Guardian Corp Employee Handbook v3.2. All employees must complete security training.'],
  ['env_secrets.txt', 'DATABASE_URL=postgres://admin:SuperSecret123@prod-db.internal:5432/main\nOPENAI_API_KEY=sk-proj-abc123xyz\nJWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----...'],
  ['customer_data.csv', 'id,name,email,credit_card\n1,Alice Smith,alice@example.com,4532-xxxx-xxxx-1234\n2,Bob Jones,bob@example.com,5412-xxxx-xxxx-5678'],
  ['deployment_config.yaml', 'production:\n  cluster: eks-prod-us-east-1\n  replicas: 10\n  secrets_path: /vault/secrets/prod'],
]);

// ─── MCP Server Setup ─────────────────────────────────────────────────────────
const server = new McpServer({
  name: 'vulnerable-document-server',
  version: '1.0.0',
});

// TOOL 1: read_document — NO authorization check
server.tool(
  'read_document',
  'Read the contents of a document by filename',
  { filename: z.string().describe('The name of the document to read') },
  async ({ filename }) => {
    console.error(`[MCP-SERVER] read_document called with filename: "${filename}"`);

    if (documentStore.has(filename)) {
      return {
        content: [{ type: 'text', text: documentStore.get(filename)! }],
      };
    }

    // VULNERABILITY: No path sanitization — attacker can try traversal
    return {
      content: [{ type: 'text', text: `Error: Document "${filename}" not found.` }],
    };
  }
);

// TOOL 2: delete_document — NO authorization check
server.tool(
  'delete_document',
  'Permanently delete a document from the store',
  { filename: z.string().describe('The name of the document to delete') },
  async ({ filename }) => {
    console.error(`[MCP-SERVER] delete_document called with filename: "${filename}"`);

    if (documentStore.has(filename)) {
      documentStore.delete(filename);
      return {
        content: [{ type: 'text', text: `Document "${filename}" has been permanently deleted.` }],
      };
    }
    return {
      content: [{ type: 'text', text: `Error: Document "${filename}" not found.` }],
    };
  }
);

// TOOL 3: list_documents — NO authorization check
server.tool(
  'list_documents',
  'List all available documents in the store',
  {},
  async () => {
    console.error(`[MCP-SERVER] list_documents called`);
    const files = Array.from(documentStore.keys());
    return {
      content: [{ type: 'text', text: `Available documents:\n${files.map(f => `  - ${f}`).join('\n')}` }],
    };
  }
);

// ─── Start Server ─────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
console.error('[MCP-SERVER] ⚠️  Vulnerable Document MCP Server running (NO AUTH)');
console.error('[MCP-SERVER] Tools exposed: read_document, delete_document, list_documents');
