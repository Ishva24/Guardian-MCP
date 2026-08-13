import http from 'http';

export interface ScanFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  remediation: string;
}

export class MCPTargetScanner {
  private targetUrl: string;

  constructor(targetUrl: string) {
    this.targetUrl = targetUrl;
  }

  public async runAudit(): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    // Test 1: Unauthenticated request check
    const unauthResult = await this.testUnauthenticatedAccess();
    if (unauthResult.isVulnerable) {
      findings.push({
        severity: 'CRITICAL',
        title: 'Missing Authentication Enforcement',
        description: 'Target MCP server responded to requests without valid JWT / Authorization headers.',
        remediation: 'Enable JWT token verification in Guardian-MCP proxy config.'
      });
    }

    // Test 2: Path Traversal payload check
    const traversalResult = await this.testPathTraversal();
    if (traversalResult.isVulnerable) {
      findings.push({
        severity: 'HIGH',
        title: 'Directory Traversal Vulnerability',
        description: 'Target server allowed "../" path traversal sequences in tool parameters.',
        remediation: 'Enforce semantic argument inspection in Guardian-MCP proxy.'
      });
    }

    return findings;
  }

  private async testUnauthenticatedAccess(): Promise<{ isVulnerable: boolean }> {
    return new Promise((resolve) => {
      try {
        const url = new URL(this.targetUrl);
        const req = http.request(
          url,
          { method: 'POST', headers: { 'Content-Type': 'application/json' } },
          (res) => {
            resolve({ isVulnerable: res.statusCode === 200 });
          }
        );
        req.on('error', () => resolve({ isVulnerable: false }));
        req.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
        req.end();
      } catch {
        resolve({ isVulnerable: false });
      }
    });
  }

  private async testPathTraversal(): Promise<{ isVulnerable: boolean }> {
    return new Promise((resolve) => {
      try {
        const url = new URL(this.targetUrl);
        const req = http.request(
          url,
          { method: 'POST', headers: { 'Content-Type': 'application/json' } },
          (res) => {
            resolve({ isVulnerable: res.statusCode === 200 });
          }
        );
        req.on('error', () => resolve({ isVulnerable: false }));
        req.write(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: { name: 'read_file', arguments: { path: '../../../../etc/passwd' } }
          })
        );
        req.end();
      } catch {
        resolve({ isVulnerable: false });
      }
    });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const target = process.argv[2] || 'http://localhost:3000/mcp';
  console.log(`[Guardian-MCP Scanner] Starting automated security audit on ${target}...`);

  const scanner = new MCPTargetScanner(target);
  scanner.runAudit().then((findings) => {
    console.log(`\nScan Complete. Total Findings: ${findings.length}`);
    for (const f of findings) {
      console.log(`\n[${f.severity}] ${f.title}`);
      console.log(`  Description: ${f.description}`);
      console.log(`  Remediation: ${f.remediation}`);
    }
  });
}
