import readline from 'readline';
import { DLPScanner } from '../../proxy/src/dlp/scanner.js';

export interface StdioInterceptorOptions {
  onBlocked?: (method: string, reason: string) => void;
  onSanitized?: (categories: string[]) => void;
}

export class StdioInterceptor {
  private dlpScanner: DLPScanner;
  private options: StdioInterceptorOptions;

  constructor(options: StdioInterceptorOptions = {}) {
    this.dlpScanner = new DLPScanner();
    this.options = options;
  }

  public start(): void {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    rl.on('line', (line: string) => {
      this.handleLine(line);
    });
  }

  private handleLine(line: string): void {
    if (!line.trim()) return;

    try {
      const jsonMessage = JSON.parse(line);

      // Inspect outgoing tool results for DLP sensitive data
      if (jsonMessage.result) {
        const { sanitizedData, matchedCategories } = this.dlpScanner.scanObject(jsonMessage.result);
        if (matchedCategories.length > 0) {
          jsonMessage.result = sanitizedData;
          if (this.options.onSanitized) {
            this.options.onSanitized(matchedCategories);
          }
        }
      }

      // Check path traversal or null-byte in tool call arguments
      if (jsonMessage.method === 'tools/call' && jsonMessage.params?.arguments) {
        const argsStr = JSON.stringify(jsonMessage.params.arguments);
        if (argsStr.includes('../') || argsStr.includes('\\x00')) {
          if (this.options.onBlocked) {
            this.options.onBlocked(jsonMessage.method, 'Path traversal / null-byte detected in arguments');
          }
          const blockedErrorResponse = {
            jsonrpc: '2.0',
            id: jsonMessage.id,
            error: {
              code: -32600,
              message: 'Blocked by Guardian-MCP Stdio Interceptor: Path traversal or invalid characters detected.'
            }
          };
          process.stdout.write(JSON.stringify(blockedErrorResponse) + '\n');
          return;
        }
      }

      process.stdout.write(JSON.stringify(jsonMessage) + '\n');
    } catch {
      // Pass through raw line if not valid JSON
      process.stdout.write(line + '\n');
    }
  }
}
