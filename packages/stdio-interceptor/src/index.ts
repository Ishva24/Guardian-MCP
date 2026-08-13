import { StdioInterceptor } from './interceptor.js';

export * from './interceptor.js';

if (import.meta.url === `file://${process.argv[1]}`) {
  const interceptor = new StdioInterceptor({
    onBlocked: (method, reason) => {
      console.error(`[Guardian-MCP Stdio] BLOCKED ${method}: ${reason}`);
    },
    onSanitized: (categories) => {
      console.error(`[Guardian-MCP Stdio] REDACTED sensitive data categories: ${categories.join(', ')}`);
    }
  });

  interceptor.start();
}
