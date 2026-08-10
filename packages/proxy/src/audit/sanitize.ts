const SENSITIVE_ARGUMENT_KEY =
  /api[_-]?key|authorization|client[_-]?secret|cookie|credential|pass(?:word|phrase)?|private[_-]?key|refresh[_-]?token|secret|session|token/i;
const SENSITIVE_VALUE_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/i,
  /\b(?:sk|sk-proj|ghp|github_pat|glpat)-[A-Za-z0-9_=-]{12,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/,
];
const MAX_AUDIT_STRING_LENGTH = 100;
const MAX_AUDIT_DEPTH = 8;
const MAX_AUDIT_ARRAY_ITEMS = 20;

/**
 * Returns a log-safe copy of MCP tool arguments.
 *
 * The goal is to preserve argument shape for incident review while ensuring
 * secrets and large prompt payloads do not become a second exposure surface.
 */
export function sanitizeAuditArguments(args: Record<string, unknown>): Record<string, unknown> {
  return sanitizeValue(args, { depth: 0, seen: new WeakSet<object>(), keyHint: '' }) as Record<string, unknown>;
}

interface SanitizeContext {
  depth: number;
  seen: WeakSet<object>;
  keyHint: string;
}

function sanitizeValue(value: unknown, context: SanitizeContext): unknown {
  const { depth, seen, keyHint } = context;

  if (typeof value === 'string') {
    if (isSensitiveKey(keyHint) || isSensitiveString(value)) {
      return '[REDACTED]';
    }

    return truncateAuditString(value);
  }

  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (depth >= MAX_AUDIT_DEPTH) {
    return '[Nested value omitted]';
  }

  if (seen.has(value)) {
    return '[Circular reference omitted]';
  }

  seen.add(value);

  if (Array.isArray(value)) {
    const visibleItems = value
      .slice(0, MAX_AUDIT_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, { depth: depth + 1, seen, keyHint }));

    if (value.length > MAX_AUDIT_ARRAY_ITEMS) {
      visibleItems.push(`[${value.length - MAX_AUDIT_ARRAY_ITEMS} additional item(s) omitted]`);
    }

    return visibleItems;
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
    sanitized[key] = isSensitiveKey(key)
      ? '[REDACTED]'
      : sanitizeValue(nestedValue, { depth: depth + 1, seen, keyHint: key });
  }
  return sanitized;
}

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_ARGUMENT_KEY.test(key);
}

function isSensitiveString(value: string): boolean {
  return SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function truncateAuditString(value: string): string {
  return value.length > MAX_AUDIT_STRING_LENGTH
    ? `[${value.length} chars - truncated]`
    : value;
}
