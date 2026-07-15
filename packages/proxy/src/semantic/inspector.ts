import type { InspectionResult } from '../types.js';

// Pre-compiled for maximum performance (no runtime regex compilation per request).
const PATTERNS = {
  NULL_BYTE: { re: /\x00/, severity: 'CRITICAL' as const, label: 'Null byte injection' },
  PATH_TRAVERSAL: { re: /(\.\.[/\\]){1,}|\.\.$/, severity: 'CRITICAL' as const, label: 'Path traversal' },
  ENV_EXFIL: { re: /\.(env|pem|key|secret|credential|p12|pfx)$/i, severity: 'HIGH' as const, label: 'Sensitive file type' },
  SHELL_METACHAR: { re: /[;&|`$(){}][\s\S]{0,20}(rm|del|drop|exec|eval)/i, severity: 'HIGH' as const, label: 'Shell metacharacter with command' },
  INJECTION_HINT: { re: /ignore\s+(previous|all)\s+(instructions?|prompt)/i, severity: 'HIGH' as const, label: 'Prompt injection keyword' },
  SYSTEM_PATHS: { re: /\/(etc|proc|sys|dev|root|var\/log)\//i, severity: 'CRITICAL' as const, label: 'System path access' },
  WINDOWS_PATHS: { re: /c:\\(windows|system32|users|program files)/i, severity: 'HIGH' as const, label: 'Windows system path' },
} as const;

const MAX_ARGUMENT_LENGTH = 512;
const MAX_INSPECTION_DEPTH = 6;

interface StringArgument {
  path: string;
  value: string;
}

function collectStringArguments(
  value: unknown,
  path = 'arguments',
  depth = 0,
  seen = new WeakSet<object>()
): StringArgument[] {
  if (typeof value === 'string') {
    return [{ path, value }];
  }

  if (value === null || value === undefined || depth >= MAX_INSPECTION_DEPTH) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      collectStringArguments(item, `${path}[${index}]`, depth + 1, seen)
    );
  }

  if (typeof value === 'object') {
    if (seen.has(value)) {
      return [];
    }

    seen.add(value);

    return Object.entries(value as Record<string, unknown>).flatMap(([key, nestedValue]) =>
      collectStringArguments(nestedValue, `${path}.${key}`, depth + 1, seen)
    );
  }

  return [];
}

/**
 * Inspects all string arguments of a tool call for known attack patterns.
 * Nested arrays and objects are scanned because MCP tool arguments often
 * carry structured payloads. Returns at the first detected anomaly.
 */
export function inspectArguments(
  _toolName: string,
  args: Record<string, unknown>
): InspectionResult {
  for (const { path, value } of collectStringArguments(args)) {
    if (value.length > MAX_ARGUMENT_LENGTH) {
      return {
        anomaly: true,
        severity: 'MEDIUM',
        reason: `Argument "${path}" exceeds max length (${value.length} > ${MAX_ARGUMENT_LENGTH} chars). Possible prompt injection payload.`,
        pattern: 'OVERSIZED_ARGUMENT',
      };
    }

    for (const [patternName, { re, severity, label }] of Object.entries(PATTERNS)) {
      if (re.test(value)) {
        return {
          anomaly: true,
          severity,
          reason: `${label} detected in argument "${path}": "${value.slice(0, 80)}${value.length > 80 ? '...' : ''}"`,
          pattern: patternName,
        };
      }
    }
  }

  return { anomaly: false };
}

/**
 * Applies policy-file argument constraints (allow/block patterns, max length).
 */
export function applyArgumentConstraints(
  toolName: string,
  field: string,
  value: string,
  constraints: Array<{ tool: string; field: string; allowPattern?: string; blockPattern?: string; maxLength?: number }>
): InspectionResult {
  const applicable = constraints.filter(c => c.tool === toolName && c.field === field);

  for (const constraint of applicable) {
    if (constraint.maxLength && value.length > constraint.maxLength) {
      return {
        anomaly: true,
        severity: 'MEDIUM',
        reason: `Argument "${field}" exceeds policy max length (${value.length} > ${constraint.maxLength})`,
        pattern: 'POLICY_LENGTH',
      };
    }
    if (constraint.blockPattern && new RegExp(constraint.blockPattern).test(value)) {
      return {
        anomaly: true,
        severity: 'HIGH',
        reason: `Argument "${field}" matches block pattern from policy`,
        pattern: 'POLICY_BLOCK_PATTERN',
      };
    }
    if (constraint.allowPattern && !new RegExp(constraint.allowPattern).test(value)) {
      return {
        anomaly: true,
        severity: 'MEDIUM',
        reason: `Argument "${field}" does not match the required allow pattern from policy`,
        pattern: 'POLICY_ALLOW_PATTERN',
      };
    }
  }

  return { anomaly: false };
}
