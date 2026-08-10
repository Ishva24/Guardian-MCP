import { describe, expect, it } from 'vitest';
import { sanitizeAuditArguments } from '../src/audit/sanitize.js';

describe('audit argument sanitization', () => {
  it('redacts sensitive keys at every nesting level', () => {
    const result = sanitizeAuditArguments({
      request: {
        authorization: 'Bearer internal-token',
        settings: [{ apiKey: 'abc123' }, { password: 'not-for-logs' }, { accessToken: 'session-secret' }],
      },
    });

    expect(result).toEqual({
      request: {
        authorization: '[REDACTED]',
        settings: [{ apiKey: '[REDACTED]' }, { password: '[REDACTED]' }, { accessToken: '[REDACTED]' }],
      },
    });
  });

  it('redacts token-like values even when the key is not sensitive', () => {
    const result = sanitizeAuditArguments({
      note: 'Bearer abcdefghijklmnopqrstuvwxyz0123456789',
      metadata: {
        raw: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456',
        jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.A1b2C3d4E5f6G7h8',
      },
    });

    expect(result).toEqual({
      note: '[REDACTED]',
      metadata: {
        raw: '[REDACTED]',
        jwt: '[REDACTED]',
      },
    });
  });

  it('truncates long nested strings while preserving normal values', () => {
    const result = sanitizeAuditArguments({
      request: {
        content: 'a'.repeat(101),
        labels: ['approved', 'b'.repeat(101)],
        retry: 2,
      },
    });

    expect(result).toEqual({
      request: {
        content: '[101 chars - truncated]',
        labels: ['approved', '[101 chars - truncated]'],
        retry: 2,
      },
    });
  });

  it('handles cyclic objects defensively', () => {
    const cyclic: Record<string, unknown> = { filename: 'report.txt' };
    cyclic.self = cyclic;

    expect(sanitizeAuditArguments(cyclic)).toEqual({
      filename: 'report.txt',
      self: '[Circular reference omitted]',
    });
  });

  it('redacts PEM private keys embedded in non-sensitive fields', () => {
    const result = sanitizeAuditArguments({
      payload: '-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----',
    });

    expect(result).toEqual({
      payload: '[REDACTED]',
    });
  });

  it('limits large arrays to keep audit records bounded', () => {
    const result = sanitizeAuditArguments({
      values: Array.from({ length: 22 }, (_, index) => `value-${index}`),
    });

    expect(result.values).toHaveLength(21);
    expect(result.values).toContain('[2 additional item(s) omitted]');
  });
});
