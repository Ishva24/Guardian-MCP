import type { IncomingHttpHeaders } from 'http';
import { verifyAndAuthorize } from './jwt/verifier.js';
import { inspectArguments, applyArgumentConstraints } from './semantic/inspector.js';
import { evaluatePolicy, getPolicy } from './policy/engine.js';
import { auditLogger } from './audit/logger.js';
import type { JsonRpcRequest, InterceptDecision } from './types.js';

/**
 * Core interception pipeline.
 * Every JSON-RPC request passes through this before forwarding.
 *
 * Pipeline order:
 *   1. Parse tool name and arguments
 *   2. JWT verification + scope check
 *   3. Semantic argument inspection
 *   4. Policy rule evaluation
 *   5. Argument constraint validation (from policy.json)
 *   6. Audit log emission
 *   7. ALLOW (forward) or DENY (return 403)
 */
export async function interceptRequest(
  payload: JsonRpcRequest,
  headers: IncomingHttpHeaders,
  startTime: number
): Promise<InterceptDecision> {

  // Only intercept tool call requests
  if (payload.method !== 'tools/call') {
    return { blocked: false };
  }

  const toolName = payload.params?.name ?? '';
  const toolArgs = (payload.params?.arguments ?? {}) as Record<string, unknown>;
  const rawToken = (headers.authorization ?? '').replace(/^Bearer\s+/i, '').trim();

  // ── Step 1: JWT Verification + Scope Authorization ────────────────────────
  const authResult = await verifyAndAuthorize(rawToken || undefined, toolName);

  if (!authResult.authorized) {
    const latencyMs = performance.now() - startTime;
    auditLogger.log({
      eventType: 'TOOL_CALL_DENIED',
      severity: authResult.type === 'TOKEN_EXPIRED' ? 'MEDIUM' : 'HIGH',
      sessionId: authResult.claims?.sessionId,
      userId: authResult.claims?.sub,
      role: authResult.claims?.role,
      tool: toolName,
      arguments: sanitizeArgs(toolArgs),
      blockReason: authResult.type,
      blockDetail: authResult.reason,
      proxyLatencyMs: latencyMs,
    });
    return {
      blocked: true,
      reason: authResult.reason,
      type: authResult.type,
      severity: 'HIGH',
      claims: authResult.claims,
    };
  }

  const claims = authResult.claims!;

  // ── Step 2: Semantic Argument Inspection ──────────────────────────────────
  const stringArgs = Object.fromEntries(
    Object.entries(toolArgs).filter(([, v]) => typeof v === 'string')
  ) as Record<string, string>;

  const semanticResult = inspectArguments(toolName, stringArgs);

  if (semanticResult.anomaly) {
    const latencyMs = performance.now() - startTime;
    auditLogger.log({
      eventType: 'TOOL_CALL_DENIED',
      severity: semanticResult.severity ?? 'HIGH',
      sessionId: claims.sessionId,
      userId: claims.sub,
      role: claims.role,
      tool: toolName,
      arguments: sanitizeArgs(toolArgs),
      blockReason: 'SEMANTIC_ANOMALY',
      blockDetail: semanticResult.reason,
      proxyLatencyMs: latencyMs,
    });
    return {
      blocked: true,
      reason: semanticResult.reason,
      type: 'SEMANTIC_ANOMALY',
      severity: semanticResult.severity,
      claims,
    };
  }

  // ── Step 3: Policy Rule Evaluation ───────────────────────────────────────
  const policyDecision = evaluatePolicy(toolName, claims.scopes ?? []);

  if (!policyDecision.allowed) {
    const latencyMs = performance.now() - startTime;
    auditLogger.log({
      eventType: 'TOOL_CALL_DENIED',
      severity: 'HIGH',
      sessionId: claims.sessionId,
      userId: claims.sub,
      role: claims.role,
      tool: toolName,
      arguments: sanitizeArgs(toolArgs),
      blockReason: 'POLICY_DENY',
      blockDetail: policyDecision.reason,
      proxyLatencyMs: latencyMs,
    });
    return { blocked: true, reason: policyDecision.reason, type: 'POLICY_DENY', severity: 'HIGH', claims };
  }

  // ── Step 4: Policy Argument Constraints ──────────────────────────────────
  const policy = getPolicy();
  for (const [field, val] of Object.entries(stringArgs)) {
    const constraintResult = applyArgumentConstraints(toolName, field, val, policy.argumentConstraints);
    if (constraintResult.anomaly) {
      const latencyMs = performance.now() - startTime;
      auditLogger.log({
        eventType: 'TOOL_CALL_DENIED',
        severity: constraintResult.severity ?? 'MEDIUM',
        sessionId: claims.sessionId,
        userId: claims.sub,
        role: claims.role,
        tool: toolName,
        arguments: sanitizeArgs(toolArgs),
        blockReason: 'SEMANTIC_ANOMALY',
        blockDetail: constraintResult.reason,
        proxyLatencyMs: latencyMs,
      });
      return { blocked: true, reason: constraintResult.reason, type: 'SEMANTIC_ANOMALY', severity: constraintResult.severity, claims };
    }
  }

  // ── ALLOWED ───────────────────────────────────────────────────────────────
  const latencyMs = performance.now() - startTime;
  auditLogger.log({
    eventType: 'TOOL_CALL_ALLOWED',
    severity: 'INFO',
    sessionId: claims.sessionId,
    userId: claims.sub,
    role: claims.role,
    tool: toolName,
    arguments: sanitizeArgs(toolArgs),
    proxyLatencyMs: latencyMs,
  });

  return { blocked: false, claims };
}

/** Remove sensitive argument values from audit logs */
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    sanitized[k] = typeof v === 'string' && v.length > 100 ? `[${v.length} chars — truncated]` : v;
  }
  return sanitized;
}
