// ─── Shared TypeScript Interfaces ─────────────────────────────────────────────

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface AgentSessionClaims {
  sub: string;           // User ID
  role: string;          // User role
  scopes: string[];      // Granted tool scopes
  sessionId: string;     // Unique session ID
  constraints?: {        // Optional parameter-level constraints
    maxRefundAmount?: number;
    allowedResourcePrefix?: string;
    allowedEnvironments?: string[];
  };
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
}

export interface InterceptDecision {
  blocked: boolean;
  reason?: string;
  type?: 'AUTH_FAILURE' | 'SCOPE_DENIED' | 'SEMANTIC_ANOMALY' | 'SESSION_CONSTRAINT' | 'POLICY_DENY' | 'TOKEN_EXPIRED' | 'TOKEN_INVALID' | 'TOKEN_MISSING' | 'UNKNOWN_TOOL';
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  claims?: AgentSessionClaims;
}

export interface InspectionResult {
  anomaly: boolean;
  reason?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  pattern?: string;
}

export interface PolicyRule {
  id: string;
  description: string;
  tool: string;
  requiredScope?: string;
  action: 'allow' | 'deny';
  reason?: string;
}

export interface ArgumentConstraint {
  tool: string;
  field: string;
  allowPattern?: string;
  blockPattern?: string;
  maxLength?: number;
}

export interface Policy {
  version: string;
  defaultAction: 'allow' | 'deny';
  rules: PolicyRule[];
  argumentConstraints: ArgumentConstraint[];
}

export interface AuditEvent {
  timestamp: string;
  eventType: 'TOOL_CALL_ALLOWED' | 'TOOL_CALL_DENIED' | 'TOKEN_ISSUED' | 'PROXY_ERROR';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sessionId?: string;
  userId?: string;
  role?: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  blockReason?: string;
  blockDetail?: string;
  proxyLatencyMs?: number;
  requestId: string;
}
