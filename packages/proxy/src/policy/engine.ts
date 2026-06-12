import { readFileSync, watch, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { Policy } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// src/policy/ → ../../ → packages/proxy/
const POLICY_PATH = process.env.POLICY_PATH ?? join(__dirname, '../../policy.json');

let currentPolicy: Policy | null = null;
let watchStarted = false;

function loadPolicy(): Policy {
  if (!existsSync(POLICY_PATH)) {
    throw new Error(`Policy file not found at: ${POLICY_PATH}`);
  }
  const raw = readFileSync(POLICY_PATH, 'utf8');
  const parsed = JSON.parse(raw) as Policy;
  console.log(`[POLICY] Loaded policy v${parsed.version} — ${parsed.rules.length} rules, default: ${parsed.defaultAction}`);
  return parsed;
}

function startWatcher(): void {
  if (watchStarted) return;
  watchStarted = true;
  // Hot-reload on policy file change (atomic reference swap — zero downtime)
  watch(POLICY_PATH, () => {
    try {
      currentPolicy = loadPolicy();
      console.log('[POLICY] ♻️  Policy hot-reloaded successfully');
    } catch (err) {
      console.error('[POLICY] ❌ Failed to reload policy — keeping previous version:', err);
    }
  });
}

export function getPolicy(): Policy {
  if (!currentPolicy) {
    currentPolicy = loadPolicy();
    startWatcher(); // Start watching only after first successful load
  }
  return currentPolicy;
}

export interface PolicyDecision {
  allowed: boolean;
  rule?: string;
  reason?: string;
}

/**
 * Evaluates the policy rules for a given tool call.
 * Returns the first matching rule's decision. Falls back to defaultAction.
 */
export function evaluatePolicy(toolName: string, grantedScopes: string[]): PolicyDecision {
  const policy = getPolicy();

  for (const rule of policy.rules) {
    if (rule.tool !== toolName) continue;

    // If rule requires a scope, check it's granted
    if (rule.requiredScope && !grantedScopes.includes(rule.requiredScope)) {
      continue; // Scope not met — try next rule
    }

    if (rule.action === 'deny') {
      return { allowed: false, rule: rule.id, reason: rule.reason ?? `Tool "${toolName}" is explicitly denied by policy rule ${rule.id}` };
    }

    if (rule.action === 'allow') {
      return { allowed: true, rule: rule.id };
    }
  }

  // No rule matched — apply default
  const defaultAllowed = policy.defaultAction === 'allow';
  return {
    allowed: defaultAllowed,
    reason: defaultAllowed
      ? 'No matching rule — default ALLOW'
      : `No matching rule for tool "${toolName}" — default DENY`,
  };
}
