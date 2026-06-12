import { createWriteStream } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import type { AuditEvent } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOG_PATH = join(__dirname, '../../audit.log');

// Append-only log stream (never truncates)
const logStream = createWriteStream(LOG_PATH, { flags: 'a' });

// ─── SSE Broadcast Bus ────────────────────────────────────────────────────────
// A simple in-process event bus — registered SSE clients receive every audit event
type SseClient = { id: string; write: (data: string) => void };
const sseClients = new Map<string, SseClient>();

export function registerSseClient(id: string, write: (data: string) => void): () => void {
  sseClients.set(id, { id, write });
  return () => sseClients.delete(id); // Returns unregister function
}

function broadcastToSse(event: AuditEvent): void {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients.values()) {
    try { client.write(payload); } catch { sseClients.delete(client.id); }
  }
}

// ─── ANSI Colors ──────────────────────────────────────────────────────────────
const COLORS = {
  RESET:    '\x1b[0m',
  RED:      '\x1b[31m',
  GREEN:    '\x1b[32m',
  YELLOW:   '\x1b[33m',
  MAGENTA:  '\x1b[35m',
  BOLD:     '\x1b[1m',
  DIM:      '\x1b[2m',
};

const SEVERITY_COLOR: Record<string, string> = {
  INFO:     COLORS.GREEN,
  LOW:      '\x1b[36m',
  MEDIUM:   COLORS.YELLOW,
  HIGH:     COLORS.RED,
  CRITICAL: COLORS.MAGENTA + COLORS.BOLD,
};

// ─── Logger ───────────────────────────────────────────────────────────────────
export function createAuditLogger() {
  function log(event: Omit<AuditEvent, 'requestId' | 'timestamp'>) {
    const fullEvent: AuditEvent = {
      ...event,
      requestId: randomUUID().slice(0, 8),
      timestamp: new Date().toISOString(),
    };

    // 1. Structured JSON to file
    logStream.write(JSON.stringify(fullEvent) + '\n');

    // 2. Broadcast to all SSE dashboard clients
    broadcastToSse(fullEvent);

    // 3. Human-readable console output
    const color = SEVERITY_COLOR[fullEvent.severity] ?? COLORS.RESET;
    const icon = fullEvent.eventType === 'TOOL_CALL_ALLOWED' ? '✅' : '🚫';
    const userInfo = fullEvent.userId ? `[${fullEvent.userId}/${fullEvent.role}]` : '';
    console.log(
      `${color}${icon} [AUDIT] ${fullEvent.eventType}${COLORS.RESET} ` +
      `${COLORS.DIM}${fullEvent.timestamp}${COLORS.RESET} ` +
      `${userInfo} tool="${fullEvent.tool ?? '-'}" ` +
      (fullEvent.blockDetail ? `reason="${fullEvent.blockDetail}" ` : '') +
      `latency=${fullEvent.proxyLatencyMs?.toFixed(2) ?? '?'}ms`
    );
  }

  return { log };
}

export const auditLogger = createAuditLogger();
