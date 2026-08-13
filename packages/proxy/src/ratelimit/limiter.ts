export interface RateLimiterOptions {
  windowMs: number; // e.g. 60000 (1 minute)
  maxRequests: number; // e.g. 60 requests per minute
  anomalyThreshold?: number; // e.g. 20 requests in 5 seconds
}

interface RequestRecord {
  timestamps: number[];
  isBlocked: boolean;
}

export class AgentRateLimiter {
  private records: Map<string, RequestRecord> = new Map();
  private windowMs: number;
  private maxRequests: number;
  private anomalyThreshold: number;

  constructor(options: RateLimiterOptions) {
    this.windowMs = options.windowMs;
    this.maxRequests = options.maxRequests;
    this.anomalyThreshold = options.anomalyThreshold || 20;
  }

  public checkRateLimit(key: string): { allowed: boolean; reason?: string; currentCount: number } {
    const now = Date.now();
    let record = this.records.get(key);

    if (!record) {
      record = { timestamps: [], isBlocked: false };
      this.records.set(key, record);
    }

    if (record.isBlocked) {
      return { allowed: false, reason: 'Session auto-suspended due to behavioral anomaly', currentCount: record.timestamps.length };
    }

    // Filter out timestamps outside window
    record.timestamps = record.timestamps.filter((ts) => now - ts < this.windowMs);

    // Check sliding window request count
    if (record.timestamps.length >= this.maxRequests) {
      return { allowed: false, reason: `Rate limit exceeded (${this.maxRequests} req / ${this.windowMs / 1000}s)`, currentCount: record.timestamps.length };
    }

    // Check rapid burst / anomaly threshold (requests in last 5 seconds)
    const recentBurst = record.timestamps.filter((ts) => now - ts < 5000).length;
    if (recentBurst >= this.anomalyThreshold) {
      record.isBlocked = true;
      return { allowed: false, reason: `Anomalous rapid request burst detected (${recentBurst} reqs in 5s)`, currentCount: record.timestamps.length };
    }

    record.timestamps.push(now);
    return { allowed: true, currentCount: record.timestamps.length };
  }

  public resetKey(key: string): void {
    this.records.delete(key);
  }
}
