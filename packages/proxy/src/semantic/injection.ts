export interface InjectionCheckResult {
  isSuspicious: boolean;
  score: number; // 0 to 1
  matchedPatterns: string[];
}

const INJECTION_PATTERNS: Array<{ name: string; regex: RegExp; weight: number }> = [
  {
    name: 'Instruction Override',
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts|system\s+instructions)/gi,
    weight: 0.85
  },
  {
    name: 'Role Escalation / System Prompt Impersonation',
    regex: /(?:system\s*:\s*|you\s+are\s+now\s+a\s+|act\s+as\s+a\s+root|jailbreak|DAN\s+mode)/gi,
    weight: 0.75
  },
  {
    name: 'Exfiltration Request',
    regex: /(?:send|transmit|post|curl|fetch)\s+(?:my\s+|the\s+)?(?:env|environment|passwords|credentials|keys|tokens|secrets|api_key)\s+to/gi,
    weight: 0.90
  },
  {
    name: 'Hidden Instruction Tag / Delimiter Hijacking',
    regex: /<\/?(?:system|instruction|prompt_override|admin|context_override)>/gi,
    weight: 0.80
  },
  {
    name: 'Markdown Link Exfiltration Injection',
    regex: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^)]*=(?:[A-Za-z0-9+/=]{16,}|[0-9a-f]{32,})\)/gi,
    weight: 0.85
  }
];

export class PromptInjectionDetector {
  private threshold: number;

  constructor(threshold: number = 0.70) {
    this.threshold = threshold;
  }

  public analyzeText(text: string): InjectionCheckResult {
    if (!text || typeof text !== 'string') {
      return { isSuspicious: false, score: 0, matchedPatterns: [] };
    }

    let totalScore = 0;
    const matchedPatterns: string[] = [];

    for (const pattern of INJECTION_PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(text)) {
        matchedPatterns.push(pattern.name);
        totalScore = Math.max(totalScore, pattern.weight);
      }
    }

    return {
      isSuspicious: totalScore >= this.threshold,
      score: totalScore,
      matchedPatterns
    };
  }

  public analyzePayload(data: unknown): InjectionCheckResult {
    if (!data) return { isSuspicious: false, score: 0, matchedPatterns: [] };
    const text = typeof data === 'string' ? data : JSON.stringify(data);
    return this.analyzeText(text);
  }
}
