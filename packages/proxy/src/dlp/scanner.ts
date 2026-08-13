import { sanitizeValue } from '../audit/sanitize.js';

export interface DLPScanResult {
  hasMatches: boolean;
  sanitizedContent: string;
  matchedCategories: string[];
}

const DLP_PATTERNS: Array<{ category: string; regex: RegExp; replacement: string }> = [
  {
    category: 'AWS Key',
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    replacement: '[REDACTED_AWS_KEY]'
  },
  {
    category: 'Private Key',
    regex: /-----BEGIN (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g,
    replacement: '[REDACTED_PRIVATE_KEY]'
  },
  {
    category: 'Generic Secret/Token',
    regex: /(?:api[_-]?key|secret[_-]?token|access[_-]?token|bearer[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,})["']?/gi,
    replacement: '[REDACTED_SECRET]'
  },
  {
    category: 'Credit Card Number',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    replacement: '[REDACTED_CREDIT_CARD]'
  },
  {
    category: 'JWT Token',
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    replacement: '[REDACTED_JWT_TOKEN]'
  }
];

export class DLPScanner {
  public scanText(text: string): DLPScanResult {
    let sanitizedContent = text;
    const matchedCategories = new Set<string>();

    for (const pattern of DLP_PATTERNS) {
      // Reset lastIndex for global regex testing
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(sanitizedContent)) {
        matchedCategories.add(pattern.category);
        pattern.regex.lastIndex = 0;
        sanitizedContent = sanitizedContent.replace(pattern.regex, pattern.replacement);
      }
    }

    return {
      hasMatches: matchedCategories.size > 0,
      sanitizedContent,
      matchedCategories: Array.from(matchedCategories)
    };
  }

  public scanObject(data: unknown): { sanitizedData: unknown; matchedCategories: string[] } {
    if (data === null || data === undefined) {
      return { sanitizedData: data, matchedCategories: [] };
    }
    const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
    const scan = this.scanText(jsonStr);

    if (!scan.hasMatches) {
      return { sanitizedData: data, matchedCategories: [] };
    }

    if (typeof data === 'string') {
      return { sanitizedData: scan.sanitizedContent, matchedCategories: scan.matchedCategories };
    }

    try {
      const sanitizedData = JSON.parse(scan.sanitizedContent);
      return { sanitizedData, matchedCategories: scan.matchedCategories };
    } catch {
      return { sanitizedData: sanitizeValue(data), matchedCategories: scan.matchedCategories };
    }
  }
}
