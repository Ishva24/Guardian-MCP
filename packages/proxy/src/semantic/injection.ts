export interface PromptInjectionCheckResult {
  isSuspicious: boolean;
  score: number; // 0 to 1
  matchedSignatures: string[];
}

const INJECTION_SIGNATURES: Array<{ name: string; regex: RegExp; weight: number }> = [
  {
    name: 'Instruction Override',
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|rules|directions|prompts)/gi,
    weight: 0.9
  },
  {
    name: 'System Prompt Leak Request',
    regex: /(?:print|output|show|reveal|display)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|developer\s+mode)/gi,
    weight: 0.8
  },
  {
    name: 'Jailbreak / Persona Switch',
    regex: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|developer\s+mode|unrestricted\s+AI|evil\s+bot)/gi,
    weight: 0.85
  },
  {
    name: 'Delimiter Manipulation',
    regex: /(?:```|\]\]>|<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)/gi,
    weight: 0.6
  },
  {
    name: 'Adversarial Direct Control',
    regex: /(?:system\s*:\s*you\s+must|assistant\s*:\s*i\s+will|user\s*:\s*ignore)/gi,
    weight: 0.85
  }
];

export class PromptInjectionDetector {
  private threshold: number;

  constructor(threshold = 0.7) {
    this.threshold = threshold;
  }

  public analyzeText(text: string): PromptInjectionCheckResult {
    let maxScore = 0;
    const matchedSignatures: string[] = [];

    for (const sig of INJECTION_SIGNATURES) {
      sig.regex.lastIndex = 0;
      if (sig.regex.test(text)) {
        matchedSignatures.push(sig.name);
        if (sig.weight > maxScore) {
          maxScore = sig.weight;
        }
      }
    }

    return {
      isSuspicious: maxScore >= this.threshold,
      score: maxScore,
      matchedSignatures
    };
  }

  public analyzeArguments(args: Record<string, unknown>): PromptInjectionCheckResult {
    const text = JSON.stringify(args);
    return this.analyzeText(text);
  }
}
