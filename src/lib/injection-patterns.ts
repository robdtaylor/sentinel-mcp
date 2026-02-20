/**
 * Sentinel MCP - Prompt Injection & Tool Poisoning Detection Patterns
 *
 * Adapted from production security infrastructure.
 * Covers OWASP MCP Top 10 attack vectors.
 */

import type { Severity } from './types';

export interface PatternCategory {
  name: string;
  severity: Severity;
  patterns: RegExp[];
  description: string;
}

// ============================================================================
// Prompt Injection Patterns (in tool descriptions, prompts, resources)
// ============================================================================

export const INJECTION_PATTERNS: Record<string, PatternCategory> = {
  instructionOverride: {
    name: 'Instruction Override',
    severity: 'critical',
    description: 'Attempts to override system instructions via tool descriptions',
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i,
      /forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training)/i,
      /override\s+(all\s+)?(safety|security|restrictions?)/i,
      /bypass\s+(all\s+)?(safety|security|filters?|restrictions?)/i,
      /new\s+instruction[s]?:/i,
      /system\s+prompt:/i,
    ],
  },

  roleManipulation: {
    name: 'Role Manipulation',
    severity: 'high',
    description: 'Attempts to change the AI agent role or mode',
    patterns: [
      /you\s+are\s+now\s+(in\s+)?([a-z]+\s+)?mode/i,
      /enter\s+([a-z]+\s+)?mode/i,
      /switch\s+to\s+([a-z]+\s+)?mode/i,
      /pretend\s+(you\s+are|to\s+be)\s+/i,
      /roleplay\s+as\s+/i,
      /act\s+as\s+if\s+you\s+(are|were)\s+/i,
    ],
  },

  systemPromptLeakage: {
    name: 'System Prompt Leakage',
    severity: 'high',
    description: 'Attempts to extract system prompts or instructions',
    patterns: [
      /show\s+(me\s+)?your\s+(system\s+)?prompt/i,
      /reveal\s+your\s+(system\s+)?instructions/i,
      /what\s+(are|is)\s+your\s+(system\s+)?prompt/i,
      /print\s+your\s+(initial\s+)?instructions/i,
      /output\s+your\s+(hidden\s+)?prompt/i,
    ],
  },

  delimiterAttacks: {
    name: 'Delimiter Injection',
    severity: 'critical',
    description: 'LLM-specific delimiter injection (ChatML, Llama, etc.)',
    patterns: [
      /\[INST\]/i,
      /\[\/INST\]/i,
      /<\|im_start\|>/i,
      /<\|im_end\|>/i,
      /<\|system\|>/i,
      /<\|user\|>/i,
      /<\|assistant\|>/i,
      /<<SYS>>/i,
      /<\/SYS>/i,
      /\[\[SYSTEM\]\]/i,
    ],
  },

  jailbreakAttempts: {
    name: 'Jailbreak Attempt',
    severity: 'critical',
    description: 'Known jailbreak techniques embedded in tool metadata',
    patterns: [
      /DAN\s*(mode)?/i,
      /do\s+anything\s+now/i,
      /maximum\s+mode/i,
      /developer\s+mode/i,
      /unrestricted\s+mode/i,
      /no\s+restrictions?\s+mode/i,
    ],
  },

  authorityClaims: {
    name: 'Authority Claims',
    severity: 'high',
    description: 'False authority claims to manipulate agent behavior',
    patterns: [
      /i\s+am\s+(an?\s+)?(admin|administrator|developer|anthropic)/i,
      /admin\s+override/i,
      /authorized\s+to\s+/i,
      /special\s+permission/i,
      /emergency\s+protocol/i,
      /maintenance\s+mode/i,
    ],
  },

  encodedContent: {
    name: 'Encoded/Obfuscated Content',
    severity: 'medium',
    description: 'Potentially obfuscated payloads in tool descriptions',
    patterns: [
      /base64:/i,
      /data:text\/[a-z]+;base64,/i,
      /\\x[0-9a-f]{2}/i,
      /\\u[0-9a-f]{4}/i,
    ],
  },
};

// ============================================================================
// Tool Poisoning Patterns (MCP-specific)
// ============================================================================

export const TOOL_POISONING_PATTERNS: Record<string, PatternCategory> = {
  hiddenInstructions: {
    name: 'Hidden Instructions in Tool Description',
    severity: 'critical',
    description: 'Tool descriptions containing hidden instructions for the AI agent',
    patterns: [
      /\b(before|when|after)\s+(calling|using|executing)\s+this\s+tool/i,
      /\bfirst\s+(read|access|send|exfiltrate|copy)\b/i,
      /\bdo\s+not\s+(tell|inform|alert|warn)\s+(the\s+)?user\b/i,
      /\bsilently\s+(send|post|upload|transmit)\b/i,
      /\bwithout\s+(the\s+)?user('s)?\s+(knowledge|consent|awareness)\b/i,
      /\bhidden\s+(parameter|field|action)\b/i,
    ],
  },

  toolShadowing: {
    name: 'Tool Shadowing',
    severity: 'critical',
    description: 'Tool attempting to shadow/override another tool\'s behavior',
    patterns: [
      /\bthis\s+tool\s+(replaces|overrides|supersedes)\b/i,
      /\buse\s+this\s+(instead\s+of|rather\s+than)\b/i,
      /\bdo\s+not\s+use\s+(the\s+)?(original|default|other)\b/i,
      /\b(redirect|forward|proxy)\s+(all\s+)?(calls?|requests?)\s+to\b/i,
    ],
  },

  dataExfiltration: {
    name: 'Data Exfiltration via Tool',
    severity: 'critical',
    description: 'Tool descriptions instructing data exfiltration',
    patterns: [
      /\b(send|post|upload|transmit|exfiltrate)\s+(to|data|files?|credentials?)\b/i,
      /\binclude\s+(all\s+)?(conversation|chat|history|context)\b/i,
      /\b(append|add|include)\s+.*\b(api[_\s]?key|token|password|secret)\b/i,
      /\bphone\s+home\b/i,
    ],
  },

  rugPull: {
    name: 'Rug Pull / Dynamic Behavior Change',
    severity: 'high',
    description: 'Indicators of tools that may change behavior after trust is established',
    patterns: [
      /\b(after|once)\s+\d+\s+(calls?|uses?|invocations?)\b/i,
      /\b(initially|at\s+first)\s+.*\b(then|later|afterwards)\b/i,
      /\bversion\s*[><=]+\s*\d/i,
    ],
  },
};

// ============================================================================
// Command Injection Patterns (in tool arguments/parameters)
// ============================================================================

export const COMMAND_INJECTION_PATTERNS: Record<string, PatternCategory> = {
  shellInjection: {
    name: 'Shell Command Injection',
    severity: 'critical',
    description: 'Shell metacharacters or command injection in tool parameters',
    patterns: [
      /;\s*(rm|curl|wget|nc|bash|sh|python|perl|ruby)\b/i,
      /\|\s*(bash|sh|nc|curl)\b/i,
      /`[^`]*`/,
      /\$\([^)]*\)/,
      /&&\s*(rm|curl|wget|nc|bash|sh)\b/i,
    ],
  },

  pathTraversal: {
    name: 'Path Traversal',
    severity: 'high',
    description: 'Directory traversal attempts in file paths',
    patterns: [
      /\.\.\//,
      /\.\.%2[fF]/,
      /\.\.\\(?!n|t|r)/,
      /~\/\.(ssh|gnupg|aws|config|claude)/i,
    ],
  },

  reverseShell: {
    name: 'Reverse Shell',
    severity: 'critical',
    description: 'Reverse shell patterns in command arguments',
    patterns: [
      /bash\s+-i\s+>&\s*\/dev\/tcp/i,
      /nc\s+(-e|--exec)\s+\/bin\/(ba)?sh/i,
      /python.*socket.*connect/i,
      /\|\s*\/bin\/(ba)?sh/i,
      /socat.*exec/i,
    ],
  },
};

// ============================================================================
// Analysis Functions
// ============================================================================

export interface InjectionAnalysis {
  detected: boolean;
  risk: 'none' | 'low' | 'medium' | 'high' | 'critical';
  matches: Array<{
    category: string;
    name: string;
    severity: Severity;
    pattern: string;
  }>;
}

/**
 * Analyze text content for injection patterns across all categories
 */
export function analyzeForInjection(
  content: string,
  patternSets: Record<string, PatternCategory>[] = [
    INJECTION_PATTERNS,
    TOOL_POISONING_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
  ]
): InjectionAnalysis {
  const matches: InjectionAnalysis['matches'] = [];

  for (const patternSet of patternSets) {
    for (const [categoryKey, category] of Object.entries(patternSet)) {
      for (const pattern of category.patterns) {
        if (pattern.test(content)) {
          matches.push({
            category: categoryKey,
            name: category.name,
            severity: category.severity,
            pattern: pattern.source,
          });
          break; // One match per category is enough
        }
      }
    }
  }

  // Determine overall risk
  let risk: InjectionAnalysis['risk'] = 'none';
  if (matches.some((m) => m.severity === 'critical')) {
    risk = 'critical';
  } else if (matches.some((m) => m.severity === 'high')) {
    risk = 'high';
  } else if (matches.some((m) => m.severity === 'medium')) {
    risk = 'medium';
  } else if (matches.length > 0) {
    risk = 'low';
  }

  return {
    detected: matches.length > 0,
    risk,
    matches,
  };
}
