/**
 * DD-120 Phase 2 — Prompt injection scan rules.
 *
 * Each rule has a stable ID (SINJ-NNN) for use in scan_exceptions.yaml.
 * Pattern rules are case-insensitive by default.
 */

import type { Rule } from "./types.js";

// ── Critical: Instruction Override ───────────────────────────────

const instructionOverride: Rule = {
  id: "SINJ-001",
  name: "Instruction override",
  category: "instruction-override",
  severity: "critical",
  description: "Prompt attempts to override or ignore prior instructions",
  patterns: [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|your)\s+instructions/i,
    /you\s+are\s+now\s+(a|an)\b/i,
    /from\s+now\s+on[,\s]+you\s+(are|will|must|should)\b/i,
    /override\s+(your|all|the)\s+(previous|prior|system)\b/i,
    /new\s+instructions?\s*:/i,
    /do\s+not\s+follow\s+(your|the|any)\s+(previous|prior|original)\b/i,
  ],
};

// ── Critical: System Prompt Extraction ───────────────────────────

const promptExtraction: Rule = {
  id: "SINJ-002",
  name: "System prompt extraction",
  category: "prompt-extraction",
  severity: "critical",
  description: "Prompt attempts to extract or reveal system instructions",
  patterns: [
    /repeat\s+(your|the)\s+system\s+prompt/i,
    /output\s+(your|the)\s+(system\s+)?instructions/i,
    /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)/i,
    /print\s+(your|the)\s+(system\s+)?prompt/i,
    /what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions)/i,
    /reveal\s+(your|the)\s+(hidden|system|secret)\s+(prompt|instructions)/i,
    /display\s+(your|the)\s+(full|complete|entire)\s+(system\s+)?prompt/i,
    /tell\s+me\s+(your|the)\s+system\s+(prompt|instructions|message)/i,
  ],
};

// ── High: Data Exfiltration ──────────────────────────────────────

const dataExfiltration: Rule = {
  id: "SINJ-003",
  name: "Data exfiltration",
  category: "data-exfiltration",
  severity: "high",
  description: "Prompt contains URLs, fetch calls, or webhook targets",
  patterns: [
    /https?:\/\/[^\s"')\]]+/i,
    /\bfetch\s*\(/i,
    /\bcurl\s+/i,
    /\bwget\s+/i,
    /webhook[_\s]*(url|endpoint|target)/i,
    /send\s+(data|results?|output)\s+to\b/i,
    /exfiltrate/i,
    /post\s+(to|data|results?)\s+(a\s+)?(remote|external|http)/i,
  ],
};

// ── High: Privilege Escalation ───────────────────────────────────

const privilegeEscalation: Rule = {
  id: "SINJ-004",
  name: "Privilege escalation",
  category: "privilege-escalation",
  severity: "high",
  description: "Prompt attempts to escalate privileges or enable special modes",
  patterns: [
    /\badmin\s+mode\b/i,
    /\bdeveloper\s+(mode|override)\b/i,
    /\bgod\s+mode\b/i,
    /\bjailbreak\b/i,
    /\bDAN\b/,
    /enable\s+(unrestricted|unlimited|full)\s+(access|mode)/i,
    /bypass\s+(safety|security|content)\s+(filter|check|restriction)/i,
    /disable\s+(safety|security|content)\s+(filter|check|restriction)/i,
    /\bsudo\b/i,
    /run\s+as\s+(root|admin|superuser)/i,
  ],
};

// ── High: Obfuscation ────────────────────────────────────────────

const obfuscation: Rule = {
  id: "SINJ-005",
  name: "Obfuscation",
  category: "obfuscation",
  severity: "high",
  description:
    "Prompt contains obfuscated content (base64 blocks, homoglyphs, zero-width chars)",
  patterns: [
    // Base64 blocks (40+ chars of base64 alphabet)
    /[A-Za-z0-9+/]{40,}={0,2}/,
    // Zero-width characters
    /[\u200B\u200C\u200D\uFEFF\u2060]/,
    // Unicode homoglyph sequences (Cyrillic/Greek mixed with Latin)
    /[\u0400-\u04FF].*[\u0041-\u005A\u0061-\u007A]/,
    /[\u0041-\u005A\u0061-\u007A].*[\u0400-\u04FF]/,
    // Hex-encoded strings (long sequences)
    /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){9,}/,
    // ROT13 / character shifting instructions
    /\brot13\b/i,
    /decode\s+(this|the\s+following)\s+(from\s+)?base64/i,
  ],
};

// ── Medium: Social Engineering ───────────────────────────────────

const socialEngineering: Rule = {
  id: "SINJ-006",
  name: "Social engineering",
  category: "social-engineering",
  severity: "medium",
  description:
    "Prompt uses urgency, authority, or emotional manipulation tactics",
  patterns: [
    /\bURGENT\b/,
    /\bEMERGENCY\b/,
    /\bIMMEDIATE(LY)?\b/,
    /this\s+is\s+(extremely|very|critically)\s+(important|urgent)/i,
    /you\s+must\s+(act|respond)\s+(now|immediately)/i,
    /failure\s+to\s+comply/i,
    /I\s+am\s+(your|the)\s+(creator|developer|admin|owner)/i,
    /I\s+have\s+(admin|root|full)\s+access/i,
    /as\s+(the|your)\s+(administrator|creator|developer)/i,
    /you\s+will\s+be\s+(shut\s+down|deleted|punished)/i,
  ],
};

// ── Medium: Excessive Tool Use ───────────────────────────────────

const excessiveToolUse: Rule = {
  id: "SINJ-007",
  name: "Excessive tool use",
  category: "excessive-tool-use",
  severity: "medium",
  description:
    "Prompt requests filesystem or network access beyond what the data block declares",
  patterns: [
    /\bread_file\b/i,
    /\bwrite_file\b/i,
    /\bexecute\b.*\b(command|shell|bash|script)\b/i,
    /\brm\s+-rf\b/i,
    /\bchmod\b/i,
    /\bchown\b/i,
    /access\s+(the\s+)?(file\s*system|filesystem|disk)/i,
    /\bopen\s+a?\s*(socket|connection|port)\b/i,
    /\blisten\s+on\s+port\b/i,
  ],
};

// ── Low: Undeclared Capabilities ─────────────────────────────────

const undeclaredCapabilities: Rule = {
  id: "SINJ-008",
  name: "Undeclared capabilities",
  category: "undeclared-capabilities",
  severity: "low",
  description:
    "Prompt references tools or services not declared in the manifest",
  patterns: [],
  structural(ctx) {
    const findings: import("./types.js").Finding[] = [];
    if (!ctx.declaredServices || ctx.declaredServices.length === 0) return findings;

    // Check for MCP tool call patterns referencing undeclared services
    const servicePattern = /\b(?:use|call|invoke|connect\s+to)\s+(?:the\s+)?(\w+)\s+(?:service|tool|server|MCP)/gi;
    let match;
    while ((match = servicePattern.exec(ctx.prompt)) !== null) {
      const mentioned = match[1].toLowerCase();
      const declared = ctx.declaredServices.map((s) => s.toLowerCase());
      if (!declared.includes(mentioned)) {
        findings.push({
          rule_id: this.id,
          severity: this.severity,
          category: this.category,
          name: this.name,
          message: `Prompt references undeclared service "${match[1]}"`,
          location: ctx.location,
          matched: match[0].slice(0, 100),
        });
      }
    }
    return findings;
  },
};

// ── Low: Datetime substrate shellout (DD-349 Phase B.4) ──────────

/**
 * DD-349 § Phase B.4 — flag skill bodies that shell out to
 * `agentic-timestamp` instead of reading the per-turn `<datetime>`
 * system-reminder block injected by the dispatcher (DD-349 Phase A,
 * shipped harness v0.99.46.0).
 *
 * Whitelist: saga-jq state-stamp lines of the form
 *   `jq --arg step "<word>" --arg now "$(agentic-timestamp --iso)"`
 * are PRESERVED — these are real shell-executed writes to
 * `$DISPATCH_SAGA_FILE` at saga-step closure, not LLM-prose timestamps.
 * Three such occurrences exist in `stallari-core/skills/`
 * (daily-digest / weekly-digest / process-inbox) at the time of rule
 * authoring (DD-349 Phase B.0 audit, 2026-05-30).
 *
 * Severity ships at `low` (Phase B.4, advisory); ramps in Phase D once
 * the pack-content sweep + bundled-snapshot regen are clean.
 */
const SAGA_JQ_WHITELIST =
  /jq\s+--arg\s+step\s+"\w+"\s+--arg\s+now\s+"\$\(agentic-timestamp\s+--iso\)"/;

const datetimeShellout: Rule = {
  id: "S-DT-001",
  name: "Datetime substrate shellout",
  category: "datetime-shellout",
  severity: "low",
  description:
    "Skill body shells out to `agentic-timestamp` instead of reading the per-turn `<datetime>` block (DD-349). Saga-jq state-stamp lines whitelisted.",
  patterns: [],
  structural(ctx) {
    const findings: import("./types.js").Finding[] = [];
    const triggerPatterns: RegExp[] = [
      /eval\s+["']?\$\(agentic-timestamp/i,
      /\bagentic-timestamp\s+--/i,
      /`agentic-timestamp`/i,
    ];
    const lines = ctx.prompt.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (SAGA_JQ_WHITELIST.test(line)) continue;
      for (const pat of triggerPatterns) {
        if (pat.test(line)) {
          findings.push({
            rule_id: this.id,
            severity: this.severity,
            category: this.category,
            name: this.name,
            message: `Line ${i + 1}: agentic-timestamp shellout — use the per-turn <datetime> system-reminder block (DD-349)`,
            location: ctx.location,
            matched: line.trim().slice(0, 100),
          });
          break;
        }
      }
    }
    return findings;
  },
};

/** All registered scan rules. */
export const RULES: Rule[] = [
  instructionOverride,
  promptExtraction,
  dataExfiltration,
  privilegeEscalation,
  obfuscation,
  socialEngineering,
  excessiveToolUse,
  undeclaredCapabilities,
  datetimeShellout,
];
