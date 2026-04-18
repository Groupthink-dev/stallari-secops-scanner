/**
 * DD-120 Phase 2 — Core scanner engine.
 *
 * Runs all registered rules against each prompt in a sealed payload.
 * Returns structured findings with severity-based pass/fail/warn result.
 */

import { RULES } from "./rules.js";
import { parsePackYAML, extractPrompts } from "./pack-parser.js";
import { detectClones, matchThreats } from "./clone.js";
import type {
  CloneFinding,
  CorpusEntry,
  Finding,
  ManifestContext,
  PackScanResult,
  ScanException,
  ScanResult,
  SealedPayload,
  Severity,
  StructuralContext,
} from "./types.js";

export const SCANNER_VERSION = "0.2.0";

export interface ScanOptions {
  /** Manifest context for structural checks. */
  manifest?: ManifestContext;
  /** Approved exceptions (from scan_exceptions.yaml). */
  exceptions?: ScanException[];
}

/**
 * Scan a single prompt string against all rules.
 */
export function scanPrompt(
  prompt: string,
  location: string,
  options?: ScanOptions,
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of RULES) {
    // Pattern-based checks
    for (const pattern of rule.patterns) {
      const match = pattern.exec(prompt);
      if (match) {
        findings.push({
          rule_id: rule.id,
          severity: rule.severity,
          category: rule.category,
          name: rule.name,
          message: rule.description,
          location,
          matched: match[0].slice(0, 120),
        });
        break; // One finding per rule per prompt
      }
    }

    // Structural checks
    if (rule.structural) {
      const ctx: StructuralContext = {
        prompt,
        location,
        declaredReads: options?.manifest?.data?.reads,
        declaredWrites: options?.manifest?.data?.writes,
        declaredServices: options?.manifest?.requires?.services?.map(
          (s) => s.service,
        ),
      };
      findings.push(...rule.structural(ctx));
    }
  }

  return findings;
}

/**
 * Scan an entire sealed payload.
 *
 * Iterates over all skills and agents, runs every rule, applies exceptions,
 * and returns a structured result.
 */
export function scanPayload(
  payload: SealedPayload,
  options?: ScanOptions,
): ScanResult {
  const allFindings: Finding[] = [];

  // Scan skill prompts
  for (const [name, prompt] of Object.entries(payload.skills)) {
    allFindings.push(...scanPrompt(prompt, `skills.${name}`, options));
  }

  // Scan agent prompts
  for (const [name, prompt] of Object.entries(payload.agents)) {
    allFindings.push(...scanPrompt(prompt, `agents.${name}`, options));
  }

  // Apply exceptions
  const exceptionIds = new Set(
    (options?.exceptions ?? []).map((e) => e.rule_id),
  );
  const exceptionsApplied: string[] = [];
  const findings = allFindings.filter((f) => {
    if (exceptionIds.has(f.rule_id)) {
      exceptionsApplied.push(f.rule_id);
      return false;
    }
    return true;
  });

  // Summarise
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    summary[f.severity]++;
  }

  // Determine result
  let result: ScanResult["result"] = "pass";
  if (summary.critical > 0 || summary.high > 0) {
    result = "fail";
  } else if (summary.medium > 0 || summary.low > 0) {
    result = "warn";
  }

  return {
    version: "1.0",
    scanner: `stallari-secops-scanner/${SCANNER_VERSION}`,
    pack: payload.pack,
    scan_date: new Date().toISOString(),
    result,
    findings,
    exceptions_applied: [...new Set(exceptionsApplied)],
    summary,
  };
}

// ── DD-147: Open pack scanning ──────────────────────────────────

export interface PackScanOptions extends ScanOptions {
  /** Pre-built corpus of existing pack prompts for clone detection. */
  corpus?: CorpusEntry[];
  /** Pre-built corpus of known malicious prompts for threat matching. */
  threats?: CorpusEntry[];
}

/**
 * Scan an open pack YAML file.
 *
 * Parses the YAML, extracts all prompts, runs SINJ rules against each,
 * and optionally runs clone detection and threat matching.
 *
 * Runtime-agnostic — caller provides corpus/threat data.
 */
export function scanPackYAML(
  yamlContent: string,
  options?: PackScanOptions,
): PackScanResult {
  const pack = parsePackYAML(yamlContent);
  const prompts = extractPrompts(pack);
  const allFindings: Finding[] = [];

  // Run SINJ rules on each prompt (reuses existing scanPrompt)
  for (const p of prompts) {
    allFindings.push(...scanPrompt(p.text, p.location, options));
  }

  // Apply exceptions to SINJ findings
  const exceptionIds = new Set(
    (options?.exceptions ?? []).map((e) => e.rule_id),
  );
  const exceptionsApplied: string[] = [];
  const findings = allFindings.filter((f) => {
    if (exceptionIds.has(f.rule_id)) {
      exceptionsApplied.push(f.rule_id);
      return false;
    }
    return true;
  });

  // Clone detection
  const cloneFindings: CloneFinding[] = [];
  if (options?.corpus && options.corpus.length > 0) {
    cloneFindings.push(...detectClones(prompts, options.corpus, pack));
  }

  // Threat matching
  if (options?.threats && options.threats.length > 0) {
    cloneFindings.push(...matchThreats(prompts, options.threats));
  }

  // Filter suppressed clone findings for result calculation
  const activeCloneFindings = cloneFindings.filter((f) => !f.suppressed);

  // Summarise
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    summary[f.severity]++;
  }
  for (const f of activeCloneFindings) {
    summary[f.severity]++;
  }

  // Determine result
  let result: PackScanResult["result"] = "pass";
  if (summary.critical > 0 || summary.high > 0) {
    result = "fail";
  } else if (summary.medium > 0 || summary.low > 0) {
    result = "warn";
  }

  return {
    version: "1.0",
    scanner: `stallari-secops-scanner/${SCANNER_VERSION}`,
    pack: pack.name,
    scan_date: new Date().toISOString(),
    result,
    findings,
    clone_findings: cloneFindings,
    exceptions_applied: [...new Set(exceptionsApplied)],
    summary,
  };
}
