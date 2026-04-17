/**
 * DD-120 Phase 2 — Core scanner engine.
 *
 * Runs all registered rules against each prompt in a sealed payload.
 * Returns structured findings with severity-based pass/fail/warn result.
 */

import { RULES } from "./rules.js";
import type {
  Finding,
  ManifestContext,
  ScanException,
  ScanResult,
  SealedPayload,
  Severity,
  StructuralContext,
} from "./types.js";

export const SCANNER_VERSION = "0.1.0";

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
