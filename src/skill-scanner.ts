/**
 * DD-370 — Skill-contract scanner.
 *
 * Runs {@link SKILL_RULES} (S-SKL-001) over a pack's skills by pairing each
 * pack.yaml `skills[].import` entry with its skill `.md` source, then building
 * a {@link SkillScanContext} carrying both contract surfaces + the body.
 *
 * Pure (string in, struct out) — the fs glue that reads pack.yaml + the skill
 * `.md` files off disk lives in `cli.ts`.
 */

import { SKILL_RULES } from "./skill-rules.js";
import {
  parseSkillImports,
  parseSkillManifest,
  skillSlug,
} from "./skill-parser.js";
import type {
  CatalogFinding,
  LintSeverity,
  SkillImportEntry,
  SkillScanContext,
  SkillScanResult,
} from "./types.js";
import { SCANNER_VERSION } from "./scanner.js";

/** Run every skill rule over one prepared context. */
export function scanSkill(ctx: SkillScanContext): CatalogFinding[] {
  const findings: CatalogFinding[] = [];
  for (const rule of SKILL_RULES) findings.push(...rule.check(ctx));
  return findings;
}

/**
 * Scan all skills declared in a pack.
 *
 * @param packName       Pack slug (for finding paths).
 * @param packYamlContent Raw pack.yaml text.
 * @param skillSources   Map of skill slug → skill `.md` text. A slug present
 *                       in the pack.yaml imports but absent here is skipped
 *                       (the fs layer reports unreadable files separately).
 */
export function scanPackSkills(
  packName: string,
  packYamlContent: string,
  skillSources: Map<string, string>,
): SkillScanResult {
  const imports = parseSkillImports(packYamlContent);
  const findings: CatalogFinding[] = [];
  let scanned = 0;

  for (const [slug, importEntry] of imports) {
    const md = skillSources.get(slug);
    if (md === undefined) continue;
    const { manifest, body } = parseSkillManifest(md);
    const ctx: SkillScanContext = {
      skillName: slug,
      packName,
      manifest,
      importEntry,
      body,
    };
    findings.push(...scanSkill(ctx));
    scanned++;
  }

  // Also scan any skill source provided without a matching import entry
  // (defensive — an orphan skill file is itself a smell, but lint it anyway).
  for (const [slug, md] of skillSources) {
    if (imports.has(slug)) continue;
    const { manifest, body } = parseSkillManifest(md);
    findings.push(
      ...scanSkill({ skillName: slug, packName, manifest, body }),
    );
    scanned++;
  }

  const summary: Record<LintSeverity, number> = { warning: 0, error: 0 };
  for (const f of findings) summary[f.severity]++;

  // S-SKL-001 ships warning-only (DD-370 OQ-1): warnings never `fail` at v1.
  // The `error` branch is here for the Phase D promotion (post-EA) without a
  // scanner code change beyond the rule's own severity flip.
  let result: SkillScanResult["result"] = "pass";
  if (summary.error > 0) result = "fail";
  else if (summary.warning > 0) result = "warn";

  return {
    version: "1.0",
    scanner: `stallari-secops-scanner/${SCANNER_VERSION}`,
    scan_date: new Date().toISOString(),
    result,
    skills_scanned: scanned,
    findings,
    summary,
  };
}

/** Re-export helpers callers commonly need alongside the scan. */
export { parseSkillImports, parseSkillManifest, skillSlug };
export type { SkillImportEntry };
