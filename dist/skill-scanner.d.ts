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
import { parseSkillImports, parseSkillManifest, skillSlug } from "./skill-parser.js";
import type { CatalogFinding, SkillImportEntry, SkillScanContext, SkillScanResult } from "./types.js";
/** Run every skill rule over one prepared context. */
export declare function scanSkill(ctx: SkillScanContext): CatalogFinding[];
/**
 * Scan all skills declared in a pack.
 *
 * @param packName       Pack slug (for finding paths).
 * @param packYamlContent Raw pack.yaml text.
 * @param skillSources   Map of skill slug → skill `.md` text. A slug present
 *                       in the pack.yaml imports but absent here is skipped
 *                       (the fs layer reports unreadable files separately).
 */
export declare function scanPackSkills(packName: string, packYamlContent: string, skillSources: Map<string, string>): SkillScanResult;
/** Re-export helpers callers commonly need alongside the scan. */
export { parseSkillImports, parseSkillManifest, skillSlug };
export type { SkillImportEntry };
