/**
 * DD-370 — Skill manifest frontmatter parser.
 *
 * The existing `pack-parser.ts` reads pack.yaml only (for prompt-injection
 * scanning of the `skills[]` import array). It does NOT read per-skill `.md`
 * frontmatter — where the DD-344 v4.5 manifest contract (`risk_class`,
 * `track_emits`, `sealed_credentials`, `domain_access`) lives. This module
 * adds that reader so S-SKL-001 can lint the contract.
 *
 * Pure functions (string in, struct out) — runtime-agnostic, no Node.js
 * built-ins, CF-Worker-safe, mirroring `pack-parser.ts`. The fs-using
 * directory helper lives in the CLI (`cli.ts`), not here.
 */
import type { PackYAML, SkillImportEntry, SkillManifest } from "./types.js";
/** Split a markdown doc into `{ frontmatter, body }` on the leading `---` fence. */
export declare function splitFrontmatter(md: string): {
    frontmatter: string;
    body: string;
};
/**
 * Parse a skill `.md` into its v4.5 manifest subset + body. Never throws on
 * a malformed/absent frontmatter — returns an empty manifest (the lint then
 * sees "no contract", which is the correct signal for an uncontracted skill).
 */
export declare function parseSkillManifest(md: string): {
    manifest: SkillManifest;
    body: string;
};
/**
 * Parse the pack.yaml `skills[]` import array into a map keyed by the import
 * path's basename (the skill slug). Tolerant of the prompt-injection
 * `PackYAML` shape used elsewhere — we read the richer raw object here.
 */
export declare function parseSkillImports(packYamlContent: string): Map<string, SkillImportEntry>;
/** Derive the skill slug from an import entry (`./skills/refund-processor.md` → `refund-processor`). */
export declare function skillSlug(entry: SkillImportEntry): string | null;
/**
 * Flatten the union of declared service ops to `service.op` form, drawing
 * from BOTH contract surfaces: the skill frontmatter `required_services` /
 * `optional_services` (post-uplift) AND the pack.yaml import `services_used`
 * (pre-uplift). De-duplicated.
 */
export declare function flattenServiceOps(manifest: SkillManifest, importEntry?: SkillImportEntry): string[];
export type { PackYAML };
