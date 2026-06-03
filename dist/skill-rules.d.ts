/**
 * DD-370 — Skill-contract lint rules (S-SKL-001).
 *
 * Sister to the `CatalogRule` family in `pack-domain-rules.ts` (S-DOM-001) and
 * `catalog-rules.ts` (S-MCP-001/002), and to `S-AUD-001` (DD-338). Those run
 * over BUILT catalog entries; these run over raw skill source (the dual
 * pack.yaml-import + skill-`.md`-frontmatter surface) via a
 * {@link SkillScanContext}. The home for the DD-344 v4.5 manifest contract
 * enforcement that DD-370 ships.
 *
 * Severity: `"warning"` (non-blocking) at v1 per DD-370 OQ-1 (warning through
 * EA, harden post-EA). Promotion to `"error"` is DD-370 Phase D, deferred
 * until after the EA marketplace cutover AND all first-party packs green.
 * The standing financial-write exposure is closed by the *uplift* (Phase B),
 * not by the lint blocking.
 *
 * Convention #23 reader-audit note: this rule reads the v4.5 contract
 * (`risk_class`, `track_emits`, `sealed_credentials`, `domain_access`)
 * introduced by DD-344. Its presence ensures uncontracted skills are
 * CI-visible rather than hand-audited.
 */
import type { SkillRule } from "./types.js";
/** True when `service.op` denotes a state-mutating operation. */
export declare function isWriteClassOp(serviceOp: string): boolean;
/**
 * S-SKL-001 — fires `"warning"` findings when a skill manifest lacks DD-344
 * v4.5 contract fields its service surface requires. Four independent checks:
 *
 *  1. **risk_class coverage** (the core check) — every declared write-class op
 *     must have a `risk_class` entry. One finding per uncovered write op.
 *  2. **domain_access presence** — a skill that reads user content must declare
 *     `domain_access`. One finding.
 *  3. **sealed_credentials** — a skill whose BODY references `op://` must
 *     declare `sealed_credentials`. One finding. (Most non-core skills get
 *     credentials from the user-configured MCP, not via `op://`, so this is
 *     silent for them — no false-positive.)
 *  4. **track_emits** — a skill whose body emits handoff-shaped work
 *     (`+/handoff/` or a `{{track.` substitution) must declare `track_emits`.
 *     One finding.
 *
 * Silent for a skill with no write-class op, no user-content read, no `op://`
 * body reference, and no handoff emission (e.g. a pure compute/format skill).
 */
export declare const S_SKL_001: SkillRule;
/** All skill-contract rules (DD-370). */
export declare const SKILL_RULES: SkillRule[];
