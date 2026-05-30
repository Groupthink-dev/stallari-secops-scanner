/**
 * DD-333 Phase A.4 — Catalog-scope lint rules.
 *
 * Distinct from prompt-injection rules in `rules.ts` (which match regex against
 * skill/agent prompt text). Catalog rules run structurally over catalog entries
 * loaded from `stallari-plugins/plugins/tools/*.json`.
 *
 * Severity uses {@link LintSeverity} (`warning`/`error`) — not the SINJ
 * `critical`/`high`/`medium`/`low` ladder — because these are lint signals
 * about authoring discipline, not threat scores.
 */
import type { CatalogRule } from "./types.js";
/**
 * S-MCP-001 — fires a `.error` for each tool inside a plugin catalog
 * entry's `tools[]` array that omits the `granularity:` block AND is not
 * listed in `non_conformance_rationale.affected_tools` (DD-333 F.1
 * accept-with-rationale silence path).
 *
 * Silent when:
 * - Entry is not type=plugin (no MCP tools to validate)
 * - Plugin omits `tools[]` entirely (omission means tools are discovered at
 *   runtime via MCP list_tools — nothing for the lint to check)
 * - Tool has a `granularity:` block (well-shaped or not — AJV in
 *   stallari-plugins build-catalog.js catches malformed shapes; this rule
 *   only cares about presence/absence)
 * - Tool name appears in `entry.non_conformance_rationale.affected_tools`
 *   (DD-333 F.1 — author has explicitly declared honest non-conformance;
 *   S-MCP-001 silences, S-MCP-002 covers rationale-block defects.)
 *
 * Promoted from `.warning` to `.error` at DD-333 Phase D (cutover 2026-05-21).
 * Extended at DD-333 F.1 (2026-05-22) to consume the non_conformance_rationale
 * accept-with-rationale path. Pairs with the schema-required gate in
 * stallari-plugins `catalog-entry.schema.json` at pack-spec 4.0.0+ — AJV
 * + build-catalog.js procedural gate block malformed/missing declarations
 * at build time; this lint covers post-build catalog auditing.
 */
export declare const S_MCP_001: CatalogRule;
/**
 * S-MCP-002 — fires `.error` findings when the `non_conformance_rationale`
 * block on a plugin catalog entry violates one of the cross-field or
 * in-block invariants.
 *
 * AJV upstream in stallari-plugins `catalog-entry.schema.json` catches
 * in-block shape violations (const:true on scope_filtering_off, minItems:1
 * on contamination_risks + affected_tools, enum membership on
 * contamination_risks values). This rule covers two cases AJV misses:
 *
 *   1. Cross-field invariant: `affected_tools[i]` MUST cross-reference an
 *      actual `tools[].name`. JSON Schema 2020-12 cannot express this; the
 *      procedural gate in stallari-plugins/scripts/build-catalog.js throws
 *      at build time, and this rule provides defence-in-depth against
 *      post-build catalog audit (e.g. hand-edited dist/catalog.json or
 *      stale build state).
 *
 *   2. Belt-and-braces in-block checks (scope_filtering_off / reason /
 *      contamination_risks / affected_tools type). Redundant with AJV at
 *      build time, but the secops scanner runs against post-build catalog
 *      state — if a downstream surface or hand edit corrupts the block, the
 *      scanner catches it.
 *
 * Silent when:
 * - Entry is not type=plugin
 * - `non_conformance_rationale` is absent (the conforming path)
 */
export declare const S_MCP_002: CatalogRule;
/** All registered catalog rules. */
export declare const CATALOG_RULES: CatalogRule[];
