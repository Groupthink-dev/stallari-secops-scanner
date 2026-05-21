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
 * S-MCP-001 — fires a `.warning` for each tool inside a plugin catalog
 * entry's `tools[]` array that omits the `granularity:` block.
 *
 * Silent at v1 when:
 * - Entry is not type=plugin (no MCP tools to validate)
 * - Plugin omits `tools[]` entirely (Phase A.3 first-party sweep is what
 *   introduces declared tools; omission means tools are discovered at
 *   runtime via MCP list_tools — nothing for the lint to check)
 * - Tool has a `granularity:` block (well-shaped or not — AJV in
 *   stallari-plugins build-catalog.js catches malformed shapes; this rule
 *   only cares about presence/absence)
 *
 * Promoted to `.error` at DD-333 Phase D once the community grace window
 * closes.
 */
export declare const S_MCP_001: CatalogRule;
/** All registered catalog rules. */
export declare const CATALOG_RULES: CatalogRule[];
