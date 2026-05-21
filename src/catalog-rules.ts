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

import type {
  CatalogEntry,
  CatalogFinding,
  CatalogRule,
} from "./types.js";

// ── DD-333: S-MCP-001 — MCP catalog tool missing granularity declaration ──

/**
 * S-MCP-001 — fires a `.error` for each tool inside a plugin catalog
 * entry's `tools[]` array that omits the `granularity:` block.
 *
 * Silent when:
 * - Entry is not type=plugin (no MCP tools to validate)
 * - Plugin omits `tools[]` entirely (omission means tools are discovered at
 *   runtime via MCP list_tools — nothing for the lint to check)
 * - Tool has a `granularity:` block (well-shaped or not — AJV in
 *   stallari-plugins build-catalog.js catches malformed shapes; this rule
 *   only cares about presence/absence)
 *
 * Promoted from `.warning` to `.error` at DD-333 Phase D (cutover 2026-05-21).
 * Pairs with the schema-required gate in stallari-plugins
 * `catalog-entry.schema.json` at pack-spec 4.0.0 — AJV blocks malformed/missing
 * declarations at build time; this lint covers post-build catalog auditing.
 */
export const S_MCP_001: CatalogRule = {
  id: "S-MCP-001",
  name: "MCP catalog tool missing granularity declaration",
  category: "mcp-granularity",
  severity: "error",
  description:
    "MCP plugin catalog tool entry missing `granularity:` block (DD-333). " +
    "Required at pack-spec 4.0.0 (Phase D cutover 2026-05-21). Declare " +
    "scope_filtering, field_projection, deterministic_ordering, and " +
    "audit_surface explicitly per DD-333 — see " +
    "stallari-pack-spec/docs/granularity.md.",
  appliesTo: "plugin",
  check(entry: CatalogEntry): CatalogFinding[] {
    if (entry.type !== "plugin") return [];
    if (!entry.tools || entry.tools.length === 0) return [];

    const findings: CatalogFinding[] = [];
    for (const tool of entry.tools) {
      if (!tool.granularity) {
        findings.push({
          rule_id: this.id,
          severity: this.severity,
          category: this.category,
          name: this.name,
          message:
            `Tool '${tool.name}' (in plugin '${entry.name}') missing ` +
            `'granularity' block. Required at pack-spec 4.0.0 — declare ` +
            `scope_filtering, field_projection, deterministic_ordering, ` +
            `and audit_surface per DD-333 (see ` +
            `stallari-pack-spec/docs/granularity.md).`,
          path: `${entry.name}.tools[${tool.name}].granularity`,
        });
      }
    }
    return findings;
  },
};

/** All registered catalog rules. */
export const CATALOG_RULES: CatalogRule[] = [S_MCP_001];
