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
export const S_MCP_001: CatalogRule = {
  id: "S-MCP-001",
  name: "MCP catalog tool missing granularity declaration",
  category: "mcp-granularity",
  severity: "warning",
  description:
    "MCP plugin catalog tool entry missing `granularity:` block (DD-333). " +
    "Assembler will infer worst-case granularity (client-side/none/unstable/" +
    "minimal) and refuse evidentiary-level packets sourcing through this " +
    "tool. Declare scope_filtering, field_projection, deterministic_ordering, " +
    "and audit_surface explicitly per DD-333 — see " +
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
            `'granularity' block. Assembler will infer worst-case ` +
            `(client-side/none/unstable/minimal) and refuse evidentiary-` +
            `level packets. Declare explicitly per DD-333 — see ` +
            `stallari-pack-spec/docs/granularity.md.`,
          path: `${entry.name}.tools[${tool.name}].granularity`,
        });
      }
    }
    return findings;
  },
};

/** All registered catalog rules. */
export const CATALOG_RULES: CatalogRule[] = [S_MCP_001];
