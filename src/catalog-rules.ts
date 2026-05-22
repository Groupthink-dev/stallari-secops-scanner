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
    "stallari-pack-spec/docs/granularity.md. " +
    "DD-333 F.1 (pack-spec 4.2.0) accept-with-rationale silence path: a " +
    "tool listed in non_conformance_rationale.affected_tools silences this " +
    "rule for that tool (S-MCP-002 covers rationale-block defects).",
  appliesTo: "plugin",
  check(entry: CatalogEntry): CatalogFinding[] {
    if (entry.type !== "plugin") return [];
    if (!entry.tools || entry.tools.length === 0) return [];

    // DD-333 F.1 — accept-with-rationale silence set.
    const affected = new Set(
      entry.non_conformance_rationale?.affected_tools ?? [],
    );

    const findings: CatalogFinding[] = [];
    for (const tool of entry.tools) {
      if (tool.granularity) continue;
      if (affected.has(tool.name)) continue;
      findings.push({
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `Tool '${tool.name}' (in plugin '${entry.name}') missing ` +
          `'granularity' block. Either declare granularity per ` +
          `stallari-pack-spec/docs/granularity.md, OR list the tool in a ` +
          `non_conformance_rationale.affected_tools block per ` +
          `stallari-pack-spec/docs/non-conformance-rationale.md (DD-333 F.1).`,
        path: `${entry.name}.tools[${tool.name}].granularity`,
      });
    }
    return findings;
  },
};

// ── DD-333 F.1: S-MCP-002 — non_conformance_rationale malformed ──

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
export const S_MCP_002: CatalogRule = {
  id: "S-MCP-002",
  name: "Non-conformance rationale block malformed",
  category: "mcp-granularity",
  severity: "error",
  description:
    "DD-333 F.1 — non_conformance_rationale block present but malformed. " +
    "AJV in stallari-plugins build-catalog.js catches in-block violations " +
    "at build time (const:true, minItems:1, enum membership); this rule " +
    "covers cross-field invariants AJV cannot express plus post-build " +
    "catalog audit defence-in-depth. See " +
    "stallari-pack-spec/docs/non-conformance-rationale.md.",
  appliesTo: "plugin",
  check(entry: CatalogEntry): CatalogFinding[] {
    if (entry.type !== "plugin") return [];
    const rationale = entry.non_conformance_rationale;
    if (!rationale) return [];

    const findings: CatalogFinding[] = [];
    const docPointer =
      "stallari-pack-spec/docs/non-conformance-rationale.md";

    // scope_filtering_off must be true.
    if (rationale.scope_filtering_off !== true) {
      findings.push({
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `non_conformance_rationale.scope_filtering_off MUST be true ` +
          `when the block is present; got ${JSON.stringify(
            rationale.scope_filtering_off,
          )}. See ${docPointer}.`,
        path: `${entry.name}.non_conformance_rationale.scope_filtering_off`,
      });
    }

    // contamination_risks must be a non-empty array.
    if (
      !Array.isArray(rationale.contamination_risks) ||
      rationale.contamination_risks.length === 0
    ) {
      findings.push({
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `non_conformance_rationale.contamination_risks MUST be a ` +
          `non-empty array. See ${docPointer} for the controlled vocabulary.`,
        path: `${entry.name}.non_conformance_rationale.contamination_risks`,
      });
    }

    // reason must be a non-empty string.
    if (
      typeof rationale.reason !== "string" ||
      rationale.reason.trim().length === 0
    ) {
      findings.push({
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `non_conformance_rationale.reason MUST be a non-empty string. ` +
          `See ${docPointer}.`,
        path: `${entry.name}.non_conformance_rationale.reason`,
      });
    }

    // affected_tools must be an array.
    if (!Array.isArray(rationale.affected_tools)) {
      findings.push({
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `non_conformance_rationale.affected_tools MUST be an array. ` +
          `See ${docPointer}.`,
        path: `${entry.name}.non_conformance_rationale.affected_tools`,
      });
    } else {
      // Cross-field invariant: every affected_tools[i] MUST reference a
      // real tools[].name. Emit one finding per mismatched name.
      const toolNames = new Set(
        (entry.tools ?? []).map((t) => t.name),
      );
      for (const ref of rationale.affected_tools) {
        if (typeof ref !== "string") continue;
        if (toolNames.has(ref)) continue;
        findings.push({
          rule_id: this.id,
          severity: this.severity,
          category: this.category,
          name: this.name,
          message:
            `non_conformance_rationale.affected_tools references tool ` +
            `name '${ref}' not present in this entry's tools[]. Every ` +
            `entry in affected_tools MUST cross-reference an actual ` +
            `tools[].name. See ${docPointer}.`,
          path: `${entry.name}.non_conformance_rationale.affected_tools[${ref}]`,
        });
      }
    }

    return findings;
  },
};

/** All registered catalog rules. */
export const CATALOG_RULES: CatalogRule[] = [S_MCP_001, S_MCP_002];
