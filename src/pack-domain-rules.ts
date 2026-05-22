/**
 * DD-341 Phase C — Pack manifest domain-access rules.
 *
 * Catalog-scope lint rule that flags pack manifests lacking the `domain_access:`
 * block introduced in stallari-pack-spec v4.3.0 (DD-341 Phase C).
 *
 * Distinct from the S-MCP-00x plugin-granularity rules in `catalog-rules.ts`
 * (which target MCP plugin catalog entries). This file targets `type: "pack"`
 * entries — packs declare domain intent via `domain_access:`, not tool
 * granularity.
 *
 * Severity uses {@link LintSeverity} — `"warning"` is the lightest available
 * lint severity (analogous to `.info` in the Swift scanner; the TypeScript
 * catalog-rule type only has `"warning"` | `"error"`). Per architect lock #5,
 * this rule ships at `"warning"` and must NOT block seal-issuance. 16
 * currently-sealed packs lack the block; an `"error"` rule would reject all of
 * them. Promotion is a future DEVFU.
 *
 * Sister rule family context:
 * - S-MCP-001 / S-MCP-002 (catalog-rules.ts) — plugin granularity declarations
 * - S-DOM-001 (this file) — pack domain-access block presence
 *
 * Convention #23 reader-audit note: this rule is itself a reader of the pack
 * manifest contract. It consumes the `domain_access` key introduced in
 * pack-spec v4.3.0. Its presence in the scanner's CATALOG_RULES set ensures
 * that post-seal audits surface packs that pre-date or omit the v4.3.0 block.
 */

import type { CatalogEntry, CatalogFinding, CatalogRule } from "./types.js";

// ── DD-341 Phase C: S-DOM-001 — Missing domain_access block ──────

/**
 * S-DOM-001 — fires a `"warning"` finding when a pack catalog entry's
 * corresponding manifest lacks the `domain_access:` block introduced in
 * stallari-pack-spec v4.3.0 (DD-341 Phase C).
 *
 * Silent when:
 * - Entry is not type="pack" (plugins declare tool granularity, not domain
 *   access; S-MCP-001 covers those).
 * - Entry already declares `domain_access` at the catalog-entry level (the
 *   stallari-plugins build pipeline lifts the `domain_access:` block from
 *   pack.yaml/stallari-plugin.yaml onto the catalog entry at build time).
 *
 * Fires `"warning"` (non-blocking) per architect lock #5 — sister to the
 * DD-333 grandfather pattern that grandfathered 16 pre-Phase-E sealed packs.
 * Promote to `"error"` only after the Pn-author migration cycle closes.
 *
 * Note on the `requested_domains` case: the spec calls for the scanner to
 * emit NO finding when a pack declares `requested_domains:` (the submission-
 * time TypeScript validator in stallari-pack-spec catches this earlier, and
 * the stallari-plugins build-pipeline + pack-spec 4.3.0 schema reject the
 * manifest before it can be sealed). Scanner is downstream; a sealed pack
 * with `requested_domains:` would be a pipeline breach, not a normal path.
 * The rule is silent on `requested_domains:` presence — that's a separate
 * threat-model concern covered upstream.
 */
export const S_DOM_001: CatalogRule = {
  id: "S-DOM-001",
  name: "Pack manifest missing domain_access block",
  category: "pack-domain-access",
  severity: "warning",
  description:
    "Pack manifest lacks 'domain_access:' block (stallari-pack-spec v4.3.0, DD-341 Phase C). " +
    "Packs without the block install without surfacing a domain consent screen; " +
    "the pack receives zero domain grants at dispatch and reads zero vault notes " +
    "via the partition substrate. Add 'domain_access:' to surface the consent " +
    "screen at install time. See stallari-pack-spec/docs/domain-access.md. " +
    "Severity: warning (non-blocking) per architect lock #5 — 16 currently-sealed " +
    "packs predate v4.3.0. Promote to error after the Pn-author migration cycle.",
  appliesTo: "pack",
  check(entry: CatalogEntry): CatalogFinding[] {
    if (entry.type !== "pack") return [];

    // If the build pipeline lifted domain_access onto the catalog entry, the
    // pack is conformant — no finding.
    if (entry.domain_access !== undefined && entry.domain_access !== null) {
      return [];
    }

    return [
      {
        rule_id: this.id,
        severity: this.severity,
        category: this.category,
        name: this.name,
        message:
          `Pack '${entry.name}' manifest lacks 'domain_access:' block ` +
          `(stallari-pack-spec v4.3.0, DD-341 Phase C). Without this block, ` +
          `the pack installs without a domain consent screen and receives zero ` +
          `domain grants at dispatch. Add 'domain_access:' with a plain-language ` +
          `description of what vault content the pack reads. ` +
          `See stallari-pack-spec/docs/domain-access.md.`,
        path: `${entry.name}.domain_access`,
      },
    ];
  },
};

/** All registered pack domain-access rules. */
export const PACK_DOMAIN_RULES: CatalogRule[] = [S_DOM_001];
