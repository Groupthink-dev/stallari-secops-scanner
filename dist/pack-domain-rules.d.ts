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
import type { CatalogRule } from "./types.js";
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
export declare const S_DOM_001: CatalogRule;
/**
 * Heuristic — argument names that strongly suggest a user-domain selector
 * on the tool's input schema. Intentionally narrow per architect lock #5
 * (DD-333 F.4 spec) to keep false-positives low. Tool authors who legitimately
 * use one of these names for a non-domain purpose may disable the check per
 * tool by adding `// scope-arg-disclaimer: <reason>` to the tool description
 * — the disclaimer downgrades any finding to an info-level note (rendered as
 * a warning-severity finding flagged with `[info-only]` in the message body;
 * the TypeScript catalog-rule type only ships `"warning" | "error"`, so the
 * informational distinction lives in the message body, not the severity).
 */
export declare const DOMAIN_SCOPE_ARG_NAME_PATTERN: RegExp;
/**
 * S-DOM-002 — fires a `"warning"` finding when a plugin catalog tool entry
 * advertises a user-domain-shaped argument (per
 * {@link DOMAIN_SCOPE_ARG_NAME_PATTERN}) while declaring
 * `granularity.domain_scope === "single"`, OR while omitting the field
 * but listed in `non_conformance_rationale.domain_scope_unspecified`
 * (which the stallari-plugins build pipeline derives as
 * `"non-conforming-explicit"`).
 *
 * The contradiction is the honesty signal: declaring "single" means the
 * tool operates within ONE user-domain per call. Exposing a scope/domain
 * argument lets the caller pick which domain — which is the surface area
 * of a `"multi"` tool. Either the granularity declaration or the argument
 * shape is wrong.
 *
 * Silent when:
 * - Entry is not type="plugin" (packs don't carry tool granularity; S-DOM-001
 *   covers their domain-access discipline.)
 * - Plugin omits `tools[]` (runtime-discovered tools cannot be lint-checked
 *   structurally).
 * - Tool omits `arguments[]` (no inventory to inspect — F.4 ships before the
 *   broader catalog backfill that adds argument inventories).
 * - Tool's `granularity.domain_scope` is `"multi"` (the scope-arg surface is
 *   legitimate when multi is declared).
 * - Tool's description contains `// scope-arg-disclaimer: <reason>` (author
 *   opt-out; finding downgraded to info-only — surfaced as a warning with
 *   `[info-only]` prefix in the message body).
 *
 * Severity: `"warning"` at F.4 ship per architect lock #7. Mirrors S-DOM-001
 * posture — promote to `"error"` only after the DD-338 A.2.dom backfill
 * brings blade-side `_meta.domain_hint` substrate online.
 *
 * Convention #23 reader-audit note: this rule reads three contract slices —
 * (a) the new `granularity.domain_scope` enum (DD-333 F.4 schema add),
 * (b) the optional `arguments[]` inventory (DD-333 F.4 catalog-entry add), and
 * (c) the new `non_conformance_rationale.domain_scope_unspecified` slot.
 * The scanner is silent on catalog entries that pre-date any of these
 * surfaces — F.4 is additive and the existing 11 packs / 30+ plugins are
 * unaffected.
 */
export declare const S_DOM_002: CatalogRule;
/** All registered pack domain-access rules. */
export declare const PACK_DOMAIN_RULES: CatalogRule[];
