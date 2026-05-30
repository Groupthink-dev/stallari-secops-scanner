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
export const S_DOM_001 = {
    id: "S-DOM-001",
    name: "Pack manifest missing domain_access block",
    category: "pack-domain-access",
    severity: "warning",
    description: "Pack manifest lacks 'domain_access:' block (stallari-pack-spec v4.3.0, DD-341 Phase C). " +
        "Packs without the block install without surfacing a domain consent screen; " +
        "the pack receives zero domain grants at dispatch and reads zero vault notes " +
        "via the partition substrate. Add 'domain_access:' to surface the consent " +
        "screen at install time. See stallari-pack-spec/docs/domain-access.md. " +
        "Severity: warning (non-blocking) per architect lock #5 — 16 currently-sealed " +
        "packs predate v4.3.0. Promote to error after the Pn-author migration cycle.",
    appliesTo: "pack",
    check(entry) {
        if (entry.type !== "pack")
            return [];
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
                message: `Pack '${entry.name}' manifest lacks 'domain_access:' block ` +
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
// ── DD-333 Phase F.4: S-DOM-002 — domain_scope honesty lint ───────
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
export const DOMAIN_SCOPE_ARG_NAME_PATTERN = /^(scope|domain|domains|domainName|domain_name)$/i;
/** Argument types that count as a user-domain selector surface. */
const DOMAIN_SCOPE_ARG_TYPES = new Set(["string", "enum"]);
/** Disclaimer marker tool authors embed in description to opt out. */
const SCOPE_ARG_DISCLAIMER_PATTERN = /\/\/\s*scope-arg-disclaimer:\s*\S/;
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
export const S_DOM_002 = {
    id: "S-DOM-002",
    name: "Tool advertises domain selector but declares single domain_scope",
    category: "domain-scope-honesty",
    severity: "warning",
    description: "Tool granularity declares `domain_scope: single` while the tool's " +
        "`arguments[]` inventory advertises a user-domain-shaped argument " +
        "(name matches /^(scope|domain|domains|domainName|domain_name)$/i and " +
        "type is string or enum). The contradiction means either the " +
        "granularity declaration or the argument shape is wrong: a single-" +
        "domain tool should not expose a domain selector. Authors may opt out " +
        "per-tool by embedding `// scope-arg-disclaimer: <reason>` in the tool " +
        "description (the finding is then downgraded to info-only). DD-333 " +
        "Phase F.4 ships at warning severity (architect lock #7) — promotion to " +
        "error follows DD-338 A.2.dom backfill. See DD-333.md § Phase F.4 and " +
        "DD-341.md for the cross-DD context.",
    appliesTo: "plugin",
    check(entry) {
        if (entry.type !== "plugin")
            return [];
        if (!entry.tools || entry.tools.length === 0)
            return [];
        // DD-333 F.4 — derived non-conformance silence set for domain_scope.
        // Tools listed here have an upstream-derived
        // domain_scope: "non-conforming-explicit", which the procedural check
        // still flags when a scope-arg is also present (the contradiction
        // remains honest: derived non-conformance != absolution from S-DOM-002).
        const unspecified = new Set(entry.non_conformance_rationale?.domain_scope_unspecified ?? []);
        const findings = [];
        for (const tool of entry.tools) {
            // No arguments inventory → cannot lint structurally.
            if (!tool.arguments || tool.arguments.length === 0)
                continue;
            // Detect a user-domain-shaped argument.
            const scopeArg = tool.arguments.find((arg) => {
                if (!arg || typeof arg.name !== "string")
                    return false;
                if (!DOMAIN_SCOPE_ARG_NAME_PATTERN.test(arg.name))
                    return false;
                // Default to string when type is omitted — most common shape.
                const type = (arg.type ?? "string").toLowerCase();
                return DOMAIN_SCOPE_ARG_TYPES.has(type);
            });
            if (!scopeArg)
                continue;
            // Resolve effective domain_scope. Either declared on the tool, or
            // derived from non_conformance_rationale.domain_scope_unspecified.
            const declared = tool.granularity?.domain_scope;
            const derived = declared ??
                (unspecified.has(tool.name)
                    ? "non-conforming-explicit"
                    : undefined);
            // Multi is the legitimate shape for a scope-arg — no finding.
            if (derived === "multi")
                continue;
            // Missing entirely (and not on the unspecified list) → silent at F.4.
            // F.4.b promotion to required will flip this branch into a finding;
            // until then we don't fire on tools that simply haven't declared yet.
            if (derived === undefined)
                continue;
            // derived is "single" or "non-conforming-explicit" — both are
            // contradictions with the scope-arg surface.
            const disclaimer = SCOPE_ARG_DISCLAIMER_PATTERN.test(tool.description ?? "");
            const baseMessage = `Tool '${tool.name}' (in plugin '${entry.name}') advertises a ` +
                `user-domain-shaped argument '${scopeArg.name}' but declares ` +
                `granularity.domain_scope='${derived}'. A single-domain tool ` +
                `should not expose a domain selector — either declare ` +
                `domain_scope='multi' or remove the '${scopeArg.name}' argument. ` +
                `See DD-333 Phase F.4 + stallari-pack-spec/docs/domain-scope.md.`;
            findings.push({
                rule_id: this.id,
                severity: this.severity,
                category: this.category,
                name: this.name,
                message: disclaimer ? `[info-only] ${baseMessage}` : baseMessage,
                path: `${entry.name}.tools[${tool.name}].granularity.domain_scope`,
            });
        }
        return findings;
    },
};
/** All registered pack domain-access rules. */
export const PACK_DOMAIN_RULES = [S_DOM_001, S_DOM_002];
