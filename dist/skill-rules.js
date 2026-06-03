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
import { flattenServiceOps } from "./skill-parser.js";
/**
 * Write-class operation detector — name-based heuristic. An op is treated as
 * write-class (and therefore requiring a `risk_class` declaration) when its
 * op name (the part after `service.`) matches a mutating verb prefix or a
 * mutating suffix.
 *
 * Biased toward catching writes: a false-positive only emits a non-blocking
 * warning nudging the author to declare `risk_class` (which a contracted
 * skill should anyway); a false-negative would let a real mutation ship
 * ungated, which is the harm this DD exists to close.
 *
 * Tuned against the real op surfaces in the six first-party non-core packs:
 * `create_adjustment`, `send`, `send_broadcast`, `create_broadcast`,
 * `create_contact`, `climate_set`, `light_control`, `lock_control`,
 * `alarm_control`, `scene_activate`, `vault.create`, `vault.append`,
 * `email.flag_bitmask_set` — and silent on the read ops (`subscriptions`,
 * `transactions`, `entity_state`, `energy_stats`, `profit_loss`,
 * `list_contacts`, `flag_bitmask_get`, `read`, `search`, …).
 */
const WRITE_VERB_PREFIX = /^(create|update|delete|append|send|set|write|mutate|activate|adjust|broadcast|put|post|patch|remove|add|control|reconcile|issue|cancel|refund|archive|publish)/i;
const WRITE_SUFFIX = /_(set|control|activate|broadcast|adjustment|contact|create|update|delete)$/i;
/** Read ops whose name could trip the verb heuristic but are reads. */
const READ_OVERRIDE = /(^|_)get$/i;
/** True when `service.op` denotes a state-mutating operation. */
export function isWriteClassOp(serviceOp) {
    const op = serviceOp.includes(".") ? serviceOp.slice(serviceOp.indexOf(".") + 1) : serviceOp;
    if (READ_OVERRIDE.test(op))
        return false;
    return WRITE_VERB_PREFIX.test(op) || WRITE_SUFFIX.test(op);
}
/**
 * Read ops that touch USER content/domain data — their presence means the
 * skill should declare a `domain_access` consent block (DD-278 scope ACL).
 * Vault reads + any billing/accounting/home/calendar/email read are user-data
 * reads. (A pure `vault.create`-only writer does not, by itself, read user
 * content — but in practice every non-core skill reads something.)
 */
const USER_READ_OP = /\.(read|search|query_properties|subscriptions|transactions|customers|products|invoices|profit_loss|balance_sheet|entity_state|entity_list|entity_history|area_list|energy_stats|scene_list)$/i;
function userReadsContent(serviceOps) {
    return serviceOps.some((s) => USER_READ_OP.test(s));
}
const RULE_ID = "S-SKL-001";
const CATEGORY = "skill-contract";
function finding(ctx, message, pathLeaf) {
    return {
        rule_id: RULE_ID,
        severity: "warning",
        category: CATEGORY,
        name: "Skill manifest missing v4.5 contract field",
        message: `Skill '${ctx.packName}/${ctx.skillName}': ${message}`,
        path: `${ctx.packName}/${ctx.skillName}.${pathLeaf}`,
    };
}
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
export const S_SKL_001 = {
    id: RULE_ID,
    name: "Skill manifest missing v4.5 contract field",
    category: CATEGORY,
    severity: "warning",
    description: "Skill manifest lacks a DD-344 v4.5 contract field its service surface requires " +
        "(risk_class on a declared write-class op, domain_access on a user-content reader, " +
        "sealed_credentials on an op://-resolving skill, or track_emits on a handoff emitter). " +
        "Uncontracted first-party/certified skills ship financial/physical writes with no DD-280 " +
        "two-gate authorizer, no DD-245 Track audit trail, and no DD-278 domain scoping. " +
        "Severity: warning (non-blocking) per DD-370 OQ-1 — promote to error at Phase D " +
        "(post-EA marketplace cutover). See stallari-pack-spec/docs/skill-contract.md.",
    check(ctx) {
        const findings = [];
        const serviceOps = flattenServiceOps(ctx.manifest, ctx.importEntry);
        const riskClass = ctx.manifest.risk_class ?? {};
        // 1. risk_class coverage on every declared write-class op.
        const writeOps = serviceOps.filter(isWriteClassOp);
        for (const op of writeOps) {
            if (!(op in riskClass)) {
                findings.push(finding(ctx, `declares write-class op '${op}' but no 'risk_class' entry covers it — ` +
                    `the DD-280 two-gate authorizer cannot gate an undeclared write`, `risk_class[${op}]`));
            }
        }
        // 2. domain_access on a user-content reader.
        const hasDomainAccess = ctx.manifest.domain_access !== undefined && ctx.manifest.domain_access !== null;
        if (userReadsContent(serviceOps) && !hasDomainAccess) {
            findings.push(finding(ctx, "reads user content but declares no 'domain_access' block — " +
                "the skill is unconstrained by the DD-278 scope ACL", "domain_access"));
        }
        // 3. sealed_credentials when the body resolves an op:// secret.
        const bodyNeedsOp = /op:\/\//.test(ctx.body);
        const hasSealed = Array.isArray(ctx.manifest.sealed_credentials) &&
            ctx.manifest.sealed_credentials.length > 0;
        if (bodyNeedsOp && !hasSealed) {
            findings.push(finding(ctx, "body references an 'op://' credential but declares no 'sealed_credentials' " +
                "block — the secret is resolved ad-hoc rather than at dispatch time", "sealed_credentials"));
        }
        // 4. track_emits when the body emits handoff-shaped work.
        const bodyEmitsHandoff = /\+\/handoff\/|\{\{\s*track\./.test(ctx.body);
        const hasTrackEmits = Array.isArray(ctx.manifest.track_emits) && ctx.manifest.track_emits.length > 0;
        if (bodyEmitsHandoff && !hasTrackEmits) {
            findings.push(finding(ctx, "emits handoff-shaped work (+/handoff/ or {{track.}}) but declares no " +
                "'track_emits' block — the action leaves no DD-245 Track audit trail", "track_emits"));
        }
        return findings;
    },
};
/** All skill-contract rules (DD-370). */
export const SKILL_RULES = [S_SKL_001];
