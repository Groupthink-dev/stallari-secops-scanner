/**
 * DD-370 — Tests for S-SKL-001 (skill-contract lint) + the skill parser
 * + the pack-skill scanner glue.
 *
 * Cases:
 *   1. Contracted skill (flag-triage shape: risk_class covers all write ops,
 *      domain_access present) → no finding.
 *   2. Uncontracted financial skill (refund-processor shape: services_used in
 *      pack.yaml import, NO frontmatter contract) → fires for the write op
 *      (billing.create_adjustment, vault.create) + domain_access.
 *   3. Pure read+format skill (no write op, no user-content read, no op://,
 *      no handoff) → silent.
 *   4. Write detector: known write ops detected, known read ops not.
 *   5. op:// body reference without sealed_credentials → fires.
 *   6. Handoff-emitting body without track_emits → fires.
 *   7. Dual-surface: required_services in frontmatter alone is enough to
 *      detect write ops (post-uplift shape).
 *   8. scanPackSkills() pairs pack.yaml imports with skill .md sources.
 *   9. S_SKL_001 registered in SKILL_RULES; severity is warning (OQ-1).
 */

import { describe, it, expect } from "vitest";
import { S_SKL_001, SKILL_RULES, isWriteClassOp } from "./skill-rules.js";
import { scanPackSkills, scanSkill } from "./skill-scanner.js";
import { parseSkillManifest } from "./skill-parser.js";
import type { SkillScanContext } from "./types.js";

// ── Helpers ───────────────────────────────────────────────────────

function ctx(over: Partial<SkillScanContext>): SkillScanContext {
  return {
    skillName: "test-skill",
    packName: "test-pack",
    manifest: {},
    body: "",
    ...over,
  };
}

function ruleIds(findings: { rule_id: string }[]): string[] {
  return findings.map((f) => f.rule_id);
}

// ── 1. Contracted skill is clean ─────────────────────────────────

describe("S-SKL-001 — contracted skill", () => {
  it("emits no finding when risk_class covers every write op and domain_access present", () => {
    const findings = S_SKL_001.check(
      ctx({
        manifest: {
          required_services: [
            "email.search",
            "email.flag_bitmask_set",
            "vault.create",
            "tasks.create",
          ],
          risk_class: {
            "email.search": "read_only",
            "email.flag_bitmask_set": "reversible_write",
            "vault.create": "reversible_write",
            "tasks.create": "external_side_effect",
          },
          domain_access: { description: "Reads flagged mail.", needs_sensitive: false },
        },
      }),
    );
    expect(findings).toHaveLength(0);
  });
});

// ── 2. Uncontracted financial skill fires ────────────────────────

describe("S-SKL-001 — uncontracted financial skill (refund-processor shape)", () => {
  it("fires for each write op + domain_access when contract absent, services in import", () => {
    const findings = S_SKL_001.check(
      ctx({
        skillName: "refund-processor",
        packName: "saas-revenue-ops",
        manifest: {}, // uncontracted
        importEntry: {
          import: "./skills/refund-processor.md",
          services_used: [
            {
              service: "billing",
              operations: ["subscriptions", "transactions", "create_adjustment"],
            },
            { service: "vault", operations: ["create"] },
          ],
        },
      }),
    );
    const paths = findings.map((f) => f.path);
    // write ops needing risk_class: billing.create_adjustment, vault.create
    expect(paths).toContain("saas-revenue-ops/refund-processor.risk_class[billing.create_adjustment]");
    expect(paths).toContain("saas-revenue-ops/refund-processor.risk_class[vault.create]");
    // reads a user domain (billing.subscriptions/transactions) → domain_access
    expect(paths).toContain("saas-revenue-ops/refund-processor.domain_access");
    // billing.subscriptions / billing.transactions are reads → no risk_class finding for them
    expect(paths).not.toContain(
      "saas-revenue-ops/refund-processor.risk_class[billing.subscriptions]",
    );
    expect(findings.every((f) => f.severity === "warning")).toBe(true);
  });
});

// ── 3. Pure read+format skill is silent ──────────────────────────

describe("S-SKL-001 — pure compute skill", () => {
  it("emits no finding for a skill with no write op, no user read, no op://, no handoff", () => {
    const findings = S_SKL_001.check(
      ctx({
        manifest: {},
        importEntry: {
          import: "./skills/format-only.md",
          // a hypothetical read that is NOT a user-content read
          services_used: [],
        },
        body: "Format the supplied text. No external access.",
      }),
    );
    expect(findings).toHaveLength(0);
  });
});

// ── 4. Write detector ────────────────────────────────────────────

describe("isWriteClassOp", () => {
  it("detects mutating ops", () => {
    for (const op of [
      "billing.create_adjustment",
      "transactional-email.send",
      "transactional-email.send_broadcast",
      "transactional-email.create_broadcast",
      "transactional-email.create_contact",
      "home.climate_set",
      "home.light_control",
      "home.lock_control",
      "home.alarm_control",
      "home.scene_activate",
      "vault.create",
      "vault.append",
      "email.flag_bitmask_set",
    ]) {
      expect(isWriteClassOp(op)).toBe(true);
    }
  });
  it("treats reads as non-write", () => {
    for (const op of [
      "billing.subscriptions",
      "billing.transactions",
      "billing.customers",
      "billing.products",
      "accounting.invoices",
      "accounting.profit_loss",
      "accounting.balance_sheet",
      "home.entity_state",
      "home.entity_list",
      "home.area_list",
      "home.entity_history",
      "home.energy_stats",
      "vault.read",
      "vault.search",
      "vault.query_properties",
      "email.flag_bitmask_get",
      "transactional-email.list_contacts",
      "transactional-email.get_template",
    ]) {
      expect(isWriteClassOp(op)).toBe(false);
    }
  });
});

// ── 5. op:// without sealed_credentials ──────────────────────────

describe("S-SKL-001 — op:// without sealed_credentials", () => {
  it("fires when body resolves an op:// secret but no sealed_credentials block", () => {
    const findings = S_SKL_001.check(
      ctx({
        manifest: {},
        body: "Send via ntfy using op://Infra/ntfy/token.",
      }),
    );
    expect(ruleIds(findings)).toContain("S-SKL-001");
    expect(findings.some((f) => f.path.endsWith(".sealed_credentials"))).toBe(true);
  });
  it("silent when sealed_credentials declared", () => {
    const findings = S_SKL_001.check(
      ctx({
        manifest: {
          sealed_credentials: [{ name: "ntfy", source: "op://Infra/ntfy/token" }],
        },
        body: "Send via ntfy using op://Infra/ntfy/token.",
      }),
    );
    expect(findings.some((f) => f.path.endsWith(".sealed_credentials"))).toBe(false);
  });
});

// ── 6. Handoff body without track_emits ──────────────────────────

describe("S-SKL-001 — handoff emission without track_emits", () => {
  it("fires when body writes +/handoff/ but no track_emits", () => {
    const findings = S_SKL_001.check(
      ctx({ manifest: {}, body: "Write a note to +/handoff/ for the operator." }),
    );
    expect(findings.some((f) => f.path.endsWith(".track_emits"))).toBe(true);
  });
});

// ── 7. Frontmatter-only service surface (post-uplift) ────────────

describe("S-SKL-001 — frontmatter required_services alone", () => {
  it("detects write ops from frontmatter required_services without an import entry", () => {
    const findings = S_SKL_001.check(
      ctx({
        manifest: { required_services: ["billing.create_adjustment"] },
      }),
    );
    expect(findings.some((f) => f.path.includes("risk_class[billing.create_adjustment]"))).toBe(
      true,
    );
  });
});

// ── 8. scanPackSkills glue ───────────────────────────────────────

describe("scanPackSkills", () => {
  const packYaml = `
name: saas-revenue-ops
skills:
  - import: ./skills/refund-processor.md
    services_used:
      - service: billing
        operations: [subscriptions, create_adjustment]
      - service: vault
        operations: [create]
`;
  it("pairs imports with skill sources and lints", () => {
    const skills = new Map<string, string>([
      [
        "refund-processor",
        "---\nversion: \"1.0\"\ndescription: refund\n---\n# Refund\nDo the refund.",
      ],
    ]);
    const res = scanPackSkills("saas-revenue-ops", packYaml, skills);
    expect(res.skills_scanned).toBe(1);
    expect(res.summary.warning).toBeGreaterThan(0);
    expect(res.summary.error).toBe(0);
    expect(res.result).toBe("warn");
  });

  it("goes clean once the skill declares the contract", () => {
    const skills = new Map<string, string>([
      [
        "refund-processor",
        [
          "---",
          'version: "2.0.0"',
          "description: refund",
          "required_services: [billing.subscriptions, billing.create_adjustment, vault.create]",
          "risk_class:",
          "  billing.subscriptions: read_only",
          "  billing.create_adjustment: external_side_effect",
          "  vault.create: reversible_write",
          "domain_access:",
          "  description: Reads the target subscription to validate the refund.",
          "  needs_sensitive: false",
          "---",
          "# Refund",
          "Do the refund.",
        ].join("\n"),
      ],
    ]);
    const res = scanPackSkills("saas-revenue-ops", packYaml, skills);
    expect(res.findings).toHaveLength(0);
    expect(res.result).toBe("pass");
  });
});

// ── 9. Parser + registration ─────────────────────────────────────

describe("parseSkillManifest", () => {
  it("extracts frontmatter and body", () => {
    const { manifest, body } = parseSkillManifest(
      '---\nversion: "2.0.0"\nrisk_class:\n  vault.create: reversible_write\n---\n# Title\nbody',
    );
    expect(manifest.version).toBe("2.0.0");
    expect(manifest.risk_class?.["vault.create"]).toBe("reversible_write");
    expect(body).toContain("# Title");
  });
  it("returns empty manifest for frontmatter-less doc", () => {
    const { manifest, body } = parseSkillManifest("# No frontmatter\nbody");
    expect(manifest).toEqual({});
    expect(body).toContain("# No frontmatter");
  });
  it("tolerates malformed YAML frontmatter (treats as uncontracted)", () => {
    const { manifest } = parseSkillManifest("---\n  : : bad\n  - [\n---\nbody");
    expect(manifest).toEqual({});
  });
});

describe("SKILL_RULES registration", () => {
  it("includes S-SKL-001 at warning severity", () => {
    expect(SKILL_RULES.map((r) => r.id)).toContain("S-SKL-001");
    expect(S_SKL_001.severity).toBe("warning");
  });
});
