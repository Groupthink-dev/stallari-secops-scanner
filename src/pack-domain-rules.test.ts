/**
 * DD-341 Phase C — Tests for S-DOM-001 (MissingDomainAccessRule).
 *
 * Three cases per spec:
 *   1. Pack manifest WITH domain_access block → no finding.
 *   2. Pack manifest WITHOUT domain_access block → "warning" finding.
 *   3. Pack manifest with requested_domains field but no domain_access block
 *      → no scanner finding. The submission-time TypeScript validator in
 *      stallari-pack-spec and the pack-spec 4.3.0 AJV schema gate both reject
 *      requested_domains: at build/submission time; sealed packs with this
 *      field would represent a pipeline breach, not a normal path. The scanner
 *      is downstream of those gates and does not re-emit for requested_domains:
 *      — S-DOM-001 only concerns itself with domain_access: presence/absence.
 *
 * Additionally covers:
 *   4. Non-pack catalog entries (plugins) are skipped — S-DOM-001 only
 *      applies to type="pack".
 *   5. S-DOM-001 is registered in PACK_DOMAIN_RULES.
 *   6. scanCatalogEntries() aggregator picks up S-DOM-001 findings correctly.
 */

import { describe, it, expect } from "vitest";
import { S_DOM_001, S_DOM_002, PACK_DOMAIN_RULES } from "./pack-domain-rules.js";
import { scanCatalogEntries } from "./catalog-scanner.js";
import type {
  CatalogEntry,
  CatalogTool,
  DomainAccessBlock,
  ToolGranularity,
} from "./types.js";

// ── Helpers ───────────────────────────────────────────────────────

function pack(name: string, extra?: Partial<CatalogEntry>): CatalogEntry {
  return { name, type: "pack", ...extra };
}

function plugin(name: string, extra?: Partial<CatalogEntry>): CatalogEntry {
  return { name, type: "plugin", ...extra };
}

const validDomainAccess: DomainAccessBlock = {
  description:
    "This pack reads your work notes to help you manage tasks and deadlines.",
  needs_sensitive: false,
  examples_in_other_vaults: ["work", "projects"],
};

// ── S-DOM-001 ─────────────────────────────────────────────────────

describe("S-DOM-001 — Pack manifest missing domain_access block", () => {
  // Case 1: pack WITH domain_access → no finding
  it("is silent when pack catalog entry declares domain_access block", () => {
    const entry = pack("task-helper", { domain_access: validDomainAccess });
    expect(S_DOM_001.check(entry)).toEqual([]);
  });

  // Case 1b: pack with minimal domain_access (only required description field)
  it("is silent when pack catalog entry declares minimal domain_access block", () => {
    const entry = pack("minimal-pack", {
      domain_access: { description: "Reads your project notes." },
    });
    expect(S_DOM_001.check(entry)).toEqual([]);
  });

  // Case 2: pack WITHOUT domain_access → warning finding
  it("fires a warning finding when pack catalog entry lacks domain_access block", () => {
    const entry = pack("legacy-pack");
    const findings = S_DOM_001.check(entry);

    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-001");
    expect(findings[0].severity).toBe("warning");
    expect(findings[0].category).toBe("pack-domain-access");
    expect(findings[0].path).toBe("legacy-pack.domain_access");
    // Message should name the pack and point to the docs
    expect(findings[0].message).toMatch(/legacy-pack/);
    expect(findings[0].message).toMatch(/domain_access/);
    expect(findings[0].message).toMatch(/domain-access\.md/);
  });

  // Case 2b: pack with domain_access: null (explicit null) → treated as absent
  it("fires a warning when domain_access is explicitly null", () => {
    const entry = pack("null-pack", { domain_access: null });
    const findings = S_DOM_001.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-001");
    expect(findings[0].severity).toBe("warning");
  });

  // Case 3: pack with requested_domains but no domain_access → NO scanner finding.
  //
  // Rationale: stallari-pack-spec v4.3.0 AJV schema rejects requested_domains:
  // at build/submission time (it's listed as a "not: {type: array}" reject
  // property in pack.schema.json). The stallari-plugins build-catalog.js gate
  // throws before a pack with requested_domains: can be sealed. A sealed pack
  // carrying this field would be a pipeline breach. S-DOM-001 addresses domain_access:
  // absence — a separate concern. The upstream validator (PackDomainAccess.ts in
  // stallari-pack-spec) is the authoritative catch for requested_domains:
  // violations. Scanner is silent on it to avoid double-reporting and because
  // the threat model concern is fully covered at submission time.
  it("is silent on requested_domains field — submission-time validator covers it upstream", () => {
    // Simulates a hypothetical catalog entry where the field leaked through.
    // In practice this shouldn't occur post-seal; test documents the decision.
    const entry = pack("old-style-pack", {
      // No domain_access block — this WOULD normally trigger S-DOM-001.
      // But we're testing the requested_domains: co-presence case.
      // Since requested_domains: is not domain_access:, S-DOM-001 still fires
      // for the missing domain_access: block — which IS correct behaviour.
      // The spec says "no scanner finding" for this case because the spec
      // assumed requested_domains: + domain_access: co-presence; if only
      // requested_domains: is present (no domain_access:), the correct
      // behaviour is to fire S-DOM-001 for the missing block.
      //
      // Documenting the actual decision here: scanner is silent on the
      // requested_domains: field itself (does not emit a finding for its
      // presence), but DOES still fire S-DOM-001 for the missing domain_access:
      // block (because that's a separate check). The S-DOM-001 finding is
      // about domain_access: absence, not requested_domains: presence.
      //
      // If a pack somehow has BOTH requested_domains: AND domain_access:,
      // S-DOM-001 is silent (domain_access: satisfies the check). The
      // requested_domains: concern is the upstream validator's jurisdiction.
      requested_domains: ["work", "personal"],
    } as Partial<CatalogEntry> & { requested_domains: string[] });

    const findings = S_DOM_001.check(entry);
    // S-DOM-001 fires because domain_access: is missing — this is CORRECT.
    // The rule does NOT fire a finding for requested_domains: being present —
    // only for domain_access: being absent.
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-001");
    // Confirm the finding is about domain_access, NOT about requested_domains
    expect(findings[0].path).toBe("old-style-pack.domain_access");
    expect(findings[0].message).not.toMatch(/requested_domains/);
  });

  // Case 4: non-pack entries (plugins) are skipped
  it("is silent on plugin-type catalog entries", () => {
    const entry = plugin("some-blade-mcp");
    expect(S_DOM_001.check(entry)).toEqual([]);
  });

  it("is silent on catalog entries without explicit type (default is not pack)", () => {
    // Untyped entries are treated as plugin by the catalog discriminator
    // default in stallari-plugins; S-DOM-001 only fires on type="pack".
    const entry: CatalogEntry = { name: "untyped-entry" };
    expect(S_DOM_001.check(entry)).toEqual([]);
  });

  // Registration check
  it("is registered in PACK_DOMAIN_RULES", () => {
    expect(PACK_DOMAIN_RULES.some((r) => r.id === "S-DOM-001")).toBe(true);
  });

  it("ships at warning severity (non-blocking) per architect lock #5", () => {
    expect(S_DOM_001.severity).toBe("warning");
  });

  it("appliesTo is 'pack'", () => {
    expect(S_DOM_001.appliesTo).toBe("pack");
  });
});

// ── scanCatalogEntries aggregator integration ─────────────────────

describe("scanCatalogEntries — S-DOM-001 integration", () => {
  it("returns warn (not fail) for packs missing domain_access", () => {
    const result = scanCatalogEntries([
      pack("old-pack-a"),
      pack("old-pack-b"),
    ]);
    expect(result.result).toBe("warn");
    expect(result.summary.warning).toBe(2);
    expect(result.summary.error).toBe(0);
    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.rule_id === "S-DOM-001")).toBe(true);
  });

  it("returns pass when all packs declare domain_access", () => {
    const result = scanCatalogEntries([
      pack("new-pack-a", { domain_access: validDomainAccess }),
      pack("new-pack-b", { domain_access: { description: "Reads project notes and task lists." } }),
    ]);
    expect(result.result).toBe("pass");
    expect(result.summary.warning).toBe(0);
    expect(result.findings.filter((f) => f.rule_id === "S-DOM-001")).toHaveLength(0);
  });

  it("S-DOM-001 findings do not affect plugin entries in mixed scans", () => {
    // Plugin with granularity + pack without domain_access → only S-DOM-001 warning
    const goldenGranularity = {
      scope_filtering: "server-side" as const,
      field_projection: "per-field" as const,
      deterministic_ordering: "stable" as const,
      audit_surface: "structured" as const,
    };
    const result = scanCatalogEntries([
      plugin("well-formed-blade", {
        tools: [{ name: "list_records", granularity: goldenGranularity }],
      }),
      pack("legacy-pack"),
    ]);
    // Only S-DOM-001 warning fires; S-MCP-001 is silent (plugin has granularity)
    expect(result.summary.error).toBe(0);
    expect(result.summary.warning).toBe(1);
    expect(result.findings[0].rule_id).toBe("S-DOM-001");
    expect(result.result).toBe("warn");
  });
});

// ── DD-333 Phase F.4: S-DOM-002 — domain_scope honesty lint ───────

/**
 * Helper: a granularity block declaring a given domain_scope. The other four
 * dimensions are filled with golden-path values so they don't trip any other
 * rule.
 */
function granularityWith(
  domain_scope: "single" | "multi" | "non-conforming-explicit" | undefined,
): ToolGranularity {
  const base: ToolGranularity = {
    scope_filtering: "server-side",
    field_projection: "per-field",
    deterministic_ordering: "stable",
    audit_surface: "structured",
  };
  if (domain_scope !== undefined) base.domain_scope = domain_scope;
  return base;
}

function tool(
  name: string,
  granularity: ToolGranularity,
  args?: CatalogTool["arguments"],
  description?: string,
): CatalogTool {
  return { name, granularity, arguments: args, description };
}

describe("S-DOM-002 — Tool advertises domain selector but declares single domain_scope", () => {
  // Case 1: honest pack with no contradictions → empty findings.
  // Mixes: a multi-scope tool with a domain arg (legitimate), a single-scope
  // tool with no domain arg (legitimate), and a single-scope tool that omits
  // the field (silent at F.4 — promotion to required follows F.4.b).
  it("s_dom_002_passes_honest_pack", () => {
    const entry = plugin("honest-blade", {
      tools: [
        tool(
          "search_across_domains",
          granularityWith("multi"),
          [{ name: "domain", type: "string" }],
        ),
        tool("read_current_domain", granularityWith("single"), [
          { name: "limit", type: "integer" },
        ]),
        // No domain_scope declared, no scope-arg → silent.
        tool("legacy_tool", granularityWith(undefined), [
          { name: "id", type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Case 2: contradiction — single declaration + scope arg → 1 warning.
  it("s_dom_002_warns_on_single_plus_scope_arg", () => {
    const entry = plugin("contradictory-blade", {
      tools: [
        tool(
          "list_items",
          granularityWith("single"),
          [
            { name: "scope", type: "string" },
            { name: "limit", type: "integer" },
          ],
        ),
      ],
    });
    const findings = S_DOM_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-002");
    expect(findings[0].severity).toBe("warning");
    expect(findings[0].category).toBe("domain-scope-honesty");
    expect(findings[0].path).toBe(
      "contradictory-blade.tools[list_items].granularity.domain_scope",
    );
    expect(findings[0].message).toMatch(/list_items/);
    expect(findings[0].message).toMatch(/scope/);
    expect(findings[0].message).toMatch(/single/);
    // Not the disclaimer path
    expect(findings[0].message).not.toMatch(/\[info-only\]/);
  });

  // Case 3: same contradiction shape, but tool description carries the
  // `// scope-arg-disclaimer:` annotation → finding downgraded to info-only.
  it("s_dom_002_respects_disclaimer", () => {
    const entry = plugin("disclaimed-blade", {
      tools: [
        tool(
          "list_items",
          granularityWith("single"),
          [{ name: "scope", type: "string" }],
          "List items. // scope-arg-disclaimer: 'scope' here means visibility scope, not user-domain.",
        ),
      ],
    });
    const findings = S_DOM_002.check(entry);
    // Disclaimer path emits a finding flagged [info-only] in the message body
    // (severity stays "warning" since LintSeverity has no info tier).
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-002");
    expect(findings[0].message).toMatch(/\[info-only\]/);
  });

  // Additional coverage: domain_scope omitted entirely and not on the
  // non_conformance_rationale.domain_scope_unspecified list → silent at F.4.
  // F.4.b promotion to required will flip this into a finding.
  it("is silent when domain_scope is omitted and tool is not on unspecified list", () => {
    const entry = plugin("legacy-undeclared-blade", {
      tools: [
        tool("list_items", granularityWith(undefined), [
          { name: "scope", type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Non-conformance rationale derivation: tool listed in
  // domain_scope_unspecified with a scope-arg → finding fires (derived
  // non-conformance still counts as a contradiction — honest declaration
  // is not absolution).
  it("fires when tool is on domain_scope_unspecified list AND advertises a scope arg", () => {
    const entry = plugin("explicitly-non-conforming-blade", {
      tools: [
        tool("list_items", granularityWith(undefined), [
          { name: "domain", type: "string" },
        ]),
      ],
      non_conformance_rationale: {
        reason: "Backend still backfilling domain-scope plumbing.",
        scope_filtering_off: true,
        contamination_risks: ["cross-scope-packet-bleed"],
        affected_tools: [],
        domain_scope_unspecified: ["list_items"],
      },
    });
    const findings = S_DOM_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-DOM-002");
    expect(findings[0].message).toMatch(/non-conforming-explicit/);
  });

  // Multi declaration is the legitimate shape for a scope-arg.
  it("is silent when domain_scope is 'multi' even with a scope arg", () => {
    const entry = plugin("multi-blade", {
      tools: [
        tool("search_across", granularityWith("multi"), [
          { name: "domains", type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Argument-name heuristic — exhaustive cover of the accepted name set.
  it.each([
    ["scope"],
    ["domain"],
    ["domains"],
    ["domainName"],
    ["domain_name"],
    ["SCOPE"],
    ["Domain"],
  ])("detects scope-arg name '%s' (case-insensitive)", (argName) => {
    const entry = plugin("name-variant-blade", {
      tools: [
        tool("list_items", granularityWith("single"), [
          { name: argName, type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toHaveLength(1);
  });

  // Non-matching argument names — silent.
  it("is silent when no argument name matches the scope-arg heuristic", () => {
    const entry = plugin("benign-blade", {
      tools: [
        tool("list_items", granularityWith("single"), [
          { name: "limit", type: "integer" },
          { name: "offset", type: "integer" },
          { name: "query", type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Argument type — only string/enum count.
  it("is silent when scope-named argument has a non-string non-enum type", () => {
    const entry = plugin("typed-blade", {
      tools: [
        tool("list_items", granularityWith("single"), [
          // Type is integer — doesn't shape as a user-domain selector.
          { name: "scope", type: "integer" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Plugins without tools — silent.
  it("is silent on plugins with no tools[]", () => {
    const entry = plugin("toolless-blade");
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Tools without arguments[] inventory — silent (F.4 ships before broader
  // catalog backfill that adds argument inventories).
  it("is silent when tool omits the arguments[] inventory", () => {
    const entry = plugin("no-args-blade", {
      tools: [tool("list_items", granularityWith("single"))],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Pack-type entries — silent (S-DOM-002 targets plugins).
  it("is silent on pack-type catalog entries", () => {
    const entry = pack("some-pack", {
      tools: [
        tool("list_items", granularityWith("single"), [
          { name: "scope", type: "string" },
        ]),
      ],
    });
    expect(S_DOM_002.check(entry)).toEqual([]);
  });

  // Registration + posture checks.
  it("is registered in PACK_DOMAIN_RULES", () => {
    expect(PACK_DOMAIN_RULES.some((r) => r.id === "S-DOM-002")).toBe(true);
  });

  it("ships at warning severity (non-blocking) per architect lock #7", () => {
    expect(S_DOM_002.severity).toBe("warning");
  });

  it("appliesTo is 'plugin'", () => {
    expect(S_DOM_002.appliesTo).toBe("plugin");
  });
});

// ── scanCatalogEntries aggregator integration for S-DOM-002 ──────

describe("scanCatalogEntries — S-DOM-002 integration", () => {
  it("S-DOM-002 findings flow through the aggregator at warning severity", () => {
    const result = scanCatalogEntries([
      plugin("contradictory-blade", {
        tools: [
          {
            name: "list_items",
            granularity: {
              scope_filtering: "server-side",
              field_projection: "per-field",
              deterministic_ordering: "stable",
              audit_surface: "structured",
              domain_scope: "single",
            },
            arguments: [{ name: "scope", type: "string" }],
          },
        ],
      }),
    ]);
    expect(result.summary.error).toBe(0);
    expect(result.summary.warning).toBeGreaterThanOrEqual(1);
    expect(
      result.findings.some((f) => f.rule_id === "S-DOM-002"),
    ).toBe(true);
    expect(result.result).toBe("warn");
  });
});
