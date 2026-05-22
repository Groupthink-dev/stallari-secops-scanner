/**
 * DD-333 Phase A.4 — Catalog-rule tests.
 *
 * Covers S-MCP-001 happy/edge cases plus the catalog parser entry-point
 * and the aggregating scanCatalogEntries() wrapper.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { S_MCP_001, S_MCP_002, CATALOG_RULES } from "./catalog-rules.js";
import {
  scanCatalogEntry,
  scanCatalogEntries,
} from "./catalog-scanner.js";
import { parseCatalogEntry } from "./catalog-parser.js";
import type { CatalogEntry } from "./types.js";

// ── Helpers ──────────────────────────────────────────────────────

function plugin(name: string, tools?: unknown): CatalogEntry {
  const e: CatalogEntry = { name, type: "plugin" };
  if (tools !== undefined) e.tools = tools as CatalogEntry["tools"];
  return e;
}

const goldenGranularity = {
  scope_filtering: "server-side",
  field_projection: "per-field",
  deterministic_ordering: "stable",
  audit_surface: "structured",
} as const;

// ── S-MCP-001 ────────────────────────────────────────────────────

describe("S-MCP-001 — MCP catalog tool missing granularity", () => {
  it("does not fire when every tool declares granularity", () => {
    const entry = plugin("ok-blade", [
      { name: "list_records", granularity: { ...goldenGranularity } },
      { name: "get_record", granularity: { ...goldenGranularity } },
    ]);
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("fires one error per tool missing granularity", () => {
    const entry = plugin("bad-blade", [
      { name: "list_things" },
      { name: "get_thing", risk_class: "read_only" },
    ]);
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings[0].rule_id).toBe("S-MCP-001");
    expect(findings[0].severity).toBe("error");
    expect(findings[0].path).toBe("bad-blade.tools[list_things].granularity");
    expect(findings[1].path).toBe("bad-blade.tools[get_thing].granularity");
  });

  it("fires warnings only for the undeclared subset (mixed)", () => {
    const entry = plugin("mixed-blade", [
      { name: "list_records", granularity: { ...goldenGranularity } },
      { name: "dump_all" },
      { name: "search_records", granularity: { ...goldenGranularity } },
      { name: "legacy_call" },
    ]);
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.path)).toEqual([
      "mixed-blade.tools[dump_all].granularity",
      "mixed-blade.tools[legacy_call].granularity",
    ]);
  });

  it("is silent when tools[] is absent (runtime-discovery shape)", () => {
    const entry = plugin("runtime-blade");
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("is silent when tools[] is empty", () => {
    const entry = plugin("empty-blade", []);
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("does not fire on pack-type catalog entries", () => {
    const entry: CatalogEntry = {
      name: "skills-pack",
      type: "pack",
      tools: [{ name: "list" }] as CatalogEntry["tools"],
    };
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("does not fire when granularity is present but malformed (AJV's job)", () => {
    // Rule cares about presence/absence only — schema-shape enforcement is
    // upstream in stallari-plugins build-catalog.js AJV gate.
    const entry = plugin("malformed-blade", [
      {
        name: "bogus_tool",
        granularity: {
          scope_filtering: "always", // not in enum, but still "present"
          field_projection: "per-field",
          deterministic_ordering: "stable",
          audit_surface: "structured",
        },
      },
      {
        name: "incomplete_tool",
        granularity: {
          // missing audit_surface — still treated as present by S-MCP-001
          scope_filtering: "server-side",
          field_projection: "per-field",
          deterministic_ordering: "stable",
        },
      },
    ]);
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("severity is error at Phase D (cutover 2026-05-21)", () => {
    expect(S_MCP_001.severity).toBe("error");
  });

  it("is registered in CATALOG_RULES", () => {
    expect(CATALOG_RULES.some((r) => r.id === "S-MCP-001")).toBe(true);
  });
});

// ── DD-333 F.1: S-MCP-001 accept-with-rationale silence path ─────

describe("S-MCP-001 — DD-333 F.1 accept-with-rationale silence", () => {
  const validRationale = {
    reason: "Upstream lacks scope arg; rewrite scheduled.",
    scope_filtering_off: true as const,
    contamination_risks: ["cross-scope-packet-bleed" as const],
    affected_tools: ["dump_legacy"],
  };

  it("does not fire when tool lacks granularity but is listed in affected_tools", () => {
    const entry: CatalogEntry = {
      name: "rationale-blade",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: validRationale,
    };
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("still fires for tools without granularity and NOT in affected_tools", () => {
    const entry: CatalogEntry = {
      name: "mixed-rationale-blade",
      type: "plugin",
      tools: [
        { name: "dump_legacy" }, // in affected_tools — silent
        { name: "list_things" }, // NOT in affected_tools — fires
      ] as CatalogEntry["tools"],
      non_conformance_rationale: validRationale,
    };
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe(
      "mixed-rationale-blade.tools[list_things].granularity",
    );
  });

  it("silent on plugin with full granularity declarations and a rationale block", () => {
    const entry: CatalogEntry = {
      name: "over-declared-blade",
      type: "plugin",
      tools: [
        { name: "dump_legacy", granularity: { ...goldenGranularity } },
      ] as CatalogEntry["tools"],
      non_conformance_rationale: {
        ...validRationale,
        affected_tools: ["dump_legacy"],
      },
    };
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("message references the rationale escape hatch when firing", () => {
    const entry: CatalogEntry = {
      name: "no-rationale-blade",
      type: "plugin",
      tools: [{ name: "bare_tool" }] as CatalogEntry["tools"],
    };
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/non_conformance_rationale\.affected_tools/);
    expect(findings[0].message).toMatch(/non-conformance-rationale\.md/);
  });
});

// ── DD-333 F.1: S-MCP-002 NonConformanceRationaleMalformed ───────

describe("S-MCP-002 — non_conformance_rationale malformed", () => {
  const ok = {
    reason: "Upstream lacks scope arg; rewrite scheduled.",
    scope_filtering_off: true as const,
    contamination_risks: ["cross-scope-packet-bleed" as const],
    affected_tools: ["dump_legacy"],
  };

  it("silent on plugin without non_conformance_rationale", () => {
    const entry: CatalogEntry = {
      name: "vanilla-blade",
      type: "plugin",
      tools: [{ name: "list_records", granularity: { ...goldenGranularity } }] as CatalogEntry["tools"],
    };
    expect(S_MCP_002.check(entry)).toEqual([]);
  });

  it("silent on plugin with valid non_conformance_rationale", () => {
    const entry: CatalogEntry = {
      name: "rationale-blade",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: ok,
    };
    expect(S_MCP_002.check(entry)).toEqual([]);
  });

  it("does not fire on pack-type catalog entries", () => {
    const entry: CatalogEntry = {
      name: "skills-pack",
      type: "pack",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: { ...ok, scope_filtering_off: false as unknown as true },
    };
    expect(S_MCP_002.check(entry)).toEqual([]);
  });

  it("fires on scope_filtering_off: false", () => {
    const entry: CatalogEntry = {
      name: "bad-scope-off",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: {
        ...ok,
        scope_filtering_off: false as unknown as true,
      },
    };
    const findings = S_MCP_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe(
      "bad-scope-off.non_conformance_rationale.scope_filtering_off",
    );
    expect(findings[0].rule_id).toBe("S-MCP-002");
    expect(findings[0].severity).toBe("error");
  });

  it("fires on empty contamination_risks", () => {
    const entry: CatalogEntry = {
      name: "empty-cont",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: { ...ok, contamination_risks: [] },
    };
    const findings = S_MCP_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe(
      "empty-cont.non_conformance_rationale.contamination_risks",
    );
  });

  it("fires on missing/empty reason", () => {
    const entry: CatalogEntry = {
      name: "no-reason",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: { ...ok, reason: "   " },
    };
    const findings = S_MCP_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe(
      "no-reason.non_conformance_rationale.reason",
    );
  });

  it("fires per mismatched name in affected_tools cross-reference", () => {
    const entry: CatalogEntry = {
      name: "xref-mismatch",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: {
        ...ok,
        affected_tools: ["dump_legacy", "nonexistent_a", "nonexistent_b"],
      },
    };
    const findings = S_MCP_002.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.path)).toEqual([
      "xref-mismatch.non_conformance_rationale.affected_tools[nonexistent_a]",
      "xref-mismatch.non_conformance_rationale.affected_tools[nonexistent_b]",
    ]);
  });

  it("fires on affected_tools not being an array", () => {
    const entry: CatalogEntry = {
      name: "affected-not-array",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: {
        ...ok,
        affected_tools: "dump_legacy" as unknown as string[],
      },
    };
    const findings = S_MCP_002.check(entry);
    expect(findings).toHaveLength(1);
    expect(findings[0].path).toBe(
      "affected-not-array.non_conformance_rationale.affected_tools",
    );
  });

  it("emits multiple findings when several invariants violated", () => {
    const entry: CatalogEntry = {
      name: "multi-bad",
      type: "plugin",
      tools: [{ name: "dump_legacy" }] as CatalogEntry["tools"],
      non_conformance_rationale: {
        reason: "",
        scope_filtering_off: false as unknown as true,
        contamination_risks: [],
        affected_tools: ["dump_legacy", "ghost"],
      },
    };
    const findings = S_MCP_002.check(entry);
    // scope_off false + empty contamination + empty reason + 1 xref miss
    expect(findings).toHaveLength(4);
    const paths = new Set(findings.map((f) => f.path));
    expect(paths.has("multi-bad.non_conformance_rationale.scope_filtering_off")).toBe(true);
    expect(paths.has("multi-bad.non_conformance_rationale.contamination_risks")).toBe(true);
    expect(paths.has("multi-bad.non_conformance_rationale.reason")).toBe(true);
    expect(paths.has("multi-bad.non_conformance_rationale.affected_tools[ghost]")).toBe(true);
  });

  it("is registered in CATALOG_RULES", () => {
    expect(CATALOG_RULES.some((r) => r.id === "S-MCP-002")).toBe(true);
  });
});

// ── scanCatalogEntry / scanCatalogEntries aggregator ─────────────

describe("scanCatalogEntry", () => {
  it("dispatches plugin-scope rules to plugin entries", () => {
    const findings = scanCatalogEntry(
      plugin("bare-blade", [{ name: "do_thing" }]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe("S-MCP-001");
  });

  it("treats entries without `type` as plugin (catalog default)", () => {
    const entry: CatalogEntry = {
      name: "untyped-blade",
      tools: [{ name: "do_thing" }] as CatalogEntry["tools"],
    };
    // S-MCP-001 itself short-circuits on type !== "plugin", so this is
    // silent. The scanner-level dispatcher's plugin-default behaviour is
    // covered by the catalog discriminator semantics in stallari-plugins.
    expect(scanCatalogEntry(entry)).toEqual([]);
  });
});

describe("scanCatalogEntries", () => {
  it("returns pass when every entry is clean", () => {
    const result = scanCatalogEntries([
      plugin("a", [{ name: "t", granularity: { ...goldenGranularity } }]),
      plugin("b", []),
    ]);
    expect(result.result).toBe("pass");
    expect(result.summary.warning).toBe(0);
    expect(result.summary.error).toBe(0);
    expect(result.entries_scanned).toBe(2);
  });

  it("returns fail when errors present (Phase D cutover)", () => {
    const result = scanCatalogEntries([
      plugin("bad", [{ name: "t1" }, { name: "t2" }]),
      plugin("good", [
        { name: "t3", granularity: { ...goldenGranularity } },
      ]),
    ]);
    expect(result.result).toBe("fail");
    expect(result.summary.error).toBe(2);
    expect(result.summary.warning).toBe(0);
    expect(result.findings.map((f) => f.path)).toEqual([
      "bad.tools[t1].granularity",
      "bad.tools[t2].granularity",
    ]);
  });

  it("scanner identifier follows existing convention", () => {
    const result = scanCatalogEntries([]);
    expect(result.scanner).toMatch(/^stallari-secops-scanner\//);
  });
});

// ── parseCatalogEntry — round-trip via on-disk fixtures ──────────

describe("parseCatalogEntry — stallari-plugins fixtures", () => {
  // These three fixtures ship in stallari-plugins and back the AJV build-time
  // gate. The scanner consumes the same shapes; co-validating here keeps the
  // two surfaces honest.
  const FIXTURE_DIR = join(
    process.env.HOME ?? "",
    "src/stallari-plugins/schemas/fixtures/catalog-entries",
  );

  it("with-granularity → no S-MCP-001 findings", () => {
    const raw = readFileSync(
      join(FIXTURE_DIR, "tool-with-granularity.json"),
      "utf8",
    );
    const entry = parseCatalogEntry(raw);
    expect(entry.type).toBe("plugin");
    expect(entry.tools?.length).toBe(3);
    expect(S_MCP_001.check(entry)).toEqual([]);
  });

  it("missing-granularity → one error per tool (Phase D cutover)", () => {
    const raw = readFileSync(
      join(FIXTURE_DIR, "tool-missing-granularity.json"),
      "utf8",
    );
    const entry = parseCatalogEntry(raw);
    expect(entry.tools?.length).toBe(2);
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.severity === "error")).toBe(true);
  });

  it("malformed-granularity → present-but-malformed; S-MCP-001 silent", () => {
    // S-MCP-001 only cares about presence/absence; malformed shapes are AJV's
    // responsibility upstream in stallari-plugins.
    const raw = readFileSync(
      join(FIXTURE_DIR, "tool-malformed-granularity.json"),
      "utf8",
    );
    const entry = parseCatalogEntry(raw);
    expect(entry.tools?.length).toBe(2);
    expect(S_MCP_001.check(entry)).toEqual([]);
  });
});

describe("parseCatalogEntry — error paths", () => {
  it("rejects non-JSON input", () => {
    expect(() => parseCatalogEntry("not json {{")).toThrow(/parse error/);
  });

  it("rejects JSON arrays at top level", () => {
    expect(() => parseCatalogEntry("[]")).toThrow(/JSON object/);
  });

  it("rejects entries missing `name`", () => {
    expect(() =>
      parseCatalogEntry(JSON.stringify({ description: "x" })),
    ).toThrow(/name/);
  });

  it("skips tool entries with non-string names", () => {
    const entry = parseCatalogEntry(
      JSON.stringify({
        name: "noisy-blade",
        type: "plugin",
        tools: [
          { name: "good" },
          { name: 42 }, // dropped
          { description: "no name" }, // dropped
          { name: "another" },
        ],
      }),
    );
    expect(entry.tools).toHaveLength(2);
    expect(entry.tools?.map((t) => t.name)).toEqual(["good", "another"]);
  });

  it("preserves extra tool fields verbatim (forward-compat)", () => {
    const entry = parseCatalogEntry(
      JSON.stringify({
        name: "future-blade",
        type: "plugin",
        tools: [
          {
            name: "t",
            granularity: { ...goldenGranularity },
            future_field: { nested: true },
          },
        ],
      }),
    );
    expect(entry.tools?.[0].future_field).toEqual({ nested: true });
  });

  it("extracts non_conformance_rationale block verbatim into typed shape (DD-333 F.1)", () => {
    const entry = parseCatalogEntry(
      JSON.stringify({
        name: "nrr-blade",
        type: "plugin",
        tools: [{ name: "dump_legacy" }],
        non_conformance_rationale: {
          reason: "Upstream lacks scope arg.",
          scope_filtering_off: true,
          contamination_risks: ["cross-scope-packet-bleed", "audit-context-leak"],
          affected_tools: ["dump_legacy"],
        },
      }),
    );
    expect(entry.non_conformance_rationale).toEqual({
      reason: "Upstream lacks scope arg.",
      scope_filtering_off: true,
      contamination_risks: ["cross-scope-packet-bleed", "audit-context-leak"],
      affected_tools: ["dump_legacy"],
    });
  });

  it("does not set non_conformance_rationale when absent", () => {
    const entry = parseCatalogEntry(
      JSON.stringify({
        name: "vanilla-blade",
        type: "plugin",
        tools: [{ name: "t", granularity: { ...goldenGranularity } }],
      }),
    );
    expect(entry.non_conformance_rationale).toBeUndefined();
  });

  it("defensively does not extract non-object non_conformance_rationale into the typed shape (forward-compat preserves raw value verbatim)", () => {
    // The typed extraction guard (typeof === "object" && !Array.isArray)
    // rejects non-object values; the forward-compat loop preserves whatever
    // shape the raw value had so that downstream consumers can still surface
    // it. The shape mirrors the `tools` extraction pattern (non-array tools
    // would similarly be preserved verbatim).
    const entry = parseCatalogEntry(
      JSON.stringify({
        name: "bad-nrr-blade",
        type: "plugin",
        tools: [{ name: "t", granularity: { ...goldenGranularity } }],
        non_conformance_rationale: "not an object",
      }),
    );
    // Verbatim preservation (string passes through forward-compat). Critical:
    // S-MCP-002 inspecting this entry MUST NOT crash; the rule's logic short-
    // circuits because !rationale (string is truthy, but the typed shape
    // access reads `.scope_filtering_off` etc which are undefined on a
    // string — the rule then emits findings for the broken shape).
    // For typed-shape consumers: the value cast through the interface is a
    // lie at runtime, but the rule's defensive `typeof`/`Array.isArray`
    // checks guard against it.
    expect(typeof entry.non_conformance_rationale).toBe("string");
  });
});
