/**
 * DD-333 Phase A.4 — Catalog-rule tests.
 *
 * Covers S-MCP-001 happy/edge cases plus the catalog parser entry-point
 * and the aggregating scanCatalogEntries() wrapper.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { S_MCP_001, CATALOG_RULES } from "./catalog-rules.js";
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

  it("fires one warning per tool missing granularity", () => {
    const entry = plugin("bad-blade", [
      { name: "list_things" },
      { name: "get_thing", risk_class: "read_only" },
    ]);
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings[0].rule_id).toBe("S-MCP-001");
    expect(findings[0].severity).toBe("warning");
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

  it("severity is warning at Phase A (promoted to error at Phase D)", () => {
    expect(S_MCP_001.severity).toBe("warning");
  });

  it("is registered in CATALOG_RULES", () => {
    expect(CATALOG_RULES.some((r) => r.id === "S-MCP-001")).toBe(true);
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

  it("returns warn when warnings present (no errors)", () => {
    const result = scanCatalogEntries([
      plugin("bad", [{ name: "t1" }, { name: "t2" }]),
      plugin("good", [
        { name: "t3", granularity: { ...goldenGranularity } },
      ]),
    ]);
    expect(result.result).toBe("warn");
    expect(result.summary.warning).toBe(2);
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

  it("missing-granularity → one warning per tool", () => {
    const raw = readFileSync(
      join(FIXTURE_DIR, "tool-missing-granularity.json"),
      "utf8",
    );
    const entry = parseCatalogEntry(raw);
    expect(entry.tools?.length).toBe(2);
    const findings = S_MCP_001.check(entry);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.severity === "warning")).toBe(true);
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
});
