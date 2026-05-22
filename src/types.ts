/** Severity levels for scan findings. */
export type Severity = "critical" | "high" | "medium" | "low";

/**
 * Lint-style severities for catalog-rule findings (DD-333 S-MCP-001).
 *
 * Distinct from {@link Severity} which scores prompt-injection risk.
 * Catalog lint rules ship at `.warning` first and may be promoted to
 * `.error` once an ecosystem grace window elapses.
 */
export type LintSeverity = "warning" | "error";

// ── DD-333: Catalog entry types ─────────────────────────────────

/**
 * Per-tool granularity declaration on a catalog plugin's tools[] entry.
 * Mirrors the JSON-schema fragment in
 * `stallari-plugins/schemas/catalog-entry.schema.json`. All four dimensions
 * are required when the block is present; the block as a whole is optional
 * at pack-spec 3.x (additive).
 */
export interface ToolGranularity {
  scope_filtering: "server-side" | "client-side" | "none" | "non-conforming-explicit";
  field_projection: "per-field" | "top-level" | "none";
  deterministic_ordering: "stable" | "unstable" | "unsorted";
  audit_surface: "structured" | "minimal" | "none";
}

/**
 * DD-333 F.1 — non-conformance rationale block on a plugin catalog entry.
 *
 * Authors declare this top-level block to acknowledge honest non-conformance
 * with the granularity contract. The stallari-plugins build pipeline
 * (`scripts/build-catalog.js`) derives `granularity.scope_filtering:
 * "non-conforming-explicit"` for each tool listed in `affected_tools` whose
 * own granularity block is omitted; the rationale block flows verbatim onto
 * the catalog row for downstream consumption.
 *
 * Sister amendments out of scope for F.1:
 * - [[DD-189]] — UI surfaces for informed-consent warning copy.
 * - [[DD-301]] — memory contamination propagation when non-conforming tools
 *   land in an `assemblySteps` chain.
 *
 * The cross-field invariant — every `affected_tools[i]` MUST cross-reference
 * a real `tools[].name` — is enforced procedurally in
 * `stallari-plugins/scripts/build-catalog.js` AND by S-MCP-002 in this
 * scanner against post-build catalog state.
 */
export interface NonConformanceRationale {
  /** Non-empty author-supplied explanation. Surfaces in UI + audit Tracks. */
  reason: string;
  /** Explicit acknowledgment. MUST be `true` when block present. */
  scope_filtering_off: true;
  /** Controlled vocabulary; non-empty. */
  contamination_risks: Array<
    | "memory-source-tainted"
    | "audit-context-leak"
    | "cross-scope-packet-bleed"
    | "other-see-reason"
  >;
  /**
   * Tool names from this entry's `tools[].name`. Cross-field invariant —
   * every entry MUST reference an actual tool.
   */
  affected_tools: string[];
}

/** Per-tool entry inside a catalog plugin's tools[] array. */
export interface CatalogTool {
  name: string;
  description?: string;
  risk_class?: string;
  granularity?: ToolGranularity;
  /** Other free-form fields are tolerated; we only consume name + granularity. */
  [key: string]: unknown;
}

/**
 * DD-341 Phase C — domain_access block lifted from pack manifest onto the
 * catalog entry by the stallari-plugins build pipeline. S-DOM-001 checks
 * for its presence on pack-type catalog entries.
 *
 * Shape mirrors pack-spec v4.3.0 `domain_access:` block. Only the presence
 * of the key matters for S-DOM-001; field-level validation is upstream in
 * the pack-spec AJV schema gate.
 */
export interface DomainAccessBlock {
  /** Plain-language explanation of what vault content the pack reads (10-240 chars). */
  description: string;
  /** True if the pack needs access to sensitive content. Default false. */
  needs_sensitive?: boolean;
  /** Display hint only — example domain names in other users' vaults. ≤8 items. */
  examples_in_other_vaults?: string[];
}

/**
 * Parsed catalog entry (subset). Plugins declare tools; packs do not.
 * Schema lives in stallari-plugins; we read only the fields S-MCP-001
 * + S-MCP-002 care about.
 */
export interface CatalogEntry {
  name: string;
  type?: "plugin" | "pack";
  description?: string;
  version?: string;
  tier?: "certified" | "verified" | "community" | null;
  tools?: CatalogTool[];
  /** DD-333 F.1 — non-conformance rationale (when declared). */
  non_conformance_rationale?: NonConformanceRationale;
  /**
   * DD-341 Phase C — domain_access block lifted from pack manifest by the
   * stallari-plugins build pipeline. Present on conformant pack entries;
   * absent on packs predating pack-spec v4.3.0 or packs that omit the block.
   * S-DOM-001 flags absence on pack-type entries.
   */
  domain_access?: DomainAccessBlock | null;
  /** Free-form catalog metadata not consumed by lint rules. */
  [key: string]: unknown;
}

/** A single finding from a catalog-rule scan. */
export interface CatalogFinding {
  rule_id: string;
  severity: LintSeverity;
  category: string;
  name: string;
  message: string;
  /** JSON-path-like locator, e.g. "example-blade-mcp.tools[list_records].granularity". */
  path: string;
}

/** A catalog rule (DD-333 S-MCP-001 onwards) — runs structurally over CatalogEntry. */
export interface CatalogRule {
  id: string;
  name: string;
  category: string;
  severity: LintSeverity;
  description: string;
  /** Which catalog entry types this rule applies to. */
  appliesTo: "plugin" | "pack" | "catalog-entry";
  check: (entry: CatalogEntry) => CatalogFinding[];
}

/** Aggregated result of a catalog scan. */
export interface CatalogScanResult {
  version: string;
  scanner: string;
  scan_date: string;
  /** "pass" when no error-severity findings; "warn" with warning-only findings. */
  result: "pass" | "warn" | "fail";
  entries_scanned: number;
  findings: CatalogFinding[];
  summary: Record<LintSeverity, number>;
}

/** A single scan rule definition. */
export interface Rule {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  description: string;
  /** Regex patterns matched against prompt text. */
  patterns: RegExp[];
  /** Optional structural check run against the full payload context. */
  structural?: (ctx: StructuralContext) => Finding[];
}

/** Context passed to structural rule checks. */
export interface StructuralContext {
  /** The prompt text being scanned. */
  prompt: string;
  /** Which skill or agent this prompt belongs to. */
  location: string;
  /** Declared data.reads from the manifest (if provided). */
  declaredReads?: string[];
  /** Declared data.writes from the manifest (if provided). */
  declaredWrites?: string[];
  /** Declared requires.services from the manifest (if provided). */
  declaredServices?: string[];
}

/** A single finding from a scan. */
export interface Finding {
  rule_id: string;
  severity: Severity;
  category: string;
  name: string;
  message: string;
  /** e.g. "skills.my-skill" or "agents.my-agent" */
  location: string;
  /** The matched text snippet (truncated). */
  matched?: string;
}

/** Exception entry — a rule explicitly approved for a pack. */
export interface ScanException {
  rule_id: string;
  justification: string;
}

/** Input payload format (decrypted sealed pack payload). */
export interface SealedPayload {
  pack: string;
  version: string;
  skills: Record<string, string>;
  agents: Record<string, string>;
}

/** Optional manifest context for structural checks. */
export interface ManifestContext {
  data?: {
    reads?: string[];
    writes?: string[];
  };
  requires?: {
    services?: Array<{ service: string }>;
  };
}

/** Full scan result. */
export interface ScanResult {
  version: string;
  scanner: string;
  pack: string;
  scan_date: string;
  result: "pass" | "fail" | "warn";
  findings: Finding[];
  exceptions_applied: string[];
  summary: Record<Severity, number>;
}

// ── DD-147: Open pack types ─────────────────────────────────────

/** Parsed open pack YAML (subset needed for scanning). */
export interface PackYAML {
  name: string;
  version: string;
  forked_from?: { name: string; version: string };
  agents: Record<string, { prompt?: string }>;
  skills: Array<{ name: string; prompt?: string }>;
}

/** A prompt extracted from a pack YAML. */
export interface ExtractedPrompt {
  text: string;
  /** e.g. "skills.site-status" or "agents.home-operator" */
  location: string;
}

/** Clone detection corpus entry (pre-computed trigrams). */
export interface CorpusEntry {
  pack_name: string;
  location: string;
  prompt: string;
  trigrams: Set<string>;
}

/** Clone/threat detection finding. */
export interface CloneFinding {
  rule_id: string;
  severity: Severity;
  category: string;
  name: string;
  message: string;
  location: string;
  source_pack: string;
  source_location: string;
  similarity: number;
  /** True if similarity is to a declared fork parent — informational only. */
  suppressed: boolean;
}

/** Full scan result for open pack YAML. */
export interface PackScanResult extends ScanResult {
  clone_findings: CloneFinding[];
}
