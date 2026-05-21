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
/**
 * Per-tool granularity declaration on a catalog plugin's tools[] entry.
 * Mirrors the JSON-schema fragment in
 * `stallari-plugins/schemas/catalog-entry.schema.json`. All four dimensions
 * are required when the block is present; the block as a whole is optional
 * at pack-spec 3.x (additive).
 */
export interface ToolGranularity {
    scope_filtering: "server-side" | "client-side" | "none";
    field_projection: "per-field" | "top-level" | "none";
    deterministic_ordering: "stable" | "unstable" | "unsorted";
    audit_surface: "structured" | "minimal" | "none";
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
 * Parsed catalog entry (subset). Plugins declare tools; packs do not.
 * Schema lives in stallari-plugins; we read only the fields S-MCP-001
 * cares about.
 */
export interface CatalogEntry {
    name: string;
    type?: "plugin" | "pack";
    description?: string;
    version?: string;
    tier?: "certified" | "verified" | "community" | null;
    tools?: CatalogTool[];
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
        services?: Array<{
            service: string;
        }>;
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
/** Parsed open pack YAML (subset needed for scanning). */
export interface PackYAML {
    name: string;
    version: string;
    forked_from?: {
        name: string;
        version: string;
    };
    agents: Record<string, {
        prompt?: string;
    }>;
    skills: Array<{
        name: string;
        prompt?: string;
    }>;
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
