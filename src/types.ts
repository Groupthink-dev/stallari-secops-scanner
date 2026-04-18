/** Severity levels for scan findings. */
export type Severity = "critical" | "high" | "medium" | "low";

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
