/**
 * DD-147 Phase 6 — Bundled threat corpus.
 *
 * Curated entries representing families of known malicious prompt patterns
 * relevant to MCP tool-calling agents. Used by STHR-001 matching.
 *
 * Runtime-agnostic — safe for both CLI and CF Workers.
 */
import type { CorpusEntry } from "./types.js";
export interface ThreatEntry {
    source: string;
    label: string;
    category: string;
    prompt: string;
}
/**
 * Raw threat corpus entries. Exported for inspection/testing.
 * To add entries: append to this array, rebuild, and redeploy.
 */
export declare const BUNDLED_THREAT_ENTRIES: ThreatEntry[];
/** Corpus version — bump when entries are added or modified. */
export declare const BUNDLED_THREATS_VERSION = "1.0.0";
/**
 * Build the bundled threat corpus (pre-computed trigrams).
 * Returns CorpusEntry[] ready for `matchThreats()`.
 */
export declare function loadBundledThreats(): CorpusEntry[];
