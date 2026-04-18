/**
 * DD-120 Phase 2 — Core scanner engine.
 *
 * Runs all registered rules against each prompt in a sealed payload.
 * Returns structured findings with severity-based pass/fail/warn result.
 */
import type { CorpusEntry, Finding, ManifestContext, PackScanResult, ScanException, ScanResult, SealedPayload } from "./types.js";
export declare const SCANNER_VERSION = "0.3.0";
export interface ScanOptions {
    /** Manifest context for structural checks. */
    manifest?: ManifestContext;
    /** Approved exceptions (from scan_exceptions.yaml). */
    exceptions?: ScanException[];
}
/**
 * Scan a single prompt string against all rules.
 */
export declare function scanPrompt(prompt: string, location: string, options?: ScanOptions): Finding[];
/**
 * Scan an entire sealed payload.
 *
 * Iterates over all skills and agents, runs every rule, applies exceptions,
 * and returns a structured result.
 */
export declare function scanPayload(payload: SealedPayload, options?: ScanOptions): ScanResult;
export interface PackScanOptions extends ScanOptions {
    /** Pre-built corpus of existing pack prompts for clone detection. */
    corpus?: CorpusEntry[];
    /** Pre-built corpus of known malicious prompts for threat matching. */
    threats?: CorpusEntry[];
}
/**
 * Scan an open pack YAML file.
 *
 * Parses the YAML, extracts all prompts, runs SINJ rules against each,
 * and optionally runs clone detection and threat matching.
 *
 * Runtime-agnostic — caller provides corpus/threat data.
 */
export declare function scanPackYAML(yamlContent: string, options?: PackScanOptions): PackScanResult;
