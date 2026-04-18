/**
 * DD-147 — Clone detection via trigram Jaccard similarity.
 *
 * Deterministic, pattern-based clone detection. No ML, no embeddings.
 * Compares pack prompts against a corpus of existing pack prompts
 * and/or a corpus of known malicious prompts.
 *
 * Runtime-agnostic — no Node.js built-ins. Safe for CF Workers.
 */
import type { CorpusEntry, CloneFinding, PackYAML, ExtractedPrompt } from "./types.js";
/** Minimum prompt length for clone/threat detection (characters). */
export declare const MIN_PROMPT_LENGTH = 100;
/** Jaccard threshold for SCLN-001 (near-copy). */
export declare const THRESHOLD_HIGH = 0.85;
/** Jaccard threshold for SCLN-002 (substantial overlap). */
export declare const THRESHOLD_MEDIUM = 0.65;
/** Jaccard threshold for STHR-001 (threat match). */
export declare const THRESHOLD_THREAT = 0.7;
/**
 * Normalize text for trigram extraction.
 * Lowercase, collapse all whitespace to single space, trim.
 */
export declare function normalize(text: string): string;
/**
 * Extract character trigrams from text.
 * Returns a Set of 3-character substrings from the normalized text.
 */
export declare function extractTrigrams(text: string): Set<string>;
/**
 * Compute Jaccard similarity coefficient between two trigram sets.
 * Returns |A ∩ B| / |A ∪ B|, range [0, 1].
 */
export declare function jaccardSimilarity(a: Set<string>, b: Set<string>): number;
/**
 * Build corpus entries from raw pack data.
 * Runtime-agnostic — accepts parsed pack data, not file paths.
 * Skips prompts shorter than MIN_PROMPT_LENGTH.
 * Silently skips packs that fail to parse.
 */
export declare function buildCorpusFromPacks(packs: Array<{
    name: string;
    yaml: string;
}>): CorpusEntry[];
/**
 * Build threat corpus from known malicious prompt strings.
 * Each entry is a labelled prompt from a threat feed.
 */
export declare function buildThreatCorpus(entries: Array<{
    source: string;
    label: string;
    prompt: string;
}>): CorpusEntry[];
/**
 * Detect clones of extracted prompts against an existing pack corpus.
 *
 * For each prompt:
 *   - Skip if < MIN_PROMPT_LENGTH characters
 *   - Skip corpus entries from the same pack (by name)
 *   - Compute Jaccard similarity on trigrams
 *   - Suppress matches to the declared fork parent (suppressed=true)
 *   - If >= THRESHOLD_HIGH → SCLN-001 (high severity)
 *   - If >= THRESHOLD_MEDIUM → SCLN-002 (medium severity)
 *
 * Returns clone findings sorted by similarity descending.
 */
export declare function detectClones(prompts: ExtractedPrompt[], corpus: CorpusEntry[], pack: PackYAML): CloneFinding[];
/**
 * Match prompts against known malicious prompt corpus.
 *
 * Uses a lower threshold (0.70) because malicious prompts are often
 * slightly modified. Severity is critical. No fork suppression —
 * a "fork" of a known jailbreak is still a jailbreak.
 */
export declare function matchThreats(prompts: ExtractedPrompt[], threats: CorpusEntry[]): CloneFinding[];
