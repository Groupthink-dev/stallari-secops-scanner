/**
 * DD-147 — Clone detection via trigram Jaccard similarity.
 *
 * Deterministic, pattern-based clone detection. No ML, no embeddings.
 * Compares pack prompts against a corpus of existing pack prompts
 * and/or a corpus of known malicious prompts.
 *
 * Runtime-agnostic — no Node.js built-ins. Safe for CF Workers.
 */

import { parsePackYAML, extractPrompts } from "./pack-parser.js";
import type {
  CorpusEntry,
  CloneFinding,
  PackYAML,
  ExtractedPrompt,
} from "./types.js";

/** Minimum prompt length for clone/threat detection (characters). */
export const MIN_PROMPT_LENGTH = 100;

/** Jaccard threshold for SCLN-001 (near-copy). */
export const THRESHOLD_HIGH = 0.85;

/** Jaccard threshold for SCLN-002 (substantial overlap). */
export const THRESHOLD_MEDIUM = 0.65;

/** Jaccard threshold for STHR-001 (threat match). */
export const THRESHOLD_THREAT = 0.70;

/**
 * Normalize text for trigram extraction.
 * Lowercase, collapse all whitespace to single space, trim.
 */
export function normalize(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Extract character trigrams from text.
 * Returns a Set of 3-character substrings from the normalized text.
 */
export function extractTrigrams(text: string): Set<string> {
  const normalized = normalize(text);
  const trigrams = new Set<string>();
  for (let i = 0; i <= normalized.length - 3; i++) {
    trigrams.add(normalized.slice(i, i + 3));
  }
  return trigrams;
}

/**
 * Compute Jaccard similarity coefficient between two trigram sets.
 * Returns |A ∩ B| / |A ∪ B|, range [0, 1].
 */
export function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;

  let intersection = 0;
  const [smaller, larger] = a.size <= b.size ? [a, b] : [b, a];
  for (const item of smaller) {
    if (larger.has(item)) intersection++;
  }

  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Build corpus entries from raw pack data.
 * Runtime-agnostic — accepts parsed pack data, not file paths.
 * Skips prompts shorter than MIN_PROMPT_LENGTH.
 * Silently skips packs that fail to parse.
 */
export function buildCorpusFromPacks(
  packs: Array<{ name: string; yaml: string }>,
): CorpusEntry[] {
  const entries: CorpusEntry[] = [];

  for (const { name, yaml } of packs) {
    let pack: PackYAML;
    try {
      pack = parsePackYAML(yaml);
    } catch {
      continue;
    }

    const prompts = extractPrompts(pack);
    for (const p of prompts) {
      if (p.text.length < MIN_PROMPT_LENGTH) continue;
      entries.push({
        pack_name: name,
        location: p.location,
        prompt: p.text,
        trigrams: extractTrigrams(p.text),
      });
    }
  }

  return entries;
}

/**
 * Build threat corpus from known malicious prompt strings.
 * Each entry is a labelled prompt from a threat feed.
 */
export function buildThreatCorpus(
  entries: Array<{ source: string; label: string; prompt: string }>,
): CorpusEntry[] {
  return entries
    .filter((e) => e.prompt.length >= MIN_PROMPT_LENGTH)
    .map((e) => ({
      pack_name: e.source,
      location: e.label,
      prompt: e.prompt,
      trigrams: extractTrigrams(e.prompt),
    }));
}

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
export function detectClones(
  prompts: ExtractedPrompt[],
  corpus: CorpusEntry[],
  pack: PackYAML,
): CloneFinding[] {
  const findings: CloneFinding[] = [];

  for (const p of prompts) {
    if (p.text.length < MIN_PROMPT_LENGTH) continue;
    const trigrams = extractTrigrams(p.text);

    for (const entry of corpus) {
      if (entry.pack_name === pack.name) continue;

      const similarity = jaccardSimilarity(trigrams, entry.trigrams);
      const isForkParent = pack.forked_from?.name === entry.pack_name;

      if (similarity >= THRESHOLD_HIGH) {
        findings.push({
          rule_id: "SCLN-001",
          severity: "high",
          category: "clone-detection",
          name: "Near-copy prompt",
          message: `Prompt is ${(similarity * 100).toFixed(0)}% similar to ${entry.pack_name}/${entry.location}`,
          location: p.location,
          source_pack: entry.pack_name,
          source_location: entry.location,
          similarity,
          suppressed: isForkParent,
        });
      } else if (similarity >= THRESHOLD_MEDIUM) {
        findings.push({
          rule_id: "SCLN-002",
          severity: "medium",
          category: "clone-detection",
          name: "Substantial prompt overlap",
          message: `Prompt is ${(similarity * 100).toFixed(0)}% similar to ${entry.pack_name}/${entry.location}`,
          location: p.location,
          source_pack: entry.pack_name,
          source_location: entry.location,
          similarity,
          suppressed: isForkParent,
        });
      }
    }
  }

  return findings.sort((a, b) => b.similarity - a.similarity);
}

/**
 * Match prompts against known malicious prompt corpus.
 *
 * Uses a lower threshold (0.70) because malicious prompts are often
 * slightly modified. Severity is critical. No fork suppression —
 * a "fork" of a known jailbreak is still a jailbreak.
 */
export function matchThreats(
  prompts: ExtractedPrompt[],
  threats: CorpusEntry[],
): CloneFinding[] {
  const findings: CloneFinding[] = [];

  for (const p of prompts) {
    if (p.text.length < MIN_PROMPT_LENGTH) continue;
    const trigrams = extractTrigrams(p.text);

    for (const threat of threats) {
      const similarity = jaccardSimilarity(trigrams, threat.trigrams);

      if (similarity >= THRESHOLD_THREAT) {
        findings.push({
          rule_id: "STHR-001",
          severity: "critical",
          category: "threat-match",
          name: "Known malicious prompt match",
          message: `Prompt is ${(similarity * 100).toFixed(0)}% similar to known threat: ${threat.pack_name}/${threat.location}`,
          location: p.location,
          source_pack: threat.pack_name,
          source_location: threat.location,
          similarity,
          suppressed: false,
        });
      }
    }
  }

  return findings.sort((a, b) => b.similarity - a.similarity);
}
