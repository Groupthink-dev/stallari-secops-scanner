/**
 * DD-147 — Open pack YAML parser.
 *
 * Extracts skill and agent prompts from pack YAML for security scanning.
 * Runtime-agnostic — no Node.js built-ins. Safe for CF Workers.
 */
import type { PackYAML, ExtractedPrompt } from "./types.js";
/**
 * Parse a pack YAML string into the PackYAML subset needed for scanning.
 * Throws on YAML parse errors or missing required fields.
 */
export declare function parsePackYAML(yamlContent: string): PackYAML;
/**
 * Extract all scannable prompts from a parsed pack YAML.
 * Returns an array of { text, location } pairs.
 */
export declare function extractPrompts(pack: PackYAML): ExtractedPrompt[];
