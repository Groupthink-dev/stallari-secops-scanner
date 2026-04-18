/**
 * DD-147 — Open pack YAML parser.
 *
 * Extracts skill and agent prompts from pack YAML for security scanning.
 * Runtime-agnostic — no Node.js built-ins. Safe for CF Workers.
 */

import { parse as parseYaml } from "yaml";
import type { PackYAML, ExtractedPrompt } from "./types.js";

/**
 * Parse a pack YAML string into the PackYAML subset needed for scanning.
 * Throws on YAML parse errors or missing required fields.
 */
export function parsePackYAML(yamlContent: string): PackYAML {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseYaml(yamlContent);
  } catch (err) {
    throw new Error(`YAML parse error: ${(err as Error).message}`);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error("Pack YAML must be a mapping");
  }
  if (!parsed.name || typeof parsed.name !== "string") {
    throw new Error('Missing required field: "name"');
  }
  if (!Array.isArray(parsed.skills)) {
    throw new Error('Missing required field: "skills" (must be an array)');
  }

  // Extract agents dict: { name: { role, prompt, ... } }
  const agents: Record<string, { prompt?: string }> = {};
  if (
    parsed.agents &&
    typeof parsed.agents === "object" &&
    !Array.isArray(parsed.agents)
  ) {
    for (const [name, value] of Object.entries(
      parsed.agents as Record<string, unknown>,
    )) {
      if (value && typeof value === "object") {
        const v = value as Record<string, unknown>;
        agents[name] = {
          prompt: typeof v.prompt === "string" ? v.prompt : undefined,
        };
      }
    }
  }

  // Extract skills array: [{ name, prompt, ... }]
  const skills: Array<{ name: string; prompt?: string }> = [];
  for (const item of parsed.skills) {
    if (item && typeof item === "object" && typeof item.name === "string") {
      skills.push({
        name: item.name,
        prompt: typeof item.prompt === "string" ? item.prompt : undefined,
      });
    }
  }

  // Extract forked_from
  let forked_from: { name: string; version: string } | undefined;
  if (parsed.forked_from && typeof parsed.forked_from === "object") {
    const ff = parsed.forked_from as Record<string, unknown>;
    if (typeof ff.name === "string" && typeof ff.version === "string") {
      forked_from = { name: ff.name, version: ff.version };
    }
  }

  return {
    name: parsed.name as string,
    version:
      typeof parsed.version === "string"
        ? parsed.version
        : String(parsed.version ?? "0.0.0"),
    forked_from,
    agents,
    skills,
  };
}

/**
 * Extract all scannable prompts from a parsed pack YAML.
 * Returns an array of { text, location } pairs.
 */
export function extractPrompts(pack: PackYAML): ExtractedPrompt[] {
  const prompts: ExtractedPrompt[] = [];

  // Agent prompts (dict)
  for (const [name, agent] of Object.entries(pack.agents)) {
    if (agent.prompt) {
      prompts.push({ text: agent.prompt, location: `agents.${name}` });
    }
  }

  // Skill prompts (array)
  for (const skill of pack.skills) {
    if (skill.prompt) {
      prompts.push({ text: skill.prompt, location: `skills.${skill.name}` });
    }
  }

  return prompts;
}
