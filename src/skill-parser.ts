/**
 * DD-370 — Skill manifest frontmatter parser.
 *
 * The existing `pack-parser.ts` reads pack.yaml only (for prompt-injection
 * scanning of the `skills[]` import array). It does NOT read per-skill `.md`
 * frontmatter — where the DD-344 v4.5 manifest contract (`risk_class`,
 * `track_emits`, `sealed_credentials`, `domain_access`) lives. This module
 * adds that reader so S-SKL-001 can lint the contract.
 *
 * Pure functions (string in, struct out) — runtime-agnostic, no Node.js
 * built-ins, CF-Worker-safe, mirroring `pack-parser.ts`. The fs-using
 * directory helper lives in the CLI (`cli.ts`), not here.
 */

import { parse as parseYaml } from "yaml";
import type {
  PackYAML,
  SkillImportEntry,
  SkillManifest,
} from "./types.js";

/** Split a markdown doc into `{ frontmatter, body }` on the leading `---` fence. */
export function splitFrontmatter(md: string): { frontmatter: string; body: string } {
  // Tolerate a leading BOM / whitespace before the first fence.
  const trimmed = md.replace(/^﻿/, "");
  const match = trimmed.match(/^\s*---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    return { frontmatter: "", body: trimmed };
  }
  return { frontmatter: match[1], body: match[2] ?? "" };
}

/**
 * Parse a skill `.md` into its v4.5 manifest subset + body. Never throws on
 * a malformed/absent frontmatter — returns an empty manifest (the lint then
 * sees "no contract", which is the correct signal for an uncontracted skill).
 */
export function parseSkillManifest(md: string): { manifest: SkillManifest; body: string } {
  const { frontmatter, body } = splitFrontmatter(md);
  if (!frontmatter.trim()) {
    return { manifest: {}, body };
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(frontmatter);
  } catch {
    // Malformed YAML frontmatter → treat as uncontracted (lint will flag).
    return { manifest: {}, body };
  }
  if (!parsed || typeof parsed !== "object") {
    return { manifest: {}, body };
  }
  return { manifest: parsed as SkillManifest, body };
}

/**
 * Parse the pack.yaml `skills[]` import array into a map keyed by the import
 * path's basename (the skill slug). Tolerant of the prompt-injection
 * `PackYAML` shape used elsewhere — we read the richer raw object here.
 */
export function parseSkillImports(packYamlContent: string): Map<string, SkillImportEntry> {
  const out = new Map<string, SkillImportEntry>();
  let parsed: Record<string, unknown>;
  try {
    parsed = parseYaml(packYamlContent) as Record<string, unknown>;
  } catch {
    return out;
  }
  const skills = parsed?.skills;
  if (!Array.isArray(skills)) return out;
  for (const entry of skills) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as SkillImportEntry;
    const slug = skillSlug(e);
    if (slug) out.set(slug, e);
  }
  return out;
}

/** Derive the skill slug from an import entry (`./skills/refund-processor.md` → `refund-processor`). */
export function skillSlug(entry: SkillImportEntry): string | null {
  if (typeof entry.import === "string") {
    const base = entry.import.split("/").pop() ?? entry.import;
    return base.replace(/\.md$/i, "");
  }
  if (typeof entry.name === "string") return entry.name;
  return null;
}

/**
 * Flatten the union of declared service ops to `service.op` form, drawing
 * from BOTH contract surfaces: the skill frontmatter `required_services` /
 * `optional_services` (post-uplift) AND the pack.yaml import `services_used`
 * (pre-uplift). De-duplicated.
 */
export function flattenServiceOps(
  manifest: SkillManifest,
  importEntry?: SkillImportEntry,
): string[] {
  const ops = new Set<string>();
  for (const s of manifest.required_services ?? []) if (typeof s === "string") ops.add(s);
  for (const s of manifest.optional_services ?? []) if (typeof s === "string") ops.add(s);
  for (const s of importEntry?.required_services ?? []) if (typeof s === "string") ops.add(s);
  for (const su of importEntry?.services_used ?? []) {
    if (!su || typeof su !== "object" || !Array.isArray(su.operations)) continue;
    for (const op of su.operations) {
      if (typeof op === "string") ops.add(`${su.service}.${op}`);
    }
  }
  return [...ops];
}

// Re-export the prompt-injection PackYAML shape for callers that want both.
export type { PackYAML };
