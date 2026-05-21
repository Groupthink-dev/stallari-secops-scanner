/**
 * DD-333 Phase A.4 — Catalog entry parser.
 *
 * Loads `stallari-plugins/plugins/tools/*.json` catalog entries for catalog-rule
 * scanning. Runtime-agnostic at the parse layer (string-in, struct-out); the
 * directory-scan helper uses node:fs and is for CLI consumption.
 *
 * Pattern mirrors `pack-parser.ts` — minimal extraction of the fields the
 * scanner cares about, tolerant of extra properties.
 */
import type { CatalogEntry } from "./types.js";
/**
 * Parse a single catalog entry JSON string. Throws on JSON parse errors or
 * missing required `name` field. Extra fields are preserved on the returned
 * record so callers can inspect them if needed.
 */
export declare function parseCatalogEntry(jsonContent: string): CatalogEntry;
/**
 * Load all catalog entries from a directory (one JSON file per entry).
 * Used by the CLI; library consumers can call `parseCatalogEntry` directly
 * for in-memory scanning.
 *
 * Silently skips non-JSON files and entries whose names aren't strings;
 * propagates parse errors with the offending filename for actionable output.
 */
export declare function loadCatalogDir(dir: string): CatalogEntry[];
