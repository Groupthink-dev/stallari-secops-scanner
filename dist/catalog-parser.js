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
import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join } from "node:path";
/**
 * Parse a single catalog entry JSON string. Throws on JSON parse errors or
 * missing required `name` field. Extra fields are preserved on the returned
 * record so callers can inspect them if needed.
 */
export function parseCatalogEntry(jsonContent) {
    let parsed;
    try {
        parsed = JSON.parse(jsonContent);
    }
    catch (err) {
        throw new Error(`Catalog JSON parse error: ${err.message}`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Catalog entry must be a JSON object");
    }
    const obj = parsed;
    if (!obj.name || typeof obj.name !== "string") {
        throw new Error('Catalog entry missing required field: "name"');
    }
    // Normalise tools[] — keep only the fields the scanner reads, but preserve
    // any extras on each tool entry.
    let tools;
    if (Array.isArray(obj.tools)) {
        tools = [];
        for (const item of obj.tools) {
            if (!item || typeof item !== "object" || Array.isArray(item))
                continue;
            const t = item;
            if (typeof t.name !== "string")
                continue;
            const tool = { name: t.name };
            if (typeof t.description === "string")
                tool.description = t.description;
            if (typeof t.risk_class === "string")
                tool.risk_class = t.risk_class;
            if (t.granularity &&
                typeof t.granularity === "object" &&
                !Array.isArray(t.granularity)) {
                tool.granularity = t.granularity;
            }
            // Preserve any other tool fields verbatim for forward-compat.
            for (const [k, v] of Object.entries(t)) {
                if (k in tool)
                    continue;
                tool[k] = v;
            }
            tools.push(tool);
        }
    }
    const entry = { name: obj.name };
    if (typeof obj.type === "string" && (obj.type === "plugin" || obj.type === "pack")) {
        entry.type = obj.type;
    }
    if (typeof obj.description === "string")
        entry.description = obj.description;
    if (typeof obj.version === "string")
        entry.version = obj.version;
    if (obj.tier === null ||
        obj.tier === "certified" ||
        obj.tier === "verified" ||
        obj.tier === "community") {
        entry.tier = obj.tier;
    }
    if (tools)
        entry.tools = tools;
    // Preserve other top-level catalog fields for forward-compat.
    for (const [k, v] of Object.entries(obj)) {
        if (k in entry)
            continue;
        entry[k] = v;
    }
    return entry;
}
/**
 * Load all catalog entries from a directory (one JSON file per entry).
 * Used by the CLI; library consumers can call `parseCatalogEntry` directly
 * for in-memory scanning.
 *
 * Silently skips non-JSON files and entries whose names aren't strings;
 * propagates parse errors with the offending filename for actionable output.
 */
export function loadCatalogDir(dir) {
    const stat = statSync(dir);
    if (!stat.isDirectory()) {
        throw new Error(`Catalog path is not a directory: ${dir}`);
    }
    const entries = [];
    for (const file of readdirSync(dir)) {
        if (extname(file) !== ".json")
            continue;
        const full = join(dir, file);
        const st = statSync(full);
        if (!st.isFile())
            continue;
        let raw;
        try {
            raw = readFileSync(full, "utf8");
        }
        catch (err) {
            throw new Error(`Failed to read ${full}: ${err.message}`);
        }
        try {
            entries.push(parseCatalogEntry(raw));
        }
        catch (err) {
            throw new Error(`${file}: ${err.message}`);
        }
    }
    return entries;
}
