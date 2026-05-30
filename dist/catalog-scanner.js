/**
 * DD-333 Phase A.4 — Catalog scanner.
 *
 * Runs registered {@link CATALOG_RULES} over a set of parsed catalog entries
 * and aggregates findings into a {@link CatalogScanResult}.
 */
import { CATALOG_RULES } from "./catalog-rules.js";
import { PACK_DOMAIN_RULES } from "./pack-domain-rules.js";
import { SCANNER_VERSION } from "./scanner.js";
/**
 * All registered catalog rules — MCP granularity rules (DD-333) plus pack
 * domain-access rules (DD-341 Phase C).
 */
const ALL_CATALOG_RULES = [
    ...CATALOG_RULES,
    ...PACK_DOMAIN_RULES,
];
/** Scan a single catalog entry against all registered catalog rules. */
export function scanCatalogEntry(entry) {
    const findings = [];
    for (const rule of ALL_CATALOG_RULES) {
        if (rule.appliesTo !== "catalog-entry") {
            // Discriminate plugin/pack — entries without an explicit type field are
            // treated as plugin per the catalog discriminated union default.
            const entryType = entry.type ?? "plugin";
            if (rule.appliesTo !== entryType)
                continue;
        }
        findings.push(...rule.check(entry));
    }
    return findings;
}
/** Scan a list of catalog entries and aggregate findings. */
export function scanCatalogEntries(entries) {
    const findings = [];
    for (const entry of entries) {
        findings.push(...scanCatalogEntry(entry));
    }
    const summary = { warning: 0, error: 0 };
    for (const f of findings)
        summary[f.severity]++;
    // DD-333 Phase D (cutover 2026-05-21): S-MCP-001 ships at .error —
    // missing granularity → `fail`. `warn` remains the outcome for any
    // future advisory rules registered at lower severity.
    let result = "pass";
    if (summary.error > 0)
        result = "fail";
    else if (summary.warning > 0)
        result = "warn";
    return {
        version: "1.0",
        scanner: `stallari-secops-scanner/${SCANNER_VERSION}`,
        scan_date: new Date().toISOString(),
        result,
        entries_scanned: entries.length,
        findings,
        summary,
    };
}
