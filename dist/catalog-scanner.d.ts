/**
 * DD-333 Phase A.4 — Catalog scanner.
 *
 * Runs registered {@link CATALOG_RULES} over a set of parsed catalog entries
 * and aggregates findings into a {@link CatalogScanResult}.
 */
import type { CatalogEntry, CatalogFinding, CatalogScanResult } from "./types.js";
/** Scan a single catalog entry against all registered catalog rules. */
export declare function scanCatalogEntry(entry: CatalogEntry): CatalogFinding[];
/** Scan a list of catalog entries and aggregate findings. */
export declare function scanCatalogEntries(entries: CatalogEntry[]): CatalogScanResult;
