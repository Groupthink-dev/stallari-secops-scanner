#!/usr/bin/env node
/**
 * DD-120 Phase 2 + DD-147 — CLI entry point.
 *
 * Usage:
 *   stallari-secops-scanner scan <payload.json> [--manifest <manifest.json>] [--exceptions <exceptions.yaml>]
 *   stallari-secops-scanner scan --stdin [--manifest <manifest.json>]
 *   stallari-secops-scanner scan-pack <pack.yaml> [--corpus <dir>] [--threats <file.json>] [--exceptions <file>]
 *
 * Exit codes:
 *   0 — pass (no findings, or only excepted findings)
 *   1 — fail (critical or high severity findings)
 *   2 — warn (medium or low severity findings only)
 */
export {};
