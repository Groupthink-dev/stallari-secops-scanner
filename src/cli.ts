#!/usr/bin/env node
/**
 * DD-120 Phase 2 — CLI entry point.
 *
 * Usage:
 *   sidereal-secops-scanner scan <payload.json> [--manifest <manifest.json>] [--exceptions <exceptions.yaml>]
 *   sidereal-secops-scanner scan --stdin [--manifest <manifest.json>]
 *
 * Exit codes:
 *   0 — pass (no findings, or only excepted findings)
 *   1 — fail (critical or high severity findings)
 *   2 — warn (medium or low severity findings only)
 */

import { readFileSync } from "node:fs";
import { scanPayload, SCANNER_VERSION } from "./scanner.js";
import type { ManifestContext, ScanException, SealedPayload } from "./types.js";

function usage(): never {
  console.error(`sidereal-secops-scanner v${SCANNER_VERSION}

Usage:
  sidereal-secops-scanner scan <payload.json> [options]
  sidereal-secops-scanner scan --stdin [options]

Options:
  --manifest <file>     Manifest JSON for structural checks
  --exceptions <file>   YAML/JSON exceptions file
  --json                Output raw JSON (default: human-readable)
  --help                Show this help

Exit codes: 0=pass, 1=fail (critical/high), 2=warn (medium/low)`);
  return process.exit(2) as never;
}

function parseArgs(argv: string[]) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("--help")) usage();
  if (args[0] !== "scan") {
    console.error(`Unknown command: ${args[0]}`);
    usage();
  }

  let payloadPath: string | null = null;
  let manifestPath: string | null = null;
  let exceptionsPath: string | null = null;
  let fromStdin = false;
  let jsonOutput = false;

  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case "--stdin":
        fromStdin = true;
        break;
      case "--manifest":
        manifestPath = args[++i];
        break;
      case "--exceptions":
        exceptionsPath = args[++i];
        break;
      case "--json":
        jsonOutput = true;
        break;
      default:
        if (args[i].startsWith("-")) {
          console.error(`Unknown option: ${args[i]}`);
          usage();
        }
        payloadPath = args[i];
    }
  }

  if (!payloadPath && !fromStdin) usage();
  return { payloadPath, manifestPath, exceptionsPath, fromStdin, jsonOutput };
}

function readPayload(path: string | null, fromStdin: boolean): SealedPayload {
  let raw: string;
  if (fromStdin) {
    raw = readFileSync(0, "utf8");
  } else {
    raw = readFileSync(path!, "utf8");
  }
  return JSON.parse(raw);
}

function readManifest(path: string | null): ManifestContext | undefined {
  if (!path) return undefined;
  return JSON.parse(readFileSync(path, "utf8"));
}

function readExceptions(path: string | null): ScanException[] | undefined {
  if (!path) return undefined;
  const raw = readFileSync(path, "utf8");
  // Support both JSON and simple YAML (array of {rule_id, justification})
  try {
    return JSON.parse(raw);
  } catch {
    // Minimal YAML parsing for simple array format
    const exceptions: ScanException[] = [];
    const lines = raw.split("\n");
    let current: Partial<ScanException> = {};
    for (const line of lines) {
      const ruleMatch = line.match(/^\s*-?\s*rule_id:\s*(.+)/);
      if (ruleMatch) {
        if (current.rule_id) exceptions.push(current as ScanException);
        current = { rule_id: ruleMatch[1].trim().replace(/^["']|["']$/g, "") };
      }
      const justMatch = line.match(/^\s*justification:\s*(.+)/);
      if (justMatch) {
        current.justification = justMatch[1].trim().replace(/^["']|["']$/g, "");
      }
    }
    if (current.rule_id) exceptions.push(current as ScanException);
    return exceptions;
  }
}

function main() {
  const opts = parseArgs(process.argv);
  const payload = readPayload(opts.payloadPath, opts.fromStdin);
  const manifest = readManifest(opts.manifestPath);
  const exceptions = readExceptions(opts.exceptionsPath);

  const result = scanPayload(payload, { manifest, exceptions });

  if (opts.jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Human-readable output
    const icon =
      result.result === "pass" ? "PASS" : result.result === "fail" ? "FAIL" : "WARN";
    console.log(`\n${icon}  ${result.pack} — ${result.findings.length} finding(s)\n`);

    if (result.findings.length > 0) {
      for (const f of result.findings) {
        const sev = f.severity.toUpperCase().padEnd(8);
        console.log(`  ${sev} [${f.rule_id}] ${f.location}`);
        console.log(`           ${f.message}`);
        if (f.matched) {
          console.log(`           matched: "${f.matched}"`);
        }
        console.log();
      }
    }

    if (result.exceptions_applied.length > 0) {
      console.log(
        `  Exceptions applied: ${result.exceptions_applied.join(", ")}`,
      );
    }

    const { critical, high, medium, low } = result.summary;
    console.log(
      `  Summary: ${critical} critical, ${high} high, ${medium} medium, ${low} low`,
    );
  }

  if (result.result === "fail") process.exit(1);
  if (result.result === "warn") process.exit(2);
  process.exit(0);
}

main();
