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

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { scanPayload, scanPackYAML, SCANNER_VERSION } from "./scanner.js";
import { buildCorpusFromPacks, buildThreatCorpus } from "./clone.js";
import type {
  CorpusEntry,
  ManifestContext,
  PackScanResult,
  ScanException,
  SealedPayload,
} from "./types.js";

function usage(): never {
  console.error(`stallari-secops-scanner v${SCANNER_VERSION}

Usage:
  stallari-secops-scanner scan <payload.json> [options]
  stallari-secops-scanner scan --stdin [options]
  stallari-secops-scanner scan-pack <pack.yaml> [options]

Commands:
  scan          Scan a sealed pack payload (JSON)
  scan-pack     Scan an open pack YAML file

Options (scan):
  --manifest <file>     Manifest JSON for structural checks
  --exceptions <file>   YAML/JSON exceptions file

Options (scan-pack):
  --corpus <dir>        Directory of pack YAMLs for clone detection
  --threats <file>      JSON file of known malicious prompts
  --exceptions <file>   YAML/JSON exceptions file

Common options:
  --json                Output raw JSON (default: human-readable)
  --help                Show this help

Exit codes: 0=pass, 1=fail (critical/high), 2=warn (medium/low)`);
  return process.exit(2) as never;
}

interface ScanArgs {
  command: "scan";
  payloadPath: string | null;
  manifestPath: string | null;
  exceptionsPath: string | null;
  fromStdin: boolean;
  jsonOutput: boolean;
}

interface ScanPackArgs {
  command: "scan-pack";
  packPath: string;
  corpusDir: string | null;
  threatsPath: string | null;
  exceptionsPath: string | null;
  jsonOutput: boolean;
}

function parseArgs(argv: string[]): ScanArgs | ScanPackArgs {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("--help")) usage();

  const command = args[0];
  if (command !== "scan" && command !== "scan-pack") {
    console.error(`Unknown command: ${command}`);
    usage();
  }

  if (command === "scan-pack") {
    let packPath: string | null = null;
    let corpusDir: string | null = null;
    let threatsPath: string | null = null;
    let exceptionsPath: string | null = null;
    let jsonOutput = false;

    for (let i = 1; i < args.length; i++) {
      switch (args[i]) {
        case "--corpus":
          corpusDir = args[++i];
          break;
        case "--threats":
          threatsPath = args[++i];
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
          packPath = args[i];
      }
    }

    if (!packPath) {
      console.error("Missing pack YAML path");
      usage();
    }

    return { command: "scan-pack", packPath, corpusDir, threatsPath, exceptionsPath, jsonOutput };
  }

  // Original "scan" command parsing
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
  return { command: "scan", payloadPath, manifestPath, exceptionsPath, fromStdin, jsonOutput };
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

// ── CLI-only I/O helpers ────────────────────────────────────────

function loadCorpusFromDir(dir: string): CorpusEntry[] {
  const files = readdirSync(dir).filter(
    (f) => f.endsWith(".yaml") || f.endsWith(".yml"),
  );
  const packs = files.map((f) => ({
    name: f.replace(/\.(yaml|yml)$/, ""),
    yaml: readFileSync(join(dir, f), "utf8"),
  }));
  return buildCorpusFromPacks(packs);
}

function loadThreatsFromFile(
  path: string,
): CorpusEntry[] {
  const raw = readFileSync(path, "utf8");
  const entries = JSON.parse(raw) as Array<{
    source: string;
    label: string;
    prompt: string;
  }>;
  return buildThreatCorpus(entries);
}

// ── Command implementations ─────────────────────────────────────

function printFindings(result: { findings: { severity: string; rule_id: string; location: string; message: string; matched?: string }[] }) {
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

function mainScan(opts: ScanArgs) {
  const payload = readPayload(opts.payloadPath, opts.fromStdin);
  const manifest = readManifest(opts.manifestPath);
  const exceptions = readExceptions(opts.exceptionsPath);

  const result = scanPayload(payload, { manifest, exceptions });

  if (opts.jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const icon =
      result.result === "pass" ? "PASS" : result.result === "fail" ? "FAIL" : "WARN";
    console.log(`\n${icon}  ${result.pack} — ${result.findings.length} finding(s)\n`);

    printFindings(result);

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

function mainScanPack(opts: ScanPackArgs) {
  const yamlContent = readFileSync(opts.packPath, "utf8");
  const exceptions = readExceptions(opts.exceptionsPath);

  const corpus = opts.corpusDir ? loadCorpusFromDir(opts.corpusDir) : undefined;
  const threats = opts.threatsPath ? loadThreatsFromFile(opts.threatsPath) : undefined;

  const result: PackScanResult = scanPackYAML(yamlContent, {
    corpus,
    threats,
    exceptions,
  });

  if (opts.jsonOutput) {
    // Serialize with Sets converted for JSON compatibility
    const jsonSafe = {
      ...result,
      clone_findings: result.clone_findings.map((f) => ({
        ...f,
        similarity: Math.round(f.similarity * 1000) / 1000,
      })),
    };
    console.log(JSON.stringify(jsonSafe, null, 2));
  } else {
    const icon =
      result.result === "pass" ? "PASS" : result.result === "fail" ? "FAIL" : "WARN";
    const cloneCount = result.clone_findings.length;
    console.log(
      `\n${icon}  ${result.pack} — ${result.findings.length} SINJ finding(s), ${cloneCount} clone/threat finding(s)\n`,
    );

    // SINJ findings
    if (result.findings.length > 0) {
      console.log("  Injection scan:\n");
      printFindings(result);
    }

    // Clone/threat findings
    if (cloneCount > 0) {
      console.log("  Clone/threat detection:\n");
      for (const cf of result.clone_findings) {
        const sev = cf.severity.toUpperCase().padEnd(8);
        const tag = cf.suppressed ? " (fork-suppressed)" : "";
        console.log(`  ${sev} [${cf.rule_id}] ${cf.location}${tag}`);
        console.log(`           ${cf.message}`);
        console.log(
          `           similarity: ${(cf.similarity * 100).toFixed(1)}%`,
        );
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
      `  Summary: ${critical} critical, ${high} high, ${medium} medium, ${low} low\n`,
    );
  }

  if (result.result === "fail") process.exit(1);
  if (result.result === "warn") process.exit(2);
  process.exit(0);
}

function main() {
  const opts = parseArgs(process.argv);
  if (opts.command === "scan") {
    mainScan(opts);
  } else {
    mainScanPack(opts);
  }
}

main();
