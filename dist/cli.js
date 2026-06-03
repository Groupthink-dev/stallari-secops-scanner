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
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { scanPayload, scanPackYAML, SCANNER_VERSION } from "./scanner.js";
import { buildCorpusFromPacks, buildThreatCorpus } from "./clone.js";
import { loadBundledThreats } from "./bundled-threats.js";
import { loadCatalogDir } from "./catalog-parser.js";
import { scanCatalogEntries } from "./catalog-scanner.js";
import { scanPackSkills } from "./skill-scanner.js";
function usage() {
    console.error(`stallari-secops-scanner v${SCANNER_VERSION}

Usage:
  stallari-secops-scanner scan <payload.json> [options]
  stallari-secops-scanner scan --stdin [options]
  stallari-secops-scanner scan-pack <pack.yaml> [options]
  stallari-secops-scanner scan-catalog <dir> [options]
  stallari-secops-scanner scan-skills <pack-or-packs-dir> [options]

Commands:
  scan            Scan a sealed pack payload (JSON)
  scan-pack       Scan an open pack YAML file
  scan-catalog    Scan a stallari-plugins/plugins/tools/ catalog dir
                  (runs DD-333 S-MCP-001 + future catalog-rule additions)
  scan-skills     Lint skill manifests against the DD-344 v4.5 contract
                  (DD-370 S-SKL-001). Accepts a single pack dir (pack.yaml +
                  skills/) or a parent dir of packs. Warning-only by default.

Options (scan):
  --manifest <file>     Manifest JSON for structural checks
  --exceptions <file>   YAML/JSON exceptions file

Options (scan-pack):
  --corpus <dir>        Directory of pack YAMLs for clone detection
  --threats <file>      JSON file of known malicious prompts
  --exceptions <file>   YAML/JSON exceptions file

Options (scan-skills):
  --strict              Treat warnings as failures (exit 1). Reserved for the
                        DD-370 Phase D promotion (post-EA). Default: off —
                        S-SKL-001 is warning-only per DD-370 OQ-1.

Common options:
  --json                Output raw JSON (default: human-readable)
  --help                Show this help

Exit codes:
  scan / scan-pack: 0=pass, 1=fail (critical/high), 2=warn (medium/low)
  scan-catalog:     0=pass, 1=fail (any error finding), 2=warn (warning-only)
  scan-skills:      0=pass OR warn (warning-only, non-blocking); 1=fail
                    (error findings, or any finding under --strict)`);
    return process.exit(2);
}
function parseArgs(argv) {
    const args = argv.slice(2);
    if (args.length === 0 || args.includes("--help"))
        usage();
    const command = args[0];
    if (command !== "scan" &&
        command !== "scan-pack" &&
        command !== "scan-catalog" &&
        command !== "scan-skills") {
        console.error(`Unknown command: ${command}`);
        usage();
    }
    if (command === "scan-skills") {
        let target = null;
        let strict = false;
        let jsonOutput = false;
        for (let i = 1; i < args.length; i++) {
            if (args[i] === "--json") {
                jsonOutput = true;
            }
            else if (args[i] === "--strict") {
                strict = true;
            }
            else if (args[i].startsWith("-")) {
                console.error(`Unknown option: ${args[i]}`);
                usage();
            }
            else {
                target = args[i];
            }
        }
        if (!target) {
            console.error("Missing pack/packs directory path");
            usage();
        }
        return { command: "scan-skills", target, strict, jsonOutput };
    }
    if (command === "scan-catalog") {
        let catalogDir = null;
        let jsonOutput = false;
        for (let i = 1; i < args.length; i++) {
            if (args[i] === "--json") {
                jsonOutput = true;
            }
            else if (args[i].startsWith("-")) {
                console.error(`Unknown option: ${args[i]}`);
                usage();
            }
            else {
                catalogDir = args[i];
            }
        }
        if (!catalogDir) {
            console.error("Missing catalog directory path");
            usage();
        }
        return { command: "scan-catalog", catalogDir, jsonOutput };
    }
    if (command === "scan-pack") {
        let packPath = null;
        let corpusDir = null;
        let threatsPath = null;
        let exceptionsPath = null;
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
    let payloadPath = null;
    let manifestPath = null;
    let exceptionsPath = null;
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
    if (!payloadPath && !fromStdin)
        usage();
    return { command: "scan", payloadPath, manifestPath, exceptionsPath, fromStdin, jsonOutput };
}
function readPayload(path, fromStdin) {
    let raw;
    if (fromStdin) {
        raw = readFileSync(0, "utf8");
    }
    else {
        raw = readFileSync(path, "utf8");
    }
    return JSON.parse(raw);
}
function readManifest(path) {
    if (!path)
        return undefined;
    return JSON.parse(readFileSync(path, "utf8"));
}
function readExceptions(path) {
    if (!path)
        return undefined;
    const raw = readFileSync(path, "utf8");
    // Support both JSON and simple YAML (array of {rule_id, justification})
    try {
        return JSON.parse(raw);
    }
    catch {
        // Minimal YAML parsing for simple array format
        const exceptions = [];
        const lines = raw.split("\n");
        let current = {};
        for (const line of lines) {
            const ruleMatch = line.match(/^\s*-?\s*rule_id:\s*(.+)/);
            if (ruleMatch) {
                if (current.rule_id)
                    exceptions.push(current);
                current = { rule_id: ruleMatch[1].trim().replace(/^["']|["']$/g, "") };
            }
            const justMatch = line.match(/^\s*justification:\s*(.+)/);
            if (justMatch) {
                current.justification = justMatch[1].trim().replace(/^["']|["']$/g, "");
            }
        }
        if (current.rule_id)
            exceptions.push(current);
        return exceptions;
    }
}
// ── CLI-only I/O helpers ────────────────────────────────────────
function loadCorpusFromDir(dir) {
    const files = readdirSync(dir).filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
    const packs = files.map((f) => ({
        name: f.replace(/\.(yaml|yml)$/, ""),
        yaml: readFileSync(join(dir, f), "utf8"),
    }));
    return buildCorpusFromPacks(packs);
}
function loadThreatsFromFile(path) {
    const raw = readFileSync(path, "utf8");
    const entries = JSON.parse(raw);
    return buildThreatCorpus(entries);
}
// ── Command implementations ─────────────────────────────────────
function printFindings(result) {
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
function mainScan(opts) {
    const payload = readPayload(opts.payloadPath, opts.fromStdin);
    const manifest = readManifest(opts.manifestPath);
    const exceptions = readExceptions(opts.exceptionsPath);
    const result = scanPayload(payload, { manifest, exceptions });
    if (opts.jsonOutput) {
        console.log(JSON.stringify(result, null, 2));
    }
    else {
        const icon = result.result === "pass" ? "PASS" : result.result === "fail" ? "FAIL" : "WARN";
        console.log(`\n${icon}  ${result.pack} — ${result.findings.length} finding(s)\n`);
        printFindings(result);
        if (result.exceptions_applied.length > 0) {
            console.log(`  Exceptions applied: ${result.exceptions_applied.join(", ")}`);
        }
        const { critical, high, medium, low } = result.summary;
        console.log(`  Summary: ${critical} critical, ${high} high, ${medium} medium, ${low} low`);
    }
    if (result.result === "fail")
        process.exit(1);
    if (result.result === "warn")
        process.exit(2);
    process.exit(0);
}
function mainScanPack(opts) {
    const yamlContent = readFileSync(opts.packPath, "utf8");
    const exceptions = readExceptions(opts.exceptionsPath);
    const corpus = opts.corpusDir ? loadCorpusFromDir(opts.corpusDir) : undefined;
    const threats = opts.threatsPath
        ? loadThreatsFromFile(opts.threatsPath)
        : loadBundledThreats();
    const result = scanPackYAML(yamlContent, {
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
    }
    else {
        const icon = result.result === "pass" ? "PASS" : result.result === "fail" ? "FAIL" : "WARN";
        const cloneCount = result.clone_findings.length;
        console.log(`\n${icon}  ${result.pack} — ${result.findings.length} SINJ finding(s), ${cloneCount} clone/threat finding(s)\n`);
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
                console.log(`           similarity: ${(cf.similarity * 100).toFixed(1)}%`);
                console.log();
            }
        }
        if (result.exceptions_applied.length > 0) {
            console.log(`  Exceptions applied: ${result.exceptions_applied.join(", ")}`);
        }
        const { critical, high, medium, low } = result.summary;
        console.log(`  Summary: ${critical} critical, ${high} high, ${medium} medium, ${low} low\n`);
    }
    if (result.result === "fail")
        process.exit(1);
    if (result.result === "warn")
        process.exit(2);
    process.exit(0);
}
function mainScanCatalog(opts) {
    const entries = loadCatalogDir(opts.catalogDir);
    const result = scanCatalogEntries(entries);
    if (opts.jsonOutput) {
        console.log(JSON.stringify(result, null, 2));
    }
    else {
        const icon = result.result === "pass"
            ? "PASS"
            : result.result === "fail"
                ? "FAIL"
                : "WARN";
        console.log(`\n${icon}  catalog (${result.entries_scanned} entries) — ${result.findings.length} finding(s)\n`);
        for (const f of result.findings) {
            const sev = f.severity.toUpperCase().padEnd(8);
            console.log(`  ${sev} [${f.rule_id}] ${f.path}`);
            console.log(`           ${f.message}`);
            console.log();
        }
        const { warning, error } = result.summary;
        console.log(`  Summary: ${error} error, ${warning} warning\n`);
    }
    if (result.result === "fail")
        process.exit(1);
    if (result.result === "warn")
        process.exit(2);
    process.exit(0);
}
// ── DD-370: scan-skills fs glue + driver ────────────────────────
/** True when `dir` is a single pack (has pack.yaml + skills/). */
function isPackDir(dir) {
    return existsSync(join(dir, "pack.yaml")) && existsSync(join(dir, "skills"));
}
/** Read a single pack dir into (packName, packYamlContent, slug→md map). */
function loadPackForSkillScan(packDir) {
    const packYaml = readFileSync(join(packDir, "pack.yaml"), "utf8");
    const skills = new Map();
    const skillsDir = join(packDir, "skills");
    if (existsSync(skillsDir)) {
        for (const file of readdirSync(skillsDir)) {
            if (!file.endsWith(".md"))
                continue;
            const slug = basename(file, ".md");
            skills.set(slug, readFileSync(join(skillsDir, file), "utf8"));
        }
    }
    return { packName: basename(packDir), packYaml, skills };
}
/** Resolve `target` to the list of pack dirs to scan (single pack or parent). */
function resolvePackDirs(target) {
    if (isPackDir(target))
        return [target];
    // Parent dir: every immediate subdir that is itself a pack dir.
    const dirs = [];
    for (const name of readdirSync(target)) {
        const full = join(target, name);
        try {
            if (statSync(full).isDirectory() && isPackDir(full))
                dirs.push(full);
        }
        catch {
            /* skip unreadable entries */
        }
    }
    return dirs.sort();
}
function mainScanSkills(opts) {
    const packDirs = resolvePackDirs(opts.target);
    if (packDirs.length === 0) {
        console.error(`No pack found at '${opts.target}' (expected a dir with pack.yaml + skills/, ` +
            `or a parent dir of such packs).`);
        process.exit(1);
    }
    const allFindings = [];
    const perPack = [];
    let totalSkills = 0;
    for (const dir of packDirs) {
        const { packName, packYaml, skills } = loadPackForSkillScan(dir);
        const res = scanPackSkills(packName, packYaml, skills);
        perPack.push(res);
        allFindings.push(...res.findings);
        totalSkills += res.skills_scanned;
    }
    const summary = { warning: 0, error: 0 };
    for (const f of allFindings)
        summary[f.severity]++;
    if (opts.jsonOutput) {
        console.log(JSON.stringify({
            version: "1.0",
            scanner: `stallari-secops-scanner/${SCANNER_VERSION}`,
            packs_scanned: packDirs.length,
            skills_scanned: totalSkills,
            findings: allFindings,
            summary,
        }, null, 2));
    }
    else {
        const hasError = summary.error > 0;
        const hasWarn = summary.warning > 0;
        const icon = hasError ? "FAIL" : hasWarn ? "WARN" : "PASS";
        console.log(`\n${icon}  skill-contract (${packDirs.length} pack(s), ${totalSkills} skill(s)) — ` +
            `${allFindings.length} finding(s)\n`);
        for (const f of allFindings) {
            const sev = f.severity.toUpperCase().padEnd(8);
            console.log(`  ${sev} [${f.rule_id}] ${f.path}`);
            console.log(`           ${f.message}`);
            console.log();
        }
        console.log(`  Summary: ${summary.error} error, ${summary.warning} warning`);
        if (summary.warning > 0 && !opts.strict) {
            console.log(`  (warning-only — non-blocking per DD-370 OQ-1; re-run with --strict to fail)\n`);
        }
        else {
            console.log();
        }
    }
    // Exit policy: errors always fail; warnings fail only under --strict
    // (the DD-370 Phase D, post-EA, promotion path).
    if (summary.error > 0)
        process.exit(1);
    if (opts.strict && summary.warning > 0)
        process.exit(1);
    process.exit(0);
}
function main() {
    const opts = parseArgs(process.argv);
    if (opts.command === "scan") {
        mainScan(opts);
    }
    else if (opts.command === "scan-pack") {
        mainScanPack(opts);
    }
    else if (opts.command === "scan-catalog") {
        mainScanCatalog(opts);
    }
    else {
        mainScanSkills(opts);
    }
}
main();
