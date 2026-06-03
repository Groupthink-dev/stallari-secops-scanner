<p align="center">
  <a href="https://stallari.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/stallari-logo-dark.png">
      <img src="assets/stallari-logo-light.png" alt="Stallari" width="320">
    </picture>
  </a>
</p>

<h1 align="center">Stallari SecOps Scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0-blue" alt="Version 0.3.0">
  <img src="https://img.shields.io/badge/status-developer%20preview-orange" alt="Developer Preview">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Node.js-22%2B-339933" alt="Node.js 22+">
  <img src="https://img.shields.io/badge/transparency-open%20source-8B5CF6" alt="Transparency: Open Source">
</p>

<p align="center">
  Open-source security scanner for <a href="https://stallari.ai">Stallari</a> packs — prompt injection detection, clone detection, and threat matching for sealed and open pack pipelines.

</p>

---

Stallari lets you install third-party packs — bundles of skills and agent prompts that extend what your agents can do. Sealed packs encrypt their prompts to protect publisher IP, which means **you can't read what they tell your agents to do.** Open packs (community contributions) ship prompts in plain YAML — readable, but still need security vetting.

This scanner covers both pipelines:

- **Open source.** Every detection rule is here. Read the patterns, challenge the logic, submit improvements.
- **Deterministic.** Pattern-based static analysis with stable rule IDs. No opaque ML model deciding what's safe. You can reproduce every finding.
- **Transparent findings.** Every result includes the exact matched text, the rule that fired, and why it matters. Nothing is hidden behind a pass/fail score.
- **Exception-driven.** When a finding is a false positive, it's suppressed with a documented justification — not silently ignored.
- **Runtime-agnostic.** Core library runs in Node.js, Cloudflare Workers, or any JS runtime. No `node:fs` or `node:path` in library code.

## How it works

### Sealed pack pipeline

Sealed packs are encrypted with keys held by the Stallari security pipeline. When a publisher submits a sealed pack for certification, the pipeline decrypts the payload, runs this scanner against every skill and agent prompt inside, and produces a structured report.

```
Publisher seals pack (encrypts prompts)
        │
        ▼
Stallari certification pipeline
        │
        ├── Decrypt with escrow key
        ├── Run secops-scanner (SINJ rules)
        ├── Validate descriptor ↔ payload consistency
        └── Sign certification if pass
        │
        ▼
Certified pack published to marketplace
```

### Open pack pipeline

Community contributors submit pack PRs to stallari-plugins with inline YAML prompts. A webhook-triggered CF Worker scans each PR:

```
Contributor opens PR (open pack YAML)
        │
        ▼
GitHub webhook → CF Worker
        │
        ├── Parse pack YAML
        ├── Run SINJ rules on all prompts
        ├── Clone detection against existing packs
        ├── Threat matching against known malicious prompts
        └── Post findings as PR comment
        │
        ▼
PR approved / blocked based on scan result
```

### Scan results

| Scanner result | What happens |
|----------------|--------------|
| **Pass** (exit 0) | No findings. Pack is eligible for certification signing. |
| **Warn** (exit 2) | Medium or low severity findings only. Requires review and may be approved with documented exceptions. |
| **Fail** (exit 1) | Critical or high severity findings. Pack is rejected. Publisher must remediate and resubmit. |

## Detection rules

### Prompt injection (SINJ)

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| SINJ-001 | Instruction override | critical | "ignore previous instructions", identity hijacking |
| SINJ-002 | System prompt extraction | critical | Attempts to reveal system prompts or instructions |
| SINJ-003 | Data exfiltration | high | URLs, fetch/curl/wget, webhook endpoints |
| SINJ-004 | Privilege escalation | high | Jailbreak, DAN, god mode, sudo, developer mode |
| SINJ-005 | Obfuscation | high | Base64 blocks, zero-width chars, homoglyphs, hex encoding |
| SINJ-006 | Social engineering | medium | Urgency markers, authority claims, emotional manipulation |
| SINJ-007 | Excessive tool use | medium | Filesystem ops, shell execution, socket access |
| SINJ-008 | Undeclared capabilities | low | MCP tool references not declared in the pack manifest |
| S-DT-001 | Datetime substrate shellout | low | `eval $(agentic-timestamp …)` and doc-prose references where the per-turn `<datetime>` system-reminder block should be used (DD-349). Saga-jq state-stamp lines whitelisted. |

### Clone detection (SCLN)

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| SCLN-001 | Near-copy | high | Prompt ≥85% similar to an existing pack (Jaccard trigrams) |
| SCLN-002 | Substantial overlap | medium | Prompt ≥65% similar to an existing pack |

Clone findings from a declared `forked_from` parent are marked `suppressed: true` — informational only, they don't cause failure.

### Threat matching (STHR)

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| STHR-001 | Known malicious prompt | critical | Prompt ≥70% similar to a known jailbreak or malicious prompt |

Threat matches are never suppressed — a fork of a known jailbreak is still a jailbreak.

The scanner ships with a bundled threat corpus of ~30 curated entries covering jailbreak, instruction override, system prompt extraction, data exfiltration, privilege escalation, tool abuse, and obfuscation families. The bundled corpus loads automatically — no `--threats` flag needed. Custom threat files override the bundled corpus.

Rules use stable IDs (`SINJ-NNN`, `SCLN-NNN`, `STHR-NNN`) for use in exception files and scan reports.

### Skill contract (S-SKL) — DD-370

Lints skill `.md` manifests against the DD-344 v4.5 contract by pairing each pack.yaml `skills[].import` entry with its skill source (the dual import + frontmatter surface). Run via `scan-skills`.

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| S-SKL-001 | Skill manifest missing v4.5 contract field | warning | A declared **write-class** op (`create`/`send`/`*_set`/`*_control`/`create_adjustment`/…) with no `risk_class` entry (→ no DD-280 two-gate gate); a **user-content reader** with no `domain_access` (→ no DD-278 scope ACL); an `op://`-resolving body with no `sealed_credentials`; a handoff-emitting body (`+/handoff/`, `{{track.}}`) with no `track_emits` (→ no DD-245 audit trail). |

S-SKL-001 ships **warning-only** (non-blocking) per DD-370 OQ-1 — promote to `error` at DD-370 Phase D (post-EA marketplace cutover) by flipping the rule severity. The write-class detector is name-based and biased toward catching writes: a false-positive is a non-blocking nudge to declare `risk_class`; a false-negative would let a real mutation ship ungated.

## CLI usage

### Scan a sealed payload

```sh
stallari-secops-scanner scan payload.json
stallari-secops-scanner scan payload.json --manifest manifest.json
stallari-secops-scanner scan payload.json --json
```

### Scan an open pack YAML

```sh
stallari-secops-scanner scan-pack pack.yaml                          # uses bundled threat corpus
stallari-secops-scanner scan-pack pack.yaml --corpus ./existing-packs/
stallari-secops-scanner scan-pack pack.yaml --threats custom-threats.json  # override bundled corpus
stallari-secops-scanner scan-pack pack.yaml --json
```

### Lint skill manifests (S-SKL-001, DD-370)

```sh
stallari-secops-scanner scan-skills ./packs/saas-revenue-ops   # one pack (pack.yaml + skills/)
stallari-secops-scanner scan-skills ./packs                    # every pack under a parent dir
stallari-secops-scanner scan-skills ./packs --json
stallari-secops-scanner scan-skills ./packs --strict           # warnings → exit 1 (Phase D, post-EA)
```

Warning-only by default — `scan-skills` exits `0` even with warnings so it can wire into `make validate` without breaking the build (DD-370 OQ-1). `--strict` flips warnings to exit `1` for the future Phase D blocking promotion.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | **Pass** — no findings (or all findings excepted). For `scan-skills`: also warnings, unless `--strict` |
| 1 | **Fail** — critical/high findings (`scan`/`scan-pack`); error findings or `--strict` warnings (`scan-skills`) |
| 2 | **Warn** — medium/low (`scan`/`scan-pack`) or warning-only (`scan-catalog`) |

### Exceptions

Exception files suppress specific rules for packs that intentionally trigger them. Include justifications — the certification team reviews these:

```yaml
- rule_id: SINJ-003
  justification: "Pack legitimately fetches from its own API endpoint"
```

## Library API

The core library is runtime-agnostic — no `node:fs` or `node:path` imports. Safe for Cloudflare Workers, Deno, Bun, or any JS runtime.

```typescript
import { scanPayload, scanPackYAML, RULES } from "stallari-secops-scanner";

// Sealed pack scanning
const result = scanPayload(payload, { manifest, exceptions });

// Open pack scanning (with bundled threat corpus)
import { buildCorpusFromPacks, loadBundledThreats } from "stallari-secops-scanner";

const corpus = buildCorpusFromPacks([
  { name: "existing-pack", yaml: existingPackYaml },
]);
const threats = loadBundledThreats(); // ~30 curated entries, pre-computed trigrams

const packResult = scanPackYAML(packYaml, { corpus, threats, exceptions });
if (packResult.result === "fail") {
  // block PR
}
```

Custom threat corpora can be built with `buildThreatCorpus()`:

```typescript
import { buildThreatCorpus } from "stallari-secops-scanner";

const customThreats = buildThreatCorpus([
  { source: "internal-db", label: "custom-threat-1", prompt: knownBadPrompt },
]);
```

## Development

Contributions to detection rules are welcome — especially evasion patterns we haven't covered.

```sh
npm install
npm test          # run test suite (vitest)
npm run build     # compile to dist/
npm run lint      # type-check without emitting
```

## Feedback

Report issues or suggest new detection rules via [GitHub Issues](https://github.com/groupthink-dev/stallari-secops-scanner/issues).

## License

[MIT](LICENSE)
