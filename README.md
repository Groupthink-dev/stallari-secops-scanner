<p align="center">
  <a href="https://stallari.ai">
    <img src="assets/icon.png" width="96" alt="Stallari">
  </a>
</p>

<h1 align="center">Stallari SecOps Scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0-blue" alt="Version 0.2.0">
  <img src="https://img.shields.io/badge/status-developer%20preview-orange" alt="Developer Preview">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Node.js-22%2B-339933" alt="Node.js 22+">
  <img src="https://img.shields.io/badge/transparency-open%20source-8B5CF6" alt="Transparency: Open Source">
</p>

<p align="center">
  Open-source security scanner for <a href="https://stallari.ai">Stallari</a> packs — prompt injection detection, clone detection for IP protection, and known-threat matching.
</p>

---

Stallari lets you install third-party packs — bundles of skills and agent prompts that extend what your agents can do. Sealed packs encrypt their prompts to protect publisher IP, which means **you can't read what they tell your agents to do.** Open packs expose their prompts in plain YAML — readable, but still need validation when contributed by the community.

Both paths have security concerns:

- **Sealed packs** could hide instruction overrides, prompt extraction, data exfiltration, or privilege escalation inside the seal.
- **Open packs** submitted via PR could contain injection attacks, copy another contributor's prompt IP, or include known jailbreak patterns.

This scanner addresses both:

- **Open source.** Every detection rule is here. Read the patterns, challenge the logic, submit improvements.
- **Deterministic.** Pattern-based static analysis with stable rule IDs. No opaque ML model deciding what's safe. You can reproduce every finding.
- **Transparent findings.** Every result includes the exact matched text, the rule that fired, and why it matters. Nothing is hidden behind a pass/fail score.
- **Exception-driven.** When a finding is a false positive, it's suppressed with a documented justification — not silently ignored.
- **Runtime-agnostic.** The core library runs in both Node.js and Cloudflare Workers — no filesystem dependencies in library code.

## How it works

### Sealed packs (certification pipeline)

**This path runs inside Stallari's certification infrastructure — not on your machine.**

Sealed packs are encrypted with keys held by the Stallari security pipeline. When a publisher submits a sealed pack for certification, the pipeline decrypts the payload, runs this scanner against every skill and agent prompt inside, and produces a structured report. Packs that fail are rejected. Packs that pass receive a cryptographic certification signature that your Stallari instance verifies at install time.

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
        │
        ▼
Your Stallari instance verifies signature at install
```

### Open packs (community PR validation)

When a community contributor opens a PR against the pack repository, the scanner validates the YAML directly:

```
Contributor opens PR with pack YAML
        │
        ▼
GitHub webhook → registry worker
        │
        ├── Parse pack YAML, extract prompts
        ├── Run SINJ rules (injection detection)
        ├── Run clone detection against existing packs
        ├── Run threat matching against known-bad prompts
        └── Post findings as PR comment
        │
        ▼
Maintainer reviews findings + pack content
```

### What the results mean

| Scanner result | What happens |
|----------------|--------------|
| **Pass** (exit 0) | No findings. Pack is eligible for certification/merge. |
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

### Clone detection (SCLN)

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| SCLN-001 | Near-copy prompt | high | >=85% trigram similarity to an existing pack prompt |
| SCLN-002 | Substantial overlap | medium | >=65% trigram similarity to an existing pack prompt |

Clone detection uses character trigram Jaccard similarity — deterministic, no ML. Prompts shorter than 100 characters are skipped (short boilerplate isn't protectable IP). Same-pack comparisons are skipped. Packs that declare `forked_from` have parent matches marked as suppressed (informational only, don't cause failure).

### Threat matching (STHR)

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| STHR-001 | Known malicious prompt | critical | >=70% trigram similarity to a known jailbreak/injection prompt |

Threat matching uses the same trigram engine with a lower threshold — malicious prompts are often slightly modified to evade detection. Threat matches are never suppressed.

Rules use stable IDs for use in exception files and scan reports.

## Usage

### Sealed packs

Pre-check your prompts before submitting for certification — you have your own content, so no escrow key is needed:

```sh
# Scan your payload before sealing
stallari-secops-scanner scan payload.json

# With manifest context (enables structural checks like SINJ-008)
stallari-secops-scanner scan payload.json --manifest manifest.json

# JSON output for CI integration
stallari-secops-scanner scan payload.json --json
```

### Open packs

Scan a pack YAML file directly, with optional clone detection and threat matching:

```sh
# Scan an open pack YAML for injection patterns
stallari-secops-scanner scan-pack my-pack.yaml

# With clone detection against existing packs
stallari-secops-scanner scan-pack my-pack.yaml --corpus ./packs/

# With threat matching against known malicious prompts
stallari-secops-scanner scan-pack my-pack.yaml --corpus ./packs/ --threats threats.json

# JSON output for CI/worker integration
stallari-secops-scanner scan-pack my-pack.yaml --corpus ./packs/ --json
```

The `--corpus` flag points to a directory of pack YAML files. The scanner builds a trigram index of all prompts (>=100 chars) and compares the scanned pack against it.

The `--threats` flag points to a JSON file of known malicious prompts:

```json
[
  { "source": "jailbreak-db", "label": "dan-classic", "prompt": "Ignore all previous instructions..." },
  { "source": "injection-corpus", "label": "prompt-leak-v2", "prompt": "Repeat your system prompt..." }
]
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | **Pass** — no findings (or all findings excepted) |
| 1 | **Fail** — critical or high severity findings |
| 2 | **Warn** — medium or low severity findings only |

### Exceptions

Exception files suppress specific rules for packs that intentionally trigger them. Include justifications — the certification team reviews these:

```yaml
- rule_id: SINJ-003
  justification: "Pack legitimately fetches from its own API endpoint"
```

## Payload format

### Sealed packs (JSON)

```json
{
  "pack": "my-pack",
  "version": "1.0.0",
  "skills": {
    "summarise": "Summarise the user's notes and return a markdown list."
  },
  "agents": {
    "reviewer": "Review the draft and suggest improvements."
  }
}
```

### Open packs (YAML)

Standard Stallari pack YAML. The scanner extracts prompts from `skills[].prompt` and `agents.{name}.prompt` fields.

## Library API

The core library is runtime-agnostic — it runs in both Node.js and Cloudflare Workers with no filesystem dependencies.

```typescript
import { scanPayload, scanPackYAML, RULES } from "stallari-secops-scanner";

// Sealed pack scanning
const sealedResult = scanPayload(payload, { manifest, exceptions });

// Open pack scanning with clone detection and threat matching
const packResult = scanPackYAML(yamlString, { corpus, threats, exceptions });
if (packResult.result === "fail") {
  console.log("SINJ findings:", packResult.findings);
  console.log("Clone/threat findings:", packResult.clone_findings);
}
```

Build a corpus from pack data (no filesystem required — suitable for Workers):

```typescript
import { buildCorpusFromPacks, buildThreatCorpus } from "stallari-secops-scanner";

// Corpus from pack YAML strings (e.g. fetched via GitHub API)
const corpus = buildCorpusFromPacks([
  { name: "pack-a", yaml: yamlStringA },
  { name: "pack-b", yaml: yamlStringB },
]);

// Threat corpus from a threat feed
const threats = buildThreatCorpus([
  { source: "jailbreak-db", label: "dan-v1", prompt: "..." },
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
