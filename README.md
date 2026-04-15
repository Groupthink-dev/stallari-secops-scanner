<p align="center">
  <a href="https://stallari.ai">
    <img src="assets/icon.png" width="96" alt="Stallari">
  </a>
</p>

<h1 align="center">stallari-secops-scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="Version 0.1.0">
  <img src="https://img.shields.io/badge/status-developer%20preview-orange" alt="Developer Preview">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Node.js-22%2B-339933" alt="Node.js 22+">
</p>

> **Developer Preview** — under active development. Rule IDs are stable; rule behaviour and severity thresholds may change between releases.

Static analysis scanner that detects prompt injection vulnerabilities in sealed [Stallari](https://stallari.ai) packs before they reach the dispatch engine.

Packs are third-party bundles of skills and agent prompts. A compromised pack can override agent instructions, extract system prompts, exfiltrate data, or escalate privileges. This scanner is the automated gate between pack submission and execution.

## Detection rules

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

Rules use stable IDs (`SINJ-NNN`) for use in exception files.

## Usage

### CLI

```sh
# Scan a sealed payload
stallari-secops-scanner scan payload.json

# With manifest context (enables structural checks like SINJ-008)
stallari-secops-scanner scan payload.json --manifest manifest.json

# Suppress known-safe findings
stallari-secops-scanner scan payload.json --exceptions exceptions.yaml

# JSON output for pipeline integration
stallari-secops-scanner scan payload.json --json

# Read from stdin
cat payload.json | stallari-secops-scanner scan --stdin
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | **Pass** — no findings (or all findings excepted) |
| 1 | **Fail** — critical or high severity findings |
| 2 | **Warn** — medium or low severity findings only |

### Library

```typescript
import { scanPayload, scanPrompt, RULES } from "stallari-secops-scanner";

const result = scanPayload(payload, { manifest, exceptions });
if (result.result === "fail") {
  // block installation
}
```

## Payload format

The scanner expects a decrypted sealed payload:

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

## Exceptions

Exception files suppress specific rules for packs that intentionally trigger them. JSON or YAML:

```yaml
- rule_id: SINJ-003
  justification: "Pack legitimately fetches from its own API endpoint"
```

## Development

```sh
npm install
npm test          # run test suite (vitest)
npm run build     # compile to dist/
npm run lint      # type-check without emitting
```

## Feedback

Report issues via [GitHub Issues](https://github.com/groupthink-dev/stallari-secops-scanner/issues).

## License

[MIT](LICENSE)
