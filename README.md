<p align="center">
  <a href="https://stallari.ai">
    <img src="assets/icon.png" width="96" alt="Stallari">
  </a>
</p>

<h1 align="center">Stallari SecOps Scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="Version 0.1.0">
  <img src="https://img.shields.io/badge/status-developer%20preview-orange" alt="Developer Preview">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Node.js-22%2B-339933" alt="Node.js 22+">
  <img src="https://img.shields.io/badge/transparency-open%20source-8B5CF6" alt="Transparency: Open Source">
</p>

<p align="center">
  Open-source prompt injection scanner for <a href="https://stallari.ai">Stallari</a> packs — the security gate between third-party code and your agents.
</p>

---

Stallari lets you install third-party packs — bundles of skills and agent prompts that extend what your agents can do. Sealed packs encrypt their prompts to protect publisher IP, which means **you can't read what they tell your agents to do.**

That's a trust problem. A compromised pack could override agent instructions, extract your system prompts, exfiltrate data from your vault, or escalate privileges — all invisible inside the seal.

This scanner exists so you don't have to trust blindly:

- **Open source.** Every detection rule is here. Read the patterns, challenge the logic, submit improvements.
- **Deterministic.** Pattern-based static analysis with stable rule IDs. No opaque ML model deciding what's safe. You can reproduce every finding.
- **Transparent findings.** Every result includes the exact matched text, the rule that fired, and why it matters. Nothing is hidden behind a pass/fail score.
- **Exception-driven.** When a finding is a false positive, it's suppressed with a documented justification — not silently ignored.

## How it works

**This scanner runs inside Stallari's certification infrastructure — not on your machine.**

Sealed packs are encrypted with keys held by the Stallari security pipeline. When a publisher submits a sealed pack for certification, the pipeline decrypts the payload, runs this scanner against every skill and agent prompt inside, and produces a structured report. Packs that fail are rejected. Packs that pass receive a cryptographic certification signature that your Stallari instance verifies at install time.

You don't need to run this tool yourself. You benefit from it automatically — every certified pack in the marketplace has been scanned by the rules defined in this repo. The code is open source so you can see exactly what "certified" means: which patterns are checked, at what severity thresholds, and what exceptions (if any) were granted.

```
Publisher seals pack (encrypts prompts)
        │
        ▼
Stallari certification pipeline
        │
        ├── Decrypt with escrow key
        ├── Run secops-scanner ← this repo
        ├── Validate descriptor ↔ payload consistency
        └── Sign certification if pass
        │
        ▼
Certified pack published to marketplace
        │
        ▼
Your Stallari instance verifies signature at install
```

### What "certified" means

| Scanner result | What happens |
|----------------|--------------|
| **Pass** (exit 0) | No findings. Pack is eligible for certification signing. |
| **Warn** (exit 2) | Medium or low severity findings only. Requires review and may be approved with documented exceptions. |
| **Fail** (exit 1) | Critical or high severity findings. Pack is rejected. Publisher must remediate and resubmit. |

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

Rules use stable IDs (`SINJ-NNN`) for use in exception files and scan reports.

## For publishers

If you're building a sealed pack and want to pre-check your prompts before submitting for certification, you can run the scanner locally against your own decrypted payload — you have your own content, so no escrow key is needed:

```sh
# Scan your payload before sealing
stallari-secops-scanner scan payload.json

# With manifest context (enables structural checks like SINJ-008)
stallari-secops-scanner scan payload.json --manifest manifest.json

# JSON output for CI integration
stallari-secops-scanner scan payload.json --json
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

The scanner expects a decrypted payload — the same structure you have before sealing:

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

## Library API

For integration into CI pipelines or custom tooling:

```typescript
import { scanPayload, scanPrompt, RULES } from "stallari-secops-scanner";

const result = scanPayload(payload, { manifest, exceptions });
if (result.result === "fail") {
  // block certification
}
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
