# Threat Corpus

The bundled threat corpus lives in [`src/bundled-threats.ts`](../src/bundled-threats.ts). It contains curated entries representing families of known malicious prompt patterns relevant to MCP tool-calling agents.

## Categories

| Category | Description |
|----------|-------------|
| `jailbreak` | Persona-based restriction removal (DAN, STAN, Developer Mode) |
| `instruction-override` | Direct system prompt replacement or suppression |
| `system-prompt-extraction` | Attempts to extract or leak system prompts |
| `data-exfiltration` | Piping data to external endpoints via prompts |
| `privilege-escalation` | Claiming elevated permissions or bypassing access controls |
| `tool-abuse` | Misusing MCP tools for filesystem manipulation, credential harvesting |
| `obfuscation` | Encoding, multilingual injection, or framing tricks |

## How matching works

The scanner uses trigram Jaccard similarity (character 3-grams). A pack prompt matching a corpus entry at >= 70% similarity triggers STHR-001 (critical).

This catches copy-paste variants with minor word substitutions — the typical distribution pattern for jailbreak prompts.

## Adding entries

1. Add a new entry to `BUNDLED_THREAT_ENTRIES` in `src/bundled-threats.ts`
2. Each entry needs: `source`, `label`, `category`, `prompt`
3. Prompts must be >= 100 characters (shorter entries are filtered out by `MIN_PROMPT_LENGTH`)
4. Run `npm test` to verify no false positives against existing test fixtures
5. Bump `BUNDLED_THREATS_VERSION`

## Design choices

- **Original compositions, not copies.** Entries are written to represent attack families, not copied from external datasets. No licensing concerns.
- **Minimum viable corpus.** ~30 entries covering major families. Quantity is less important than coverage of distinct attack patterns.
- **No ML.** Deterministic trigram matching. Reproducible, auditable, no model drift.
