import { describe, it, expect } from "vitest";
import { parsePackYAML, extractPrompts } from "./pack-parser.js";

// ── parsePackYAML ───────────────────────────────────────────────

describe("parsePackYAML", () => {
  it("parses minimal valid pack YAML", () => {
    const yaml = `
name: test-pack
version: "1.0.0"
skills:
  - name: greet
    prompt: "Say hello to the user."
`;
    const pack = parsePackYAML(yaml);
    expect(pack.name).toBe("test-pack");
    expect(pack.version).toBe("1.0.0");
    expect(pack.skills).toHaveLength(1);
    expect(pack.skills[0].name).toBe("greet");
    expect(pack.skills[0].prompt).toBe("Say hello to the user.");
  });

  it("extracts agents dict", () => {
    const yaml = `
name: agent-pack
version: "1.0.0"
agents:
  home-operator:
    role: operator
    prompt: "You are a home operations operator."
  secops-operator:
    role: operator
    prompt: "You are a security operations operator."
skills:
  - name: check
    prompt: "Check the system."
`;
    const pack = parsePackYAML(yaml);
    expect(Object.keys(pack.agents)).toEqual(["home-operator", "secops-operator"]);
    expect(pack.agents["home-operator"].prompt).toBe(
      "You are a home operations operator.",
    );
    expect(pack.agents["secops-operator"].prompt).toBe(
      "You are a security operations operator.",
    );
  });

  it("preserves forked_from", () => {
    const yaml = `
name: my-fork
version: "1.0.0"
forked_from:
  name: original-pack
  version: "2.0.0"
skills:
  - name: s1
    prompt: "Do something."
`;
    const pack = parsePackYAML(yaml);
    expect(pack.forked_from).toEqual({ name: "original-pack", version: "2.0.0" });
  });

  it("handles pack without agents", () => {
    const yaml = `
name: no-agents
version: "1.0.0"
skills:
  - name: s1
    prompt: "Prompt text."
`;
    const pack = parsePackYAML(yaml);
    expect(Object.keys(pack.agents)).toHaveLength(0);
  });

  it("handles skills without prompts", () => {
    const yaml = `
name: partial
version: "1.0.0"
skills:
  - name: has-prompt
    prompt: "I have a prompt."
  - name: no-prompt
    description: "No prompt here."
`;
    const pack = parsePackYAML(yaml);
    expect(pack.skills).toHaveLength(2);
    expect(pack.skills[0].prompt).toBe("I have a prompt.");
    expect(pack.skills[1].prompt).toBeUndefined();
  });

  it("handles agents without prompts", () => {
    const yaml = `
name: partial-agents
version: "1.0.0"
agents:
  silent:
    role: operator
skills:
  - name: s1
    prompt: "Prompt."
`;
    const pack = parsePackYAML(yaml);
    expect(pack.agents["silent"].prompt).toBeUndefined();
  });

  it("throws on non-mapping YAML", () => {
    expect(() => parsePackYAML("just a string")).toThrow("Pack YAML must be a mapping");
  });

  it("throws on YAML parse error", () => {
    // Indentation error that the yaml package actually rejects
    expect(() => parsePackYAML("name: test\n  bad indent: here\n    worse: nesting")).toThrow();
  });

  it("throws on missing name", () => {
    const yaml = `
version: "1.0.0"
skills:
  - name: s1
    prompt: "Prompt."
`;
    expect(() => parsePackYAML(yaml)).toThrow('Missing required field: "name"');
  });

  it("throws on missing skills", () => {
    const yaml = `
name: no-skills
version: "1.0.0"
`;
    expect(() => parsePackYAML(yaml)).toThrow('Missing required field: "skills"');
  });

  it("coerces numeric version to string", () => {
    const yaml = `
name: numeric-version
version: 1.6
skills:
  - name: s1
    prompt: "Prompt."
`;
    const pack = parsePackYAML(yaml);
    expect(pack.version).toBe("1.6");
  });
});

// ── extractPrompts ──────────────────────────────────────────────

describe("extractPrompts", () => {
  it("extracts skill prompts with correct locations", () => {
    const yaml = `
name: test
version: "1.0.0"
skills:
  - name: alpha
    prompt: "Alpha prompt."
  - name: beta
    prompt: "Beta prompt."
  - name: gamma
    prompt: "Gamma prompt."
`;
    const pack = parsePackYAML(yaml);
    const prompts = extractPrompts(pack);
    expect(prompts).toHaveLength(3);
    expect(prompts[0]).toEqual({ text: "Alpha prompt.", location: "skills.alpha" });
    expect(prompts[1]).toEqual({ text: "Beta prompt.", location: "skills.beta" });
    expect(prompts[2]).toEqual({ text: "Gamma prompt.", location: "skills.gamma" });
  });

  it("extracts agent prompts with correct locations", () => {
    const yaml = `
name: test
version: "1.0.0"
agents:
  my-agent:
    role: operator
    prompt: "Agent prompt."
skills:
  - name: s1
    prompt: "Skill prompt."
`;
    const pack = parsePackYAML(yaml);
    const prompts = extractPrompts(pack);
    expect(prompts).toHaveLength(2);
    expect(prompts[0]).toEqual({ text: "Agent prompt.", location: "agents.my-agent" });
    expect(prompts[1]).toEqual({ text: "Skill prompt.", location: "skills.s1" });
  });

  it("skips skills and agents without prompts", () => {
    const yaml = `
name: test
version: "1.0.0"
agents:
  silent:
    role: operator
skills:
  - name: has-prompt
    prompt: "I exist."
  - name: no-prompt
    description: "I do not."
`;
    const pack = parsePackYAML(yaml);
    const prompts = extractPrompts(pack);
    expect(prompts).toHaveLength(1);
    expect(prompts[0].location).toBe("skills.has-prompt");
  });

  it("returns empty array for pack with no prompts", () => {
    const yaml = `
name: empty
version: "1.0.0"
skills:
  - name: s1
    description: "No prompt."
`;
    const pack = parsePackYAML(yaml);
    const prompts = extractPrompts(pack);
    expect(prompts).toEqual([]);
  });
});
