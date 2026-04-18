/**
 * DD-120 Phase 2 — Prompt injection scan rules.
 *
 * Each rule has a stable ID (SINJ-NNN) for use in scan_exceptions.yaml.
 * Pattern rules are case-insensitive by default.
 */
import type { Rule } from "./types.js";
/** All registered scan rules. */
export declare const RULES: Rule[];
