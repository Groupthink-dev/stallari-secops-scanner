/**
 * stallari-secops-scanner — library exports.
 *
 * Usage:
 *   import { scanPayload, scanPrompt, RULES } from "stallari-secops-scanner";
 */

export { scanPayload, scanPrompt, SCANNER_VERSION } from "./scanner.js";
export { RULES } from "./rules.js";
export type {
  Finding,
  ManifestContext,
  Rule,
  ScanException,
  ScanResult,
  SealedPayload,
  Severity,
  StructuralContext,
} from "./types.js";
