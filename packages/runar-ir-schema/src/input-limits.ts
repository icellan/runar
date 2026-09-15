/**
 * Shared DoS-bound input limits + typed error class used by all public
 * canonical-JSON / IR-loading entry points across the runar-ir-schema
 * package and its downstream consumers.
 *
 * Justifications:
 * - MAX_SCRIPT_BYTES = 4 MiB — the largest legitimate script measured by
 *   the script-size benchmark is `p384-wallet` at ~1.87 MB; 4 MiB gives
 *   ~2× headroom without enabling pathological 50 MB scripts. An earlier
 *   1 MiB cap incorrectly rejected p384-wallet — calibration bug caught
 *   by the script-size baseline (Major-2).
 * - MAX_IR_BYTES = 16 MiB — empirically the largest compiled-IR JSON
 *   observed during conformance is ~2 MiB (Mode 3 STARK contracts);
 *   16 MiB is 8× headroom.
 * - MAX_NESTING = 512 — JS engine stack typically tolerates ~10k frames;
 *   512 is well below crash threshold but accommodates legitimate deep
 *   covenant ANF. This bound serves the `--ir` loader
 *   (runar-compiler/src/index.ts), which reads a TRUSTED local file.
 * - MAX_WIRE_NESTING = 100 — the bound for anything crossing a tier
 *   boundary: canonicalJson's emit side and verifyEnvelope's parse side.
 *   Different threat model from MAX_NESTING (unauthenticated network input,
 *   not a local file), so deliberately a separate constant rather than a
 *   shared one. 100 is Ruby's `JSON.parse` native default EXACTLY (100
 *   accepted, 101 rejected) and 27 below rust serde_json's hard ceiling of
 *   127, so every tier stays inside its own library's default without
 *   hand-rolling or reconfiguring a parser, and no tier is anywhere near its
 *   stack — at 1024 Python's canonical_json dies of native stack exhaustion
 *   and the JVM crashes on a 513-deep object, so a higher bound would trade a
 *   clean typed rejection for a crash. Headroom is ample: the deepest of the
 *   227 checked-in conformance artifacts measures depth 15, and
 *   conformance/sdk-envelope/fixtures.json tops out at 6.
 * - MAX_STRING_BYTES = 4 MiB — accommodates the largest checked-in hex
 *   pushdata (witness-assisted Groth16 VK) with ~3× headroom.
 */
export const InputLimits = {
  MAX_IR_BYTES: 16 * 1024 * 1024,       // 16 MiB — uncompressed ANF IR JSON
  MAX_SCRIPT_BYTES: 4 * 1024 * 1024,    // 4 MiB — single compiled Bitcoin Script
                                         // (p384-wallet hits ~1.87 MB; 2× headroom)
  MAX_NESTING: 512,                      // recursion depth for JSON / ANF traversal
                                         // (trusted local --ir input)
  MAX_WIRE_NESTING: 100,                 // recursion depth for anything crossing a
                                         // tier boundary (canonicalJson emit,
                                         // verifyEnvelope parse) — untrusted input
  MAX_STRING_BYTES: 4 * 1024 * 1024,    // 4 MiB — single string field inside JSON
  MAX_SOURCE_BYTES: 4 * 1024 * 1024,    // 4 MiB — single Rúnar source file
                                         // (BUG-008 follow-up: source parser entry guard
                                         //  across all 7 tiers)
} as const;

export type InputLimitsKey = keyof typeof InputLimits;

/**
 * Thrown when a public canonical-JSON / IR-loading entry point detects
 * input that exceeds a documented InputLimits bound. Distinct typed
 * exception so callers can distinguish DoS-bound rejection from generic
 * RangeError / SyntaxError.
 */
export class CanonicalJsonError extends Error {
  readonly code: 'depth' | 'bytes' | 'string-bytes' | 'circular' | 'invalid' | 'lone-surrogate';
  readonly limit?: number;
  readonly actual?: number;

  constructor(
    code: 'depth' | 'bytes' | 'string-bytes' | 'circular' | 'invalid' | 'lone-surrogate',
    message: string,
    info?: { limit?: number; actual?: number },
  ) {
    super(message);
    this.name = 'CanonicalJsonError';
    this.code = code;
    this.limit = info?.limit;
    this.actual = info?.actual;
  }
}
