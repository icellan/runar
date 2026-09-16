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
 * - MAX_IR_BYTES = 16 MiB — the largest compiled-IR JSON in the corpus is
 *   `conformance/tests/math-demo/expected-ir.json` at 88,311 B (0.084 MiB),
 *   so 16 MiB is ~190× headroom. An earlier note put the largest at "~2 MiB
 *   (Mode 3 STARK contracts)" and the headroom at 8×; no checked-in
 *   `expected-ir.json` has ever come within 24× of that figure. The bound is
 *   sized against a pathological producer, not against this corpus, so the
 *   real number being far larger is fine — it is the stated one that was
 *   wrong, and a wrong one invites the next person to recalibrate downward
 *   against a fiction.
 * - MAX_NESTING = 512 — JS engine stack typically tolerates ~10k frames;
 *   512 is well below crash threshold but accommodates legitimate deep
 *   covenant ANF. This bound serves the `--ir` loader
 *   (runar-compiler/src/index.ts), which reads a TRUSTED local file.
 * - MAX_WIRE_NESTING = 100 — the bound for anything crossing a tier
 *   boundary: canonicalJson's emit side and verifyEnvelope's parse side.
 *   Different threat model from MAX_NESTING (unauthenticated network input,
 *   not a local file), so deliberately a separate constant rather than a
 *   shared one. 100 is the largest depth Ruby's `JSON.parse` accepts for
 *   EVERY payload shape at its native default — measured on ruby 4.0.2 /
 *   json 2.18.0, 100-deep parses for both arrays and objects, a 101-deep
 *   OBJECT raises JSON::NestingError, and a 101-deep ARRAY still parses; the
 *   gem counts the two shapes one level apart, so an earlier flat "100
 *   accepted, 101 rejected" is true of objects and false of arrays. 100 is
 *   also 27 below rust serde_json's hard ceiling of 127, so every tier stays
 *   inside its own library's default without hand-rolling or reconfiguring a
 *   parser, and no tier is anywhere near its stack — at 1024 Python's
 *   canonical_json dies of native stack exhaustion and the JVM crashes on a
 *   513-deep object, so a higher bound would trade a clean typed rejection
 *   for a crash. Headroom is ample: the deepest of the 157 checked-in
 *   conformance artifacts measures depth 15, and
 *   conformance/sdk-envelope/fixtures.json tops out at 6.
 * - MAX_STRING_BYTES = 4 MiB — the binding case is a compiled script carried
 *   as a hex string, not a verification key. The largest checked-in script is
 *   `conformance/tests/p384-wallet/expected-script.hex`: 1,963,362 script
 *   bytes = 3,926,724 hex characters, which is 93.6% of this bound. Real
 *   headroom is 1.07×. An earlier note claimed "~3× headroom" against "the
 *   largest checked-in hex pushdata (witness-assisted Groth16 VK)" — that
 *   artifact, `examples/go/SP1Verifier.groth16.vk.json`, is 3,287 bytes in
 *   total and was never the worst case; the justification named the wrong
 *   artifact and overstated the margin by ~3×.
 *
 *   Structural consequence worth stating plainly: MAX_SCRIPT_BYTES admits
 *   4 MiB of SCRIPT, and hex doubles it. So anything that reaches
 *   signEnvelope as a hex string through canonicalJson is capped at 2 MiB of
 *   script — HALF the advertised script bound — and the largest script in
 *   the tree already sits at 93.6% of that. The next script family that
 *   clears ~2 MiB needs a coordinated seven-tier bump of this constant, not
 *   a local one: raising it in one tier splits the wire.
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
                                         // (hex doubles: an effective 2 MiB script
                                         //  ceiling on the wire; today's largest is
                                         //  at 93.6% of it)
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
