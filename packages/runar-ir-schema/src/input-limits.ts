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
 *   `conformance/tests/math-demo/expected-ir.json` at 99,763 B (0.095 MiB),
 *   so 16 MiB is ~168× headroom (re-measured for F-024, whose value check
 *   grew math-demo's 14 default-continuation methods past token-ft). An earlier note put the largest at "~2 MiB
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
 *   accepted, 101 rejected" is true of objects and false of arrays. That
 *   asymmetry is the whole reason the bound is 100 rather than 101: raising
 *   it to the depth Ruby accepts for ARRAYS would keep working on every
 *   array payload and start rejecting 101-deep OBJECTS at the Ruby tier
 *   only — a shape-dependent, one-tier failure, which is the worst kind to
 *   debug on a signed wire. 100 is
 *   also 27 below rust serde_json's hard ceiling of 127, so every tier stays
 *   inside its own library's default without hand-rolling or reconfiguring a
 *   parser, and no tier is anywhere near its stack — at 1024 Python's
 *   canonical_json dies of native stack exhaustion and the JVM crashes on a
 *   513-deep object, so a higher bound would trade a clean typed rejection
 *   for a crash. Headroom is ample: the deepest of the 197 checked-in
 *   conformance artifacts measures depth 15, and
 *   conformance/sdk-envelope/fixtures.json tops out at 6.
 * - MAX_STRING_BYTES = 4 MiB — the binding case is a compiled script carried
 *   as a hex string, not a verification key. The largest checked-in script is
 *   `conformance/tests/p384-wallet/expected-script.hex`: 1,958,727 script
 *   bytes = 3,917,454 hex characters, which is 93.4% of this bound. Real
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
 * - MAX_SOURCE_NESTING = 128 — the nesting bound for Rúnar SOURCE (F-213).
 *   MAX_SOURCE_BYTES alone never bounded recursion: 2,000 nested parens is a
 *   4 KB file, and before this bound the Rust tier SIGABRTed on it, Zig
 *   SIGABRTed on a 5,000-term `a + a + …` chain, and Python/Ruby/Java/TS
 *   answered with whatever recursion error their runtime threw first. A source
 *   is refused, with the one diagnostic
 *   `source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)`, when
 *   either of two measures exceeds this bound — every tier computes both, the
 *   same way, on every surface:
 *     (A) parse nesting: a counter the parser keeps, +1 per statement parsed
 *         in a body (an else-if is a statement of the else branch), +1 per
 *         entry into the full-expression parser (statement expressions,
 *         conditions, initializers, parenthesised groups, call arguments,
 *         index expressions, array elements, ternary arms), +1 per prefix
 *         unary operand, +1 per nested type argument, +1 per operand of an
 *         intersection (`&`) or union (`|`) type (N-311; the operands of one
 *         flat `A & B & C` list share a level, so only operator nesting
 *         deepens it). Binary operands parsed by the precedence loops and
 *         postfix chains add nothing. Type operators exist only where a
 *         tier's `.runar.ts` grammar has them — ts, go (tree-sitter) and rust
 *         (swc); the python, zig, ruby and java `.runar.ts` parsers have no
 *         `&`, `|` or `(` in type position and refuse the first one, with
 *         nothing to bound.
 *     (B) AST nesting: statement level (body top level = 1, +1 per if / else
 *         / for body, for init/update at +1) plus expression-tree depth
 *         (leaf = 1); a property initializer is at level 0.
 *   (A) is what bounds the parsers' own recursion; (B) is what bounds every
 *   later pass, and catches the left-deep trees the parsers build in loops.
 *   Headroom, measured over all 1,131 git-tracked `*.runar.*` sources with the
 *   TS reference parser: deepest statement nesting 10 (tic-tac-toe), deepest
 *   expression tree 7 (integer-boundary), deepest statement + expression 14
 *   (tic-tac-toe v2), deepest lexical `(`/`[` nesting 6 — so ~9× headroom on
 *   (B). The ceiling is set by the most stack-hungry tier, not the corpus:
 *   the Rust release build on a 2 MiB thread stack (Rust's default for
 *   spawned threads, where `compile_check` may run) overflowed between 300
 *   and 400 nested parens, so 256 would leave under 1.5× margin there.
 * - MAX_CALL_DEPTH = 128 — the bound on the method CALL GRAPH of a Rúnar
 *   source (N-180). Private methods are inlined at every call site, so a
 *   chain of helpers `verify -> m0 -> m1 -> … -> mN` is N+1 nested inlinings
 *   even when every body is one flat statement that MAX_SOURCE_NESTING never
 *   sees. Before this bound a 20,000-link chain (~1 MB, a quarter of
 *   MAX_SOURCE_BYTES) SIGABRTed Rust at 8,000 links, segfaulted Zig at 4,000,
 *   raised SystemStackError in Ruby at 2,000 and StackOverflowError in Java at
 *   8,000, and ran Go past 156 s of CPU; the recursion check in every tier
 *   restarted its DFS from each method (quadratic) and recursed once per
 *   link. The measure: the call depth of a method is 0 if it calls no
 *   contract method, else 1 + the largest call depth among the contract
 *   methods it calls; a source is refused, with the one diagnostic
 *   `call depth of method '<m>' exceeds MAX_CALL_DEPTH (limit=128)` naming the
 *   first method in declaration order past the bound, when any method that
 *   does not reach a call cycle (a cycle is the recursion diagnostic instead)
 *   has a call depth above this bound. Headroom: the deepest call depth over
 *   all 1,174 parseable git-tracked `*.runar.*` sources is 2 (tic-tac-toe),
 *   so 64× headroom. Ceiling: the Rust release CLI under a 2 MiB stack
 *   (`ulimit -s 2048`, the Rust spawned-thread default) compiles a 1,000-link
 *   chain, so 128 keeps ~8× margin in the most stack-hungry tier.
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
  MAX_SOURCE_NESTING: 128,               // nesting depth of a Rúnar source (F-213):
                                         // parse nesting (A) and AST nesting (B),
                                         // both enforced in all 7 tiers
  MAX_CALL_DEPTH: 128,                   // longest private-method call chain of a
                                         // Rúnar source (N-180), enforced by the
                                         // validator in all 7 tiers
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
