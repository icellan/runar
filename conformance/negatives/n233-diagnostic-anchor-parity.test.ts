import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-233 — tiers anchor the same diagnostic at the same AST NODE.
 *
 * N-078 made every tier print a 0-based column; this item is about which node
 * the column points at. The TS reference is the anchor (dispatcher decision).
 *
 * Converged here — N175-N179, the `.runar.go` ambiguous operator precedence
 * refusal (N-056). TS anchors it at the ambiguous binary expression, whose
 * position is its leftmost operand. Before this item Go and Rust, Python,
 * Ruby and Java printed the message with no location at all (Go's only
 * location was a follow-on "unsupported Go statement" at the statement), and
 * Zig pointed at the token after the expression. The expected column is
 * computed from the fixture text (`lineText.indexOf(anchor)`), never copied
 * from a compiler's output, and it is read from the line that carries the
 * precedence message, not from whatever location a tier prints first.
 *
 * Converged by N-463 — the `.runar.ts` typecheck refusals N15-N17 and
 * N200-N209. TS anchors each at the offending EXPRESSION: the left operand of
 * a non-bigint comparison (N15, a call `this.hp()`), the satoshis argument of
 * addOutput (N16, `this.blob`), the ternary (N17, its condition `f`), and the
 * re-consumed affine identifier (N200-N209, `sig`). Before N-463 Go, Python,
 * Ruby and Java anchored them at the enclosing statement, Rust at the method
 * header, and Zig printed no location at all, because their expression nodes
 * carried no source position. The message fragment is matched rather than the
 * full text because the tiers word these four messages slightly differently
 * (`Left`/`left`, Java's `'X' vs 'Y'`), which this item does not change.
 *
 * Converged by N-464 — the verifyRabinSig public-key refusal N220-N228, one
 * fixture per surface. User decision R186: the anchor is the 4th argument
 * itself, on all nine surfaces in all seven tiers. Before N-464 TS put it at
 * the call on `.runar.ts`, at the call's `(` on `.runar.rs` and at the method
 * header on the other seven surfaces, and the other tiers scattered between
 * statement, method and parameter. Every surface parser in every tier now
 * records an identifier's token as its location (Zig: the call's per-argument
 * locations), and every validator anchors the refusal there, falling back to
 * the old anchor when the argument carries none.
 *
 * Converged by N-472 — the residual typecheck anchors N-463 left behind, one
 * crafted negative per shape (fixtures N472-*). Unary `-` / `~` operand errors
 * anchor at the OPERATOR token (TS records a location on the unary node);
 * a composite whose first token is `(` anchors at that `(` (TS locates a
 * binary node by its own start), while a parenthesised operand is the
 * expression INSIDE the parentheses; a bigint or boolean literal operand has
 * no location in TS, so every tier prints none instead of falling back to the
 * statement; the second argument of addRawOutput / addDataOutput anchors at
 * that argument; the right / bitwise / shift operand and the affine
 * method-consumed-property sites are pinned too. Four rows run on other
 * surfaces: a literal argument of addRawOutput on `.runar.sol` and
 * `.runar.zig` falls back to the statement (Zig used to print the literal's
 * own position), and a composite argument on `.runar.zig` anchors at its
 * first token, also when it follows a `ctx` handle that Zig drops from the
 * argument list. A `null` anchor below means "the message line carries no
 * location at all".
 *
 * ANCHOR_PENDING (now empty) is where a row goes when a decision on the
 * anchor is needed; such a row is pinned as divergent so that converging it
 * fails here until it moves into CASES.
 *
 * What this proves: for every CASES row every tier is present, refuses, and
 * prints the row's message at `<file>:<line>:<column of the anchor text>`.
 * What it does NOT prove: node parity for any other diagnostic, or for the
 * N-463 / N-472 diagnostics on the surfaces other than those four rows
 * (TS's own parsers disagree between surfaces: `.runar.zig` locates a
 * composite argument, `.runar.sol` does not); the verifyRabinSig
 * anchor when the 4th argument is a composite (arithmetic, ternary, call) or
 * the refusal comes from a private helper's parameter; that a tier's
 * follow-on diagnostics (Go's "unsupported Go statement") agree; anchor
 * agreement for an ambiguous edge nested under a non-ambiguous parent, where
 * Go precedence and the C ladder pick different parent nodes; a composite
 * that starts with a bigint / boolean literal (`5n + this.pk > x`) or with a
 * parenthesised call or ternary; the other members of the families beyond
 * the one shape each row exercises.
 */

const TIERS = buildSourceTiers();
const PRECEDENCE = 'ambiguous operator precedence in .runar.go';
const AFFINE = "affine value 'sig' has already been consumed";
const AFFINE_PROP = "affine value 'this.sig' has already been consumed";
const RAW_SATS = 'addRawOutput() first argument (satoshis) must be bigint';
const RAW_SCRIPT = 'addRawOutput() second argument (scriptBytes) must be ByteString';
const DATA_SATS = 'addDataOutput() first argument (satoshis) must be bigint';
const DATA_SCRIPT = 'addDataOutput() second argument (scriptBytes) must be ByteString';
const RABIN = 'verifyRabinSig public key (4th argument) must be a contract property or a literal';

/**
 * [fixture, 1-based line, anchor text whose first character is the position,
 *  message fragment the located line must carry]. A null anchor expects the
 * message line to carry no location at all.
 */
const CASES: Array<[string, number, string | null, string]> = [
  ['N175-go-precedence-and-add.runar.go', 20, 'a & b + 1', PRECEDENCE],
  ['N176-go-precedence-add-shift.runar.go', 20, 'a + b << 2', PRECEDENCE],
  ['N177-go-precedence-or-add.runar.go', 20, 'a | b + d', PRECEDENCE],
  ['N178-go-precedence-and-eq.runar.go', 22, 'a & 255 == 15', PRECEDENCE],
  ['N179-go-precedence-shift-mul.runar.go', 20, 'a << b * d', PRECEDENCE],
  // N-463: the offending expression, not the statement or method.
  ['N15-unknown-operand-type.runar.ts', 36, 'this.hp() > x', "operand of '>' must be bigint"],
  ['N16-bytestring-satoshis.runar.ts', 47, 'this.blob,', 'first argument (satoshis) must be bigint'],
  ['N17-ternary-branch-types.runar.ts', 43, 'f ? this.blob', 'ranches have incompatible types'],
  // The second consumption of `sig` on every path is the refused one.
  ['N200-ts-affine-sig-then-arm-and-after-if.runar.ts', 20, 'sig,', AFFINE],
  ['N201-ts-affine-sig-else-arm-and-after-if.runar.ts', 22, 'sig,', AFFINE],
  ['N202-ts-affine-sig-both-arms-and-after-if.runar.ts', 23, 'sig,', AFFINE],
  ['N203-ts-affine-sig-nested-arm-and-after-if.runar.ts', 25, 'sig,', AFFINE],
  ['N204-ts-affine-sig-alias-arm-and-after-if.runar.ts', 24, 'sig,', AFFINE],
  ['N205-ts-affine-sig-before-if-and-in-arm.runar.ts', 19, 'sig,', AFFINE],
  ['N206-ts-affine-sig-twice-in-then-arm.runar.ts', 19, 'sig,', AFFINE],
  ['N207-ts-affine-sig-twice-in-else-arm.runar.ts', 21, 'sig,', AFFINE],
  // Loop body unrolled: iteration 1 consumes in one arm, iteration 2's then
  // arm (the first statement it reaches) is the second consumption.
  ['N208-ts-affine-sig-if-else-in-repeating-loop.runar.ts', 20, 'sig,', AFFINE],
  ['N209-ts-affine-sig-if-condition-and-arm.runar.ts', 21, 'sig,', AFFINE],
  // N-464 (user decision R186): the verifyRabinSig public-key refusal is
  // anchored at the 4th argument itself, on all nine surfaces. Here that
  // argument is the method parameter `n`. On `.runar.rs` it is written `&n`;
  // every tier's Rust-DSL parser drops the `&` and the argument node is the
  // identifier `n`, so the anchor is `n`, not `&`.
  ['N220-ts-rabin-pubkey-param.runar.ts', 17, 'n)', RABIN],
  ['N221-sol-rabin-pubkey-param.runar.sol', 16, 'n)', RABIN],
  ['N222-move-rabin-pubkey-param.runar.move', 15, 'n)', RABIN],
  ['N223-go-rabin-pubkey-param.runar.go', 16, 'n)', RABIN],
  ['N224-rs-rabin-pubkey-param.runar.rs', 16, 'n)', RABIN],
  ['N225-py-rabin-pubkey-param.runar.py', 18, 'n)', RABIN],
  ['N226-zig-rabin-pubkey-param.runar.zig', 18, 'n)', RABIN],
  ['N227-rb-rabin-pubkey-param.runar.rb', 18, 'n)', RABIN],
  ['N228-java-rabin-pubkey-param.runar.java', 28, 'n)', RABIN],
  // N-472: the residual N-463 shapes. The message fragments omit the first
  // letter's case (`Left`/`left`) because the tiers word them differently.
  ['N472-ts-unary-minus-operand.runar.ts', 20, '-this.hp()', "perand of unary '-' must be bigint"],
  ['N472-ts-unary-tilde-operand.runar.ts', 20, '~flag', "perand of '~' must be bigint or ByteString"],
  ['N472-ts-paren-composite-left.runar.ts', 20, '(this.pk + this.pk) + this.pk', "eft operand of '>' must be bigint"],
  ['N472-ts-paren-wrapped-operand.runar.ts', 18, 'this.pk + this.pk', "eft operand of '*' must be bigint"],
  ['N472-ts-literal-left-operand.runar.ts', 20, null, "eft operand of '>' must be bigint"],
  ['N472-ts-bigint-literal-left-operand.runar.ts', 20, null, "eft operand of '&&' must be boolean"],
  ['N472-ts-right-operand.runar.ts', 20, 'flag >', "ight operand of '-' must be bigint"],
  ['N472-ts-bitwise-operand.runar.ts', 20, 'flag)', "ight operand of '&' must be bigint or ByteString"],
  ['N472-ts-shift-operand.runar.ts', 20, 'flag)', "ight operand of '<<' must be bigint"],
  ['N472-ts-raw-output-satoshis.runar.ts', 16, 'x > 0n', RAW_SATS],
  ['N472-ts-raw-output-script.runar.ts', 16, 'flag)', RAW_SCRIPT],
  ['N472-ts-data-output-satoshis.runar.ts', 16, 'flag,', DATA_SATS],
  ['N472-ts-data-output-script.runar.ts', 16, 'x + 1n', DATA_SCRIPT],
  // The second call of a helper that consumes a Sig property: the first
  // argument when it has one, else the statement.
  ['N472-ts-affine-property-helper-no-arg.runar.ts', 24, 'this.h();', AFFINE_PROP],
  ['N472-ts-affine-property-helper-with-arg.runar.ts', 25, 'n);', AFFINE_PROP],
  // Other surfaces. A literal argument has no location, so TS falls back to
  // the statement; `.runar.zig` locates a composite argument at its first
  // token.
  ['N472-sol-raw-output-literal-satoshis.runar.sol', 15, 'this.addRawOutput', RAW_SATS],
  ['N472-zig-raw-output-literal-satoshis.runar.zig', 17, 'ctx.addRawOutput', RAW_SATS],
  ['N472-zig-raw-output-composite-script.runar.zig', 17, 'n + 1', RAW_SCRIPT],
  // `self.check(ctx, sig)`: Zig drops the `ctx` argument, and the location of
  // the argument that remains must keep its index.
  ['N472-zig-ctx-helper-affine-arg.runar.zig', 26, 'sig);', AFFINE],
];

/** Still divergent on the anchor node (see header). [fixture, message fragment]. */
const ANCHOR_PENDING: Array<[string, string]> = [];

function expectedColumn(fixture: string, line: number, anchor: string): number {
  const text = readFileSync(join(REPO, 'conformance/negatives', fixture), 'utf8').split('\n')[line - 1] ?? '';
  const col = text.indexOf(anchor);
  if (col < 0) throw new Error(`${fixture}:${line}: anchor ${JSON.stringify(anchor)} not on that line`);
  if (text.indexOf(anchor, col + 1) >= 0) throw new Error(`${fixture}:${line}: anchor ${JSON.stringify(anchor)} not unique`);
  return col;
}

/** The `L:C` printed on the first diagnostic line carrying `message`, or null. */
function locationOf(diag: string, fixture: string, message: string): string | null {
  const esc = fixture.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const line = diag.split('\n').find((l) => l.includes(message));
  if (line === undefined) return null;
  const m = line.match(new RegExp(`${esc}:(\\d+):(\\d+):`));
  return m ? `${m[1]}:${m[2]}` : null;
}

describe('N-233: every tier anchors a diagnostic at the same node', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, line, anchor, message] of CASES) {
    it(`${fixture} -> ${anchor === null ? 'no location' : `:${line}:<column of ${JSON.stringify(anchor)}>`}`, () => {
      const want = anchor === null ? null : `${line}:${expectedColumn(fixture, line, anchor)}`;
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print ${JSON.stringify(message)}`).toContain(message);
        got[tier.id] = locationOf(r.diag, fixture, message);
        if (anchor === null) {
          // `file:line:` without a column would also read as "no location" above.
          const carried = r.diag.split('\n').find((l) => l.includes(message));
          expect(carried, `${tier.id} must print the message`).not.toContain(`${fixture}:`);
        }
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, want])));
    }, 900_000);
  }

  for (const [fixture, message] of ANCHOR_PENDING) {
    it(`${fixture} still diverges on the anchor node (pending; move to CASES when fixed)`, () => {
      const got = new Set<string | null>();
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print ${JSON.stringify(message)}`).toContain(message);
        got.add(locationOf(r.diag, fixture, message));
      }
      expect(got.size).toBeGreaterThan(1);
    }, 900_000);
  }
});
