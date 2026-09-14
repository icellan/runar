/**
 * R-126 — the reference tier CRASHES on a type error in a tuple-form
 * `addOutput`, where the other six print a diagnostic.
 *
 * `flattenAddOutputArgs` (shared by 03-typecheck and 04-anf-lower) rewrites
 * `[sats, <array_literal>]` into `[sats, e0, e1, ...]`, so a tuple-form call
 * arrives at the state-value loop with `args.length === 2` and
 * `normalizedArgs.length === 1 + slots`. The loop iterates the NORMALIZED list
 * but three copies of the diagnostic indexed the RAW one:
 *
 *     args[i + 1]!.sourceLocation      // undefined for every i >= 1
 *
 * which is a TypeError thrown out of `checkCallExpr`. `compile()` catches it
 * and files it as a diagnostic, so the failure does not look like a crash from
 * the outside — it looks like a compiler error whose text happens to be
 * "Cannot read properties of undefined (reading 'sourceLocation')". That is
 * why every expectation below pins the MESSAGE and a real source location, and
 * none of them merely assert that nothing threw: a test written the loose way
 * passes against the broken compiler.
 *
 * Measured before the fix, same contract in each surface:
 *
 *   ts                          TypeError: Cannot read properties of undefined
 *   go/rust/python/ruby/zig/java  addOutput() argument 3 (b) must be 'bigint',
 *                                 got 'ByteString'
 *
 * There are three copies because `addOutput` is reached through three distinct
 * callee shapes, and each surface exercises a different one. All three are
 * covered here so that re-breaking any single site reddens exactly one row:
 *
 *   property_access            `self.addOutput(...)`  (.runar.zig, .runar.move)
 *   member_expr / <this>       `self.add_output(...)` (.runar.py)
 *   member_expr / ctx param    `ctx.AddOutput(...)`   (.runar.go)
 *
 * The third was already correct when this file was written; it is here as the
 * shape the other two were fixed to match, and as a regression guard on it.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** The one diagnostic every tier but TypeScript already produced. */
const EXPECTED = "addOutput() argument 3 (b) must be 'bigint', got 'ByteString'";

/**
 * Three mutable slots, and the SECOND state value is a ByteString where a
 * bigint belongs. The second matters: `args[i + 1]` is still in range for
 * `i === 0` (it lands on the array literal itself — the wrong node, but a
 * defined one), so an error on the first state value would not crash.
 */
const ZIG_PROPERTY_ACCESS = `const runar = @import("runar");

pub const Tup = struct {
    pub const Contract = runar.StatefulSmartContract;

    a: i64 = 0,
    b: i64 = 0,
    blob: runar.ByteString = "",

    pub fn init(a: i64, b: i64, blob: runar.ByteString) Tup {
        return .{ .a = a, .b = b, .blob = blob };
    }

    pub fn m(self: *Tup, x: i64) void {
        self.addOutput(1000, .{ x, self.blob, self.blob });
    }
};
`;

const MOVE_PROPERTY_ACCESS = `module Tup {
    resource struct Tup {
        a: &mut bigint,
        b: &mut bigint,
        blob: &mut ByteString,
    }

    public fun m(contract: &mut Tup, x: bigint) {
        contract.addOutput(1000, [x, contract.blob, contract.blob]);
    }
}
`;

const PYTHON_MEMBER_THIS = `from runar import (
    StatefulSmartContract, Bigint, ByteString, public,
)


class Tup(StatefulSmartContract):
    a: Bigint
    b: Bigint
    blob: ByteString

    def __init__(self, a: Bigint, b: Bigint, blob: ByteString):
        super().__init__(a, b, blob)
        self.a = a
        self.b = b
        self.blob = blob

    @public
    def m(self, x: Bigint):
        self.add_output(1000, [x, self.blob, self.blob])
`;

/**
 * The `ctx: StatefulContext` calling convention, which is the ONLY shape that
 * reaches the third copy. Zig's `ctx.addOutput(...)` does not: its parser emits
 * `property_access` for any dotted call, so it lands back on the first copy.
 * The Go DSL emits `member_expr` with a `StatefulContext`-typed object, which
 * is what `isStatefulContextType` tests for.
 */
const GO_MEMBER_CTX = `//go:build ignore

package x

import runar "github.com/icellan/runar/packages/runar-go"

type Tup struct {
	runar.StatefulSmartContract

	A    runar.Bigint
	B    runar.Bigint
	Blob runar.ByteString
}

func (c *Tup) M(ctx runar.StatefulContext, x runar.Bigint) {
	ctx.AddOutput(1000, {x, c.Blob, c.Blob})
}
`;

const CASES: ReadonlyArray<readonly [string, string, string, string]> = [
  ['property_access', 'Tup.runar.zig', ZIG_PROPERTY_ACCESS, 'self.addOutput'],
  ['property_access', 'Tup.runar.move', MOVE_PROPERTY_ACCESS, 'contract.addOutput'],
  ['member_expr / <this>', 'Tup.runar.py', PYTHON_MEMBER_THIS, 'self.add_output'],
  ['member_expr / ctx param', 'Tup.runar.go', GO_MEMBER_CTX, 'ctx.AddOutput'],
];

describe('R-126: tuple-form addOutput reports a type error instead of crashing', () => {
  for (const [site, fileName, source, callShape] of CASES) {
    it(`${fileName} (${site}, ${callShape}) gets the diagnostic, not a TypeError`, () => {
      const result = compile(source, { fileName });
      const errors = (result.diagnostics ?? []).filter((d) => d.severity === 'error');

      // The whole point: the crash arrives DISGUISED as a diagnostic, so the
      // message is the assertion. `toEqual` on the full list also catches a
      // fix that silences the error rather than locating it.
      expect(errors.map((d) => d.message)).toEqual([EXPECTED]);

      // ...and it must point somewhere real. `args[i + 1]!.sourceLocation` on
      // an undefined element is what threw; a fix that dropped the location
      // entirely would pass the message check above.
      const loc = errors[0]!.loc;
      expect(loc, 'the diagnostic carries no source location').toBeDefined();
      expect(loc!.file).toBe(fileName);
      expect(loc!.line).toBeGreaterThan(0);
      expect(loc!.column).toBeGreaterThan(0);
    });
  }

  it('the same contract with correct state-value types compiles', () => {
    // Vacuity guard. Every row above asserts a REJECTION, so a compiler that
    // refused these surfaces outright would score four green rows. This is the
    // zig contract with the ByteString slot fed a ByteString.
    const ok = ZIG_PROPERTY_ACCESS.replace(
      'self.addOutput(1000, .{ x, self.blob, self.blob });',
      'self.addOutput(1000, .{ x, x, self.blob });',
    );
    const result = compile(ok, { fileName: 'Tup.runar.zig' });
    const errors = (result.diagnostics ?? []).filter((d) => d.severity === 'error');
    expect(errors.map((d) => d.message)).toEqual([]);
    expect(result.artifact?.script).toMatch(/^[0-9a-f]+$/);
  });
});
