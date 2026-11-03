import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge, REPO, type Tier } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-453 — a `StatefulContext` handle threaded into a PRIVATE helper on the
 * .runar.zig surface, seven-tier parity.
 *
 * On .runar.zig a stateful method takes `ctx: runar.StatefulContext` and writes
 * `ctx.addOutput(...)` / `ctx.addDataOutput(...)` (the form a native Zig test
 * needs, since Zig 0.16 cannot inject intrinsics into the contract struct).
 * The context is a compiler-re-injected handle, not a spending parameter, so
 * every tier elides it from a method's parameter list (N-304). A call site
 * `self.record(ctx, payload)` still PASSED it, though: TS, Go, Rust, Python,
 * Ruby and Java refused with "record() expects 1 argument(s), got 2" plus
 * "Undefined variable 'ctx'", and Zig (whose own parser keeps the parameter
 * and elided it only on public methods) died in stack lowering with
 * "method parameter 'ctx' is not on the stack ... SilentOpZeroRefused".
 *
 * Fixed: a bare identifier naming a StatefulContext parameter of the enclosing
 * method is dropped from a `self.method(...)` argument list (the parser in the
 * six tiers; ANF lowering + typecheck arity in Zig, which also strips the
 * handle from a private helper's own parameter list). Anywhere else a bare
 * `ctx` is still not a value and is refused.
 *
 * What this proves:
 *   - the ctx-threading spelling of the private-helper-outputs fixture
 *     compiles, on every available tier and in both fold modes, to the
 *     checked-in golden conformance/tests/private-helper-outputs/
 *     expected-script.hex (the non-ctx spelling's bytes) — so the handle
 *     contributes nothing to the script;
 *   - a helper that names its handle differently from the caller (`c` vs
 *     `ctx`) compiles to the same bytes;
 *   - a bare `ctx` assigned to a local, passed to a builtin, or returned is
 *     refused by every tier with "Undefined variable 'ctx'".
 * What it does NOT prove: any surface other than .runar.zig (no other
 *   surface has a ctx-style handle), a handle passed in a position other than
 *   a `self.method(...)` argument, or the on-chain behaviour of the bytes
 *   (that is the golden's own witness).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const GOLDEN = readFileSync(
  join(REPO, 'conformance/tests/private-helper-outputs/expected-script.hex'),
  'utf-8',
).trim();

/** The private-helper-outputs fixture with the context threaded through
 *  the private helpers (`self.record(ctx, payload)`). */
function ctxVariant(helperCtx: string): string {
  return `const runar = @import("runar");

pub const PrivateHelperOutputs = struct {
    pub const Contract = runar.StatefulSmartContract;

    counter: i64 = 0,

    pub fn init(counter: i64) PrivateHelperOutputs {
        return .{ .counter = counter };
    }

    fn bump(self: *PrivateHelperOutputs) void {
        self.counter = self.counter + 1;
    }

    fn record(self: *PrivateHelperOutputs, ${helperCtx}: runar.StatefulContext, payload: runar.ByteString) void {
        ${helperCtx}.addDataOutput(0, payload);
    }

    fn forkOutput(self: *PrivateHelperOutputs, ${helperCtx}: runar.StatefulContext, amount: i64, leftover: i64) void {
        ${helperCtx}.addOutput(amount, .{leftover});
    }

    pub fn commit(self: *PrivateHelperOutputs) void {
        self.bump();
        runar.assert(true);
    }

    pub fn log(self: *PrivateHelperOutputs, ctx: runar.StatefulContext, payload: runar.ByteString) void {
        self.record(ctx, payload);
        runar.assert(true);
    }

    pub fn partition(self: *PrivateHelperOutputs, ctx: runar.StatefulContext, amount: i64, leftover: i64) void {
        self.forkOutput(ctx, amount, leftover);
        runar.assert(true);
    }
};
`;
}

/** A stateful contract whose public method body is `body`; `helpers` are
 *  extra private methods. Used for the refusal rows. */
function refusal(helpers: string, body: string): string {
  return `const runar = @import("runar");

pub const CtxMisuse = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) CtxMisuse {
        return .{ .count = count };
    }
${helpers}
    pub fn bump(self: *CtxMisuse, ctx: runar.StatefulContext, x: i64) void {
${body}
        self.count = self.count + x;
        runar.assert(true);
    }
};
`;
}

const POSITIVE: Array<[string, string]> = [
  ['the ctx-threading private-helper-outputs', ctxVariant('ctx')],
  ['a helper naming its handle `c`', ctxVariant('c')],
];

const REFUSED: Array<[string, string]> = [
  ['a bare ctx assigned to a local', refusal('', '        const h = ctx;\n        runar.assert(h == h);')],
  ['a bare ctx passed to a builtin', refusal('', '        runar.assert(runar.len(runar.sha256(ctx)) == 32);')],
  [
    'a bare ctx returned from a private helper',
    refusal(
      '\n    fn pick(self: *CtxMisuse, ctx: runar.StatefulContext) i64 {\n        return ctx;\n    }\n',
      '        runar.assert(self.pick(ctx) == 1);',
    ),
  ],
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n453-zig-stateful-context-'));
});

let seq = 0;
function write(name: string, src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, name);
  writeFileSync(p, src);
  return p;
}

describe('N-453 StatefulContext threaded into a private helper (.runar.zig) — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, src] of POSITIVE) {
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the private-helper-outputs golden`, () => {
          expect(compileHex(tier, write('PrivateHelperOutputs.runar.zig', src))).toBe(GOLDEN);
        });
      }
    }
  }

  for (const [name, src] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const { verdict, diag } = judge(tier, write('CtxMisuse.runar.zig', src));
        expect(verdict).toBe('rejected');
        expect(diag).toContain("Undefined variable 'ctx'");
      });
    }
  }
});
