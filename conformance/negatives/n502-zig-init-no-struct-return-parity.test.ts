import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-502 — a `.runar.zig` `init` that does not `return .{ ... }` gets implicit
 * param-to-property assignments in every tier.
 *
 * The TS parser appends `this.<p> = <p>` for every property that shares a name
 * with an `init` parameter when the body has no struct return. Rust's
 * parser_zig.rs left that branch empty (a comment saying a fallback handled
 * it), so the constructor assigned nothing and the contract compiled to
 * different bytes.
 *
 * Proves, for every available tier, in both fold modes: the contract whose
 * `init` has an empty body compiles to the same hex as TS, and that hex equals
 * the hex of the same contract written with an explicit
 * `return .{ .a = a, .b = b }`. Does not prove: init bodies that mix other
 * statements with a missing struct return, nor non-Zig surfaces.
 */

const IMPLICIT =
  'const runar = @import("runar");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    a: i64,\n    b: i64,\n    pub fn init(a: i64, b: i64) P {\n    }\n    pub fn check(self: *const P, x: i64) void {\n        runar.assert(x + self.a == self.b);\n    }\n};\n';
const EXPLICIT = IMPLICIT.replace('    pub fn init(a: i64, b: i64) P {\n    }', '    pub fn init(a: i64, b: i64) P { return .{ .a = a, .b = b }; }');

const TIMEOUT_MS = 600_000;
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n502-'));
});
let seq = 0;
function write(text: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'P.runar.zig');
  writeFileSync(p, text);
  return p;
}

describe('N-502 .runar.zig init without struct return', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [['fold-on', TIERS], ['fold-off', FOLD_OFF]] as const) {
    it(`${mode}: every tier compiles the implicit init to the explicit-return TS bytes`, () => {
      const ts = tiers.find((t) => t.id === 'ts');
      expect(ts, 'the TS reference tier is required').toBeDefined();
      const want = compileHex(ts!, write(EXPLICIT));
      expect(compileHex(ts!, write(IMPLICIT)), 'ts implicit vs explicit').toBe(want);
      const file = write(IMPLICIT);
      for (const tier of tiers) {
        expect(compileHex(tier, file), `${tier.id} on implicit init`).toBe(want);
      }
    }, TIMEOUT_MS);
  }
});
