import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, type Tier } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-470 — the Zig discard statement `_ = <name>;` on the .runar.zig surface,
 * seven-tier regression pin.
 *
 * Native Zig requires every parameter to be used, so a stateful method that
 * takes `ctx: runar.StatefulContext` (or any other parameter it does not read)
 * writes `_ = ctx;`. The finding was that all seven tiers refused it as
 * "Undefined variable 'ctx'". N-053 (977907fdd) already fixed that: each Zig
 * surface parser drops a discard whose right-hand side is a bare identifier
 * (reading a name has no effect). This test pins the behaviour so a tier that
 * regresses to refusing, or to emitting a statement for it, goes red.
 *
 * What this proves: for a stateful contract with `_ = ctx;` and `_ = x;` as
 * the first statements of a public method, `_ = ctx;` after other statements,
 * and `_ = ctx;` inside a private helper reached via `self.helper(ctx, ...)`,
 * every available tier produces hex byte-identical to the same contract with
 * the `_ =` lines removed, in both fold modes, and all tiers agree with each
 * other.
 * What it does NOT prove: a discard of a non-name expression (that one is kept
 * as an expression statement, by N-053), any surface other than .runar.zig, or
 * on-chain behaviour of the bytes.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

/** `discard` is the text of each `_ = name;` line; empty for the baseline. */
function contract(discard: (name: string) => string): string {
  return `const runar = @import("runar");

pub const Ledger = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Ledger {
        return .{ .count = count };
    }

    fn record(self: *Ledger, ctx: runar.StatefulContext, payload: runar.ByteString) void {
${discard('ctx')}        ctx.addDataOutput(0, payload);
    }

    pub fn bump(self: *Ledger, ctx: runar.StatefulContext, x: i64, unused: i64) void {
${discard('ctx')}${discard('unused')}        self.count = self.count + x;
${discard('x')}        runar.assert(true);
    }

    pub fn log(self: *Ledger, ctx: runar.StatefulContext, payload: runar.ByteString) void {
        self.count = self.count + 1;
${discard('ctx')}        self.record(ctx, payload);
        runar.assert(true);
    }
};
`;
}

const WITH_DISCARDS = contract((n) => `        _ = ${n};\n`);
const BASELINE = contract(() => '');

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n470-zig-discard-'));
});

let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'Ledger.runar.zig');
  writeFileSync(p, src);
  return p;
}

describe('N-470 `_ = <name>;` discard (.runar.zig) — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    const hexes = new Map<string, string>();
    for (const tier of tiers) {
      it(`${tier.id} (${mode}) compiles the discard spelling to the baseline's bytes`, () => {
        const base = compileHex(tier, write(BASELINE));
        const got = compileHex(tier, write(WITH_DISCARDS));
        expect(got).toBe(base);
        hexes.set(tier.id, got);
      });
    }
    it(`all tiers agree on the discard spelling (${mode})`, () => {
      expect(hexes.size).toBe(tiers.length);
      expect(new Set(hexes.values()).size).toBe(1);
    });
  }
});
