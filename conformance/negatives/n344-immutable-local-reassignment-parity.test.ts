import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';

/**
 * N-344 — reassigning an immutable local on the `.runar.rs` (`let` without
 * `mut`) and `.runar.zig` (`const`) surfaces is refused by every tier, with the
 * ONE sentence N-342 introduced for `.runar.ts`.
 *
 * N-342 found that the probe matrix accepted `let s = 1; s = s + x;` (Rust DSL)
 * and `const s = 1; s = s + x;` (Zig) in all seven tiers: every parser records
 * the declaration kind (`mutable`, or a separate const/let node in the Zig
 * tier) and nothing read it. User decision R121: refuse, all seven tiers.
 *
 * What this proves, per tier and per surface:
 *   - an immutable local reassigned by `=`, by a compound assignment, from
 *     inside a nested `if` body and from inside a loop body is refused with
 *     "Cannot assign to '<name>' because it is a constant.";
 *   - on `.runar.zig`, a `const` loop variable advanced by the `while`
 *     continue expression is refused too;
 *   - the mutable twin (`let mut` / `var`) of every program is accepted and all
 *     seven tiers compile it to the same hex (so the controls are real
 *     programs, and a tier that refuses everything cannot pass);
 *   - scope is respected: an immutable binding in a sibling block does not
 *     freeze a later mutable binding of the same name.
 * What it does NOT prove:
 *   - ++ / -- : neither the Rust DSL nor Zig has them, so there is nothing to
 *     probe on these surfaces;
 *   - Rust shadowing (`let s = 1; let s = s + x;`) is a new binding, not a
 *     reassignment, and is not exercised here;
 *   - element writes through an immutable local, parameters, `self.<prop>`;
 *   - the Go `const`, Java `final`, Python, Ruby, Solidity-like and Move
 *     surfaces, which have no immutable-local spelling the compilers accept.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n344-'));
let n = 0;

function write(ext: string, text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, `Probe.runar.${ext}`);
  writeFileSync(path, text);
  return path;
}

const rs = (body: string) => `use runar::prelude::*;

#[runar::contract]
struct Probe {
    #[readonly]
    n: Int,
}

impl Probe {
    pub fn verify(&self, x: Int) {
${body}
    }
}
`;

const zig = (body: string) => `const runar = @import("runar");

pub const Probe = struct {
    pub const Contract = runar.SmartContract;

    n: i64,

    pub fn init(n: i64) Probe {
        return .{ .n = n };
    }

    pub fn verify(self: *const Probe, x: i64) void {
${body}
    }
};
`;

interface Case {
  surface: 'rs' | 'zig';
  name: string;
  bad: string;
  good: string;
}

const CASES: Case[] = [
  {
    surface: 'rs',
    name: 'plain assignment',
    bad: rs(`        let s: Int = 1;\n        s = s + x;\n        assert!(s == self.n);`),
    good: rs(`        let mut s: Int = 1;\n        s = s + x;\n        assert!(s == self.n);`),
  },
  {
    surface: 'rs',
    name: 'compound assignment',
    bad: rs(`        let s: Int = 1;\n        s += x;\n        assert!(s == self.n);`),
    good: rs(`        let mut s: Int = 1;\n        s += x;\n        assert!(s == self.n);`),
  },
  {
    surface: 'rs',
    name: 'reassigned inside an if branch',
    bad: rs(`        let s: Int = 1;\n        if x > 0 {\n            s = s + x;\n        }\n        assert!(s == self.n);`),
    good: rs(`        let mut s: Int = 1;\n        if x > 0 {\n            s = s + x;\n        }\n        assert!(s == self.n);`),
  },
  {
    surface: 'rs',
    name: 'reassigned inside a for body',
    bad: rs(`        let s: Int = 0;\n        for i in 0..3 {\n            s = s + i;\n        }\n        assert!(s == x + self.n);`),
    good: rs(`        let mut s: Int = 0;\n        for i in 0..3 {\n            s = s + i;\n        }\n        assert!(s == x + self.n);`),
  },
  {
    surface: 'zig',
    name: 'plain assignment',
    bad: zig(`        const s: i64 = 1;\n        s = s + x;\n        runar.assert(s == self.n);`),
    good: zig(`        var s: i64 = 1;\n        s = s + x;\n        runar.assert(s == self.n);`),
  },
  {
    surface: 'zig',
    name: 'compound assignment',
    bad: zig(`        const s: i64 = 1;\n        s += x;\n        runar.assert(s == self.n);`),
    good: zig(`        var s: i64 = 1;\n        s += x;\n        runar.assert(s == self.n);`),
  },
  {
    surface: 'zig',
    name: 'reassigned inside an if branch',
    bad: zig(`        const s: i64 = 1;\n        if (x > 0) {\n            s = s + x;\n        }\n        runar.assert(s == self.n);`),
    good: zig(`        var s: i64 = 1;\n        if (x > 0) {\n            s = s + x;\n        }\n        runar.assert(s == self.n);`),
  },
  {
    surface: 'zig',
    name: 'reassigned inside a while body',
    bad: zig(
      `        const s: i64 = 0;\n        var i: i64 = 0;\n        while (i < 3) : (i += 1) {\n            s = s + i;\n        }\n        runar.assert(s == x + self.n);`,
    ),
    good: zig(
      `        var s: i64 = 0;\n        var i: i64 = 0;\n        while (i < 3) : (i += 1) {\n            s = s + i;\n        }\n        runar.assert(s == x + self.n);`,
    ),
  },
  {
    surface: 'zig',
    name: 'const loop variable advanced by the while continue expression',
    bad: zig(
      `        var s: i64 = 0;\n        const i: i64 = 0;\n        while (i < 3) : (i += 1) {\n            s = s + 1;\n        }\n        runar.assert(s == x + self.n);`,
    ),
    good: zig(
      `        var s: i64 = 0;\n        var i: i64 = 0;\n        while (i < 3) : (i += 1) {\n            s = s + 1;\n        }\n        runar.assert(s == x + self.n);`,
    ),
  },
];

// Scope control: the immutable `t` lives only in the if block; the later
// mutable `t` is a different binding and must stay assignable.
const SCOPE_CONTROLS: { surface: 'rs' | 'zig'; src: string }[] = [
  {
    surface: 'rs',
    src: rs(
      `        if x > 0 {\n            let t: Int = 2;\n            assert!(t == 2);\n        }\n        let mut t: Int = 1;\n        t = t + x;\n        assert!(t == self.n);`,
    ),
  },
  {
    surface: 'zig',
    src: zig(
      `        if (x > 0) {\n            const t: i64 = 2;\n            runar.assert(t == 2);\n        }\n        var t: i64 = 1;\n        t = t + x;\n        runar.assert(t == self.n);`,
    ),
  },
];

const SENTENCE = /Cannot assign to '[A-Za-z_]\w*' because it is a constant\./;

describe('N-344: immutable local reassignment is refused by every tier on .runar.rs and .runar.zig', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const c of CASES) {
    it(`.runar.${c.surface} ${c.name}: mutable twin accepted with one hex, immutable program refused by every tier`, () => {
      const goodPath = write(c.surface, c.good);
      const badPath = write(c.surface, c.bad);
      const hexes = new Set<string>();
      for (const tier of TIERS) {
        const hex = compileHex(tier, goodPath);
        expect(hex.length, `${tier.id} control produced no hex`).toBeGreaterThan(0);
        hexes.add(hex);
      }
      expect(hexes.size, 'all tiers agree on the mutable twin').toBe(1);

      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, badPath);
        got[tier.id] =
          r.verdict === 'rejected'
            ? SENTENCE.test(r.diag)
              ? 'rejected'
              : `rejected with wrong diagnostic: ${r.diag.slice(0, 200)}`
            : 'ACCEPTED';
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'rejected'])));
    }, 900_000);
  }

  for (const s of SCOPE_CONTROLS) {
    it(`.runar.${s.surface} scope: an immutable binding in a sibling block does not freeze a later mutable one`, () => {
      const path = write(s.surface, s.src);
      const hexes = new Set<string>();
      for (const tier of TIERS) hexes.add(compileHex(tier, path));
      expect(hexes.size).toBe(1);
    }, 900_000);
  }
});
