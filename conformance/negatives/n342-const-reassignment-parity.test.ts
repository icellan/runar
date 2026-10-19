import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';

/**
 * N-342 — reassigning a `const` local on the `.runar.ts` surface is refused by
 * every tier, with ONE shared diagnostic.
 *
 * spec/grammar.md §9: "`const` variables cannot be reassigned." No tier
 * enforced it. The reference parser recorded `mutable: false` for `const` and
 * then nothing ever read it; the other six tiers either recorded it and never
 * read it (Go, Rust, Python, Ruby) or dropped it from the AST outright (Java).
 * So `const s = 1n; s = s + x;` compiled everywhere — fail-open, in the
 * reference too.
 *
 * What this proves, per tier:
 *   - a `const` local reassigned by `=`, by a compound assignment, by `++` /
 *     `--`, from inside a nested `if` and from inside a `for` body, and a
 *     `const` for-initializer advanced by `i++`, is refused with the sentence
 *     "Cannot assign to '<name>' because it is a constant.";
 *   - the `let` twin of each program is accepted, and all seven tiers compile
 *     it to the same hex (non-vacuous: the controls are real programs);
 *   - scope is respected: a `const t` in a sibling block does not make a later
 *     `let t` immutable.
 * What it does NOT prove:
 *   - element writes through a const local (`const a = ...; a[0] = ...`):
 *     TypeScript allows them and this item does not change that;
 *   - other surfaces' immutable-local spellings (Rust `let` without `mut`,
 *     Zig `const`, Java `final`, Go `const`): they are probed in the N-342
 *     log, but their mutability rules are a separate design decision and no
 *     tier enforces them yet;
 *   - const-ness of parameters, or of `this.<prop>` (readonly is separate).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n342-'));
let n = 0;

function write(text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, 'Probe.runar.ts');
  writeFileSync(path, text);
  return path;
}

const wrap = (body: string) => `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public verify(x: bigint): void {
${body}
  }
}
`;

interface Case {
  name: string;
  bad: string;
  good: string;
}

const CASES: Case[] = [
  {
    name: 'plain assignment',
    bad: wrap(`    const s: bigint = 1n;\n    s = s + x;\n    assert(s === this.n);`),
    good: wrap(`    let s: bigint = 1n;\n    s = s + x;\n    assert(s === this.n);`),
  },
  {
    name: 'compound assignment',
    bad: wrap(`    const s: bigint = 1n;\n    s += x;\n    assert(s === this.n);`),
    good: wrap(`    let s: bigint = 1n;\n    s += x;\n    assert(s === this.n);`),
  },
  {
    name: 'postfix increment',
    bad: wrap(`    const s: bigint = 1n;\n    s++;\n    assert(s === this.n + x);`),
    good: wrap(`    let s: bigint = 1n;\n    s++;\n    assert(s === this.n + x);`),
  },
  {
    name: 'prefix decrement',
    bad: wrap(`    const s: bigint = 1n;\n    --s;\n    assert(s === this.n + x);`),
    good: wrap(`    let s: bigint = 1n;\n    --s;\n    assert(s === this.n + x);`),
  },
  {
    name: 'reassigned inside an if branch',
    bad: wrap(
      `    const s: bigint = 1n;\n    if (x > 0n) {\n      s = s + x;\n    }\n    assert(s === this.n);`,
    ),
    good: wrap(
      `    let s: bigint = 1n;\n    if (x > 0n) {\n      s = s + x;\n    }\n    assert(s === this.n);`,
    ),
  },
  {
    name: 'reassigned inside a for body',
    bad: wrap(
      `    const s: bigint = 0n;\n    for (let i: bigint = 0n; i < 3n; i++) {\n      s = s + i;\n    }\n    assert(s === x + this.n);`,
    ),
    good: wrap(
      `    let s: bigint = 0n;\n    for (let i: bigint = 0n; i < 3n; i++) {\n      s = s + i;\n    }\n    assert(s === x + this.n);`,
    ),
  },
  {
    name: 'const for-initializer advanced by i++',
    bad: wrap(
      `    let s: bigint = 0n;\n    for (const i: bigint = 0n; i < 3n; i++) {\n      s = s + i;\n    }\n    assert(s === x + this.n);`,
    ),
    good: wrap(
      `    let s: bigint = 0n;\n    for (let i: bigint = 0n; i < 3n; i++) {\n      s = s + i;\n    }\n    assert(s === x + this.n);`,
    ),
  },
];

// Scope control: `const t` lives only in the if block; the later `let t` is a
// different, mutable binding and must stay assignable.
const SCOPE_CONTROL = wrap(
  `    if (x > 0n) {\n      const t: bigint = 2n;\n      assert(t === 2n);\n    }\n    let t: bigint = 1n;\n    t = t + x;\n    assert(t === this.n);`,
);

const SENTENCE = /Cannot assign to '[A-Za-z_]\w*' because it is a constant\./;

describe('N-342: const local reassignment is refused by every tier on .runar.ts', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const c of CASES) {
    it(`${c.name}: let twin accepted with one hex, const program refused by every tier`, () => {
      const goodPath = write(c.good);
      const badPath = write(c.bad);
      const hexes = new Set<string>();
      for (const tier of TIERS) {
        const hex = compileHex(tier, goodPath);
        expect(hex.length, `${tier.id} control produced no hex`).toBeGreaterThan(0);
        hexes.add(hex);
      }
      expect(hexes.size, 'all tiers agree on the let twin').toBe(1);

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

  it('scope: a const in a sibling block does not freeze a later let of the same name', () => {
    const path = write(SCOPE_CONTROL);
    const hexes = new Set<string>();
    for (const tier of TIERS) hexes.add(compileHex(tier, path));
    expect(hexes.size).toBe(1);
  }, 900_000);
});
