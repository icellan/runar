import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-056 (R51) — the controls and the shared diagnostic behind negatives
 * N175-N179 (ambiguous Go/C operator precedence on `.runar.go`).
 *
 * The Go tier parses `.runar.go` with Go precedence and the other six with the
 * C ladder, so every tier now refuses an unparenthesised mix on which the two
 * schemes group differently. The rule must not reach anything else:
 * `go-precedence-control.runar.go` holds every agreeing operator pair
 * unparenthesised and both parenthesisations of every disagreeing pair (each
 * with a well-typed operand choice), and every tier must compile it
 * byte-identically to the TypeScript reference.
 *
 * rejection-parity.test.ts only checks that each tier refuses N175-N179; this
 * file also checks that each refusal carries the one shared diagnostic.
 *
 * What this proves: the control compiles and agrees across all available
 * tiers, so the refusal is scoped to the 72 ambiguous pairs; every tier
 * refuses each negative with the same message.
 * What it does not prove: the 100 operator shapes that type-check under no
 * operand typing (covered at parse level by each tier's N-056 unit test), or
 * on-chain behaviour of the control.
 */

const DIR = __dirname;
const CONTROL = join(DIR, 'go-precedence-control.runar.go');

const GO_PREC: Record<string, number> = {
  '*': 5, '/': 5, '%': 5, '<<': 5, '>>': 5, '&': 5,
  '+': 4, '-': 4, '|': 4, '^': 4,
  '==': 3, '!=': 3, '<': 3, '<=': 3, '>': 3, '>=': 3,
  '&&': 2, '||': 1,
};
const C_PREC: Record<string, number> = {
  '*': 10, '/': 10, '%': 10, '+': 9, '-': 9, '<<': 8, '>>': 8,
  '<': 7, '<=': 7, '>': 7, '>=': 7, '==': 6, '!=': 6,
  '&': 5, '^': 4, '|': 3, '&&': 2, '||': 1,
};

const message = (x: string, y: string) =>
  `ambiguous operator precedence in .runar.go: \`a ${x} b ${y} c\` groups differently ` +
  `under Go precedence than in Rúnar's other surfaces; add parentheses`;

const NEGATIVES: Array<[string, string, string]> = [
  ['N175-go-precedence-and-add.runar.go', '&', '+'],
  ['N176-go-precedence-add-shift.runar.go', '+', '<<'],
  ['N177-go-precedence-or-add.runar.go', '|', '+'],
  ['N178-go-precedence-and-eq.runar.go', '&', '=='],
  ['N179-go-precedence-shift-mul.runar.go', '<<', '*'],
];

const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const ts = tiers.find((t) => t.id === 'ts');

describe('N-056 control: agreeing and parenthesised operator mixes stay accepted', () => {
  it('the TS reference tier is available (else the comparison is vacuous)', () => {
    expect(ts).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  it('the control covers every agreeing pair (no shape silently dropped)', () => {
    // Every operator pair appears in the control in at least one shape:
    // unparenthesised when the schemes agree, parenthesised when they do not.
    const body = readFileSync(CONTROL, 'utf8');
    const ops = Object.keys(GO_PREC);
    let agreeing = 0;
    for (const x of ops) {
      for (const y of ops) {
        if ((GO_PREC[x]! >= GO_PREC[y]!) !== (C_PREC[x]! >= C_PREC[y]!)) continue;
        agreeing++;
        const any = new RegExp(`\\b[abdpqr] ${escapeRe(x)} [abdpqr] ${escapeRe(y)} [abdpqr]\\b`);
        if (any.test(body)) continue;
        // Only shapes that are ill-typed under every operand choice may be
        // missing: a logical operator next to an arithmetic one, or a
        // comparison feeding an arithmetic/relational operand.
        expect(illTyped(x, y), `agreeing pair \`${x}\` / \`${y}\` is missing from the control`).toBe(true);
      }
    }
    expect(agreeing).toBe(252);
  });

  let want: string | undefined;
  const reference = (): string => (want ??= compileHex(ts!, CONTROL));
  for (const tier of tiers) {
    if (tier.id === 'ts') continue;
    it(`${tier.id} compiles the control byte-identically to ts`, () => {
      expect(reference().length).toBeGreaterThan(0);
      expect(compileHex(tier, CONTROL)).toBe(reference());
    }, tier.timeoutMs);
  }
});

describe('N-056 negatives: every tier refuses with the one shared diagnostic', () => {
  for (const [fixture, x, y] of NEGATIVES) {
    for (const tier of tiers) {
      it(`${tier.id} refuses ${fixture} with the shared message`, () => {
        const argv = [...tier.prefix, ...tier.argsFor(join(DIR, fixture))];
        const res = spawnSync(tier.cmd!, argv, {
          cwd: tier.cwd,
          encoding: 'utf-8',
          timeout: tier.timeoutMs,
        });
        expect(res.error).toBeUndefined();
        expect(res.status).not.toBe(0);
        expect(`${res.stderr ?? ''}\n${res.stdout ?? ''}`).toContain(message(x, y));
      }, tier.timeoutMs);
    }
  }
});

function escapeRe(op: string): string {
  return op.replace(/[|^*+?.()[\]{}\\$]/g, '\\$&');
}

/** True when `a x b y c` (under the shared grouping) type-checks for no
 *  choice of bigint/bool operands — the shapes the control cannot hold. */
function illTyped(x: string, y: string): boolean {
  type T = 'int' | 'bool' | null;
  const kind = (op: string) =>
    ['<', '<=', '>', '>='].includes(op) ? 'rel'
      : ['==', '!='].includes(op) ? 'eq'
        : ['&&', '||'].includes(op) ? 'logic' : 'arith';
  const res = (op: string, l: T, r: T): T => {
    if (l === null || r === null) return null;
    switch (kind(op)) {
      case 'arith': return l === 'int' && r === 'int' ? 'int' : null;
      case 'rel': return l === 'int' && r === 'int' ? 'bool' : null;
      case 'eq': return l === r ? 'bool' : null;
      default: return l === 'bool' && r === 'bool' ? 'bool' : null;
    }
  };
  const left = C_PREC[x]! >= C_PREC[y]!;
  for (const t1 of ['int', 'bool'] as const)
    for (const t2 of ['int', 'bool'] as const)
      for (const t3 of ['int', 'bool'] as const) {
        const t = left ? res(y, res(x, t1, t2), t3) : res(x, t1, res(y, t2, t3));
        if (t !== null) return false;
      }
  return true;
}
