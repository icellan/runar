import { describe, it, expect } from 'vitest';
import { parseGoSource } from '../passes/01-parse-go.js';

/**
 * N-056 (CL-BUG-192) — `.runar.go` operator precedence differed across tiers.
 *
 * The Go tier parses `.runar.go` with go/parser, so it uses Go's five-level
 * precedence (`* / % << >> & &^` > `+ - | ^` > comparisons > `&&` > `||`).
 * The TS reference and the other five tiers parse it with the C ladder that
 * every Rúnar surface shares (MulDiv > AddSub > Shift > Comparison > Equality
 * > BitAnd > BitXor > BitOr > And > Or). So `a & b + 1` was `(a & b) + 1` in
 * the Go tier and `a & (b + 1)` everywhere else: one source, two scripts.
 *
 * R51 (user decision): every tier refuses an unparenthesised binary expression
 * whose grouping differs between the two schemes, with one shared diagnostic
 * asking for parentheses. Expressions where the schemes agree, and every
 * parenthesised form, compile unchanged.
 *
 * The oracle below is independent of the parser's constant: it recomputes the
 * conflict set from the two precedence tables. `x OP1 y OP2 z` groups left in
 * a scheme iff prec(OP1) >= prec(OP2) (all binary operators are left
 * associative), so the pair is ambiguous iff the two schemes disagree on
 * that. 72 of the 324 ordered operator pairs are ambiguous.
 *
 * What this proves: the TS reference refuses all 72 ambiguous pairs with the
 * shared text, accepts the 252 agreeing pairs and every parenthesised form, and
 * treats call results (including BigintBig helper rewrites) as operands.
 * What it does not prove: the other tiers (their own tests plus conformance
 * negatives N175-N179 and the agreeing-pairs control) or emitted bytes.
 */

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
const OPS = Object.keys(GO_PREC);

const ambiguous = (x: string, y: string) =>
  (GO_PREC[x]! >= GO_PREC[y]!) !== (C_PREC[x]! >= C_PREC[y]!);

const pairs = OPS.flatMap((x) => OPS.map((y) => [x, y] as const));
const conflicting = pairs.filter(([x, y]) => ambiguous(x, y));
const agreeing = pairs.filter(([x, y]) => !ambiguous(x, y));

const message = (x: string, y: string) =>
  `ambiguous operator precedence in .runar.go: \`a ${x} b ${y} c\` groups differently ` +
  `under Go precedence than in Rúnar's other surfaces; add parentheses`;

const source = (expr: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {
	runar.SmartContract
	T runar.Int \`runar:"readonly"\`
}

func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {
	x := ${expr}
	runar.Assert(x == c.T)
}
`;

function errorsOf(expr: string): string[] {
  return parseGoSource(source(expr), 'Probe.runar.go').errors
    .filter((e) => e.severity === 'error')
    .map((e) => e.message);
}

describe('N-056: ambiguous Go/C precedence mixes are refused on .runar.go', () => {
  it('the derived conflict set has the expected size', () => {
    expect(conflicting.length).toBe(72);
    expect(agreeing.length).toBe(252);
  });

  it.each(conflicting)('refuses `a %s b %s d` with the shared diagnostic', (x, y) => {
    expect(errorsOf(`a ${x} b ${y} d`)).toEqual([message(x, y)]);
  });

  it.each(agreeing)('accepts `a %s b %s d` (both schemes agree)', (x, y) => {
    expect(errorsOf(`a ${x} b ${y} d`)).toEqual([]);
  });

  it.each(conflicting)('accepts both parenthesisations of `a %s b %s d`', (x, y) => {
    expect(errorsOf(`(a ${x} b) ${y} d`)).toEqual([]);
    expect(errorsOf(`a ${x} (b ${y} d)`)).toEqual([]);
  });

  it('refuses the F-197 probes', () => {
    expect(errorsOf('a & b + 1')).toEqual([message('&', '+')]);
    expect(errorsOf('a + b << 2')).toEqual([message('+', '<<')]);
    expect(errorsOf('a | b + d')).toEqual([message('|', '+')]);
    expect(errorsOf('a & 255 == 15')).toEqual([message('&', '==')]);
  });

  it('accepts `a ^ b * d` (both schemes group b * d first)', () => {
    expect(errorsOf('a ^ b * d')).toEqual([]);
  });

  it('refuses an ambiguous mix nested inside parentheses or call arguments', () => {
    expect(errorsOf('(a & b + 1) * d')).toEqual([message('&', '+')]);
    expect(errorsOf('runar.Abs(a + b << 2)')).toEqual([message('+', '<<')]);
    expect(errorsOf('a * (d + (a | b + d))')).toEqual([message('|', '+')]);
  });

  it('checks every edge of a longer unparenthesised chain', () => {
    expect(errorsOf('a + b * d - a')).toEqual([]);
    expect(errorsOf('a * b + d << 1')).toEqual([message('+', '<<')]);
  });

  it('treats `&^` as `&` (both lex to an `&` over a complemented operand)', () => {
    expect(errorsOf('a &^ b')).toEqual([]);
    expect(errorsOf('a &^ b + d')).toEqual([message('&', '+')]);
    expect(errorsOf('(a &^ b) + d')).toEqual([]);
  });

  it('treats a call result, including a BigintBig rewrite, as an operand', () => {
    expect(errorsOf('runar.BigintBigAdd(a, b) << 2')).toEqual([]);
    expect(errorsOf('runar.Abs(a + b) << 2')).toEqual([]);
  });

  it('treats a unary operand as an atom', () => {
    expect(errorsOf('-a + b << 2')).toEqual([message('+', '<<')]);
    expect(errorsOf('-(a + b) << 2')).toEqual([]);
  });
});
