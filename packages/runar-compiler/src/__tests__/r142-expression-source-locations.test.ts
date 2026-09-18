import { describe, it, expect } from 'vitest';
import { parse } from '../index.js';
import type { ContractNode, Expression, Statement } from '../ir/index.js';

/**
 * R-142 / CL-BUG-041 — Expression AST nodes carry no `sourceLocation`, so the
 * diagnostics that read one report no line or column.
 *
 * `03-typecheck.ts` reads `expr.sourceLocation` / `expr.left.sourceLocation` at
 * fifteen sites (comparison mismatches, ternary mismatches, index /
 * increment / decrement errors on compound operands). None of the parsers set
 * it on `binary_expr`, `unary_expr`, `call_expr`, `member_expr`,
 * `ternary_expr`, `index_access`, `increment_expr`, `decrement_expr` or
 * `array_literal`, so every one of those diagnostics came out as a bare
 * sentence.
 *
 * The gap propagates: `ParserCore.parsePostfixChain` and the precedence-climbing
 * chain in `parser-core.ts` build these nodes for the hand-written Solidity,
 * Move, Go, Rust, Python, Zig and Java surface parsers, so one missing field
 * unlocated the diagnostics on seven surfaces at once. `parser-core.ts` already
 * had a `loc()` helper — the locations were in hand and simply not attached.
 *
 * This test walks a contract's whole expression tree per surface and requires a
 * location on every node of a kind the typechecker reports against. It is
 * deliberately structural rather than diagnostic-driven: a diagnostic test can
 * only reach the handful of shapes it thinks to write, while the AST is the
 * thing the fifteen sites actually read.
 */

const TS_SOURCE = `import { SmartContract, assert, ByteString, len } from 'runar-lang';

export class Shapes extends SmartContract {
  readonly a: bigint;
  readonly b: ByteString;

  constructor(a: bigint, b: ByteString) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public go(x: bigint, y: bigint) {
    let i: bigint = 0n;
    i++;
    i--;
    const sum: bigint = x + y * 2n - 1n;
    const cmp: boolean = sum > this.a && x !== y;
    const pick: bigint = cmp ? sum : this.a;
    const l: bigint = len(this.b);
    const neg: bigint = -sum;
    const inv: boolean = !cmp;
    assert(pick + l + neg + i > 0n || inv);
  }
}
`;

const RUST_SOURCE = `use runar::prelude::*;

#[runar::contract]
struct Shapes {
    #[readonly]
    a: Int,
    #[readonly]
    b: ByteString,
}

impl Shapes {
    pub fn go(&self, x: Int, y: Int) {
        let mut i: Int = 0;
        i = i + 1;
        let sum: Int = x + y * 2 - 1;
        let cmp: bool = sum > self.a && x != y;
        let l: Int = len(self.b);
        let neg: Int = -sum;
        let inv: bool = !cmp;
        assert!(sum + l + neg + i > 0 || inv);
    }
}
`;


/** A minimal Solidity-surface probe for the known-gap case below. */
const SOL_SOURCE_PROBE = `pragma runar ^1.0;

contract Probe {
    bigint immutable a;

    constructor(bigint a_) {
        a = a_;
    }

    function go(bigint x) public {
        assert(x + a > 0);
    }
}
`;

/** Expression kinds 03-typecheck reports diagnostics against. */
const LOCATED_KINDS = new Set([
  'binary_expr',
  'unary_expr',
  'call_expr',
  'member_expr',
  'ternary_expr',
  'index_access',
  'increment_expr',
  'decrement_expr',
  'array_literal',
]);

interface Located {
  kind: string;
  sourceLocation?: { file?: string; line?: number; column?: number };
}

function walkExpr(e: Expression | undefined, out: Located[]): void {
  if (!e) return;
  const node = e as unknown as Located & Record<string, unknown>;
  if (LOCATED_KINDS.has(node.kind)) out.push(node);
  for (const key of ['left', 'right', 'operand', 'callee', 'object', 'index', 'condition', 'consequent', 'alternate']) {
    walkExpr(node[key] as Expression | undefined, out);
  }
  for (const key of ['args', 'elements']) {
    const list = node[key];
    if (Array.isArray(list)) for (const c of list) walkExpr(c as Expression, out);
  }
}

function walkStmt(s: Statement, out: Located[]): void {
  const node = s as unknown as Record<string, unknown>;
  for (const key of ['init', 'value', 'target', 'expression', 'condition', 'update']) {
    const v = node[key];
    if (v && typeof v === 'object' && 'kind' in (v as object)) {
      const k = (v as { kind: string }).kind;
      if (k.endsWith('_statement') || k === 'variable_decl' || k === 'assignment') {
        walkStmt(v as Statement, out);
      } else {
        walkExpr(v as Expression, out);
      }
    }
  }
  for (const key of ['then', 'else', 'body']) {
    const list = node[key];
    if (Array.isArray(list)) for (const c of list) walkStmt(c as Statement, out);
  }
}

function locatedExpressions(source: string, fileName: string): Located[] {
  const result = parse(source, fileName) as unknown as { contract?: ContractNode } & ContractNode;
  const contract = result.contract ?? (result as ContractNode);
  const out: Located[] = [];
  for (const m of contract.methods ?? []) for (const s of m.body ?? []) walkStmt(s, out);
  return out;
}

function assertAllLocated(source: string, fileName: string): void {
  const nodes = locatedExpressions(source, fileName);
  expect(nodes.length, `${fileName}: found no reportable expressions to check`).toBeGreaterThan(8);
  const missing = nodes.filter((n) => !n.sourceLocation || !(n.sourceLocation.line! > 0));
  const kinds = [...new Set(missing.map((m) => m.kind))].sort();
  expect(
    kinds,
    `${fileName}: ${missing.length}/${nodes.length} expression nodes carry no location. ` +
      `03-typecheck reads expr.sourceLocation at fifteen sites; every diagnostic ` +
      `raised against one of these kinds comes out with no line or column.`,
  ).toEqual([]);
}

describe('R-142 expression nodes carry a source location', () => {
  it('covers every kind the typechecker reports against', () => {
    const kinds = new Set(locatedExpressions(TS_SOURCE, 'Shapes.runar.ts').map((n) => n.kind));
    // A probe that exercises three kinds proves nothing about the other six.
    for (const k of ['binary_expr', 'unary_expr', 'call_expr', 'ternary_expr', 'increment_expr', 'decrement_expr']) {
      expect(kinds, `the probe contract no longer produces a ${k}`).toContain(k);
    }
  });

  it('.runar.ts (ts-morph parser)', () => {
    assertAllLocated(TS_SOURCE, 'Shapes.runar.ts');
  });

  it('.runar.rs (ParserCore — shared with the Go and Zig surface parsers)', () => {
    assertAllLocated(RUST_SOURCE, 'Shapes.runar.rs');
  });

  /**
   * Scope. This change covers the two files the finding names: the ts-morph
   * parser and `parser-core.ts`, the latter serving the Rust, Go and Zig
   * surfaces. The Solidity, Move, Python and Java parsers are standalone
   * classes carrying their own copy of the precedence chain — 29, 24, 37 and 36
   * construction sites — and each already has its own `loc()` helper, so the
   * same edit applies; it is simply not this change. Pinned as a known gap so
   * the next pass has a number to work against rather than a guess.
   */
  it('records the surfaces still missing expression locations', () => {
    const stillMissing: string[] = [];
    for (const [src, file] of [[SOL_SOURCE_PROBE, 'Probe.runar.sol']] as const) {
      const nodes = locatedExpressions(src, file);
      if (nodes.some((n) => !n.sourceLocation)) stillMissing.push(file);
    }
    // Solidity is the representative: if this ever goes green on its own,
    // the standalone parsers were fixed and this case should be widened to
    // assert the same invariant as the two above.
    expect(stillMissing).toEqual(['Probe.runar.sol']);
  });
});
