import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';

// Frontend parity: every format's native else-if chain (`else if`, Python
// `elif`, Ruby `elsif`) must lower to the same AST as the explicitly nested
// `else { if ... }` form. The TS-tier Solidity and Move parsers refused
// `else if` outright ("expected '{'"), while the other tiers accepted it.
//
// Proves: for .runar.sol and .runar.move, a three-arm chain (with and without
// a terminal else) parses without errors to the same method body as the
// nested form, source locations aside.
// Does not prove: other tiers (pinned by conformance/tests/selector, whose
// nine sources all use the native chain form and which the multi-format
// and parser-only matrices run in every tier).

function stripLocations(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripLocations);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === 'sourceLocation') continue;
      out[k] = stripLocations(x);
    }
    return out;
  }
  return v;
}

function body(source: string, fileName: string): unknown {
  const r = parse(source, fileName);
  expect(r.errors.map((e) => e.message)).toEqual([]);
  return stripLocations(r.contract!.methods.find((m) => m.name === 'set')!.body);
}

const SOL = (stmt: string) => `
pragma runar ^0.1.0;
contract Sel is StatefulSmartContract {
    bigint a;
    constructor(bigint _a) { a = _a; }
    function set(bigint i, bigint v) public {
${stmt}
    }
}
`;

const MOVE = (stmt: string) => `
module Sel {
    resource struct Sel { a: &mut bigint }
    public fun set(contract: &mut Sel, i: bigint, v: bigint) {
${stmt}
    }
}
`;

/** Line (1-based) of the inner `if` of the first `else if` in `source`. */
function elseIfLine(source: string): number {
  return source.split('\n').findIndex((l) => l.includes('else if')) + 1;
}

function innerIfLine(source: string, fileName: string): number | undefined {
  const r = parse(source, fileName);
  const outer = r.contract!.methods.find((m) => m.name === 'set')!.body[0] as {
    else?: Array<{ sourceLocation?: { line: number } }>;
  };
  return outer.else?.[0]?.sourceLocation?.line;
}

describe('else-if chains lower to the nested form', () => {
  it('.runar.sol: else if ... else if ... else', () => {
    const chain = SOL(`
        if (i == 0) { this.a = v; }
        else if (i == 1) { this.a = v + 1; }
        else if (i == 2) { this.a = v + 2; }
        else { require(false); }`);
    const nested = SOL(`
        if (i == 0) { this.a = v; }
        else { if (i == 1) { this.a = v + 1; }
        else { if (i == 2) { this.a = v + 2; }
        else { require(false); } } }`);
    expect(body(chain, 'Sel.runar.sol')).toEqual(body(nested, 'Sel.runar.sol'));
  });

  it('.runar.sol: else if without a terminal else', () => {
    const chain = SOL(`
        if (i == 0) { this.a = v; }
        else if (i == 1) { this.a = v + 1; }`);
    const nested = SOL(`
        if (i == 0) { this.a = v; }
        else { if (i == 1) { this.a = v + 1; } }`);
    expect(body(chain, 'Sel.runar.sol')).toEqual(body(nested, 'Sel.runar.sol'));
  });

  it('.runar.move: else if ... else if ... else', () => {
    const chain = MOVE(`
        if (i == 0) { contract.a = v; }
        else if (i == 1) { contract.a = v + 1; }
        else if (i == 2) { contract.a = v + 2; }
        else { assert!(false, 0); };`);
    const nested = MOVE(`
        if (i == 0) { contract.a = v; }
        else { if (i == 1) { contract.a = v + 1; }
        else { if (i == 2) { contract.a = v + 2; }
        else { assert!(false, 0); } } };`);
    expect(body(chain, 'Sel.runar.move')).toEqual(body(nested, 'Sel.runar.move'));
  });

  it('.runar.move: else if without a terminal else', () => {
    const chain = MOVE(`
        if (i == 0) { contract.a = v; }
        else if (i == 1) { contract.a = v + 1; };`);
    const nested = MOVE(`
        if (i == 0) { contract.a = v; }
        else { if (i == 1) { contract.a = v + 1; } };`);
    expect(body(chain, 'Sel.runar.move')).toEqual(body(nested, 'Sel.runar.move'));
  });

  it('locates the else-if statement at its own if keyword', () => {
    const sol = SOL(`
        if (i == 0) { this.a = v; }
        else if (i == 1) { this.a = v + 1; }`);
    const move = MOVE(`
        if (i == 0) { contract.a = v; }
        else if (i == 1) { contract.a = v + 1; };`);
    expect(innerIfLine(sol, 'Sel.runar.sol')).toBe(elseIfLine(sol));
    expect(innerIfLine(move, 'Sel.runar.move')).toBe(elseIfLine(move));
  });
});
