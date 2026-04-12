import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { expandFixedArrays } from '../passes/03b-expand-fixed-arrays.js';
import type { ContractNode, Statement, Expression } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function expand(source: string): ReturnType<typeof expandFixedArrays> {
  return expandFixedArrays(parseContract(source));
}

/** Collect all property names from a contract's (expanded) property list. */
function propertyNames(c: ContractNode): string[] {
  return c.properties.map(p => p.name);
}

/** Find a method body by name in a ContractNode. */
function methodBody(c: ContractNode, name: string): Statement[] {
  const m = c.methods.find(mm => mm.name === name);
  if (!m) throw new Error(`Method ${name} not found`);
  return m.body;
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const BASIC_ARRAY = `
class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public setZero(v: bigint) {
    this.board[0] = v;
    assert(true);
  }

  public setRuntime(idx: bigint, v: bigint) {
    this.board[idx] = v;
    assert(true);
  }
}
`;

const NESTED_ARRAY = `
class Grid extends StatefulSmartContract {
  g: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public tick() {
    this.g[0][1] = 7n;
    assert(true);
  }
}
`;

const OUT_OF_RANGE_LIT = `
class Oor extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bad() {
    this.board[5] = 9n;
    assert(true);
  }
}
`;

const BAD_LENGTH_INIT = `
class BadInit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n];

  constructor() {
    super();
  }

  public m() {
    assert(true);
  }
}
`;

const SIDE_EFFECT_INDEX = `
class SE extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public doStuff(base: bigint) {
    this.board[base + 1n] = 5n;
    assert(true);
  }
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('expandFixedArrays', () => {
  describe('property expansion', () => {
    it('expands a flat FixedArray<bigint,3> into 3 scalar siblings', () => {
      const { contract, errors } = expand(BASIC_ARRAY);
      expect(errors).toEqual([]);
      const names = propertyNames(contract);
      expect(names).toEqual(['board__0', 'board__1', 'board__2']);
      for (const p of contract.properties) {
        expect(p.type.kind).toBe('primitive_type');
        expect((p.type as { kind: 'primitive_type'; name: string }).name).toBe('bigint');
      }
    });

    it('distributes array_literal initializers across scalar siblings', () => {
      const src = `
        class Init extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [1n, 2n, 3n];
          constructor() { super(); }
          public m() { assert(true); }
        }
      `;
      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      const inits = contract.properties.map(p => (p.initializer as { value: bigint } | undefined)?.value);
      expect(inits).toEqual([1n, 2n, 3n]);
    });

    it('rejects FixedArray<void, N>', () => {
      const src = `
        class Bad extends StatefulSmartContract {
          board: FixedArray<void, 3>;
          constructor() { super(); this.board = [0n, 0n, 0n]; }
          public m() { assert(true); }
        }
      `;
      // First see if the parser rejects void as an element type. If so,
      // ensure our pass is defensive by passing an AST manually.
      const result = expand(src);
      // Either parser error or our pass error.
      const combined = result.errors.map(e => e.message).join('|');
      expect(combined.length).toBeGreaterThan(0);
    });

    it('rejects initializer length mismatch', () => {
      const { errors } = expand(BAD_LENGTH_INIT);
      expect(errors.some(e => e.message.includes('does not match'))).toBe(true);
    });

    it('expands nested FixedArray recursively', () => {
      const { contract, errors } = expand(NESTED_ARRAY);
      expect(errors).toEqual([]);
      const names = propertyNames(contract);
      expect(names).toEqual([
        'g__0__0', 'g__0__1',
        'g__1__0', 'g__1__1',
      ]);
    });
  });

  describe('literal index access', () => {
    it('rewrites `this.board[0] = v` to `this.board__0 = v`', () => {
      const { contract, errors } = expand(BASIC_ARRAY);
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'setZero');
      const assign = body.find((s): s is Extract<Statement, { kind: 'assignment' }> => s.kind === 'assignment');
      expect(assign).toBeTruthy();
      expect(assign!.target.kind).toBe('property_access');
      expect((assign!.target as { property: string }).property).toBe('board__0');
    });

    it('errors on out-of-range literal index', () => {
      const { errors } = expand(OUT_OF_RANGE_LIT);
      expect(errors.some(e => e.message.includes('out of range'))).toBe(true);
    });
  });

  describe('runtime index write', () => {
    it('rewrites runtime index write to an if/else chain', () => {
      const { contract, errors } = expand(BASIC_ARRAY);
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'setRuntime');
      // The first statement must be an if_statement (no hoisting needed since idx
      // is already a pure identifier).
      const first = body[0]!;
      expect(first.kind).toBe('if_statement');
      // Walk the else chain; should bottom out in an assert(false).
      let node: Statement | undefined = first;
      let branches = 0;
      while (node && node.kind === 'if_statement') {
        branches++;
        const elseList: Statement[] = node.else ?? [];
        node = elseList[0];
      }
      expect(branches).toBe(3);
    });

    it('hoists impure index expressions', () => {
      const { contract, errors } = expand(SIDE_EFFECT_INDEX);
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'doStuff');
      // First statement should be a const __idx_* decl.
      const first = body[0]!;
      expect(first.kind).toBe('variable_decl');
      expect((first as { name: string }).name.startsWith('__idx_')).toBe(true);
    });
  });

  describe('runtime index read', () => {
    it('rewrites statement-form `const v = this.board[idx]` as fallback-init + if-chain', () => {
      // Statement-level context: runtime-index read on the RHS of a
      // `variable_decl`. The pass replaces the original const with a
      // `let v = board__{N-1}` (the fallback / last-slot read) followed by
      // an if/else-if chain reassigning `v` to the matching slot for each
      // in-range index `0..N-2`. Out-of-range falls through to the
      // fallback, matching the ternary-form semantics — runtime reads do
      // NOT bounds-check. (Deviation 2.)
      const src = `
        class R extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];
          constructor() { super(); }
          public m(idx: bigint) {
            const v = this.board[idx];
            assert(v == 0n);
          }
        }
      `;
      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'm');

      // First stmt: the rewritten variable_decl with a direct property_access
      // fallback init — NOT a nested ternary chain.
      const decl = body[0] as Extract<Statement, { kind: 'variable_decl' }>;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.name).toBe('v');
      const init = decl.init as Expression;
      expect(init.kind).toBe('property_access');
      expect((init as { property: string }).property).toBe('board__2');

      // Second stmt: if-chain reassigning `v`. We expect N-1 = 2 branches
      // (one for idx === 0, one for idx === 1). The last slot is the
      // fallback so no explicit branch is emitted for it.
      const ifStmt = body[1] as Extract<Statement, { kind: 'if_statement' }>;
      expect(ifStmt.kind).toBe('if_statement');
      let node: Statement | undefined = ifStmt;
      let branches = 0;
      while (node && node.kind === 'if_statement') {
        branches++;
        // Each branch reassigns `v` to a property_access on a board__ slot.
        const then0 = node.then[0] as Extract<Statement, { kind: 'assignment' }>;
        expect(then0.kind).toBe('assignment');
        expect((then0.target as { name: string }).name).toBe('v');
        const elseList: Statement[] = node.else ?? [];
        node = elseList[0];
      }
      expect(branches).toBe(2);
    });

    it('still uses the nested ternary chain for expression-form runtime reads', () => {
      // Runtime-index read inside a larger expression (here: addition).
      // The statement-form rewriter cannot apply — it only matches when
      // the entire RHS of a variable_decl / assignment is a bare
      // `this.board[idx]`. The fallback path emits a nested ternary chain.
      const src = `
        class R extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];
          constructor() { super(); }
          public m(idx: bigint): bigint {
            return this.board[idx] + 1n;
          }
        }
      `;
      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'm');
      // The return statement's value should now be a binary_expr whose
      // left operand is the ternary dispatch chain.
      const ret = body.find(s => s.kind === 'return_statement') as Extract<Statement, { kind: 'return_statement' }>;
      expect(ret).toBeTruthy();
      const val = ret.value as Expression;
      expect(val.kind).toBe('binary_expr');
      const bin = val as Extract<Expression, { kind: 'binary_expr' }>;
      expect(bin.left.kind).toBe('ternary_expr');
    });
  });
});
