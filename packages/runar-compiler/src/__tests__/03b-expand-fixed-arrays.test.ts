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

    it('attaches a single-element __syntheticArrayChain on flat FixedArray leaves', () => {
      const { contract, errors } = expand(BASIC_ARRAY);
      expect(errors).toEqual([]);
      const chains = contract.properties.map(p => p.__syntheticArrayChain);
      expect(chains).toEqual([
        [{ base: 'board', index: 0, length: 3 }],
        [{ base: 'board', index: 1, length: 3 }],
        [{ base: 'board', index: 2, length: 3 }],
      ]);
    });

    it('attaches a two-element __syntheticArrayChain on 2D FixedArray leaves', () => {
      const { contract, errors } = expand(NESTED_ARRAY);
      expect(errors).toEqual([]);
      const chains = contract.properties.map(p => ({
        name: p.name,
        chain: p.__syntheticArrayChain,
      }));
      // Order: outermost-first, so [0] is the user-declared name's level,
      // and the last element is the innermost containing sub-array.
      expect(chains).toEqual([
        {
          name: 'g__0__0',
          chain: [
            { base: 'g', index: 0, length: 2 },
            { base: 'g__0', index: 0, length: 2 },
          ],
        },
        {
          name: 'g__0__1',
          chain: [
            { base: 'g', index: 0, length: 2 },
            { base: 'g__0', index: 1, length: 2 },
          ],
        },
        {
          name: 'g__1__0',
          chain: [
            { base: 'g', index: 1, length: 2 },
            { base: 'g__1', index: 0, length: 2 },
          ],
        },
        {
          name: 'g__1__1',
          chain: [
            { base: 'g', index: 1, length: 2 },
            { base: 'g__1', index: 1, length: 2 },
          ],
        },
      ]);
    });

    it('attaches a three-element __syntheticArrayChain on 3D FixedArray leaves', () => {
      const src = `
        class Cube extends StatefulSmartContract {
          c: FixedArray<FixedArray<FixedArray<bigint, 2>, 2>, 2> = [
            [[0n, 0n], [0n, 0n]],
            [[0n, 0n], [0n, 0n]],
          ];
          constructor() { super(); }
          public m() { assert(true); }
        }
      `;
      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      const leafC101 = contract.properties.find(p => p.name === 'c__1__0__1');
      expect(leafC101).toBeDefined();
      expect(leafC101!.__syntheticArrayChain).toEqual([
        { base: 'c', index: 1, length: 2 },
        { base: 'c__1', index: 0, length: 2 },
        { base: 'c__1__0', index: 1, length: 2 },
      ]);
      // There should be 2*2*2 = 8 leaves.
      expect(contract.properties.length).toBe(8);
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

  // -------------------------------------------------------------------------
  // N-048 (external "PrematurePeek"): a computed runtime index is hoisted to
  // a `const __idx_K` binding in front of its STATEMENT. That is only sound
  // when nothing the statement evaluates before the read can observe or be
  // observed by the move. The reported exploit was
  //   assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
  // where `__idx_0 = this.cursor % 2n` was bound before the increment, so the
  // gate read the PRE-increment slot. The AST has no let-expression, so the
  // index cannot be bound at the read's own position; the pass refuses every
  // hoist that would reorder evaluation, with one shared diagnostic.
  //
  // Proves: each reordering shape below is refused, and each order-preserving
  // shape still expands without error. Does not prove on-chain behaviour —
  // that is runar-testing's n048-fixed-array-index-order-vm.test.ts.
  // -------------------------------------------------------------------------
  describe('N-048: hoisted runtime index keeps source evaluation order', () => {
    const ORDER_DIAG = 'FixedArray index would be evaluated out of source order';
    const contractWith = (body: string) => `
      class Peek extends StatefulSmartContract {
        readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
        slots: FixedArray<bigint, 2> = [0n, 0n];
        cursor: bigint;
        constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }
        public release(k: bigint, c: boolean) {
          ${body}
        }
      }
    `;
    const refused: Array<[string, string]> = [
      ['the reported shape: index after ++ in the left operand of &&',
        'assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);'],
      ['index after an earlier ++ with no short-circuit',
        'assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);'],
      ['index after an earlier output intrinsic call',
        'assert(this.addRawOutput(1n, toByteString("00")) === this.enabled[this.cursor % 2n]);'],
      ['effect-free index in the right operand of && (spec 3.7)',
        'assert(k > 0n && this.enabled[k - 1n] === 1n);'],
      ['effect-free index in the right operand of ||',
        'assert(k === 0n || this.enabled[k - 1n] === 1n);'],
      ['index in a ternary arm',
        'assert((c ? this.enabled[k + 1n] : 0n) === 0n);'],
      ['index whose own ++ moves ahead of an earlier read',
        'assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);'],
      ['value-side read whose index follows the target index side effect',
        'this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);'],
    ];
    for (const [what, body] of refused) {
      it(`refuses: ${what}`, () => {
        const { errors } = expand(contractWith(body));
        expect(errors.map(e => e.message).join('\n')).toContain(ORDER_DIAG);
      });
    }

    const accepted: Array<[string, string]> = [
      ['the increment in its own statement before the read',
        '++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);'],
      ['index in the left operand of &&',
        'assert(this.enabled[k - 1n] === 1n && k > 0n);'],
      ['index in a ternary condition',
        'assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);'],
      ['effect after the read',
        'assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);'],
      ['statement-form read', 'const v = this.enabled[k + 1n]; assert(v === 1n);'],
      ['runtime write with a computed index and a side-effecting value',
        'this.slots[this.cursor % 2n] = ++this.cursor; assert(true);'],
    ];
    for (const [what, body] of accepted) {
      it(`accepts: ${what}`, () => {
        const { errors } = expand(contractWith(body));
        expect(errors.map(e => e.message).join('\n')).not.toContain(ORDER_DIAG);
      });
    }

    it('hoists the split form after the increment, not before it', () => {
      const { contract, errors } = expand(contractWith(
        '++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);',
      ));
      expect(errors).toEqual([]);
      const body = methodBody(contract, 'release');
      expect(body[0]!.kind).toBe('expression_statement');
      expect(body[1]!.kind).toBe('variable_decl');
      expect((body[1] as { name: string }).name.startsWith('__idx_')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Field preservation (R-025 / R-026)
  // -------------------------------------------------------------------------
  //
  // This pass rebuilds AST nodes as it rewrites them. The reference tier copies
  // with object spread, so it preserves fields it never names — but six ports
  // reconstruct field-by-field, and there each unnamed field silently reverts
  // to its default. Two fields were being lost in the ports, both of which move
  // emitted bytes. These tests pin the invariant here so a porter has something
  // to port, and so a future spread-to-explicit-fields refactor of this file
  // goes red instead of quiet.
  describe('preserves fields it does not rewrite', () => {
    it('keeps a non-default @sighash on a method it rewrites', () => {
      // Validate has already ACCEPTED the directive by the time this pass runs;
      // losing it compiles a different signature-hash commitment than declared.
      const src = `
        class Boardy extends StatefulSmartContract {
          board: FixedArray<bigint, 3> = [0n, 0n, 0n];
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          /** @sighash SINGLE|FORKID */
          public bump(): void {
            this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n);
          }
        }
      `;
      const before = parseContract(src);
      expect(before.methods.find(m => m.name === 'bump')?.sighashType).toBe(0x43);

      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      expect(contract.methods.find(m => m.name === 'bump')?.sighashType).toBe(0x43);
    });

    it('keeps asmReturnType on an expression-form asm<T>() call', () => {
      // The captured T is what tells ANF lowering the value is byte-typed,
      // which is what makes `+` lower to OP_CAT rather than OP_ADD.
      const src = `
        class Boardy extends UnsafeSmartContract {
          readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];
          readonly n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          public go(): void {
            const a: ByteString = asm<ByteString>({ body: '00', in_arity: 0, out_arity: 1 });
            const c: ByteString = a + a;
            assert(len(c) === 2n);
            assert(this.board[0] === this.n);
          }
        }
      `;
      const { contract, errors } = expand(src);
      expect(errors).toEqual([]);
      const decl = methodBody(contract, 'go')[0] as Extract<Statement, { kind: 'variable_decl' }>;
      expect(decl.name).toBe('a');
      const call = decl.init as Extract<Expression, { kind: 'call_expr' }>;
      expect(call.kind).toBe('call_expr');
      expect(call.asmReturnType).toBe('ByteString');
    });
  });
});
