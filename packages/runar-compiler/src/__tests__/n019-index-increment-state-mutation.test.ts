/**
 * N-019 (port of R-018, Rust): `this.arr[i]++` must be recognised as a state
 * mutation.
 *
 * Two blind spots, both keyed on the operand of an increment/decrement being a
 * bare `property_access`:
 *
 *   1. **Lowering** — `04-anf-lower.ts` emits an `update_prop` for an
 *      increment ONLY when the operand is a `property_access`. After pass 3b
 *      has run, `this.board[i]` (runtime index) is a ternary read chain over
 *      the expanded slots, so the new value is computed and DISCARDED.
 *
 *   2. **Side-effect summary** — `collectExpr` in `side-effect-summary.ts` has
 *      the identical guard, so `mutatesState` stays false, `continuationShape`
 *      returns `isTerminal: true`, and NO continuation assertion is injected at
 *      all: a method that mutates state emits nothing binding that mutation.
 *
 * The root cause is neither site: pass 3b rewrites only the increment's
 * OPERAND, leaving a `ternary_expr` where both sites expect a property access.
 *
 * The control below (`this.count++`, a plain scalar property) is the shape that
 * already works and must stay unchanged — it discriminates the two paths.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { expandFixedArrays } from '../passes/03b-expand-fixed-arrays.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import {
  computeSideEffectSummary,
  continuationShape,
  type ContinuationShape,
} from '../passes/side-effect-summary.js';
import type { ContractNode } from '../ir/index.js';
import type { ANFBinding } from '../ir/anf-ir.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Runtime index (`i` is a parameter), so pass 3b cannot fold to a slot. */
const INDEX_INCREMENT = `
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]++;
  }
}
`;

const INDEX_DECREMENT = `
class BumpDecr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i]--;
  }
}
`;

/** The hand-written form `this.board[i]++` must be equivalent to. */
const INDEX_EXPLICIT_ADD = `
class BumpIncr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[i] = this.board[i] + 1n;
  }
}
`;

/** Literal index — already folds to `this.board__0`; must be untouched. */
const LITERAL_INDEX_INCREMENT = `
class BumpLit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board[0]++;
  }
}
`;

const LITERAL_INDEX_EXPLICIT = `
class BumpLit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.board__0++;
  }
}
`;

/** `this.board[i]++` used for its VALUE. Must not silently drop the write. */
const INDEX_INCREMENT_IN_EXPRESSION = `
class BumpExpr extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  seen: bigint = 0n;

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.seen = this.board[i]++;
  }
}
`;

/** Histogram bump inside a loop — exercises the for-statement prelude path. */
const INDEX_INCREMENT_IN_LOOP = `
class BumpLoop extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bumpAll() {
    for (let i: bigint = 0n; i < 3n; i++) {
      this.board[i]++;
    }
  }
}
`;

/** Control: the already-working shape, a plain mutable scalar property. */
const PLAIN_PROP_INCREMENT = `
class BumpProp extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public bump(i: bigint) {
    this.count++;
  }
}
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse + run pass 3b, exactly as `compile()` does before ANF lowering. */
function expanded(source: string): ContractNode {
  const parsed = parse(source);
  expect(parsed.errors, `parse errors: ${JSON.stringify(parsed.errors)}`).toEqual([]);
  const contract = parsed.contract;
  if (!contract) throw new Error('parse returned no contract');
  const result = expandFixedArrays(contract);
  expect(
    result.errors,
    `expand-fixed-arrays errors: ${JSON.stringify(result.errors)}`,
  ).toEqual([]);
  return result.contract;
}

/** Every `update_prop` name in the body, including if arms and loop bodies. */
function updatePropNames(bindings: ANFBinding[], out: string[]): void {
  for (const b of bindings) {
    const v = b.value;
    switch (v.kind) {
      case 'update_prop':
        out.push(v.name);
        break;
      case 'if':
        updatePropNames(v.then, out);
        updatePropNames(v.else, out);
        break;
      case 'loop':
        updatePropNames(v.body, out);
        break;
      default:
        break;
    }
  }
}

function updatedProps(source: string, method: string): string[] {
  const program = lowerToANF(expanded(source));
  const m = program.methods.find(mm => mm.name === method);
  if (!m) throw new Error(`method ${method} not found`);
  const out: string[] = [];
  updatePropNames(m.body, out);
  return out;
}

function paramNames(source: string, method: string): string[] {
  const program = lowerToANF(expanded(source));
  const m = program.methods.find(mm => mm.name === method);
  if (!m) throw new Error(`method ${method} not found`);
  return m.params.map(p => p.name);
}

function shapeOf(
  source: string,
  method: string,
): { mutates: boolean; shape: ContinuationShape } {
  const summary = computeSideEffectSummary(expanded(source));
  const eff = summary.get(method);
  if (!eff) throw new Error(`no side-effect entry for ${method}`);
  return { mutates: eff.mutatesState, shape: continuationShape(eff) };
}

// ---------------------------------------------------------------------------
// Control — the shape that already works. Must pass before AND after the fix.
// ---------------------------------------------------------------------------

describe('N-019 control: plain property increment', () => {
  it('produces an update_prop and is non-terminal', () => {
    const props = updatedProps(PLAIN_PROP_INCREMENT, 'bump');
    expect(
      props,
      `control regressed: \`this.count++\` produced no update_prop; got ${JSON.stringify(props)}`,
    ).toContain('count');

    const { mutates, shape } = shapeOf(PLAIN_PROP_INCREMENT, 'bump');
    expect(mutates, 'control regressed: `this.count++` is not mutating').toBe(true);
    expect(shape.isTerminal, 'control regressed: treated as terminal').toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Half 1 — lowering: the increment through an index must produce update_prop.
// ---------------------------------------------------------------------------

describe('N-019 lowering: runtime-index increment emits update_prop', () => {
  it('this.board[i]++ produces an update_prop for a board slot', () => {
    const props = updatedProps(INDEX_INCREMENT, 'bump');
    expect(
      props.length,
      '`this.board[i]++` produced NO update_prop at all — the mutation was computed and discarded',
    ).toBeGreaterThan(0);
    expect(
      props.some(p => p.startsWith('board')),
      `no update_prop for a board slot; got ${JSON.stringify(props)}`,
    ).toBe(true);
  });

  it('this.board[i]-- produces an update_prop for a board slot', () => {
    const props = updatedProps(INDEX_DECREMENT, 'bump');
    expect(
      props.some(p => p.startsWith('board')),
      `no update_prop for a board slot; got ${JSON.stringify(props)}`,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Half 2 — side-effect summary: the method is NOT terminal.
// ---------------------------------------------------------------------------

describe('N-019 side effects: runtime-index increment mutates state', () => {
  it('this.board[i]++ sets mutatesState and is non-terminal', () => {
    const { mutates, shape } = shapeOf(INDEX_INCREMENT, 'bump');
    expect(
      mutates,
      '`this.board[i]++` did not set mutatesState — no continuation is injected',
    ).toBe(true);
    expect(
      shape.isTerminal,
      '`this.board[i]++` classified terminal: no continuation assertion binds the mutation',
    ).toBe(false);
    expect(shape.needsChange).toBe(true);
    expect(shape.needsNewAmount).toBe(true);
  });

  it('this.board[i]-- sets mutatesState and is non-terminal', () => {
    const { mutates, shape } = shapeOf(INDEX_DECREMENT, 'bump');
    expect(mutates, '`this.board[i]--` did not set mutatesState').toBe(true);
    expect(shape.isTerminal, '`this.board[i]--` classified terminal').toBe(false);
  });

  it('the bump inside a for-loop mutates state', () => {
    const props = updatedProps(INDEX_INCREMENT_IN_LOOP, 'bumpAll');
    expect(
      props.some(p => p.startsWith('board')),
      `loop-bumped element produced no update_prop; got ${JSON.stringify(props)}`,
    ).toBe(true);

    const { mutates, shape } = shapeOf(INDEX_INCREMENT_IN_LOOP, 'bumpAll');
    expect(mutates, 'loop-bumped array element did not set mutatesState').toBe(true);
    expect(shape.isTerminal, 'loop-bumping method classified terminal').toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The desugar must be FAITHFUL, not merely present.
// ---------------------------------------------------------------------------

describe('N-019 fidelity', () => {
  it('this.board[i]++ lowers identically to this.board[i] = this.board[i] + 1n', () => {
    const sugar = lowerToANF(expanded(INDEX_INCREMENT));
    const explicit = lowerToANF(expanded(INDEX_EXPLICIT_ADD));
    expect(sugar).toEqual(explicit);
  });

  it('the literal-index path is unchanged (goldens must not move)', () => {
    const sugar = lowerToANF(expanded(LITERAL_INDEX_INCREMENT));
    const explicit = lowerToANF(expanded(LITERAL_INDEX_EXPLICIT));
    expect(sugar).toEqual(explicit);
  });

  it('the runtime-index increment gets the same continuation params as the control', () => {
    expect(paramNames(INDEX_INCREMENT, 'bump')).toEqual(
      paramNames(PLAIN_PROP_INCREMENT, 'bump'),
    );
  });
});

// ---------------------------------------------------------------------------
// Expression position cannot write back through the dispatch chain.
// ---------------------------------------------------------------------------

describe('N-019 expression position', () => {
  it('this.seen = this.board[i]++ is rejected rather than silently dropped', () => {
    const parsed = parse(INDEX_INCREMENT_IN_EXPRESSION);
    expect(parsed.errors).toEqual([]);
    const contract = parsed.contract;
    if (!contract) throw new Error('parse returned no contract');
    const result = expandFixedArrays(contract);
    expect(
      result.errors.length,
      '`this.seen = this.board[i]++` was accepted; the array write is silently dropped',
    ).toBeGreaterThan(0);
  });
});
