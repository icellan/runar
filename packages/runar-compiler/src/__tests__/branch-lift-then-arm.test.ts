/**
 * Regression test: the branch-lift must not zero the matched arm.
 *
 * `liftBranchUpdateProps` (04-anf-lower.ts) flattens a dispatch chain
 *
 *     if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
 *     else { assert(false); }
 *
 * into one single-valued `if` per property plus a top-level `update_prop`.
 * The `if`'s then-arm is supposed to evaluate to the assigned value and its
 * else-arm to the property's old value.
 *
 * The defect: the then-arm was built from `branch.valueBindings` — everything
 * BEFORE the `update_prop` in the original arm. That only happens to end on the
 * assigned value when the value was computed INSIDE the arm. When the arm
 * assigns something bound outside it (a local, a parameter, anything hoisted
 * before the chain) `valueBindings` is empty, so the arm was emitted EMPTY and
 * stack lowering padded it with OP_0:
 *
 *     OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF      (63 00 67 76 68)
 *
 * i.e. the MATCHED branch pushed zero. `if (p == 0n) { this.c0 = local; }`
 * compiled to `this.c0 = 0` — a silent state-corrupting miscompile in every
 * tier, since all seven run the same pass.
 *
 * `examples/ts/tic-tac-toe/TicTacToe.runar.ts` escapes it only because it
 * writes `this.cN = this.turn`, whose `load_prop` lands inside the arm.
 *
 * These tests assert on BOTH levels — the ANF (then-arm non-empty and ending
 * on the assigned value) and the emitted bytes — because either alone can pass
 * for the wrong reason. The control locks in that an arm which LEGITIMATELY
 * assigns zero still emits the zero push, so the fix cannot be satisfied by
 * suppressing the byte pattern.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF — the matched branch pushing zero. */
const ZEROED_ARM = '6300677668';

/** Count byte-aligned occurrences of a hex sequence. */
function countByteSequence(hex: string, seq: string): number {
  let count = 0;
  for (let i = 0; i + seq.length <= hex.length; i += 2) {
    if (hex.slice(i, i + seq.length) === seq) count++;
  }
  return count;
}

/**
 * The dispatch chain assigns a LOCAL bound before the chain, so nothing in the
 * arm computes the value. This is the shape that miscompiled.
 */
const LOCAL_VALUE_DISPATCH = `
class LocalValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public poke(position: bigint, value: bigint) {
    const doubled: bigint = value + value;
    if (position == 0n) { this.c0 = doubled; }
    else if (position == 1n) { this.c1 = doubled; }
    else { assert(false); }
  }
}
`;

/**
 * Same chain assigning a PARAMETER directly — also nothing bound in the arm.
 */
const PARAM_VALUE_DISPATCH = `
class ParamValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public poke(position: bigint, value: bigint) {
    if (position == 0n) { this.c0 = value; }
    else if (position == 1n) { this.c1 = value; }
    else { assert(false); }
  }
}
`;

/**
 * CONTROL: the arms genuinely assign the literal 0. The zero push is correct
 * here and must survive — a fix that just suppresses the byte pattern fails
 * this.
 */
const LITERAL_ZERO_DISPATCH = `
class LiteralZeroDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public clear(position: bigint) {
    if (position == 0n) { this.c0 = 0n; }
    else if (position == 1n) { this.c1 = 0n; }
    else { assert(false); }
  }
}
`;

/**
 * CONTROL: the arms compute the value inside themselves (the TicTacToe shape).
 * Already correct before the fix; must stay correct and must not gain bytes.
 */
const IN_ARM_VALUE_DISPATCH = `
class InArmValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;
  turn: bigint;

  constructor(c0: bigint, c1: bigint, turn: bigint) {
    super(c0, c1, turn);
    this.c0 = c0;
    this.c1 = c1;
    this.turn = turn;
  }

  public poke(position: bigint) {
    if (position == 0n) { this.c0 = this.turn; }
    else if (position == 1n) { this.c1 = this.turn; }
    else { assert(false); }
  }
}
`;

/**
 * The lifted, flattened form: every top-level `update_prop` whose value is an
 * `if` binding, paired with that `if`.
 */
function liftedAssignments(source: string) {
  const result = compile(source);
  expect(result.success).toBe(true);
  const method = result.anf!.methods.find(m => m.name === 'poke' || m.name === 'clear');
  expect(method).toBeDefined();
  const bindings = method!.body;

  const pairs: Array<{ prop: string; then: unknown[]; else: unknown[] }> = [];
  for (const b of bindings) {
    if (b.value.kind !== 'update_prop') continue;
    const valueRef = b.value.value;
    const producer = bindings.find(x => x.name === valueRef);
    if (!producer || producer.value.kind !== 'if') continue;
    pairs.push({ prop: b.value.name, then: producer.value.then, else: producer.value.else });
  }
  return { result, pairs };
}

describe('branch-lift: the matched arm carries the assigned value', () => {
  it('does not drop the then-arm when the value is a local bound before the chain', () => {
    const { pairs } = liftedAssignments(LOCAL_VALUE_DISPATCH);

    // The chain covers c0 and c1, so the lift produces two flattened
    // assignments. If this is 0 the pass stopped recognising the shape and the
    // rest of the test would pass vacuously.
    expect(pairs.map(p => p.prop)).toEqual(['c0', 'c1']);

    for (const pair of pairs) {
      expect(pair.then.length,
        `then-arm for this.${pair.prop} is empty; stack lowering will pad it with OP_0`,
      ).toBeGreaterThan(0);
      expect(pair.else.length).toBeGreaterThan(0);
    }
  });

  it('does not drop the then-arm when the value is a parameter', () => {
    const { pairs } = liftedAssignments(PARAM_VALUE_DISPATCH);
    expect(pairs.map(p => p.prop)).toEqual(['c0', 'c1']);
    for (const pair of pairs) {
      expect(pair.then.length,
        `then-arm for this.${pair.prop} is empty`,
      ).toBeGreaterThan(0);
    }
  });

  it('never emits a zeroed matched arm for a non-zero assignment', () => {
    for (const source of [LOCAL_VALUE_DISPATCH, PARAM_VALUE_DISPATCH]) {
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(countByteSequence(result.artifact!.script, ZEROED_ARM)).toBe(0);
    }
  });

  it('CONTROL: an arm that really assigns 0n still pushes zero', () => {
    const result = compile(LITERAL_ZERO_DISPATCH);
    expect(result.success).toBe(true);
    // Two properties, two arms that legitimately push OP_0 against an OP_DUP
    // of the old value.
    expect(countByteSequence(result.artifact!.script, ZEROED_ARM)).toBe(2);
  });

  it('CONTROL: the in-arm (TicTacToe) shape still lifts and is unaffected', () => {
    const { pairs } = liftedAssignments(IN_ARM_VALUE_DISPATCH);
    expect(pairs.map(p => p.prop)).toEqual(['c0', 'c1']);
    for (const pair of pairs) {
      // A single load_prop of `turn` — the value already lands inside the arm,
      // so the fix must add nothing here.
      expect(pair.then.length).toBe(1);
    }
  });
});
