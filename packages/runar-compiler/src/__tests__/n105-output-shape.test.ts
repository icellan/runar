/**
 * N-105 (2/2) — the rest of TypeScript's output-intrinsic CONTRACT: the
 * StatefulSmartContract gate, the arity of all three intrinsics, and the types
 * of addOutput's state values.
 *
 * TypeScript is the reference here and already performs all three. The other
 * six tiers performed none of them, and each hole had an executed consequence
 * measured through the Go tier:
 *
 *   this.addOutput(1000n)                  1352 hexchars — the state value is
 *     with one mutable property            simply MISSING from the
 *                                          continuation; the correct call
 *                                          emits 1362.
 *   this.addOutput(1000n, this.count, 5n)  1368 hexchars — the surplus value is
 *                                          appended to a state serialization
 *                                          the next spend deserializes by fixed
 *                                          offsets.
 *   this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes — the
 *     with count: bigint                   ByteString is serialized where an
 *                                          8-byte LE number belongs.
 *   this.addRawOutput(...) in a            152 hexchars — a "continuation" in a
 *     stateless SmartContract              contract that has no state.
 *
 * This file is the reference tier's regression guard: the six ports each pin
 * the same wording and the same ACCEPT set, which is what makes it a parity
 * gate rather than six independent opinions.
 *
 * It also pins the ONE place where the reference rule is known to be wrong —
 * see `the arity rule and FixedArray state` below. That case is asserted as it
 * behaves today, not as it should behave, so the defect cannot be lost.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const HEAD = `import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  owner: PubKey;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
    super(count, owner, base, blob);
    this.count = count;
    this.owner = owner;
    this.base = base;
    this.blob = blob;
  }

  private anything(): bigint { return this.base; }

`;

const STATELESS_HEAD = `import { SmartContract, ByteString, assert } from 'runar-lang';

class C extends SmartContract {
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(base: bigint, blob: ByteString) {
    super(base, blob);
    this.base = base;
    this.blob = blob;
  }

`;

const stateful = (body: string): string => `${HEAD}${body}}\n`;
const stateless = (body: string): string => `${STATELESS_HEAD}${body}}\n`;

function errorsOf(source: string): string[] {
  const r = compile(source, { fileName: 'C.runar.ts' });
  return (r.diagnostics ?? [])
    .filter((d) => d.severity === 'error')
    .map((d) => d.message);
}

function hexOf(source: string): string {
  const r = compile(source, { fileName: 'C.runar.ts' });
  const errs = (r.diagnostics ?? []).filter((d) => d.severity === 'error');
  expect(errs.map((d) => d.message), 'expected this contract to compile').toEqual([]);
  return r.artifact!.script;
}

// ---------------------------------------------------------------------------
// REJECT
// ---------------------------------------------------------------------------

const ARITY_TOO_FEW = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count);
  }
`);

const ARITY_TOO_MANY = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner, 5n);
  }
`);

const RAW_ARITY_ONE = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n);
  }
`);

const RAW_ARITY_THREE = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n, this.blob, 7n);
  }
`);

const DATA_ARITY_THREE = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addDataOutput(500n, this.blob, 7n);
  }
`);

const STATE_VALUE_WRONG_TYPE = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.blob, this.owner);
  }
`);

const STATELESS_ADD_OUTPUT = stateless(`  public m(n: bigint) {
    this.addOutput(1000n, n);
    assert(n > 0n);
  }
`);

const STATELESS_ADD_RAW_OUTPUT = stateless(`  public m(n: bigint) {
    this.addRawOutput(1000n, this.blob);
    assert(n > 0n);
  }
`);

const STATELESS_ADD_DATA_OUTPUT = stateless(`  public m(n: bigint) {
    this.addDataOutput(1000n, this.blob);
    assert(n > 0n);
  }
`);

// ---------------------------------------------------------------------------
// ACCEPT
// ---------------------------------------------------------------------------

const SHAPE_EXACT = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
  }
`);

/**
 * A ByteString value in a PubKey state slot. `isSubtype` treats the ByteString
 * family as bidirectionally compatible, so this is ACCEPTED — and four of the
 * seven tiers' own `isSubtype` is narrower, which is why their ports of the
 * state-value check go through a dedicated predicate rather than reusing it.
 */
const SHAPE_FAMILY_WIDENING = stateful(`  public m(n: bigint, b: ByteString) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count, b);
  }
`);

/** A private helper's declared return type is discarded at parse time in EVERY
 *  tier, so this infers as `<unknown>` and must stay ACCEPTED. */
const SHAPE_UNKNOWN_STATE_VALUE = stateful(`  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.anything(), this.owner);
  }
`);

const ONE_PROP = `import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, blob: ByteString) {
    super(count, blob);
    this.count = count;
    this.blob = blob;
  }

  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
}
`;

/**
 * The Boardy contract from
 * `compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py`.
 * It is checked into this repo and all six non-TS tiers compile it.
 */
const FIXED_ARRAY_STATE = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
}
`;

/** The same contract passing the array WHOLE, which is what the arity rule
 *  wants. It type-checks and then dies in stack lowering. */
const FIXED_ARRAY_STATE_WHOLE = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board, this.n); }
}
`;

describe('N-105: output-intrinsic arity', () => {
  it('addOutput wants satoshis + one value per mutable property', () => {
    expect(errorsOf(ARITY_TOO_FEW)).toContain(
      'addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2',
    );
    expect(errorsOf(ARITY_TOO_MANY)).toContain(
      'addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4',
    );
  });

  it('addRawOutput and addDataOutput want exactly (satoshis, scriptBytes)', () => {
    expect(errorsOf(RAW_ARITY_ONE)).toContain(
      'addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1',
    );
    expect(errorsOf(RAW_ARITY_THREE)).toContain(
      'addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3',
    );
    expect(errorsOf(DATA_ARITY_THREE)).toContain(
      'addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3',
    );
  });
});

describe('N-105: addOutput state-value types', () => {
  it("a ByteString in a bigint state slot is rejected", () => {
    expect(errorsOf(STATE_VALUE_WRONG_TYPE)).toContain(
      "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'",
    );
  });
});

describe('N-105: the output intrinsics are StatefulSmartContract-only', () => {
  it('addOutput', () => {
    expect(errorsOf(STATELESS_ADD_OUTPUT)).toContain(
      'addOutput() is only available in StatefulSmartContract',
    );
  });
  it('addRawOutput', () => {
    expect(errorsOf(STATELESS_ADD_RAW_OUTPUT)).toContain(
      'addRawOutput() is only available in StatefulSmartContract',
    );
  });
  it('addDataOutput', () => {
    expect(errorsOf(STATELESS_ADD_DATA_OUTPUT)).toContain(
      'addDataOutput() is only available in StatefulSmartContract',
    );
  });
});

describe('N-105: output shapes that must stay ACCEPTED', () => {
  it('exact arity and exact types', () => {
    expect(hexOf(SHAPE_EXACT).length).toBeGreaterThan(0);
  });

  it('a ByteString value in a PubKey state slot', () => {
    expect(hexOf(SHAPE_FAMILY_WIDENING).length).toBeGreaterThan(0);
  });

  it("a private helper call, whose return type infers as '<unknown>'", () => {
    expect(hexOf(SHAPE_UNKNOWN_STATE_VALUE).length).toBeGreaterThan(0);
  });

  it('the arity is derived from the mutable properties, not hardcoded', () => {
    expect(hexOf(ONE_PROP).length).toBeGreaterThan(0);
    expect(hexOf(SHAPE_EXACT).length).toBeGreaterThan(0);
  });
});

/**
 * A KNOWN DEFECT in the reference rule, pinned so it cannot be lost.
 *
 * `typecheck` runs BEFORE `expandFixedArrays` (see `compile` in
 * `packages/runar-compiler/src/index.ts`), so the arity rule counts the
 * DECLARED mutable properties — `board` and `n`, two of them — while the pass
 * that follows splits `board` into three scalar siblings. The only call shape
 * that reaches a working script is therefore the EXPANDED one, and this rule
 * rejects it; the form the rule wants instead type-checks and then dies in
 * stack lowering, so there is no accepted way to use addOutput in a contract
 * with FixedArray state.
 *
 * The six ports of this rule are scoped out of contracts with FixedArray state
 * for exactly this reason — porting it verbatim would have deleted a contract
 * this repo checks in. Fixing it here means moving the property count to the
 * post-expansion view (or moving the pass), which is a separate change.
 */
describe('N-105: the arity rule and FixedArray state (KNOWN DEFECT)', () => {
  it('rejects the expanded form, which is the only form that lowers', () => {
    expect(errorsOf(FIXED_ARRAY_STATE)).toContain(
      'addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 5',
    );
  });

  it('and the form it asks for instead dies in stack lowering', () => {
    const errs = errorsOf(FIXED_ARRAY_STATE_WHOLE);
    expect(errs.join('\n')).toContain('Stack lowering');
    expect(errs.join('\n')).toContain("property 'board'");
  });
});
