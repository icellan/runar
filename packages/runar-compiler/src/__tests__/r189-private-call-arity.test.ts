import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import type { ContractNode } from '../ir/index.js';

/**
 * R-189 — a private method may shadow a builtin, and nothing upstream of ANF
 * lowering notices when the two disagree about arity.
 *
 * Typecheck resolves a BARE-IDENTIFIER call against the builtin table BEFORE
 * it looks at the contract's own methods; ANF lowering resolves the same call
 * against private methods FIRST. So `min(x, y)` against
 * `private min(a, b, c)` type-checks as the two-argument BUILTIN `min` and
 * then lowers as the three-parameter METHOD `min`. No validator forbids the
 * shadowing.
 *
 * The zip that bound params to args stopped at the shorter list. When the
 * surplus parameter was never read the contract compiled CLEAN — an arity
 * mismatch silently accepted. When it was read, the defect surfaced two passes
 * later as "method parameter 'c' is not on the stack", a stack-lowering
 * message about a pass the author never wrote in.
 */

/** The silent case: `c` is never read, so nothing downstream ever noticed. */
const SURPLUS_PARAM_UNREAD = `
class R189Unread extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
`;

/** Too many arguments: `y` was evaluated and then dropped on the floor. */
const TOO_MANY_ARGS = `
class R189Extra extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint): bigint {
    this.count = a;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
`;

/**
 * Control 1: the SAME builtin-shadowing private, called at its real arity
 * through `this.` — the bare form cannot reach pass 4 at arity 3, because
 * pass 3 checks it against the two-argument BUILTIN `min` and refuses.
 */
const CONTROL_SHADOWING_AT_REAL_ARITY = `
class R189ControlShadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b + c;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint, z: bigint) {
    this.min(x, y, z);
  }
}
`;

/**
 * Control 2: an ordinary private helper, bare-identifier call at matching
 * arity — the Move / Go-DSL lowering path this refusal sits directly on.
 * Without the controls, a refusal that simply rejected every private call
 * would pass both tests above.
 */
const CONTROL_PLAIN_PRIVATE = `
class R189ControlPlain extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private tally(a: bigint, b: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    tally(x, y);
  }
}
`;

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

describe('R-189: private-method call arity', () => {
  it('reaches pass 4 — typecheck does not catch the builtin shadowing', () => {
    // If this ever starts failing, the two refusal tests below stop testing
    // pass 4 and start testing pass 3.
    const errors = typecheck(parseContract(SURPLUS_PARAM_UNREAD)).errors;
    expect(errors).toHaveLength(0);
  });

  it('refuses a surplus parameter instead of leaving it unbound', () => {
    expect(() => lowerToANF(parseContract(SURPLUS_PARAM_UNREAD))).toThrow(
      /private method 'min' expects 3 argument\(s\), got 2\./,
    );
  });

  it('refuses a surplus argument instead of dropping it on the floor', () => {
    expect(() => lowerToANF(parseContract(TOO_MANY_ARGS))).toThrow(
      /private method 'min' expects 1 argument\(s\), got 2\./,
    );
  });

  it('still lowers a builtin-shadowing private called at its real arity', () => {
    expect(() => lowerToANF(parseContract(CONTROL_SHADOWING_AT_REAL_ARITY))).not.toThrow();
  });

  it('still lowers a plain private helper called as a bare identifier', () => {
    expect(() => lowerToANF(parseContract(CONTROL_PLAIN_PRIVATE))).not.toThrow();
  });
});
