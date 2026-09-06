import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import { compile } from '../index.js';
import type { ValidationResult } from '../passes/02-validate.js';
import type { ContractNode } from '../ir/index.js';

// ---------------------------------------------------------------------------
// NEW-012 — `return` inside a PUBLIC method.
//
// SPEC (the rule already exists; six of seven compilers just never enforced it):
//
//   spec/grammar.md:161  "Public methods MUST return `void`."
//   spec/grammar.md:162  "Public methods MUST end with an `assert(...)` call as
//                         their final statement. This assert encodes the
//                         spending condition: if it fails, the transaction is
//                         invalid."
//   spec/grammar.md:168  "Private methods may return a value."
//
// And the operational semantics has no notion of an early exit AT ALL:
//
//   spec/semantics.md §4.6  <e,env,σ> -->* v  ⊢  <return e, env, σ> ==> (v, σ)
//        — `return` is defined ONLY as "the value of this method is v", which
//          is the private-helper/inlining semantics.
//   spec/semantics.md §4.7  <S1,env,σ> ==> <env',σ'>,  <S2,env',σ'> ==> <env'',σ''>
//                           ⊢ <S1;S2, env, σ> ==> <env'',σ''>
//        — sequencing is UNCONDITIONAL. There is no rule under which S2 is
//          skipped, so "return early and skip the rest" is not underspecified,
//          it is unspecified.
//
// What the compiler did instead of enforcing that:
//
//   * `return;`      → the arm carrying it produced OP_0, so the whole script
//                      evaluated FALSE. Source accepts, `Spend` rejects with
//                      "The top stack element must be truthy after script
//                      evaluation." A legal-looking method became unspendable.
//   * `return expr;` → WORSE, and fail-OPEN: the returned value became the
//                      branch result and therefore the script's final
//                      truthiness, so any truthy `expr` spent the contract
//                      WITHOUT reaching the guarding `assert`. Interpreter,
//                      ScriptVM and `Spend` all agreed it was a valid spend,
//                      which is why no differential oracle ever saw it.
//   * either form, when the arm also rebinds a live local → an internal
//                      codegen error ("branch result layout mismatch").
//
// Rejecting at validation is the fix: `spec/grammar.md:161` already forbade
// `return expr;` (the Java tier has enforced it all along, message "public
// method '<name>' must not return a value"), no in-repo contract uses `return`
// in a public method (0 of ~800 `.runar.*` files), and a compile error beats
// both an unspendable script and an unguarded one.
// ---------------------------------------------------------------------------

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function validateSource(source: string): ValidationResult {
  return validate(parseContract(source));
}

function errorsMatching(result: ValidationResult, substring: string): string[] {
  return result.errors.filter(e => e.message.includes(substring)).map(e => e.message);
}

const RETURN_IN_PUBLIC = 'must not use `return`';

describe('return in a public method is rejected', () => {
  it('rejects a bare `return;` that would compile to a FALSE branch result', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) {
      return;
    }
    assert(x === this.secret);
  }
}
`);
    expect(errorsMatching(result, RETURN_IN_PUBLIC)).toHaveLength(1);
    expect(result.errors[0]!.message).toContain('unlock');
  });

  it('rejects `return expr;`, which compiled to an UNGUARDED spending path', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) {
      return x;
    }
    assert(x === this.secret);
  }
}
`);
    expect(errorsMatching(result, RETURN_IN_PUBLIC)).toHaveLength(1);
  });

  it('rejects a `return` nested inside a for loop in a public method', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    for (let i: bigint = 0n; i < 4n; i++) {
      if (x > i) {
        return;
      }
    }
    assert(x === this.secret);
  }
}
`);
    expect(errorsMatching(result, RETURN_IN_PUBLIC)).toHaveLength(1);
  });

  it('reports every offending return, not just the first', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    if (x < 0n) { return; }
    assert(x === this.secret);
  }
}
`);
    expect(errorsMatching(result, RETURN_IN_PUBLIC)).toHaveLength(2);
  });

  it('names the spec rule and the private-method alternative in the message', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    assert(x === this.secret);
  }
}
`);
    const msg = result.errors[0]!.message;
    // A diagnostic that only says "no" leaves the author guessing which of the
    // two legal shapes they wanted.
    expect(msg).toMatch(/private/);
    expect(msg).toMatch(/assert/);
  });

  it('does not fire on a `return` in a PRIVATE helper (spec/grammar.md:168)', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  private double(v: bigint): bigint {
    return v + v;
  }

  public unlock(x: bigint) {
    assert(this.double(x) === this.secret);
  }
}
`);
    expect(errorsMatching(result, RETURN_IN_PUBLIC)).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('does not fire on a public method with no return at all', () => {
    const result = validateSource(`
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    assert(x === this.secret);
  }
}
`);
    expect(result.errors).toHaveLength(0);
  });
});

describe('the shapes the rejection replaces', () => {
  // Non-vacuity, and the whole reason the rule is worth having: these two
  // programs used to reach codegen. Compiling them must now FAIL rather than
  // emit an unspendable (or, worse, unguarded) locking script.
  const BARE = `import { SmartContract, assert } from 'runar-lang';

class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    assert(x === this.secret);
  }
}
`;

  const VALUED = BARE.replace('return;', 'return x;');

  it('no longer emits a locking script for the bare-return contract', () => {
    const result = compile(BARE, {
      fileName: 'Guard.runar.ts',
      constructorArgs: { secret: 999n },
    });
    expect(result.artifact).toBeUndefined();
    expect(
      result.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('\n'),
    ).toContain(RETURN_IN_PUBLIC);
  });

  it('no longer emits a locking script for the valued-return contract', () => {
    const result = compile(VALUED, {
      fileName: 'Guard.runar.ts',
      constructorArgs: { secret: 999n },
    });
    expect(result.artifact).toBeUndefined();
    expect(
      result.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('\n'),
    ).toContain(RETURN_IN_PUBLIC);
  });
});
