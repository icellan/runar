// W4 / PhantomLap — a for-loop condition that does not test the iterator.
//
// `validateForStatement` carried the comment "the condition should compare the
// iter var to a constant" and then read only `stmt.condition.right`. Nothing in
// any tier required `condition.left` to BE the iterator, and `extractLoopShape`
// ignores left entirely: it computes `count = bound - start`. So
//
//   for (let i = 0n; i + 1n < 2n; i++)
//
// runs ONCE in TypeScript (i=0: 0+1 < 2; i=1: 1+1 < 2 is false) and TWICE in
// the emitted script (count = 2 - 0). The extra lap executes the `else` arm the
// source can never reach.
//
// That is a fund-theft shape, not a cosmetic one. Measured on the vault below
// through `@bsv/sdk` `Spend.validate()` -- not the ANF interpreter, which
// agrees with the compiler's own unroll model and therefore sees nothing:
//
//   `i + 1n < 2n`, EMPTY signature   ->   validate() === true    (spent)
//   `i < 1n`,      EMPTY signature   ->   validate() === false
//
// Two loops with identical source semantics, opposite on-chain outcomes. The
// first lap runs the real `checkSig`; the phantom second lap overwrites the
// result with `true`.
//
// Every tier must refuse this. Refusing rather than lowering is deliberate:
// evaluating a general condition on each unrolled iteration means running an
// interpreter at ANF time, which is a language extension with no golden behind
// it. The loop model the ANF node can carry is exactly `start + k*step` tested
// against a constant bound, so the condition must name the iterator on the
// left. Canonical loops (`i < 10n`, the `i--` countdown, non-zero starts) are
// untouched -- `conformance/tests/` carries 104 loops and not one of them has a
// non-identifier left-hand side.
//
// The Zig tier needed a parser change to gate this at all: its `ForStmt` is
// pre-digested to `{var_name, init_value, bound, descending, inclusive}` and
// the condition's left-hand side was discarded at parse time, so there was
// nothing for the validator to look at. It now records `cond_tests_iter`
// alongside `bound_is_const`.

import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class StrideVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public spend(sig: Sig) {
    let authorized: boolean = false;
    for (let i = 0n; i + 1n < 2n; i++) {
      if (i === 0n) {
        authorized = checkSig(sig, this.owner);
      } else {
        authorized = true;
      }
    }
    assert(authorized);
  }
}
