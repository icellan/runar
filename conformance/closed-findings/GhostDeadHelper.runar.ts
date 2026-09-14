// GK-BUG-009 — the shape that proves the hole is a TYPECHECK hole and not a
// cosmetic one.
//
// In GhostEq the six non-TS tiers still exit non-zero, but only because stack
// lowering later refuses to emit an OP_0 placeholder for a name it cannot find
// on the stack. That net only fires for a reference that reaches codegen. Put
// the same unresolvable identifier somewhere codegen never walks — an uncalled
// private helper — and the net never fires. Measured at the parent commit:
//
//   ts                             Undefined variable 'notDeclaredAnywhere'
//   go rust python zig ruby java   exit 0, script hex 009c
//
// A compiler that emits a locking script for a contract naming a variable that
// does not exist is not refusing anything; it is agreeing with the other five
// about a program it never understood.
//
// MUST NOT COMPILE.
import { SmartContract, assert } from 'runar-lang';

export class GhostDeadHelper extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }

  private neverCalled(): bigint {
    assert(notDeclaredAnywhere === 1n);
    return 1n;
  }

  public verify(seed: bigint) {
    assert(seed === this.target);
  }
}
