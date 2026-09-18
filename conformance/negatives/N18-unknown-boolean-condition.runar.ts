// N-101: `<unknown>` in a boolean-CONDITION position.
//
// The ninth instance of the class `bca3bb4f` (R-092) closed eight of, and the
// one that commit explicitly left filed: Java carried `&& !"<unknown>".equals(cond)`
// on the `if`, `for` and ternary condition checks that its six peers do not.
//
//     ts / go / rust / python / zig / ruby   REJECT ("if condition must be
//                                            boolean, got '<unknown>'")
//     java                                   ACCEPT, 24 hexchars
//
// `assert()` IS escaped in every tier — TS, Go, Rust, Python, Zig and Ruby all
// carry `condType !== BOOLEAN && condType !== '<unknown>'` there — so the
// escape itself is not the error; carrying it at three MORE sites than the
// reference does is.
//
// The value in condition position here is a private helper's return type, which
// no tier derives (`MethodNode` has no `returnType`), so it infers as
// `<unknown>`. This tier then lowered a 33-byte PubKey into a branch condition,
// where post-Genesis it is simply truthy — the `if` the author wrote is not the
// `if` that ends up on chain. That is the same soundness argument R-092 made
// for the operand positions, and the same resolution: converge on the strict
// six, never on the permissive one.
//
// The shape stays invalid if the root cause is ever fixed: `PubKey` is not
// `boolean`, so this is a type error whether the helper's return type is
// derived as `<unknown>` (today) or as the declared `PubKey` (after a
// `returnType` port).
//
// The `for`-condition escape is the third site deleted alongside these two, but
// it is NOT reachable from source: this tier's validator requires a for-loop
// condition to be a comparison against a compile-time constant and refuses
// `for (...; this.hp(); ...)` before the typechecker sees it. It is deleted as
// dead code, exactly as bca3bb4f deleted its unreachable `isSubtype` conjuncts,
// and characterised in the Java tier's own N101 test rather than here.
import { SmartContract, assert, PubKey } from 'runar-lang';

export class UnknownBooleanCondition extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  private hp(): PubKey {
    return this.pk;
  }

  public go(x: bigint) {
    let y: bigint = 0n;
    if (this.hp()) {
      y = y + 1n;
    }
    assert(x > y);
  }
}
