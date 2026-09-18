// R-092 / N-091: a private helper's declared return type is discarded at parse
// time in every tier (`MethodNode` carries no `returnType`), so a call to one
// infers as `<unknown>`. Six tiers then refuse that value in any operand
// position that demands a number — `isBigintFamily("<unknown>")` is false and
// there is no escape hatch. Java carried an extra `&& !"<unknown>".equals(t)`
// conjunct at eight such checks (arithmetic, relational, shift, bitwise, unary
// `-`, unary `~`, `++`/`--`, array index) and alone ACCEPTED this source,
// emitting `7c00ad007ca0`.
//
// That is not a cosmetic divergence. `hp()` returns a 33-byte PubKey; feeding
// it to OP_GREATERTHAN succeeds post-Genesis and silently computes a
// meaningless comparison, so the spending guard the author wrote is not the
// guard that ends up on chain. Converging the seven tiers on the strict six —
// never the permissive one — is the fix, and this fixture is the gate.
//
// The shape is deliberately one that stays invalid if the root cause is ever
// fixed: `PubKey` is not in the bigint family, so `hp() > x` is a type error
// whether the helper's return type is derived as `<unknown>` (today) or as the
// declared `PubKey` (after a `returnType` port).
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

export class UnknownOperand extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  private hp(): PubKey {
    return this.pk;
  }

  public go(s: Sig, x: bigint) {
    assert(checkSig(s, this.hp()));
    assert(this.hp() > x);
  }
}
