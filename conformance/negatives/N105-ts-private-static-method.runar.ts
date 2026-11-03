// N-050 (StaticSiphon): a static / class-level method is not a contract method.
// Pre-fix, TS/Go/Rust compiled this as a private helper while Zig/Java/Python/
// Ruby refused it by accident ("no public methods"); its `public static` twin
// (N104) was an unsigned spend path. Every tier must refuse:
//   static methods are not allowed in Rúnar contracts; method 'requirePositive' is declared static
// Shape: `private static` on the TypeScript surface (refused too: static is not a contract method at all).
import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';

export class Vault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  private static requirePositive(amount: bigint) {
    assert(amount > 0n);
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
