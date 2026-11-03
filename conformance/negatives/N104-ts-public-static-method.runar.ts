// N-050 (StaticSiphon): a static / class-level method is not a contract method.
// Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
// tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
// Spend.validate accepted it against the TS artifact). Every tier must refuse:
//   static methods are not allowed in Rúnar contracts; method 'requirePositive' is declared static
// Shape: `public static` on the TypeScript surface.
import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';

export class Vault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public static requirePositive(amount: bigint) {
    assert(amount > 0n);
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
