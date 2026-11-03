// N-050 (StaticSiphon): a static / class-level method is not a contract method.
// Pre-fix, `requirePositive` became a PUBLIC spending entry point in several
// tiers — a path anyone satisfies with `<1>` and no signature (@bsv/sdk
// Spend.validate accepted it against the TS artifact). Every tier must refuse:
//   static methods are not allowed in Rúnar contracts; method 'requirePositive' is declared static
// Shape: `@Public static` on the Java surface.
package runar.examples.vault;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import java.math.BigInteger;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

class Vault extends SmartContract {

    @Readonly PubKey owner;

    Vault(PubKey owner) {
        super(owner);
        this.owner = owner;
    }

    @Public
    static void requirePositive(BigInteger amount) {
        assertThat(amount.compareTo(BigInteger.ZERO) > 0);
    }

    @Public
    void withdraw(Sig sig) {
        assertThat(checkSig(sig, owner));
    }
}
