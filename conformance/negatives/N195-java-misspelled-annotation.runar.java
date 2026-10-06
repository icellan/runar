// F-205: a misspelled annotation (@Publlic, for @Public) is a loud parse
// error on the TS reference ("unsupported annotation @Publlic"), not a
// silent visibility downgrade. Pre-fix, six tiers (Go, Rust, Python, Zig,
// Ruby, Java) accepted this with zero errors and left `withdraw` at the
// default PRIVATE visibility — not a spending entry point, but with no
// diagnostic telling the author why. Every tier must refuse.
package runar.examples.vault;

import runar.lang.SmartContract;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

class Vault extends SmartContract {

    @Readonly PubKey owner;

    Vault(PubKey owner) {
        super(owner);
        this.owner = owner;
    }

    @Publlic
    void withdraw(Sig sig) {
        assertThat(checkSig(sig, owner));
    }
}
