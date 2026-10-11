// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Java surface, @Public method parameter (a bare field name IS a property read; a parameter is not).
package runar.examples;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifyRabinSig;

class RabinParam extends SmartContract {
    @Readonly RabinPubKey pk;

    RabinParam(RabinPubKey pk) {
        super(pk);
        this.pk = pk;
    }

    @Public
    void settle(ByteString msg, RabinSig sig, ByteString padding, RabinPubKey n) {
        assertThat(verifyRabinSig(msg, sig, padding, n));
    }
}
