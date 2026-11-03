// N-268: an `embedAlways` marker on a readonly field on the Java surface.
// Only .runar.ts honours the directive; every other surface must refuse it
// with the one shared "not supported by the Java surface parser" message
// (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
// each used their own, differently worded text here).
// With the marker replaced by prose, metadataId is an ordinary unreferenced
// readonly field: every tier eliminates it by DCE, so this compiles to the
// same P2PKH-shaped script everywhere.
package runar.examples.meta;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class Meta extends SmartContract {

    @Readonly Addr pubKeyHash;
    /** @embedAlways */
    @Readonly ByteString metadataId;

    Meta(Addr pubKeyHash, ByteString metadataId) {
        super(pubKeyHash, metadataId);
        this.pubKeyHash = pubKeyHash;
        this.metadataId = metadataId;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
