package runar.examples.compilerdirectives;

import runar.lang.SmartContract;
import runar.lang.annotations.EmbedAlways;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.annotations.Sighash;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

/**
 * Directives -- Java port of
 * {@code examples/ts/compiler-directives/Directives.runar.ts}.
 *
 * <p>The two compiler directives in their native Java spelling (N-093): the
 * field annotation {@code EmbedAlways} keeps {@code deployTag} in the locking
 * script although no method reads it, and the method annotation
 * {@code Sighash("SINGLE|FORKID")} declares the BIP-143 mode
 * {@code spendSingle} commits to.
 */
class Directives extends SmartContract {

    @Readonly Addr pubKeyHash;
    @Readonly @EmbedAlways ByteString deployTag;

    Directives(Addr pubKeyHash, ByteString deployTag) {
        super(pubKeyHash, deployTag);
        this.pubKeyHash = pubKeyHash;
        this.deployTag = deployTag;
    }

    @Public
    void spendAll(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }

    @Public
    @Sighash("SINGLE|FORKID")
    void spendSingle(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
