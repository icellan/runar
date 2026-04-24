package runar.examples.bsv21token;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

/**
 * BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
 *
 * <p>BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens
 * instead of tick-based. The token ID is derived from the deploy
 * transaction ({@code <txid>_<vout>}), eliminating ticker squatting and
 * enabling admin-controlled distribution.
 *
 * <h2>BSV-21 Token Lifecycle</h2>
 * <ol>
 *   <li><strong>Deploy + Mint</strong> -- A single inscription deploys the
 *       token and mints the initial supply in one atomic operation. The
 *       token ID is the outpoint of the output containing this
 *       inscription.</li>
 *   <li><strong>Transfer</strong> -- Inscribe a transfer JSON referencing
 *       the token ID and amount.</li>
 * </ol>
 *
 * <p>The SDK helpers {@code bsv21DeployMint()} and {@code bsv21Transfer()}
 * build the correct inscription payloads for each operation.
 */
class BSV21Token extends SmartContract {

    @Readonly Addr pubKeyHash;

    BSV21Token(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    /** Unlock by proving ownership of the private key corresponding to pubKeyHash. */
    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
