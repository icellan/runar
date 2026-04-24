package runar.examples.bsv20token;

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
 * BSV20Token -- Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
 *
 * <p>BSV-20 is a 1sat ordinals token standard where fungible tokens are
 * represented as inscriptions on P2PKH UTXOs. The contract logic is
 * standard P2PKH -- the token semantics (deploy, mint, transfer) are
 * encoded in the inscription envelope and interpreted by indexers, not
 * by the script itself.
 *
 * <h2>BSV-20 Token Lifecycle</h2>
 * <ol>
 *   <li><strong>Deploy</strong> -- Inscribe a deploy JSON
 *       ({@code {"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}})
 *       onto a UTXO to register a new ticker. First deployer wins.</li>
 *   <li><strong>Mint</strong> -- Inscribe a mint JSON
 *       ({@code {"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}}) to
 *       claim tokens up to the per-mint limit.</li>
 *   <li><strong>Transfer</strong> -- Inscribe a transfer JSON
 *       ({@code {"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}}) to
 *       move tokens between addresses.</li>
 * </ol>
 *
 * <p>The SDK helpers {@code bsv20Deploy()}, {@code bsv20Mint()}, and
 * {@code bsv20Transfer()} build the correct inscription payloads for
 * each operation.
 */
class BSV20Token extends SmartContract {

    @Readonly Addr pubKeyHash;

    BSV20Token(Addr pubKeyHash) {
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
