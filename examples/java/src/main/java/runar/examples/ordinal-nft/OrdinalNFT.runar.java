package runar.examples.ordinalnft;

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
 * OrdinalNFT -- Pay-to-Public-Key-Hash lock for a 1sat ordinal inscription.
 *
 * <p>This is a stateless P2PKH contract used to lock an ordinal NFT. The
 * owner (holder of the private key whose public key hashes to
 * {@code pubKeyHash}) can unlock and transfer the ordinal by providing
 * a valid signature and public key.
 *
 * <h2>Ordinal Inscriptions</h2>
 *
 * <p>A 1sat ordinal NFT is a UTXO carrying exactly 1 satoshi with an
 * inscription envelope embedded in the locking script. The inscription
 * is a no-op ({@code OP_FALSE OP_IF ... OP_ENDIF}) that doesn't affect
 * script execution but permanently records content (image, text, JSON,
 * etc.) on-chain.
 *
 * <p>The inscription envelope is injected by the SDK's
 * {@code withInscription()} method at deployment time -- the contract
 * logic itself is just standard P2PKH.
 *
 * <h2>Script Layout</h2>
 * <pre>
 *   Unlocking: &lt;sig&gt; &lt;pubKey&gt;
 *   Locking:   OP_DUP OP_HASH160 &lt;pubKeyHash&gt; OP_EQUALVERIFY OP_CHECKSIG [inscription envelope]
 * </pre>
 */
class OrdinalNFT extends SmartContract {

    @Readonly Addr pubKeyHash;

    OrdinalNFT(Addr pubKeyHash) {
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
