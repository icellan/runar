package runar.examples.postquantumwallet;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.verifyWOTS;

/**
 * Hybrid ECDSA + WOTS+ post-quantum wallet.
 *
 * <p>Ports
 * {@code examples/python/post-quantum-wallet/PostQuantumWallet.runar.py}
 * to Java.
 *
 * <h2>Security model: two-layer authentication</h2>
 * <ol>
 *   <li>ECDSA proves the signature commits to this specific transaction
 *       (via {@code OP_CHECKSIG} over the sighash preimage).</li>
 *   <li>WOTS+ proves the ECDSA signature was authorized by the WOTS key
 *       holder -- the ECDSA signature bytes ARE the message that WOTS
 *       signs.</li>
 * </ol>
 *
 * <p>A quantum attacker who can break ECDSA could forge a valid ECDSA
 * signature, but they cannot produce a valid WOTS+ signature over their
 * forged sig without knowing the WOTS secret key. WOTS+ security relies
 * only on SHA-256 collision resistance.
 */
class PostQuantumWallet extends SmartContract {

    Addr ecdsaPubKeyHash;
    ByteString wotsPubKeyHash;

    PostQuantumWallet(Addr ecdsaPubKeyHash, ByteString wotsPubKeyHash) {
        super(ecdsaPubKeyHash, wotsPubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.wotsPubKeyHash = wotsPubKeyHash;
    }

    @Public
    void spend(ByteString wotsSig, ByteString wotsPubKey, Sig sig, PubKey pubKey) {
        // Step 1: Verify ECDSA -- proves sig commits to this transaction.
        assertThat(hash160(pubKey).equals(this.ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        // Step 2: Verify WOTS+ -- proves ECDSA sig was authorized by WOTS key holder.
        assertThat(hash160(wotsPubKey).equals(this.wotsPubKeyHash));
        // verifyWOTS(message, signature, publicKey): the ECDSA sig bytes are the message.
        assertThat(verifyWOTS(sig, wotsSig, wotsPubKey));
    }
}
