package runar.examples.sphincswallet;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.verifySLHDSA_SHA2_128s;

/**
 * Hybrid ECDSA + SLH-DSA-SHA2-128s (SPHINCS+) post-quantum wallet.
 *
 * <p>Ports {@code examples/python/sphincs-wallet/SPHINCSWallet.runar.py}
 * to Java.
 *
 * <h2>Security model: two-layer authentication</h2>
 * <ol>
 *   <li>ECDSA proves the signature commits to this specific transaction
 *       (via {@code OP_CHECKSIG} over the sighash preimage).</li>
 *   <li>SLH-DSA proves the ECDSA signature was authorized by the SLH-DSA
 *       key holder -- the ECDSA signature bytes ARE the message that
 *       SLH-DSA signs.</li>
 * </ol>
 *
 * <p>A quantum attacker who can break ECDSA could forge a valid ECDSA
 * signature, but they cannot produce a valid SLH-DSA signature over
 * their forged sig without knowing the SLH-DSA secret key. SLH-DSA
 * security relies only on SHA-256 collision resistance, not on any
 * number-theoretic assumption vulnerable to Shor's algorithm.
 *
 * <p>Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
 * can sign many messages -- it is NIST FIPS 205 standardized.
 */
class SPHINCSWallet extends SmartContract {

    Addr ecdsaPubKeyHash;
    ByteString slhdsaPubKeyHash;

    SPHINCSWallet(Addr ecdsaPubKeyHash, ByteString slhdsaPubKeyHash) {
        super(ecdsaPubKeyHash, slhdsaPubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.slhdsaPubKeyHash = slhdsaPubKeyHash;
    }

    @Public
    void spend(ByteString slhdsaSig, ByteString slhdsaPubKey, Sig sig, PubKey pubKey) {
        // Step 1: Verify ECDSA -- proves sig commits to this transaction.
        assertThat(hash160(pubKey).equals(this.ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        // Step 2: Verify SLH-DSA -- proves ECDSA sig was authorized by SLH-DSA key holder.
        assertThat(hash160(slhdsaPubKey).equals(this.slhdsaPubKeyHash));
        assertThat(verifySLHDSA_SHA2_128s(sig, slhdsaSig, slhdsaPubKey));
    }
}
