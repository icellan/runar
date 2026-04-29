package runar.examples.sphincswallet;

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
import static runar.lang.Builtins.verifySLHDSA_SHA2_128s;

/**
 * SPHINCSWallet -- Hybrid ECDSA + SLH-DSA-SHA2-128s (SPHINCS+) post-quantum
 * wallet.
 *
 * <p>Ports {@code examples/go/sphincs-wallet/SPHINCSWallet.runar.go} (the
 * language gold-standard reference) and
 * {@code examples/python/sphincs-wallet/SPHINCSWallet.runar.py} to Java.
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
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code ecdsaPubKeyHash} ({@link Addr}, readonly) -- HASH160 of the
 *       compressed ECDSA public key (20 bytes).</li>
 *   <li>{@code slhdsaPubKeyHash} ({@link ByteString}, readonly) -- HASH160
 *       of the 32-byte SLH-DSA public key (20 bytes).</li>
 * </ul>
 *
 * <h2>Locking script layout (~200 KB)</h2>
 * <pre>
 *   Unlocking: &lt;slhdsaSig(7856B)&gt; &lt;slhdsaPubKey(32B)&gt; &lt;ecdsaSig(~72B)&gt; &lt;ecdsaPubKey(33B)&gt;
 *
 *   Locking:
 *     // --- ECDSA verification (P2PKH) ---
 *     OP_OVER OP_TOALTSTACK
 *     OP_DUP OP_HASH160 &lt;ecdsaPubKeyHash(20B)&gt; OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *     // --- SLH-DSA pubkey commitment ---
 *     OP_DUP OP_HASH160 &lt;slhdsaPubKeyHash(20B)&gt; OP_EQUALVERIFY
 *     // --- SLH-DSA verification ---
 *     OP_FROMALTSTACK OP_ROT OP_ROT
 *     &lt;verifySLHDSA ~200KB inline&gt;
 * </pre>
 *
 * <h2>Parameter sizes</h2>
 * <ul>
 *   <li>{@code slhdsaSig}: 7,856 bytes (SLH-DSA-SHA2-128s signature).</li>
 *   <li>{@code slhdsaPubKey}: 32 bytes ({@code PK.seed || PK.root}).</li>
 *   <li>{@code ecdsaSig}: ~72 bytes (DER-encoded ECDSA + sighash flag).</li>
 *   <li>{@code ecdsaPubKey}: 33 bytes (compressed secp256k1 public key).</li>
 * </ul>
 *
 * <p>Peer to {@link runar.examples.postquantumwallet.PostQuantumWallet} (WOTS+),
 * {@link runar.examples.p256wallet.P256Wallet}, and
 * {@link runar.examples.p384wallet.P384Wallet}.
 */
class SPHINCSWallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString slhdsaPubKeyHash;

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
