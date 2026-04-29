package runar.examples.postquantumwallet;

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
import static runar.lang.Builtins.verifyWOTS;

/**
 * PostQuantumWallet -- Hybrid ECDSA + WOTS+ post-quantum wallet.
 *
 * <p>Ports {@code examples/go/post-quantum-wallet/PostQuantumWallet.runar.go}
 * (the language gold-standard reference) and
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
 * only on SHA-256 collision resistance, not on any number-theoretic
 * assumption vulnerable to Shor's algorithm.
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code ecdsaPubKeyHash} ({@link Addr}, readonly) -- HASH160 of the
 *       compressed ECDSA public key (20 bytes).</li>
 *   <li>{@code wotsPubKeyHash} ({@link ByteString}, readonly) -- HASH160 of
 *       the 64-byte WOTS+ public key {@code (pubSeed[32] || pkRoot[32])},
 *       20 bytes.</li>
 * </ul>
 *
 * <h2>Locking script layout (~10 KB)</h2>
 * <pre>
 *   Unlocking: &lt;wotsSig(2144B)&gt; &lt;wotsPubKey(64B)&gt; &lt;ecdsaSig(~72B)&gt; &lt;ecdsaPubKey(33B)&gt;
 *
 *   Locking:
 *     // --- ECDSA verification (P2PKH) ---
 *     OP_OVER OP_TOALTSTACK            // copy ecdsaSig to alt stack for WOTS
 *     OP_DUP OP_HASH160 &lt;ecdsaPubKeyHash(20B)&gt; OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *     // --- WOTS+ pubkey commitment ---
 *     OP_DUP OP_HASH160 &lt;wotsPubKeyHash(20B)&gt; OP_EQUALVERIFY
 *     // --- WOTS+ verification ---
 *     OP_FROMALTSTACK OP_ROT OP_ROT    // bring ecdsaSig back as WOTS message
 *     &lt;verifyWOTS ~10KB inline&gt;
 * </pre>
 *
 * <h2>Parameter sizes</h2>
 * <ul>
 *   <li>{@code wotsSig}: 2,144 bytes (67 chains x 32 bytes).</li>
 *   <li>{@code wotsPubKey}: 64 bytes ({@code pubSeed[32] || pkRoot[32]}).</li>
 *   <li>{@code ecdsaSig}: ~72 bytes (DER-encoded ECDSA + sighash flag).</li>
 *   <li>{@code ecdsaPubKey}: 33 bytes (compressed secp256k1 public key).</li>
 * </ul>
 *
 * <p><strong>Note:</strong> WOTS+ is a one-time signature. Re-using the
 * same WOTS keypair to sign two different ECDSA-sig messages leaks
 * enough information to forge further signatures. For multi-spend wallets,
 * see the SLH-DSA-based {@link runar.examples.sphincswallet.SPHINCSWallet}
 * which uses the same hybrid pattern with a stateless many-time signature.
 */
class PostQuantumWallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString wotsPubKeyHash;

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
