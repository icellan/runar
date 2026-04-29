package runar.examples.p384wallet;

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
import static runar.lang.Builtins.verifyECDSA_P384;

/**
 * P384Wallet -- Hybrid secp256k1 + NIST P-384 wallet.
 *
 * <h2>Security model: two-layer authentication</h2>
 * <p>This contract binds a spend to two independent keys living on
 * different elliptic curves:
 * <ol>
 *   <li>secp256k1 {@code OP_CHECKSIG} proves the signature commits to this
 *       specific transaction (via the Bitcoin sighash preimage).</li>
 *   <li>P-384 ECDSA verifies the secp256k1 signature bytes -- proving the
 *       transaction was also authorized by the P-384 (NIST / high-
 *       assurance HSM) key holder.</li>
 * </ol>
 *
 * <p>The secp256k1 signature bytes ARE the message that P-384 signs. This
 * lets a FIPS-140 validated HSM (which often speaks P-384) gate Bitcoin
 * spending without any new opcode.
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code ecdsaPubKeyHash} ({@link Addr}, readonly) -- HASH160 of the
 *       compressed secp256k1 public key (20 bytes).</li>
 *   <li>{@code p384PubKeyHash} ({@link ByteString}, readonly) -- HASH160 of
 *       the 49-byte compressed P-384 public key (20 bytes).</li>
 * </ul>
 *
 * <h2>Locking script layout</h2>
 * <pre>
 *   Unlocking: &lt;p384Sig(96B)&gt; &lt;p384PubKey(49B)&gt; &lt;ecdsaSig(~72B)&gt; &lt;ecdsaPubKey(33B)&gt;
 *
 *   Locking:
 *     // --- secp256k1 verification (P2PKH) ---
 *     OP_OVER OP_TOALTSTACK
 *     OP_DUP OP_HASH160 &lt;ecdsaPubKeyHash&gt; OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *     // --- P-384 pubkey commitment ---
 *     OP_DUP OP_HASH160 &lt;p384PubKeyHash&gt; OP_EQUALVERIFY
 *     // --- P-384 verification (~500 KB inline) ---
 *     OP_FROMALTSTACK OP_ROT OP_ROT
 *     &lt;verifyECDSA_P384 inline&gt;
 * </pre>
 *
 * <p>The compiled P-384 verifier is ~500 KB (larger than P-256's ~200 KB
 * because of 48-byte coordinates and the bigger field prime). It still
 * fits well within BSV's 32 MB stack memory limit.
 *
 * <h2>Parameter sizes</h2>
 * <ul>
 *   <li>{@code p384Sig}: 96 bytes (raw r[48] || s[48]).</li>
 *   <li>{@code p384PubKey}: 49 bytes (02/03 prefix + x[48]).</li>
 *   <li>{@code ecdsaSig}: ~72 bytes.</li>
 *   <li>{@code ecdsaPubKey}: 33 bytes.</li>
 * </ul>
 *
 * <p>Ports {@code examples/go/p384-wallet/P384Wallet.runar.go}; peer to
 * {@code P256Wallet}, {@code SPHINCSWallet}, and {@code PostQuantumWallet}.
 */
class P384Wallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString p384PubKeyHash;

    P384Wallet(Addr ecdsaPubKeyHash, ByteString p384PubKeyHash) {
        super(ecdsaPubKeyHash, p384PubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.p384PubKeyHash = p384PubKeyHash;
    }

    @Public
    void spend(ByteString p384Sig, ByteString p384PubKey, Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        assertThat(hash160(p384PubKey).equals(p384PubKeyHash));
        assertThat(verifyECDSA_P384(sig, p384Sig, p384PubKey));
    }
}
