package runar.examples.p256wallet;

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
import static runar.lang.Builtins.verifyECDSA_P256;

/**
 * P256Wallet -- Hybrid secp256k1 + NIST P-256 wallet.
 *
 * <h2>Security model: two-layer authentication</h2>
 * <p>This contract binds a spend to two independent keys living on
 * different elliptic curves:
 * <ol>
 *   <li>secp256k1 {@code OP_CHECKSIG} proves the signature commits to this
 *       specific transaction (via the Bitcoin sighash preimage).</li>
 *   <li>P-256 ECDSA verifies the secp256k1 signature bytes -- proving the
 *       transaction was also authorized by the P-256 (NIST / Web PKI) key
 *       holder.</li>
 * </ol>
 *
 * <p>The secp256k1 signature bytes ARE the message that P-256 signs. This
 * means a hardware-security-module or browser WebAuthn key (which speaks
 * P-256) can gate Bitcoin spending without any new opcode.
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code ecdsaPubKeyHash} ({@link Addr}, readonly) -- HASH160 of the
 *       compressed secp256k1 public key (20 bytes).</li>
 *   <li>{@code p256PubKeyHash} ({@link ByteString}, readonly) -- HASH160 of
 *       the 33-byte compressed P-256 public key (20 bytes).</li>
 * </ul>
 *
 * <h2>Locking script layout</h2>
 * <pre>
 *   Unlocking: &lt;p256Sig(64B)&gt; &lt;p256PubKey(33B)&gt; &lt;ecdsaSig(~72B)&gt; &lt;ecdsaPubKey(33B)&gt;
 *
 *   Locking:
 *     // --- secp256k1 verification (P2PKH) ---
 *     OP_OVER OP_TOALTSTACK
 *     OP_DUP OP_HASH160 &lt;ecdsaPubKeyHash&gt; OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *     // --- P-256 pubkey commitment ---
 *     OP_DUP OP_HASH160 &lt;p256PubKeyHash&gt; OP_EQUALVERIFY
 *     // --- P-256 verification (~200 KB inline) ---
 *     OP_FROMALTSTACK OP_ROT OP_ROT
 *     &lt;verifyECDSA_P256 inline&gt;
 * </pre>
 *
 * <h2>Parameter sizes</h2>
 * <ul>
 *   <li>{@code p256Sig}: 64 bytes (raw r[32] || s[32]).</li>
 *   <li>{@code p256PubKey}: 33 bytes (compressed P-256 public key).</li>
 *   <li>{@code ecdsaSig}: ~72 bytes (DER-encoded secp256k1 + sighash flag).</li>
 *   <li>{@code ecdsaPubKey}: 33 bytes (compressed secp256k1 public key).</li>
 * </ul>
 *
 * <p>Ports {@code examples/go/p256-wallet/P256Wallet.runar.go}; peer to
 * {@code P384Wallet}, {@code SPHINCSWallet}, and {@code PostQuantumWallet}.
 */
class P256Wallet extends SmartContract {

    @Readonly Addr ecdsaPubKeyHash;
    @Readonly ByteString p256PubKeyHash;

    P256Wallet(Addr ecdsaPubKeyHash, ByteString p256PubKeyHash) {
        super(ecdsaPubKeyHash, p256PubKeyHash);
        this.ecdsaPubKeyHash = ecdsaPubKeyHash;
        this.p256PubKeyHash = p256PubKeyHash;
    }

    @Public
    void spend(ByteString p256Sig, ByteString p256PubKey, Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(ecdsaPubKeyHash));
        assertThat(checkSig(sig, pubKey));

        assertThat(hash160(p256PubKey).equals(p256PubKeyHash));
        // The secp256k1 signature bytes are themselves the message that
        // P-256 signs — Sig extends ByteString so we pass it directly.
        assertThat(verifyECDSA_P256(sig, p256Sig, p256PubKey));
    }
}
