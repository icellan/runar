package runar.examples.p2blake3pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.blake3Hash;
import static runar.lang.Builtins.checkSig;

/**
 * P2Blake3PKH -- Pay-to-BLAKE3-Public-Key-Hash.
 *
 * <p>A variant of P2PKH that uses BLAKE3 (32-byte digest) instead of
 * HASH160 (20-byte SHA-256+RIPEMD-160) for the public-key commitment.
 * BLAKE3 offers a larger pre-image space and resistance to length-
 * extension attacks.
 *
 * <p>This is a stateless {@link SmartContract}.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li><strong>Hash check</strong> -- {@code blake3Hash(pubKey)} must
 *       equal the {@code pubKeyHash} stored in the locking script.</li>
 *   <li><strong>Signature check</strong> -- {@code checkSig(sig, pubKey)}
 *       proves ownership of the private key.</li>
 * </ol>
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code pubKeyHash} ({@link ByteString}, readonly) -- 32-byte
 *       BLAKE3 hash of the compressed secp256k1 public key.</li>
 * </ul>
 *
 * <h2>Script layout</h2>
 * <p>Unlike P2PKH which uses the single {@code OP_HASH160} opcode, this
 * contract inlines the BLAKE3 compression function (~7K-10K opcodes)
 * directly into the locking script.
 * <pre>
 *   Unlocking: &lt;sig(~72B)&gt; &lt;pubKey(33B)&gt;
 *   Locking:   OP_DUP &lt;blake3 compression inlined&gt; &lt;pubKeyHash(32B)&gt;
 *              OP_EQUALVERIFY OP_CHECKSIG
 * </pre>
 *
 * <p>Ports {@code examples/go/p2blake3pkh/P2Blake3PKH.runar.go}; peer
 * implementations exist for the other Rúnar frontends.
 */
class P2Blake3PKH extends SmartContract {

    @Readonly ByteString pubKeyHash;

    P2Blake3PKH(ByteString pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(blake3Hash(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
