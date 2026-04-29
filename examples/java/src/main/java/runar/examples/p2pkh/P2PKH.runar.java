package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

// Contract classes in .runar.java files are package-private so that javac
// accepts the compound .runar.java suffix (which does not match a bare
// public class name). Cross-package consumers use the typed wrappers
// emitted by the Rúnar SDK codegen (milestone 10).

/**
 * P2PKH -- Pay-to-Public-Key-Hash, the canonical Bitcoin spending pattern.
 *
 * <p>Funds are locked to {@code HASH160(pubKey)} (SHA-256 then
 * RIPEMD-160). To spend, the recipient provides their full public key and
 * a valid ECDSA signature over the transaction.
 *
 * <p>This is a stateless {@link SmartContract} -- the same logic as
 * standard Bitcoin P2PKH transactions, expressed in Rúnar.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li><strong>Hash check</strong> -- {@code hash160(pubKey)} must equal
 *       the {@code pubKeyHash} stored in the locking script, proving the
 *       provided pubkey matches the one committed to at deploy time.</li>
 *   <li><strong>Signature check</strong> -- {@code checkSig(sig, pubKey)}
 *       proves the spender holds the private key.</li>
 * </ol>
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code pubKeyHash} ({@link Addr}, readonly) -- 20-byte HASH160 of
 *       the compressed secp256k1 public key.</li>
 * </ul>
 *
 * <h2>Script layout</h2>
 * <pre>
 *   Unlocking: &lt;sig(~72B)&gt; &lt;pubKey(33B)&gt;
 *   Locking:   OP_DUP OP_HASH160 &lt;pubKeyHash(20B)&gt; OP_EQUALVERIFY OP_CHECKSIG
 * </pre>
 *
 * <p>Ports {@code examples/go/p2pkh/P2PKH.runar.go}; peer implementations
 * exist for every Rúnar frontend (TS, Sol, Move, Go, Rust, Python, Zig,
 * Ruby).
 */
class P2PKH extends SmartContract {

    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
