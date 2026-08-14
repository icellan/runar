package runar.examples.r1k1wallet;

import java.math.BigInteger;
import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkPreimage;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;
import static runar.lang.Builtins.len;
import static runar.lang.Builtins.sha256;
import static runar.lang.Builtins.substr;
import static runar.lang.Builtins.verifyECDSA_P256;

/** Hardware-backed P-256 primary spending with independent K1 recovery. */
class R1K1Wallet extends SmartContract {
    @Readonly Addr r1SaltedPubKeyHash;
    @Readonly Addr k1PubKeyHash;

    R1K1Wallet(Addr r1SaltedPubKeyHash, Addr k1PubKeyHash) {
        super(r1SaltedPubKeyHash, k1PubKeyHash);
        this.r1SaltedPubKeyHash = r1SaltedPubKeyHash;
        this.k1PubKeyHash = k1PubKeyHash;
    }

    @Public
    void spendR1(ByteString r1Sig, ByteString r1PubKey, ByteString r1Salt, SigHashPreimage txPreimage) {
        assertThat(len(r1Salt).equals(BigInteger.valueOf(32)));
        assertThat(hash160(cat(r1PubKey, r1Salt)).equals(r1SaltedPubKeyHash));
        assertThat(substr(txPreimage, len(txPreimage).minus(Bigint.of(4)).value(), Bigint.of(4).value())
            .equals(ByteString.fromHex("41000000")));
        assertThat(checkPreimage(txPreimage));
        assertThat(verifyECDSA_P256(sha256(txPreimage), r1Sig, r1PubKey));
    }

    @Public
    void recoverK1(Sig k1Sig, PubKey k1PubKey) {
        assertThat(hash160(k1PubKey).equals(k1PubKeyHash));
        assertThat(checkSig(k1Sig, k1PubKey));
    }
}
