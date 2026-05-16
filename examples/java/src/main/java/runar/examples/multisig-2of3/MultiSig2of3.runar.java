// MultiSig2of3 — a 2-of-3 multi-signature contract.
//
// Funds are locked to three public keys. To spend, the unlocker must supply
// two valid ECDSA signatures from any two of the committed keys. The signing
// pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
// signatures must match the order of the corresponding pubkeys in the
// committed array.
//
// checkMultiSig(new Sig[]{sig1, sig2}, new PubKey[]{this.pk1, this.pk2,
// this.pk3}) lowers to two array_literal ANF nodes — one for the signature
// array, one for the pubkey array. This is the canonical site where
// array_literal is emitted and is useful as a cross-compiler conformance
// fixture.
//
// Script layout:
//   Unlocking: <sig1> <sig2>
//   Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
//              OP_VERIFY

package runar.examples.multisig2of3;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkMultiSig;

/**
 * MultiSig2of3 -- 2-of-3 multi-signature spending condition. Cross-compiler
 * conformance fixture for the {@code array_literal} ANF node and
 * {@code OP_CHECKMULTISIG} stack-IR lowering.
 */
class MultiSig2of3 extends SmartContract {

    @Readonly PubKey pk1;
    @Readonly PubKey pk2;
    @Readonly PubKey pk3;

    MultiSig2of3(PubKey pk1, PubKey pk2, PubKey pk3) {
        super(pk1, pk2, pk3);
        this.pk1 = pk1;
        this.pk2 = pk2;
        this.pk3 = pk3;
    }

    /** Unlock requires two valid signatures from any two of the three committed pubkeys. */
    @Public
    void unlock(Sig sig1, Sig sig2) {
        assertThat(checkMultiSig(
            new Sig[]{sig1, sig2},
            new PubKey[]{this.pk1, this.pk2, this.pk3}));
    }
}
