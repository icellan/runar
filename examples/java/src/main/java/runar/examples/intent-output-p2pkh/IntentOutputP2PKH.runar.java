package runar.examples.intentoutputp2pkh;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.requireOutputP2PKH;

/**
 * IntentOutputP2PKH -- exercises the {@code requireOutputP2PKH} intent
 * intrinsic. Asserts that output 0 of the spending transaction is a
 * standard P2PKH output paying exactly {@code bondAmount} satoshis to
 * {@code bondPKH}.
 */
class IntentOutputP2PKH extends StatefulSmartContract {

    @Readonly ByteString bondPKH;
    @Readonly Bigint bondAmount;
    Bigint count;

    IntentOutputP2PKH(ByteString bondPKH, Bigint bondAmount, Bigint count) {
        super(bondPKH, bondAmount, count);
        this.bondPKH = bondPKH;
        this.bondAmount = bondAmount;
        this.count = count;
    }

    @Public
    void payBond() {
        requireOutputP2PKH(0L, this.bondPKH, this.bondAmount);
        this.count = this.count.plus(Bigint.ONE);
    }
}
