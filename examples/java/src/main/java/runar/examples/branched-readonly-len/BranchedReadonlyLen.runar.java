package runar.examples.branchedreadonlylen;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.len;

/**
 * BranchedReadonlyLen -- exercises a state-mutating if/else branched
 * on a read-only intrinsic value ({@code len}).
 */
class BranchedReadonlyLen extends StatefulSmartContract {

    Bigint count;
    ByteString tag;

    BranchedReadonlyLen(Bigint count, ByteString tag) {
        super(count, tag);
        this.count = count;
        this.tag = tag;
    }

    @Public
    void spend(ByteString scratch) {
        if (len(scratch).gt(Bigint.ZERO)) {
            this.count = this.count.plus(Bigint.ONE);
            this.tag = scratch;
        } else {
            this.count = this.count.minus(Bigint.ONE);
            this.tag = ByteString.fromHex("3030");
        }
        this.addOutput(1000L, this.count, this.tag);
    }
}
