package runar.examples.ifwithoutelsemultitemp;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bin2num;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.num2bin;
import static runar.lang.Builtins.substr;

/**
 * StackTrackerReproV10min -- minimal reproducer for issue #36 in Java form.
 *
 * <p>The first {@code if (... &lt; outCount)} branch leaves {@code scriptLen},
 * {@code blobLen}, and {@code blob} as branch-private locals on the stack.
 * Without the lowerIf branch reconciliation fix, post-ENDIF cleanup
 * misindexed against {@code p} and the downstream OP_SPLIT aborted.
 * Mirrors the TS fixture in {@code examples/ts/if-without-else-multi-temp/}.
 */
class StackTrackerReproV10min extends SmartContract {

    StackTrackerReproV10min() {
        super();
    }

    @Public
    void verifyMneeTxContainsBothOutputs(
            ByteString rawTx,
            ByteString expectedMneeOutputBytes,
            ByteString expectedExtraDataOutputBytes) {
        Bigint p = Bigint.of(46);

        Bigint outCount = bin2num(cat(substr(rawTx, p, Bigint.of(1)), num2bin(Bigint.of(0), Bigint.of(1))));
        assertThat(outCount.lt(Bigint.of(253)));
        assertThat(outCount.le(Bigint.of(8)));
        p = p.plus(Bigint.ONE);

        boolean foundMnee = false;
        boolean foundExtra = false;

        if (Bigint.of(0).lt(outCount)) {
            Bigint scriptLen = bin2num(cat(substr(rawTx, p.plus(Bigint.of(8)), Bigint.of(1)), num2bin(Bigint.of(0), Bigint.of(1))));
            assertThat(scriptLen.lt(Bigint.of(253)));
            Bigint blobLen = Bigint.of(8).plus(Bigint.ONE).plus(scriptLen);
            ByteString blob = substr(rawTx, p, blobLen);
            if (blob.equals(expectedMneeOutputBytes)) { foundMnee = true; }
            if (blob.equals(expectedExtraDataOutputBytes)) { foundExtra = true; }
            p = p.plus(blobLen);
        }
        if (Bigint.ONE.lt(outCount)) {
            Bigint scriptLen = bin2num(cat(substr(rawTx, p.plus(Bigint.of(8)), Bigint.of(1)), num2bin(Bigint.of(0), Bigint.of(1))));
            assertThat(scriptLen.lt(Bigint.of(253)));
            Bigint blobLen = Bigint.of(8).plus(Bigint.ONE).plus(scriptLen);
            ByteString blob = substr(rawTx, p, blobLen);
            if (blob.equals(expectedMneeOutputBytes)) { foundMnee = true; }
            if (blob.equals(expectedExtraDataOutputBytes)) { foundExtra = true; }
            p = p.plus(blobLen);
        }

        assertThat(foundMnee);
        assertThat(foundExtra);
    }

    @Public
    void other(ByteString x) {
        assertThat(x.equals(x));
    }
}
