package runar.examples.intentprevoutputscript;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.extractPrevOutputScript;
import static runar.lang.Builtins.len;

/**
 * IntentPrevOutputScript -- exercises the {@code extractPrevOutputScript}
 * intent intrinsic. Reads input 0's previous-output locking script via the
 * witness-bridge pattern and asserts it is non-empty after the
 * hash-equality check the intrinsic emits internally.
 */
class IntentPrevOutputScript extends StatefulSmartContract {

    @Readonly ByteString expectedHash;
    Bigint count;

    IntentPrevOutputScript(ByteString expectedHash, Bigint count) {
        super(expectedHash, count);
        this.expectedHash = expectedHash;
        this.count = count;
    }

    @Public
    void bind() {
        ByteString s = extractPrevOutputScript(0L, this.expectedHash);
        assertThat(len(s).gt(Bigint.ZERO));
        this.count = this.count.plus(Bigint.ONE);
    }
}
