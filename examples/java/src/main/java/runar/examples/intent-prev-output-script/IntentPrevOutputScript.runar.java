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
 * intent intrinsic.
 *
 * It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
 * caller-supplied byte string hashes to `expectedHash` and returns it; this
 * contract then asserts the string is non-empty. The first argument is a
 * compile-time label naming the auto-injected witness parameter
 * `_prevOutScript_0`, which the unlocking script supplies. There is no vin
 * lookup, no parent transaction and no input-count check in the emitted
 * script. For a construction that binds a specific companion INPUT, see
 * `examples/ts/companion-verifier/`.
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
