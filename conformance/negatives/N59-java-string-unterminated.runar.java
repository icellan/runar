// F-011: an unterminated .runar.java string literal that swallowed the
// assertThat on the next line in run-to-next-quote tokenizers.
// Every tier must refuse; the hand-written Java surfaces say
//   unterminated string literal
// and the Java tier (javac) reports its own unclosed-literal error.
package runar.examples.guarded;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

class Guarded extends SmartContract {
    Guarded() {
        super();
    }

    @Public
    void unlock(Bigint y) {
        ByteString tag = ByteString.fromHex("cafe
        assertThat(y.lt(Bigint.of(5)));
        // ");
        assertThat(y.ge(Bigint.ZERO));
    }
}
