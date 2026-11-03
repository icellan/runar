// F-026: `2147483648` does not fit a Java int literal (JLS 3.10.1: legal only
// as the operand of unary minus). javac refuses it ("integer number too
// large"); pre-fix the other six tiers accepted it. Every tier must refuse;
// the hand-written tokenizers say:
//   invalid Java integer literal '2147483648'
package t;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class T extends SmartContract {

    @Readonly Bigint target;

    T(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void verify(Bigint a) {
        assertThat(a.gt(Bigint.of(2147483648)));
    }
}
