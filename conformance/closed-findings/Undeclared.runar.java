// R-085 — Java undeclared bare identifiers passed type checking. The
// diagnostic must be LOCATED (file:line:col), not a silent acceptance.
// MUST NOT COMPILE.
package runar.examples.undeclared;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Undeclared extends SmartContract {
    @Readonly Bigint target;
    Undeclared(Bigint target) { super(target); this.target = target; }

    @Public
    void verify(Bigint seed) {
        assertThat(notDeclaredAnywhere.gt(this.target));
    }
}
