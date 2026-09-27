package runar.examples.propertyshadow;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * PropertyShadow — N-016 conformance fixture, Java port. A local that shares
 * a field's name never captures {@code this.<field>}.
 */
class PropertyShadow extends StatefulSmartContract {

    @Readonly Bigint target;
    Bigint count;

    PropertyShadow(Bigint target, Bigint count) {
        super(target, count);
        this.target = target;
        this.count = count;
    }

    @Public
    void bump(Bigint n) {
        Bigint target = n.plus(Bigint.ONE);
        assertThat(target.eq(this.target));
        Bigint count = n;
        this.count = this.count.plus(count);
        assertThat(this.count.gt(count));
    }
}
