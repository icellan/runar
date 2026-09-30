package runar.examples.paramshadowbrancharm;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * ParamShadowBranchArm — N-007 conformance fixture, Java port. The parameter
 * {@code count} shares the field's name; inside the {@code if} arm it is still
 * the parameter, and {@code this.count} is the field.
 */
class ParamShadowBranchArm extends StatefulSmartContract {

    Bigint count;

    ParamShadowBranchArm(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void set(Bigint count, boolean flag) {
        if (flag) {
            assertThat(count.eq(Bigint.of(5)));
        }
        this.count = count;
    }
}
