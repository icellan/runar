package runar.examples.currentblockheighthelperternary;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.currentBlockHeight;

/**
 * CurrentBlockHeightHelperTernary -- see CurrentBlockHeightHelperTernary.runar.ts.
 */
class CurrentBlockHeightHelperTernary extends StatefulSmartContract {

    @Readonly Bigint start;
    Bigint count;

    CurrentBlockHeightHelperTernary(Bigint start, Bigint count) {
        super(start, count);
        this.start = start;
        this.count = count;
    }

    private Bigint height() {
        return Bigint.of(currentBlockHeight());
    }

    @Public
    void spend() {
        assertThat(this.height().ge(this.start));
        Bigint h = this.count.gt(Bigint.of(5)) ? Bigint.of(currentBlockHeight()) : this.start;
        assertThat(h.ge(this.start));
        this.count = this.count.plus(Bigint.ONE);
    }
}
