// GK-BUG-009 control — the case the fix must NOT break.
//
// Java lets a method name an instance field without `this.`, and the Solidity
// frontend emits the same shape. `ffbbf190` taught go/rust/python/ruby to
// resolve a bare identifier against the contract's properties precisely so
// that source like this compiles in all seven tiers. The GK-BUG-009 fix adds
// an error on the fall-through AFTER that lookup; if the lookup is removed or
// reordered, this contract stops compiling and ffbbf190 is undone.
//
// `strikePrice` is a declared property referenced with no receiver, in the
// right operand of `>` — the position whose type demand exposed the split.
// MUST COMPILE, in every tier, to the same bytes.
package runar.examples.bareprop;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class BareProp extends SmartContract {

    @Readonly Bigint strikePrice;

    BareProp(Bigint strikePrice) {
        super(strikePrice);
        this.strikePrice = strikePrice;
    }

    @Public
    void settle(Bigint price) {
        assertThat(price > strikePrice);
    }
}
