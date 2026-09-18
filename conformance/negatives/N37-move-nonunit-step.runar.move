// R-102 — a NON-UNIT step in a Move `while` must be refused, not coerced.
//
// Move has no C-style `for`, so a bounded loop is an induction variable
// declared just before a `while`, and the step is the last statement of the
// body. Six of the seven tiers folded that pattern on `i = i + <anything>` and
// emitted `i++` as the update, so the loop below ran 6 times over i = 0..5
// instead of 3 times over i = 0, 2, 4 — byte-identical to the unit-step loop,
// with no diagnostic anywhere.
//
// The ANF `loop` node carries `{count, iterVar, start, step}` and synthesizes
// iteration k as `start + k*step` with step ±1. There is no slot for a
// non-unit step, so refusing is the only representable answer.
//
// The Zig tier was the outlier that already refused this, and it refused it
// through `validate.zig`'s update-clause check rather than the fold — so the
// pinned claim "all seven reject a non-unit Move step" was never true, and
// nothing measured it across tiers until this fixture.
module MoveNonUnitStep {
    use runar::types::{Int};

    struct MoveNonUnitStep {
        expected_sum: Int,
    }

    public fun verify(contract: &MoveNonUnitStep, start: Int) {
        let sum: Int = 0;
        let i: Int = 0;
        while (i < 6) {
            sum = sum + start + i;
            i = i + 2;
        };
        assert_eq!(sum, contract.expected_sum);
    }
}
