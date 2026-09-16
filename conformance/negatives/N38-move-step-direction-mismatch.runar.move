// R-102 — a Move `while` whose step runs AWAY from its bound must be refused.
//
// `i` starts at 0, the guard is `i < 6`, and the body decrements. The loop
// never terminates, so there is no trip count to compute and nothing to unroll.
//
// What the seven tiers did with it instead: six folded nothing (the fold
// matched `i = i + …` only) and fell through to the synthetic stub — a
// for_statement over a dummy iterator `_w = 0` — whose trip count came out of
// the dummy's start rather than `i`'s, and Zig read the comparison as
// ascending and the bound as 6 and unrolled SIX times over an `i` that never
// advances. Neither is the program. An explicit refusal is.
//
// This is the same fold hole as the dropped countdown body, entered from the
// other side: there, `while (i > 1) { ...; i = i - 1; }` was a real loop the
// fold did not recognise and silently ran zero times. Recognising the step's
// SIGN is what separates the two — it is what makes the countdown compile and
// what makes this refuse.
module MoveStepDirectionMismatch {
    use runar::types::{Int};

    struct MoveStepDirectionMismatch {
        expected_sum: Int,
    }

    public fun verify(contract: &MoveStepDirectionMismatch, start: Int) {
        let sum: Int = 0;
        let i: Int = 0;
        while (i < 6) {
            sum = sum + start + i;
            i = i - 1;
        };
        assert_eq!(sum, contract.expected_sum);
    }
}
