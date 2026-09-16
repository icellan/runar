package conformance

import (
	"fmt"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// The Move surface's descending `while` loop silently dropped its body.
//
// Move has no C-style `for`, so the Move frontend folds the canonical
//
//	let i: Int = K;
//	while (i < N) { ...; i = i + 1; }
//
// into the same bounded `for_statement` the TypeScript surface produces. The
// fold only ever matched `i = i + <expr>`. A DESCENDING loop — `i = i - 1` —
// missed the fold and fell through to the unfolded `while` path, which
// synthesises a for_statement over a dummy iterator `_w = 0` whose update is
// the literal `0`. Downstream `extractLoopShape` then read start = 0 (the
// dummy), inferred step = -1 from the `>` comparison, and computed
// count = start - bound = 0 - 1 = -1, clamped to 0.
//
// Trip count zero. The loop body — every assertion inside it — was dropped
// from the locking script, and the compiler exited 0 with no diagnostic. That
// is the direction that costs money: a guard that silently never runs.
//
// A hex diff cannot say that. `55007b7c9c77` is not visibly missing anything.
// These tests spend the compiled script on the go-sdk consensus interpreter
// and assert the thing that actually costs money — that an input the contract
// must reject is ACCEPTED.
//
// The compiler under test is TypeScript (one of the six tiers that produced
// the dropped body); the interpreter is the go-sdk consensus engine. The
// cross-tier half of the same defect is gated by the `countdown-loop`
// conformance fixture, which every tier must compile to byte-identical hex.
// ---------------------------------------------------------------------------

// moveGuardSource builds a stateless Move-surface contract whose single public
// method runs `assert!(x > contract.floor)` inside a bounded loop, then a
// trailing `assert!(x > 0)` OUTSIDE the loop.
//
// The trailing assert is what makes this a real oracle rather than a
// stack-shape accident: with the loop body dropped the script is still
// well-formed and still ends with a truthy value on the stack, so a
// pre-fix "accept" is a genuine consensus accept of an input the contract
// spells out that it rejects — not an artifact of an empty stack.
//
// `header` / `footer` carry the loop spelling so the descending case and the
// ascending control differ in exactly that one line.
func moveGuardSource(structName, loopInit, loopCond, loopStep string) string {
	return fmt.Sprintf(`module %[1]s {
    use runar::types::{Int};

    struct %[1]s {
        floor: Int,
    }

    public fun verify(contract: &%[1]s, x: Int) {
        let i: Int = %[2]s;
        while (%[3]s) {
            assert!(x > contract.floor, 0);
            i = %[4]s;
        };
        assert!(x > 0, 0);
    }
}
`, structName, loopInit, loopCond, loopStep)
}

// spendMoveGuard compiles the Move contract with `floor` baked in as the one
// constructor arg and spends it with `x`. Reports whether the consensus
// interpreter ACCEPTED.
func spendMoveGuard(t *testing.T, structName, loopInit, loopCond, loopStep string, floor, x int64) bool {
	t.Helper()
	src := moveGuardSource(structName, loopInit, loopCond, loopStep)
	args := fmt.Sprintf(`{"floor":"%d"}`, floor)
	lockingHex, err := compileRúnarInline(src, args, structName+".runar.move")
	if err != nil {
		t.Fatalf("compiling %s: %v", structName, err)
	}
	// One public method, so there is no method selector to push.
	return executeScript(lockingHex, encodePushBigInt(big.NewInt(x))) == nil
}

// TestMoveDescendingLoop_BodyIsNotDropped is the exploit. The contract says
// `x > 100` must hold; the loop that says so counts DOWN. Pre-fix the body was
// dropped and x = 1 spent the output.
func TestMoveDescendingLoop_BodyIsNotDropped(t *testing.T) {
	const floor = 100
	// i = 3; while (i > 0) { ...; i = i - 1; }  -> 3 iterations
	desc := func(x int64) bool {
		return spendMoveGuard(t, "MoveCountdownGuard", "3", "i > 0", "i - 1", floor, x)
	}

	if desc(1) {
		t.Fatal("DESCENDING loop body was dropped: the consensus interpreter ACCEPTED x=1 " +
			"against a contract whose loop asserts x > 100. Every assertion inside a " +
			"counting-down Move loop silently never ran.")
	}
	if !desc(200) {
		t.Fatal("descending loop rejected a valid spend (x=200 > floor=100): the loop guard " +
			"is now over-rejecting, which is a different bug from the one under test")
	}
}

// TestMoveAscendingLoop_Control is the control. The identical contract with an
// ASCENDING loop already worked, and must keep working, so a harness that
// simply rejects everything cannot pass the pair.
func TestMoveAscendingLoop_Control(t *testing.T) {
	const floor = 100
	asc := func(x int64) bool {
		return spendMoveGuard(t, "MoveAscendingGuard", "0", "i < 3", "i + 1", floor, x)
	}

	if asc(1) {
		t.Fatal("ascending loop body was dropped too: x=1 accepted against `x > 100`")
	}
	if !asc(200) {
		t.Fatal("ascending control rejected a valid spend (x=200 > floor=100) — the harness " +
			"rejects everything and proves nothing about the descending case")
	}
}

// moveCountdownSumSource sums the ITERATOR across a descending loop. Running
// the body the right number of times is not enough; the iterator has to hold
// start + n*step on iteration n. `i = 5 down to 2` sums to 14; an ascending
// `0..3` loop of the same trip count sums to 6.
func moveCountdownSumSource(structName string) string {
	return fmt.Sprintf(`module %[1]s {
    use runar::types::{Int};

    struct %[1]s {
        target: Int,
    }

    public fun verify(contract: &%[1]s, seed: Int) {
        let acc: Int = seed;
        let i: Int = 5;
        while (i > 1) {
            acc = acc + i;
            i = i - 1;
        };
        assert_eq!(acc, contract.target);
    }
}
`, structName)
}

// TestMoveCountdownLoop_IteratorValues pins the iterator VALUES, not just the
// trip count: the descending loop must sum 5+4+3+2 = 14, and must not accept
// the 0+1+2+3 = 6 an ascending loop of the same length would produce.
func TestMoveCountdownLoop_IteratorValues(t *testing.T) {
	spend := func(target, seed int64) bool {
		src := moveCountdownSumSource("MoveCountdownSum")
		lockingHex, err := compileRúnarInline(src, fmt.Sprintf(`{"target":"%d"}`, target), "MoveCountdownSum.runar.move")
		if err != nil {
			t.Fatalf("compiling MoveCountdownSum: %v", err)
		}
		return executeScript(lockingHex, encodePushBigInt(big.NewInt(seed))) == nil
	}

	if !spend(14, 0) {
		t.Fatal("descending loop did not sum its iterator to 5+4+3+2=14")
	}
	if spend(6, 0) {
		t.Fatal("descending loop accepted 0+1+2+3=6 — the iterator is ascending, or the " +
			"body ran with the wrong start/step")
	}
	if spend(0, 0) {
		t.Fatal("descending loop accepted target=0 — the body was dropped entirely " +
			"(acc stayed at seed)")
	}
}
