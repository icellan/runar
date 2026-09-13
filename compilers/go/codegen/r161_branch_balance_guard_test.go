package codegen

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// R-161 / CL-BUG-131 — the #99 branch-balance guard could not fire, and the
// padding it advertised as guarded is the mechanism that writes a placeholder
// into a taken arm.
//
// Phase 3 of lowerIf reconciles arm depths with two loops. Each adds exactly
// one slot to the SHALLOWER arm and terminates only at equality, so by the time
// control reached the panic that followed them the depths were equal by
// construction. A guard citing GitHub issue #99 that reads as protection and
// provides none.
//
// Measured before the change: across 154 contracts in examples/ and
// conformance/, instrumented phase-3 padding executed ZERO times. Both the
// padding and the guard paired with it were dead — the drop phase above them
// already balances every arm pair the corpus produces. (An `--ir` program with
// a 2-binding then-arm and a 1-binding else-arm does NOT reach it either: the
// drop phase emits OP_NIP and the arms come out level.)
//
// The check now sits inside the padding, on the one shape that is not a
// faithful reconciliation: padding a NON-EMPTY arm. Padding an empty else arm
// is the legitimate #99 fallback — the arm computed nothing, so an unnamed
// placeholder stands in for the then-arm's result. Padding an arm that DID
// compute something means the depths disagree for a reason phase 3 cannot see,
// and the empty push becomes a value the post-ENDIF code reads.
//
// This test is structural. The behavioural case cannot be constructed from
// outside the compiler today — that is the finding — so what is pinned is that
// the dead guard does not come back and the live one does not leave.

func stackSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("stack.go")
	if err != nil {
		t.Fatalf("reading stack.go: %v", err)
	}
	return string(b)
}

func TestR161_DeadPostReconciliationGuardIsGone(t *testing.T) {
	src := stackSource(t)
	// The old guard: a depth-inequality panic AFTER the reconciliation loops.
	dead := regexp.MustCompile(`if thenCtx\.sm\.depth\(\) != elseCtx\.sm\.depth\(\) \{\s*\n\s*panic\(`)
	if dead.MatchString(src) {
		t.Fatal("the post-reconciliation depth-inequality panic is back. " +
			"Phase 3's loops terminate only at equality, so it cannot fire; " +
			"a guard that cannot fire reads as protection and provides none.")
	}
}

func TestR161_PaddingItselfIsGuarded(t *testing.T) {
	src := stackSource(t)
	if !strings.Contains(src, "to balance a NON-EMPTY else arm") {
		t.Error("the else-arm padding is no longer guarded against padding a " +
			"non-empty arm — the shape that writes a placeholder the post-ENDIF " +
			"code reads as a value")
	}
	if !strings.Contains(src, "to balance a NON-EMPTY then arm") {
		t.Error("the then-arm padding is no longer guarded")
	}
}

func TestR161_TheIssue99ReferenceSurvives(t *testing.T) {
	// The issue number is the only pointer a future reader has to the history.
	// It must move WITH the guard, not stay behind on dead code.
	src := stackSource(t)
	idx := strings.Index(src, "to balance a NON-EMPTY else arm")
	if idx < 0 {
		t.Skip("guard text already asserted by the test above")
	}
	window := src[idx : idx+600]
	if !strings.Contains(window, "#99") {
		t.Error("the live guard does not cite issue #99; the reference was " +
			"left behind on the guard that was removed")
	}
}
