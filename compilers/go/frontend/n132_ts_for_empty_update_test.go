package frontend

import (
	"strings"
	"testing"
)

// N-132. The Go .runar.ts parser filled an EMPTY for-header update slot
// (`for (let i = 0n; i < 3n; )`) with a `0n` placeholder expression and moved
// on, so the contract compiled (938 hexchars, byte-identical to `i++`): the
// source loop never advances `i`, the compiled loop does. The TS reference's
// parseForStatement refuses the empty slot with
// "For loop must have an update expression".
//
// Proves: the Go .runar.ts parser refuses an empty update slot with the TS
// reference's diagnostic text. Does not prove: other Go-tier surfaces, whose
// empty-update shapes are pinned by the conformance negatives N180/N181 across
// all seven tiers.
func TestN132_EmptyForUpdateIsRefused(t *testing.T) {
	res := ParseSource([]byte(n133Wrap("", "i < 6n")), "UpdateProbe.runar.ts")
	for _, e := range res.Errors {
		if strings.Contains(e.Message, "For loop must have an update expression") {
			return
		}
	}
	t.Fatalf("empty for-update was not refused with the TS diagnostic; errors: %v", res.Errors)
}
