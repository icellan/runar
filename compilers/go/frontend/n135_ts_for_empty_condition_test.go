package frontend

import (
	"strings"
	"testing"
)

// N-135. An EMPTY for-header condition slot on .runar.ts,
// `for (let i = 3n; ; i++)`. The TS reference's parseForStatement refuses it
// with "For loop must have a condition". The Go .runar.ts parser refused it
// only incidentally: tree-sitter hands the empty slot over as an
// `empty_statement` node, which the expression parser rejected as
// "Unsupported expression kind: empty_statement".
//
// The shifted header `for (let i = 3n; ; i < 6n; i++)` is invalid TypeScript;
// tree-sitter marks it ERROR and ParseSource refuses the whole file with a
// syntax error before any statement is walked (TS also reports TypeScript
// syntax errors for it). The second case pins that refusal.
//
// Proves: the Go .runar.ts parser refuses an empty condition slot with the TS
// reference's diagnostic text, and refuses the shifted header. Does not prove:
// other Go-tier surfaces, or other tiers (pinned by the conformance negatives
// N274/N275).
func TestN135_EmptyForConditionIsRefused(t *testing.T) {
	res := ParseSource([]byte(n133Wrap("i++", "")), "UpdateProbe.runar.ts")
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e.Message, "For loop must have a condition") {
			found = true
		}
	}
	if !found {
		t.Errorf("empty for-condition was not refused with the TS diagnostic; errors: %v", res.Errors)
	}
}

func TestN135_ShiftedForHeaderIsRefused(t *testing.T) {
	res := ParseSource([]byte(n133Wrap("i < 6n; i++", "")), "UpdateProbe.runar.ts")
	if len(res.Errors) == 0 || res.Contract != nil {
		t.Fatalf("shifted for-header `;; cond; update` was not refused; errors: %v", res.Errors)
	}
}
