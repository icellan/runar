package frontend

import (
	"fmt"
	"testing"
)

// N-056 (CL-BUG-192) — this tier parses .runar.go with go/parser, i.e. Go
// precedence; the TS reference and the other five tiers use the C ladder, so
// `a & b + 1` compiled to `(a & b) + 1` here and `a & (b + 1)` elsewhere.
// R51: every tier refuses an unparenthesised mix whose grouping differs
// between the two schemes, with the shared diagnostic from 01-parse-go.ts.
//
// The oracle recomputes the 72 ambiguous ordered operator pairs from the two
// precedence tables rather than reusing the parser's constant.
//
// Proves: the Go tier refuses every ambiguous pair with the shared text,
// accepts the 252 agreeing pairs and both parenthesisations, and treats `&^`
// as `&` and call results as operands.
// Does not prove: emitted bytes or the other tiers (conformance negatives
// N175-N179 and the agreeing-pairs control cover cross-tier agreement).

var n056GoPrec = map[string]int{
	"*": 5, "/": 5, "%": 5, "<<": 5, ">>": 5, "&": 5,
	"+": 4, "-": 4, "|": 4, "^": 4,
	"==": 3, "!=": 3, "<": 3, "<=": 3, ">": 3, ">=": 3,
	"&&": 2, "||": 1,
}

var n056CPrec = map[string]int{
	"*": 10, "/": 10, "%": 10, "+": 9, "-": 9, "<<": 8, ">>": 8,
	"<": 7, "<=": 7, ">": 7, ">=": 7, "==": 6, "!=": 6,
	"&": 5, "^": 4, "|": 3, "&&": 2, "||": 1,
}

func n056Message(x, y string) string {
	return fmt.Sprintf("ambiguous operator precedence in .runar.go: `a %s b %s c` groups differently "+
		"under Go precedence than in Rúnar's other surfaces; add parentheses", x, y)
}

func n056Errors(t *testing.T, expr string) []string {
	t.Helper()
	src := fmt.Sprintf(`package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {
	runar.SmartContract
	T runar.Int `+"`runar:\"readonly\"`"+`
}

func (c *Probe) Unlock(a runar.Int, b runar.Int, d runar.Int) {
	x := %s
	runar.Assert(x == c.T)
}
`, expr)
	result := ParseGoContract([]byte(src), "Probe.runar.go")
	var out []string
	for _, e := range result.Errors {
		out = append(out, e.Message)
	}
	return out
}

func n056ExpectRefused(t *testing.T, expr, x, y string) {
	t.Helper()
	got := n056Errors(t, expr)
	want := n056Message(x, y)
	for _, m := range got {
		if m == want {
			return
		}
	}
	t.Errorf("%s: errors %q, want the shared diagnostic %q", expr, got, want)
}

func n056ExpectAccepted(t *testing.T, expr string) {
	t.Helper()
	if got := n056Errors(t, expr); len(got) > 0 {
		t.Errorf("%s: unexpected errors %q", expr, got)
	}
}

func TestN056_GoDSL_AmbiguousPrecedencePairs(t *testing.T) {
	conflicts, agree := 0, 0
	for x := range n056GoPrec {
		for y := range n056GoPrec {
			goLeft := n056GoPrec[x] >= n056GoPrec[y]
			cLeft := n056CPrec[x] >= n056CPrec[y]
			expr := fmt.Sprintf("a %s b %s d", x, y)
			if goLeft != cLeft {
				conflicts++
				n056ExpectRefused(t, expr, x, y)
				n056ExpectAccepted(t, fmt.Sprintf("(a %s b) %s d", x, y))
				n056ExpectAccepted(t, fmt.Sprintf("a %s (b %s d)", x, y))
			} else {
				agree++
				n056ExpectAccepted(t, expr)
			}
		}
	}
	if conflicts != 72 || agree != 252 {
		t.Fatalf("derived %d conflicting / %d agreeing pairs, want 72 / 252", conflicts, agree)
	}
}

func TestN056_GoDSL_Probes(t *testing.T) {
	n056ExpectRefused(t, "a & b + 1", "&", "+")
	n056ExpectRefused(t, "a + b << 2", "+", "<<")
	n056ExpectRefused(t, "a | b + d", "|", "+")
	n056ExpectRefused(t, "a & 255 == 15", "&", "==")
	n056ExpectAccepted(t, "a ^ b * d")
	n056ExpectRefused(t, "(a & b + 1) * d", "&", "+")
	n056ExpectRefused(t, "runar.Abs(a + b << 2)", "+", "<<")
	n056ExpectRefused(t, "a * (d + (a | b + d))", "|", "+")
	n056ExpectAccepted(t, "a + b * d - a")
	n056ExpectRefused(t, "a * b + d << 1", "+", "<<")
	n056ExpectAccepted(t, "a &^ b")
	n056ExpectRefused(t, "a &^ b + d", "&", "+")
	n056ExpectAccepted(t, "(a &^ b) + d")
	n056ExpectAccepted(t, "runar.BigintBigAdd(a, b) << 2")
	n056ExpectAccepted(t, "runar.Abs(a + b) << 2")
	n056ExpectRefused(t, "-a + b << 2", "+", "<<")
	n056ExpectAccepted(t, "-(a + b) << 2")
}
