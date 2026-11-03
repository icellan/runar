package frontend

// N-181: adversarial sources under MAX_SOURCE_BYTES are refused in time
// linear in their size.
//
// Two quadratic paths, both reached before any refusal:
//   - .runar.ts: tree-sitter error recovery leaves a node with ~n children
//     for n unbalanced openers, and the pre-conversion walks
//     (checkNumericLiterals, checkOptionalChaining, firstBadNode) visited
//     children with n.Child(i), which tree-sitter answers by iterating from
//     the first child: O(n) per call, O(n²) per node. 10k `[` took 1.6 s,
//     40k 25 s CPU (CLI); the 4 MiB shapes extrapolate to hours.
//   - .runar.rb / .runar.zig: the tokenizers grew string literals and
//     identifiers one byte at a time with `val += string(c)`, which copies
//     the whole string each time. An unterminated `"((((…` on .runar.rb took
//     3.1 s CPU at 160k bytes and was killed after 1042 s at 4 MiB (CLI).
//
// What this proves: each shape, filling MAX_SOURCE_BYTES, is refused with a
// parse error within a fixed CPU budget (process CPU from getrusage, polled
// while a goroutine parses, so a regression fails at the budget instead of
// running for hours). What it does NOT prove: anything about the other
// surfaces or tiers, or about the converter on a wide but VALID tree, which
// the .runar.ts refusals here never reach.

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

const n181Cap = MaxSourceBytes - 4096

// n181Budget is the CPU budget per shape. Measured on the development host
// (Apple silicon, heavily loaded): after the fix the .runar.ts shapes take
// ~12-13 s (tree-sitter plus four full-tree walks through the cgo binding,
// linear: 0.4 s at 160k openers), the .runar.rb / .runar.zig shapes ~30 ms.
// Before it, 40k `[` took 25 s and the 4 MiB .runar.rb string was killed
// after 1042 s, so the budget sits well clear of both sides.
const n181Budget = 60 * time.Second

func n181CPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func n181TS(stmt, expr string) string {
	return "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n " + stmt + "\n const r: bigint = " + expr + ";\n assert(r == this.t);\n }\n}\n"
}

func n181RB(expr string) string {
	return "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :t, Bigint\n\n  def initialize(t)\n    super(t)\n    @t = t\n  end\n\n  runar_public a: Bigint, b: Bigint\n  def verify(a, b)\n    r = " + expr + "\n    assert r == @t\n  end\nend\n"
}

func n181Zig(expr string) string {
	return "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    t: i64,\n    pub fn init(t: i64) P { return .{ .t = t }; }\n    pub fn verify(self: *const P, a: i64, b: i64) void {\n        const r = " + expr + ";\n        runar.assert(r == self.t);\n    }\n};\n"
}

func TestN181AdversarialShapesParseWithinCPUBudget(t *testing.T) {
	// malformed: the source must be refused at parse time. The 4 MiB
	// identifiers are well-formed syntax (an undefined name is a later pass's
	// diagnostic), so for them only the CPU budget is asserted.
	shapes := []struct {
		name, file, src string
		malformed       bool
	}{
		{"ts unbalanced [", "P.runar.ts", n181TS("", strings.Repeat("[", n181Cap)), true},
		{"ts unbalanced (", "P.runar.ts", n181TS("", strings.Repeat("(", n181Cap)), true},
		{"ts unbalanced {", "P.runar.ts", n181TS(strings.Repeat("{", n181Cap), "a"), true},
		{"rb unterminated \"(((", "P.runar.rb", n181RB("\"" + strings.Repeat("(", n181Cap)), true},
		{"rb 4 MiB identifier", "P.runar.rb", n181RB(strings.Repeat("a", n181Cap)), false},
		{"zig unterminated \"(((", "P.runar.zig", n181Zig("\"" + strings.Repeat("(", n181Cap)), true},
		{"zig 4 MiB identifier", "P.runar.zig", n181Zig(strings.Repeat("a", n181Cap)), false},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) { n181Check(t, s.name, s.file, s.src, s.malformed) })
	}
}

// n181Check parses src in a goroutine and fails once the process has spent
// n181Budget of CPU on it. A goroutine left running by a failure keeps
// burning CPU, so after a failure later subtests can fail too; run one with
// -run to see its own number.
func n181Check(t *testing.T, name, file, source string, malformed bool) *ParseResult {
	if len(source) > MaxSourceBytes {
		t.Fatalf("%s: %d bytes is over MAX_SOURCE_BYTES", name, len(source))
	}
	done := make(chan *ParseResult, 1)
	start := n181CPU()
	go func() { done <- ParseSource([]byte(source), file) }()
	var res *ParseResult
wait:
	for {
		select {
		case res = <-done:
			break wait
		case <-time.After(50 * time.Millisecond):
			if used := n181CPU() - start; used > n181Budget {
				t.Fatalf("%s: still parsing after %v CPU (budget %v): not linear", name, used, n181Budget)
			}
		}
	}
	used := n181CPU() - start
	t.Logf("%s: %v CPU, %d errors", name, used, len(res.Errors))
	if used > n181Budget {
		t.Fatalf("%s: %v CPU (budget %v)", name, used, n181Budget)
	}
	if malformed && len(res.Errors) == 0 {
		t.Fatalf("%s: malformed source accepted", name)
	}
	if res.SourceSizeErr != nil {
		t.Fatalf("%s: refused by the size cap, so the parser never ran", name)
	}
	return res
}

// TestN181CursorWalkMatchesChildIndexWalk pins that tsWalk visits exactly the
// nodes, in exactly the order, that the n.Child(i) stack walk it replaced did — on a valid contract and on malformed ones with ERROR and
// MISSING nodes — so the three pre-conversion checks see the same tree.
func TestN181CursorWalkMatchesChildIndexWalk(t *testing.T) {
	sources := []string{
		n181TS("", "this.t + 0x10 + 012"),
		n181TS("", "this?.t"),
		n181TS("", strings.Repeat("[", 300)),
		n181TS(strings.Repeat("{", 300), "a"),
		n181TS("", "(((a"),
		n181TS("this.t = ;", "a"),
		n181TS("", "a and b"),
	}
	describe := func(n *sitter.Node) string {
		return fmt.Sprintf("%s:%d-%d:%v:%v", n.Type(), n.StartByte(), n.EndByte(), n.IsError(), n.IsMissing())
	}
	byIndex := func(root *sitter.Node) []string {
		var out []string
		stack := []*sitter.Node{root}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			out = append(out, describe(n))
			for i := int(n.ChildCount()) - 1; i >= 0; i-- {
				stack = append(stack, n.Child(i))
			}
		}
		return out
	}
	byCursor := func(root *sitter.Node) []string {
		var out []string
		tsWalk(root, func(n *sitter.Node) bool { out = append(out, describe(n)); return true })
		return out
	}
	for i, src := range sources {
		parser := sitter.NewParser()
		parser.SetLanguage(typescript.GetLanguage())
		tree, err := parser.ParseCtx(context.Background(), nil, []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		want := byIndex(tree.RootNode())
		got := byCursor(tree.RootNode())
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("source %d: cursor walk (%d nodes) differs from Child(i) walk (%d nodes)", i, len(got), len(want))
		}
	}
}
