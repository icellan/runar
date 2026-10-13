package frontend

// N-180: the shared call-depth limit, MAX_CALL_DEPTH = 128.
//
// A chain of private helpers verify -> m0 -> m1 -> ... -> mN is flat source
// (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 this
// tier's recursion check restarted its DFS from every method, so a
// 20000-link chain ran past 156 s of CPU.
//
// What these tests prove, on the .ts, .sol (bare `m(x)` calls) and .go
// surfaces: the chain at the limit (N=127, verify at depth 128) passes
// Validate; one past (N=128) is refused with the shared diagnostic naming
// `verify`; N=20000 is refused naming `m0`, promptly; and a cycle is still the
// recursion diagnostic, once per method that reaches it.
//
// What they do NOT prove: that the other surfaces agree, or that the accepted
// chain compiles to the TS bytes (conformance/negatives/
// n180-call-depth-parity.test.ts drives every CLI on all nine surfaces), nor
// anything about the --ir JSON path.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func n180Diag(m string) string {
	return fmt.Sprintf("call depth of method '%s' exceeds MAX_CALL_DEPTH (limit=128)", m)
}

func n180Chain(ext string, n int) []byte {
	var b strings.Builder
	switch ext {
	case "ts":
		b.WriteString("import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, " private m%d(x: bigint): bigint { return this.m%d(x); }\n", i, i+1)
		}
		fmt.Fprintf(&b, " private m%d(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n", n)
	case "sol":
		b.WriteString("pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, " function m%d(int x) private returns (int) { return m%d(x); }\n", i, i+1)
		}
		fmt.Fprintf(&b, " function m%d(int x) private returns (int) { return x; }\n function verify(int a) public { require(m0(a) == t); }\n}\n", n)
	case "go":
		b.WriteString("package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tT runar.Int `runar:\"readonly\"`\n}\n\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "func (c *P) m%d(x runar.Int) runar.Int { return c.m%d(x) }\n", i, i+1)
		}
		fmt.Fprintf(&b, "func (c *P) m%d(x runar.Int) runar.Int { return x }\nfunc (c *P) Verify(a runar.Int) { runar.Assert(c.m0(a) == c.T) }\n", n)
	}
	return []byte(b.String())
}

func n180Validate(t *testing.T, ext string, n int) *ValidationResult {
	t.Helper()
	res := ParseSource(n180Chain(ext, n), "P.runar."+ext)
	if len(res.Errors) > 0 || res.Contract == nil {
		t.Fatalf("parse: %v", res.ErrorStrings())
	}
	return Validate(res.Contract)
}

func n180Msgs(v *ValidationResult) []string {
	out := make([]string, len(v.Errors))
	for i, d := range v.Errors {
		out[i] = d.Message
	}
	return out
}

func TestN180_MaxCallDepthIs128(t *testing.T) {
	if MaxCallDepth != 128 {
		t.Fatalf("MaxCallDepth = %d, want 128 (InputLimits.MAX_CALL_DEPTH)", MaxCallDepth)
	}
}

func TestN180_ChainBoundary(t *testing.T) {
	for _, ext := range []string{"ts", "sol", "go"} {
		ext := ext
		t.Run(ext+"/at-limit", func(t *testing.T) {
			if v := n180Validate(t, ext, 127); len(v.Errors) > 0 {
				t.Fatalf("want accept, got %v", n180Msgs(v))
			}
		})
		t.Run(ext+"/one-past", func(t *testing.T) {
			v := n180Validate(t, ext, 128)
			if got := n180Msgs(v); len(got) != 1 || got[0] != n180Diag("verify") {
				t.Fatalf("want exactly [%q], got %v", n180Diag("verify"), got)
			}
		})
		t.Run(ext+"/deep-20000", func(t *testing.T) {
			start := time.Now()
			v := n180Validate(t, ext, 20000)
			if el := time.Since(start); el > 20*time.Second {
				t.Fatalf("validate took %v (quadratic call-graph walk?)", el)
			}
			got := n180Msgs(v)
			if len(got) != 1 || got[0] != n180Diag("m0") {
				t.Fatalf("want exactly [%q], got %v", n180Diag("m0"), got)
			}
		})
	}
}

func TestN180_CycleStillReportedAsRecursion(t *testing.T) {
	src := "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n" +
		" private a(x: bigint): bigint { return this.b(x); }\n" +
		" private b(x: bigint): bigint { return this.c(x); }\n" +
		" private c(x: bigint): bigint { return this.b(x); }\n" +
		" private d(x: bigint): bigint { return x; }\n" +
		" public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n"
	res := ParseSource([]byte(src), "P.runar.ts")
	if res.Contract == nil {
		t.Fatalf("parse: %v", res.ErrorStrings())
	}
	got := n180Msgs(Validate(res.Contract))
	var want []string
	for _, m := range []string{"a", "b", "c", "verify"} {
		want = append(want, fmt.Sprintf("recursion detected: method '%s' calls itself directly or indirectly", m))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("want %v, got %v", want, got)
	}
}
