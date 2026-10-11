package frontend

// F-213: the shared source-nesting limit, MAX_SOURCE_NESTING = 128.
//
// What these tests prove, for every one of the nine source surfaces:
//   - at the boundary shapes the TS reference pins (parens n=126 / 127,
//     nested-if n=126 / 127, unary `-(` n=63 / 64, `a + a + …` chain
//     k=127 / 128) this tier accepts and refuses at exactly the same place,
//     refusing with the shared diagnostic text;
//   - a deep (n=20000) source and a 500000-term chain under MAX_SOURCE_BYTES
//     are refused with the shared diagnostic, promptly, without killing the
//     process (a Go stack overflow is fatal, not a recoverable panic);
//   - measure (B) is applied by every exported per-format parser, not only by
//     the ParseSource dispatcher;
//   - an accepted at-limit program also passes Validate and TypeCheck.
//
// What they do NOT prove: that the accepted programs compile to the same hex
// as the TS reference (the F-213 boundary harness, check_tier.py, drives the
// CLI for that), nor anything about the --ir JSON path, which has its own
// nesting guard.

import (
	"fmt"
	"strings"
	"testing"
)

const f213Diag = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)"

type f213Surface struct {
	ext    string
	head   string
	assign func(e string) string
	ifWrap func(n int, inner string) string
}

func f213BraceIf(open, close string) func(int, string) string {
	return func(n int, inner string) string {
		return strings.Repeat(open, n) + inner + "\n" + strings.Repeat(close, n)
	}
}

var f213Surfaces = []f213Surface{
	{"ts", "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
		func(e string) string { return "    result = " + e + ";" }, f213BraceIf("if (mode) {\n", "}\n")},
	{"sol", "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
		func(e string) string { return "        result = " + e + ";" }, f213BraceIf("if (mode) {\n", "}\n")},
	{"move", "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
		func(e string) string { return "        result = " + e + ";" }, f213BraceIf("if (mode) {\n", "};\n")},
	{"go", "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n",
		func(e string) string { return "\tresult = " + e }, f213BraceIf("if mode {\n", "}\n")},
	{"rs", "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
		func(e string) string { return "        result = " + e + ";" }, f213BraceIf("if mode {\n", "}\n")},
	{"py", "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
		func(e string) string { return "        result = " + e },
		func(n int, inner string) string {
			var b strings.Builder
			for i := 0; i < n; i++ {
				b.WriteString("        " + strings.Repeat(" ", i) + "if mode:\n")
			}
			b.WriteString("        " + strings.Repeat(" ", n) + strings.TrimSpace(inner))
			return b.String()
		}},
	{"zig", "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n",
		func(e string) string { return "        result = " + e + ";" }, f213BraceIf("if (mode) {\n", "}\n")},
	{"rb", "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
		func(e string) string { return "    result = " + e }, f213BraceIf("if mode\n", "end\n")},
	{"java", "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
		func(e string) string { return "        result = " + e + ";" }, f213BraceIf("if (mode) {\n", "}\n")},
}

// f213Source mirrors the F-213 shape generator (remediation-logs gen.py).
func f213Source(s f213Surface, shape string, n int) []byte {
	var body string
	switch shape {
	case "parens":
		body = s.assign(strings.Repeat("(", n) + "value" + strings.Repeat(")", n))
	case "if":
		body = s.ifWrap(n, strings.TrimSpace(s.assign("value")))
	case "neg":
		body = s.assign(strings.Repeat("-(", n) + "value" + strings.Repeat(")", n))
	case "chain":
		terms := make([]string, n)
		for i := range terms {
			terms[i] = "value"
		}
		body = s.assign(strings.Join(terms, " + "))
	default:
		panic("bad shape " + shape)
	}
	return []byte(strings.Replace(s.head, "{BODY}", body, 1))
}

func f213HasDiag(res *ParseResult) bool {
	for _, d := range res.Errors {
		if d.Message == f213Diag {
			return true
		}
	}
	return false
}

func TestF213_MaxSourceNestingIs128(t *testing.T) {
	if MaxSourceNesting != 128 {
		t.Fatalf("MaxSourceNesting = %d, want 128 (InputLimits.MAX_SOURCE_NESTING)", MaxSourceNesting)
	}
	if SourceNestingMessage != f213Diag {
		t.Fatalf("SourceNestingMessage = %q, want %q", SourceNestingMessage, f213Diag)
	}
}

func TestF213_BoundaryShapes(t *testing.T) {
	cases := []struct {
		shape  string
		n      int
		accept bool
	}{
		{"parens", 126, true}, {"parens", 127, false},
		{"if", 126, true}, {"if", 127, false},
		{"neg", 63, true}, {"neg", 64, false},
		{"chain", 127, true}, {"chain", 128, false},
	}
	for _, s := range f213Surfaces {
		for _, c := range cases {
			s, c := s, c
			t.Run(fmt.Sprintf("%s/%s-%d", s.ext, c.shape, c.n), func(t *testing.T) {
				res := ParseSource(f213Source(s, c.shape, c.n), "P.runar."+s.ext)
				if c.accept {
					if len(res.Errors) > 0 || res.Contract == nil {
						t.Fatalf("want accept, got errors %v", res.ErrorStrings())
					}
					if v := Validate(res.Contract); len(v.Errors) > 0 {
						t.Fatalf("validate: %v", v.ErrorStrings())
					}
					if tc := TypeCheck(res.Contract); len(tc.Errors) > 0 {
						t.Fatalf("typecheck: %v", tc.ErrorStrings())
					}
					return
				}
				if !f213HasDiag(res) || res.Contract != nil {
					t.Fatalf("want refusal with %q, got contract=%v errors %v", f213Diag, res.Contract != nil, res.ErrorStrings())
				}
			})
		}
	}
}

func TestF213_DeepShapesRefused(t *testing.T) {
	cases := []struct {
		shape string
		n     int
	}{
		{"parens", 20000}, {"if", 20000}, {"neg", 20000}, {"chain", 20000}, {"chain", 500000},
	}
	for _, s := range f213Surfaces {
		for _, c := range cases {
			s, c := s, c
			if s.ext == "py" && c.shape == "if" {
				c.n = 2500 // 20000 levels of indentation exceed MAX_SOURCE_BYTES
			}
			t.Run(fmt.Sprintf("%s/%s-%d", s.ext, c.shape, c.n), func(t *testing.T) {
				src := f213Source(s, c.shape, c.n)
				if len(src) > MaxSourceBytes {
					t.Fatalf("probe is %d bytes, over MAX_SOURCE_BYTES", len(src))
				}
				res := ParseSource(src, "P.runar."+s.ext)
				if !f213HasDiag(res) || res.Contract != nil {
					t.Fatalf("want refusal with %q, got contract=%v errors %v", f213Diag, res.Contract != nil, res.ErrorStrings())
				}
			})
		}
	}
}

// A `.runar.ts` type annotation of ~4M `&` (`let q: &&…&Int = a;`) is a VALID
// ~4M-deep tree-sitter intersection_type chain that measure (A) does not
// count, because the converter reads a type annotation as text and never
// recurses into it. The F-026 numeric-literal walk used to recurse over the raw
// tree and died with `fatal error: stack overflow` (the F-213 refuter's
// ref_type_rs shape). This proves the parse now returns: the annotation is an
// unknown custom type, which TypeCheck refuses. A crash here kills the test
// binary rather than failing one test.
func TestF213_DeepTsIntersectionTypeDoesNotOverflow(t *testing.T) {
	head := "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n let q: "
	tail := "Int = a;\n assert(q > 0n);\n }\n}\n"
	src := []byte(head + strings.Repeat("&", MaxSourceBytes-len(head)-len(tail)) + tail)
	if len(src) > MaxSourceBytes {
		t.Fatalf("probe is %d bytes, over MAX_SOURCE_BYTES", len(src))
	}
	res := ParseSource(src, "P.runar.ts")
	if res.Contract == nil {
		if len(res.Errors) == 0 {
			t.Fatal("no contract and no diagnostic")
		}
		return
	}
	if tc := TypeCheck(res.Contract); len(tc.Errors) == 0 {
		t.Fatal("a 4M-deep intersection type annotation type-checked as valid")
	}
}

// Measure (B) must hold at every exported per-format entry point, not only
// behind the ParseSource dispatcher: a 128-term chain is within measure (A)
// (it is parsed by loops) and only (B) refuses it.
func TestF213_PerFormatEntryPointsApplyMeasureB(t *testing.T) {
	entries := map[string]func([]byte, string) *ParseResult{
		"ts": Parse, "sol": ParseSolidity, "move": ParseMove, "go": ParseGoContract,
		"rs": ParseRustMacro, "py": ParsePython, "zig": ParseZig, "rb": ParseRuby, "java": ParseJava,
	}
	for _, s := range f213Surfaces {
		res := entries[s.ext](f213Source(s, "chain", 128), "P.runar."+s.ext)
		if !f213HasDiag(res) || res.Contract != nil {
			t.Errorf("%s: want refusal with %q, got contract=%v errors %v", s.ext, f213Diag, res.Contract != nil, res.ErrorStrings())
		}
		res = entries[s.ext](f213Source(s, "chain", 127), "P.runar."+s.ext)
		if len(res.Errors) > 0 || res.Contract == nil {
			t.Errorf("%s: chain-127 want accept, got %v", s.ext, res.ErrorStrings())
		}
	}
}
