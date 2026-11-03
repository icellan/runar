package frontend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// F-011 (CL-BUG-196): an unterminated string or byte-string literal is
// refused, never scanned onward into the lines that follow it.
//
// Pre-fix, this tier's .runar.py tokenizer scanned `b"cafe` up to the next
// matching quote, three lines down in a comment, so the guard
// `assert_(y < 5)` became literal DATA and the emitted script had no guard:
// @bsv/sdk Spend.validate accepted y = 100 against it (evidence in the F-011
// remediation log). Its Java-surface tokenizer also skipped a char literal up
// to the next single quote without a diagnostic, dropping the guard the same
// way.
//
// The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
// UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
// end of file before its closing quote is refused with exactly
// "unterminated string literal" at its opening quote; on .runar.rs and for
// Python triple-quoted strings only end of file counts; a Java char literal
// is refused with "char literals are unsupported in Rúnar Java contracts".
//
// What this proves: every hand-written surface of this tier refuses the
// conformance negatives N52-N62 with that exact text at the opening quote's
// line; the closed-literal controls, Python docstrings and a Rust string that
// spans lines are not refused for it; .runar.go (go/parser) and .runar.ts
// (tree-sitter) still refuse N63/N64 with their own parser's error.
// What this does not prove: anything about the other tiers (their suites and
// conformance/negatives/rejection-parity.test.ts), or literal forms the
// hand-written tokenizers never scanned (raw strings, heredocs, text blocks).
// ---------------------------------------------------------------------------

const f011Msg = "unterminated string literal"
const f011CharMsg = "char literals are unsupported in Rúnar Java contracts"

type f011Fixture struct {
	file   string
	line   int
	open   string
	closed string
	msg    string // "" for surfaces this tier does not hand-write
}

var f011Fixtures = []f011Fixture{
	{"N52-py-bytes-unterminated-swallow.runar.py", 22, "b\"cafe\n", "b\"cafe\"\n", f011Msg},
	{"N53-py-string-unterminated.runar.py", 13, "'cafe\n", "'cafe'\n", f011Msg},
	{"N54-py-docstring-unterminated.runar.py", 19, "follows.\n", "follows.\"\"\"\n", f011Msg},
	{"N55-sol-string-unterminated.runar.sol", 13, "\"cafe\n", "\"cafe\";\n", f011Msg},
	{"N56-move-string-unterminated.runar.move", 12, "\"cafe\n", "\"cafe\";\n", f011Msg},
	{"N57-zig-string-unterminated.runar.zig", 12, "\"cafe\n", "\"cafe\";\n", f011Msg},
	{"N58-rs-string-unterminated.runar.rs", 13, "\"cafe;\n", "\"cafe\";\n", f011Msg},
	{"N59-java-string-unterminated.runar.java", 22, "\"cafe\n", "\"cafe\");\n", f011Msg},
	{"N60-java-char-literal.runar.java", 21, "", "", f011CharMsg},
	{"N61-rb-single-quote-unterminated.runar.rb", 10, "'cafe\n", "'cafe'\n", f011Msg},
	{"N62-rb-double-quote-unterminated.runar.rb", 9, "\"cafe\n", "\"cafe\"\n", f011Msg},
	{"N63-go-string-unterminated.runar.go", 18, "\"cafe\n", "\"cafe\"\n", ""},
	{"N64-ts-string-unterminated.runar.ts", 14, "\"cafe;\n", "\"cafe\";\n", ""},
}

func f011Read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func f011Find(r *ParseResult, msg string) *Diagnostic {
	for i := range r.Errors {
		if r.Errors[i].Message == msg {
			return &r.Errors[i]
		}
	}
	return nil
}

func f011ExpectAt(t *testing.T, src, file, msg string, line int) {
	t.Helper()
	r := ParseSource([]byte(src), file)
	d := f011Find(r, msg)
	if d == nil {
		t.Fatalf("%s: want diagnostic %q, got %q", file, msg, r.ErrorStrings())
	}
	if d.Loc == nil || d.Loc.Line != line {
		t.Fatalf("%s: want %q at line %d, got loc %+v", file, msg, line, d.Loc)
	}
}

func f011ExpectNone(t *testing.T, src, file string) {
	t.Helper()
	r := ParseSource([]byte(src), file)
	if f011Find(r, f011Msg) != nil {
		t.Fatalf("%s: refused as unterminated but it is not: %q", file, r.ErrorStrings())
	}
}

func TestF011_ConformanceNegatives(t *testing.T) {
	for _, f := range f011Fixtures {
		t.Run(f.file, func(t *testing.T) {
			src := f011Read(t, f.file)
			if f.msg == "" {
				// Not hand-written in this tier: go/parser / tree-sitter must
				// still refuse it.
				if r := ParseSource([]byte(src), f.file); len(r.Errors) == 0 {
					t.Fatalf("%s: accepted", f.file)
				}
				return
			}
			f011ExpectAt(t, src, f.file, f.msg, f.line)
			if f.open != "" {
				ctl := strings.Replace(src, f.open, f.closed, 1)
				if ctl == src {
					t.Fatalf("%s: control replacement did not apply", f.file)
				}
				f011ExpectNone(t, ctl, f.file)
			}
		})
	}
}

func TestF011_Shapes(t *testing.T) {
	py := func(body string) string {
		return "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\n" +
			"class G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n" +
			"    @public\n    def unlock(self, y: Bigint):\n" + body
	}
	for _, lit := range []string{`b"ca`, `b'ca`, `"ca`, `'ca`} {
		f011ExpectAt(t, py("        t: ByteString = "+lit+"\n        assert_(y < 5)\n"), "G.runar.py", f011Msg, 10)
		f011ExpectAt(t, py("        assert_(y < 5)\n        t: ByteString = "+lit), "G.runar.py", f011Msg, 11)
	}
	f011ExpectAt(t, py("        t: ByteString = b\"ca\\\n        assert_(y < 5)\n"), "G.runar.py", f011Msg, 10)
	f011ExpectAt(t, py("        assert_(y < 5)\n        x = \"\"\"note\n"), "G.runar.py", f011Msg, 11)
	f011ExpectNone(t, py("        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n"), "G.runar.py")

	f011ExpectAt(t, "pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", "G.runar.sol", f011Msg, 3)
	f011ExpectAt(t, "module G {\n    public fun f(y: Int) {\n        let t: ByteString = b\"ca\\\n", "G.runar.move", f011Msg, 3)
	f011ExpectAt(t, "const runar = @import(\"runar", "G.runar.zig", f011Msg, 1)
	f011ExpectAt(t, "class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"\n  }\n}\n", "G.runar.java", f011Msg, 2)
	f011ExpectNone(t, "class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"fe\"); }\n}\n", "G.runar.java")
	for _, lit := range []string{"'c';", "'c", `'\''`} {
		f011ExpectAt(t, "class G extends SmartContract {\n  void f() { "+lit+"\n  }\n}\n", "G.runar.java", f011CharMsg, 2)
	}
	f011ExpectAt(t, "require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", "G.runar.rb", f011Msg, 4)
	f011ExpectNone(t, "require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", "G.runar.rb")

	rs := "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n"
	f011ExpectAt(t, rs+"        let t: ByteString = \"ca\\\"\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs", f011Msg, 9)
	f011ExpectNone(t, rs+"        let t: ByteString = \"ca\nfe\";\n        assert!(y < 5);\n    }\n}\n", "G.runar.rs")
}

// ---------------------------------------------------------------------------
// N-077: on a .runar.py source with no `class` statement at all, the Go
// tokenizer still accumulates an "unterminated string literal" diagnostic
// for an open string/byte-string literal that reaches end of file via a
// trailing backslash. Pre-fix, parsePythonSurface discarded those
// accumulated tokenizer diagnostics the moment parseContract() failed with
// "expected 'class' keyword", so only the class-keyword message reached the
// caller — matching the TS reference (packages/runar-compiler/src/passes/
// 01-parse-python.ts), which keeps a single running errors array across
// tokenize + parse and reports BOTH diagnostics for this exact input.
//
// This also covers the backslash-at-EOF shape (no trailing newline after
// the backslash) that TestF011_Shapes did not exercise: every existing
// backslash case there is followed by more source (a newline then another
// statement); here the backslash is the very last byte of the file.
//
// What this proves: for a class-less .runar.py source ending in an open
// string/byte-string literal whose last character is a backslash, this
// tier's tokenizer-level "unterminated string literal" diagnostic survives
// the subsequent class-keyword parse failure instead of being dropped.
// What this does not prove: anything about other parse-error paths out of
// parseContract (e.g. "unknown parent class"), about other tiers, or about
// a file with a `class` statement present (TestF011_ConformanceNegatives /
// TestF011_Shapes already cover that case).
// ---------------------------------------------------------------------------

func TestF011_ClassLessBackslashAtEOF(t *testing.T) {
	f011ExpectAt(t, `x = "abc\`, "x.runar.py", f011Msg, 1)
	f011ExpectAt(t, `x = b"abc\`, "x.runar.py", f011Msg, 1)
}
