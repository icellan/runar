package frontend

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// F-026 (CL-BUG-198): an integer literal means what its host language says it
// means, on every surface, or it is refused.
//
// Pre-fix, this tier's hand-written tokenizers scanned decimal digits (and
// sometimes 0x) only. `0b1010` on .runar.py lexed as `0` + identifier `b1010`,
// and legacy / prefixed forms took per-tokenizer readings (`012` was 12 here
// but 10 in the Go tier's own .runar.go path). The .runar.zig parser read `0x`
// as a ByteString. With an identifier `b1010` in scope, the stray token was
// absorbed and a threshold guard compiled to `> 0`.
//
// The rule is the TS reference's (packages/runar-compiler/src/passes/int-literal.ts,
// user decision R15): the number token runs over every glued [0-9A-Za-z_]
// character and must be an integer literal of the surface's host language,
// with that language's value. The table is conformance/negatives/
// int-literal-cases.json, generated from the host toolchains. Anything else is
// refused with "invalid <Language> integer literal '<text>'". Also: .zig call
// and array-literal lists require commas, and .py refuses a second statement
// on one line.
//
// What this proves: this tier's validator reproduces every table row; every
// hand-written tokenizer, the go/parser .runar.go path and the tree-sitter
// .runar.ts path accept exactly the table's forms with its values and refuse
// the rest with the shared text. The attempt-1 exploit
// shapes read 10, and the absorbing paths are closed.
// What this does not prove: the other tiers (their suites and
// conformance/negatives), or the Solidity and Move rows themselves, which come
// from documentation.
// ---------------------------------------------------------------------------

const f026ZigComma = "expected ',' between list elements"
const f026PyLineBreak = "expected a line break between statements"

var f026Surfaces = []string{"ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"}

var f026Template = map[string]func(string) string{
	"ts":   func(l string) string { return "import { SmartContract, assert } from 'runar-lang';\n\nclass T extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(a: bigint): void {\n    assert(a > " + l + ");\n  }\n}\n" },
	"sol":  func(l string) string { return "pragma runar ^0.1.0;\n\ncontract T is SmartContract {\n    int immutable target;\n\n    constructor(int _target) {\n        target = _target;\n    }\n\n    function verify(int a) public {\n        require(a > " + l + ");\n    }\n}\n" },
	"move": func(l string) string { return "module T {\n    use runar::types::{Int};\n\n    struct T {\n        target: Int,\n    }\n\n    public fun verify(contract: &T, a: Int) {\n        assert!(a > " + l + ");\n    }\n}\n" },
	"go":   func(l string) string { return "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *T) Verify(a runar.Int) {\n\trunar.Assert(a > " + l + ")\n}\n" },
	"rs":   func(l string) string { return "use runar::prelude::*;\n\n#[runar::contract]\nstruct T {\n    #[readonly]\n    target: Int,\n}\n\nimpl T {\n    pub fn verify(&self, a: Int) {\n        assert!(a > " + l + ");\n    }\n}\n" },
	"py":   func(l string) string { return "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > " + l + ")\n" },
	"zig":  func(l string) string { return "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, a: i64) void {\n        _ = self;\n        runar.assert(a > " + l + ");\n    }\n};\n" },
	"rb":   func(l string) string { return "require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > " + l + "\n  end\nend\n" },
	"java": func(l string) string { return "package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n        assertThat(a.gt(Bigint.of(" + l + ")));\n    }\n}\n" },
}

// f026HandWritten says whether a refused literal must carry the shared text.
// Every surface does in this tier: the hand-written tokenizers, .runar.go
// (go/parser, whose number tokens are pre-checked with go/scanner) and
// .runar.ts (tree-sitter number nodes, checked before the ERROR-node refusal).
var f026HandWritten = map[string]bool{"ts": true, "go": true, "sol": true, "move": true, "rs": true, "py": true, "zig": true, "rb": true, "java": true}

func f026Cases(t *testing.T) map[string][][2]*string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "int-literal-cases.json"))
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var doc struct {
		Cases map[string][][2]*string `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	return doc.Cases
}

// f026Literals parses src and returns the bigint literals in method verify
// (source order) and the error messages.
func f026Literals(src, file string) ([]*big.Int, []string) {
	r := ParseSource([]byte(src), file)
	var errs []string
	for _, e := range r.Errors {
		if e.Severity == SeverityError {
			errs = append(errs, e.Message)
		}
	}
	var vals []*big.Int
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Interface, reflect.Ptr:
			if !v.IsNil() {
				if lit, ok := v.Interface().(BigIntLiteral); ok {
					vals = append(vals, lit.Value)
					return
				}
				if lit, ok := v.Interface().(*BigIntLiteral); ok {
					vals = append(vals, lit.Value)
					return
				}
				walk(v.Elem())
			}
		case reflect.Struct:
			if lit, ok := v.Interface().(BigIntLiteral); ok {
				vals = append(vals, lit.Value)
				return
			}
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		}
	}
	if r.Contract != nil {
		for _, m := range r.Contract.Methods {
			if m.Name == "verify" {
				walk(reflect.ValueOf(m.Body))
			}
		}
	}
	return vals, errs
}

func f026Has(errs []string, want string) bool {
	for _, e := range errs {
		if e == want || strings.HasSuffix(e, ": "+want) || strings.Contains(e, want) {
			return true
		}
	}
	return false
}

func TestF026_ValidatorReproducesHostTable(t *testing.T) {
	cases := f026Cases(t)
	if len(cases) != 9 {
		t.Fatalf("expected 9 surfaces, got %d", len(cases))
	}
	for surf, rows := range cases {
		for _, row := range rows {
			lit := *row[0]
			got := parseIntLiteral(surf, lit)
			var gotS *string
			if got != nil && !got.NegOnly {
				s := got.Value.String()
				gotS = &s
			}
			if (gotS == nil) != (row[1] == nil) || (gotS != nil && *gotS != *row[1]) {
				t.Errorf("%s %q: want %v, got %v", surf, lit, strPtr(row[1]), strPtr(gotS))
			}
		}
	}
}

func strPtr(s *string) string {
	if s == nil {
		return "refused"
	}
	return *s
}

func TestF026_EveryTokenizerAppliesTheTable(t *testing.T) {
	cases := f026Cases(t)
	for _, surf := range f026Surfaces {
		for _, row := range cases[surf] {
			lit := *row[0]
			vals, errs := f026Literals(f026Template[surf](lit), "T.runar."+surf)
			if row[1] == nil {
				if len(errs) == 0 {
					t.Errorf("%s %q: accepted as %v, want a refusal", surf, lit, vals)
				} else if f026HandWritten[surf] && !f026Has(errs, invalidIntegerLiteralMsg(surf, lit)) {
					t.Errorf("%s %q: refused without the shared diagnostic: %v", surf, lit, errs)
				}
				continue
			}
			want, _ := new(big.Int).SetString(*row[1], 10)
			if len(errs) > 0 || len(vals) != 1 || vals[0].Cmp(want) != 0 {
				t.Errorf("%s %q: want [%s], got %v %v", surf, lit, want, vals, errs)
			}
		}
	}
}

func TestF026_UnaryMinusOnlyLiterals(t *testing.T) {
	accept := []struct{ surf, src string; want string }{
		{"java", "-2147483648", "2147483648"},
		{"java", "- 9223372036854775808L", "9223372036854775808"},
		{"rs", "-128i8", "128"},
		{"rs", "-(128i8)", "128"},
		{"rs", "-9223372036854775808i64", "9223372036854775808"},
	}
	for _, c := range accept {
		vals, errs := f026Literals(f026Template[c.surf](c.src), "T.runar."+c.surf)
		if len(errs) > 0 || len(vals) != 1 || vals[0].String() != c.want {
			t.Errorf("%s %q: want [%s], got %v %v", c.surf, c.src, c.want, vals, errs)
		}
	}
	refuse := []struct{ surf, src, lit string }{
		{"java", "-(2147483648)", "2147483648"},
		{"java", "1 - 2147483648", "2147483648"},
		{"java", "2147483648", "2147483648"},
		{"java", "-9223372036854775808", "9223372036854775808"},
		{"rs", "128i8", "128i8"},
		{"rs", "1 - 128i8", "128i8"},
		{"rs", "-129i8", "129i8"},
	}
	for _, c := range refuse {
		_, errs := f026Literals(f026Template[c.surf](c.src), "T.runar."+c.surf)
		if !f026Has(errs, invalidIntegerLiteralMsg(c.surf, c.lit)) {
			t.Errorf("%s %q: want the shared refusal of %q, got %v", c.surf, c.src, c.lit, errs)
		}
	}
}

func f026Zig(params, body string) string {
	return "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, amount: i64" + params + ") void {\n        _ = self;\n" + body + "\n    }\n};\n"
}

func f026Py(params, body string) string {
	return "from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint" + params + "):\n" + body + "\n"
}

func TestF026_ExploitShapesReadTheLiteral(t *testing.T) {
	// zig: `amount > 0b1010` with a ByteString `b1010` in scope.
	vals, errs := f026Literals(f026Zig(", b1010: runar.ByteString", "        runar.assert(amount > 0b1010);"), "T.runar.zig")
	if len(errs) > 0 || len(vals) != 1 || vals[0].Int64() != 10 {
		t.Errorf("zig 0b1010 beside b1010: got %v %v", vals, errs)
	}
	// zig: an upper-case prefix beside a same-named identifier is refused.
	_, errs = f026Literals(f026Zig(", B1010: i64", "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), "T.runar.zig")
	if !f026Has(errs, invalidIntegerLiteralMsg("zig", "0B1010")) {
		t.Errorf("zig 0B1010 beside B1010: not refused: %v", errs)
	}
	// zig: a field default reads the literal.
	for _, lit := range []string{"0b1010", "0o12", "0xa"} {
		src := "const runar = @import(\"runar\");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64 = " + lit + ",\n\n    pub fn verify(self: *const T, amount: i64) void {\n        runar.assert(amount > self.target);\n    }\n};\n"
		r := ParseSource([]byte(src), "T.runar.zig")
		if len(r.Errors) > 0 || r.Contract == nil {
			t.Errorf("zig field default %s: %v", lit, r.Errors)
			continue
		}
		init, ok := r.Contract.Properties[0].Initializer.(BigIntLiteral)
		if !ok || init.Value.Int64() != 10 {
			t.Errorf("zig field default %s: initializer %#v", lit, r.Contract.Properties[0].Initializer)
		}
	}
	// py: `lim = 0b1010` with `b1010` in scope.
	vals, errs = f026Literals(f026Py(", b1010: Bigint", "        lim = 0b1010\n        assert_(amount > lim)"), "T.runar.py")
	if len(errs) > 0 || len(vals) != 1 || vals[0].Int64() != 10 {
		t.Errorf("py 0b1010 beside b1010: got %v %v", vals, errs)
	}
	// py: a class-level default reads the literal.
	for _, lit := range []string{"0o12", "0b1010"} {
		src := "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n    limit: Bigint = " + lit + "\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n"
		r := ParseSource([]byte(src), "T.runar.py")
		if len(r.Errors) > 0 || r.Contract == nil {
			t.Errorf("py class default %s: %v", lit, r.Errors)
			continue
		}
		init, ok := r.Contract.Properties[1].Initializer.(BigIntLiteral)
		if !ok || init.Value.Int64() != 10 {
			t.Errorf("py class default %s: initializer %#v", lit, r.Contract.Properties[1].Initializer)
		}
	}
	// ts (tree-sitter): `0b102` / `0o19` are refused, not read as 2 / 1.
	for _, lit := range []string{"0b102", "0o19"} {
		_, errs := f026Literals(f026Template["ts"](lit), "T.runar.ts")
		if !f026Has(errs, invalidIntegerLiteralMsg("ts", lit)) {
			t.Errorf("ts %s: not refused with the shared text: %v", lit, errs)
		}
	}
}

func TestF026_AbsorbingPaths(t *testing.T) {
	_, errs := f026Literals(f026Zig(", b: i64", "        runar.assert(runar.within(amount b, 20));"), "T.runar.zig")
	if !f026Has(errs, f026ZigComma) {
		t.Errorf("zig call without comma: %v", errs)
	}
	_, errs = f026Literals(f026Zig(", b: i64", "        runar.assert(runar.within(amount, b, 20,));"), "T.runar.zig")
	if f026Has(errs, f026ZigComma) {
		t.Errorf("zig call with trailing comma refused: %v", errs)
	}
	// (This tier has no `[_]T{...}` form, so the bracket form stands in.)
	_, errs = f026Literals(f026Zig("", "        const xs = [ 1 2, 3 ];\n        runar.assert(amount > xs[0]);"), "T.runar.zig")
	if !f026Has(errs, f026ZigComma) {
		t.Errorf("zig [...] without comma: %v", errs)
	}
	_, errs = f026Literals(f026Zig("", "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig")
	if !f026Has(errs, f026ZigComma) {
		t.Errorf("zig .{} without comma: %v", errs)
	}
	_, errs = f026Literals(f026Py(", b: Bigint", "        lim = 10 b\n        assert_(amount > lim)"), "T.runar.py")
	if !f026Has(errs, f026PyLineBreak) {
		t.Errorf("py two statements on one line: %v", errs)
	}
	_, errs = f026Literals(f026Py("", "        assert_(amount > 1) assert_(amount > 2)"), "T.runar.py")
	if !f026Has(errs, f026PyLineBreak) {
		t.Errorf("py two asserts on one line: %v", errs)
	}
	cls := "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n"
	r := ParseSource([]byte(cls), "T.runar.py")
	var msgs []string
	for _, e := range r.Errors {
		msgs = append(msgs, e.Message)
	}
	if !f026Has(msgs, f026PyLineBreak) {
		t.Errorf("py class field with trailing token: %v", msgs)
	}
	// ts: a syntax error tree-sitter recovers from is refused.
	_, errs = f026Literals(strings.Replace(f026Template["ts"]("10"), "assert(a > 10);", "assert(a > 10;", 1), "T.runar.ts")
	if len(errs) == 0 {
		t.Errorf("ts unclosed call accepted")
	}
}
