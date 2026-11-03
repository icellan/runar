package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// F-203 (CL-BUG-208..213): .runar.py byte literals decode escapes the way
// CPython bytes literals do.
//
// Pre-fix this tier's pyByteStringToHex decoded only \xHH; every other escape
// was hex-encoded character by character, so b'\0' became 5c30 here while the
// Python tier emitted 00 and CPython (what pytest runs) has one NUL byte.
// Plain '..' strings kept their backslashes raw.
//
// The rule is the TS reference's (packages/runar-compiler/src/passes/
// 01-parse-python.ts, decodePyLiteral): b'..' decodes \\ \' \" \a \b \f \n \r
// \t \v, octal \NNN (1-3 digits, at most 0o377) and \xHH (two hex digits);
// any other escape is refused with "invalid escape sequence '<esc>'", a
// non-ASCII character with "bytes can only contain ASCII literal characters".
// Plain strings decode the same escapes and refuse \u, \U, \N.
// Every expected hex value is CPython's own b'..'.hex().
//
// What this proves: this tier's .runar.py frontend produces CPython's bytes
// for each escape and refuses each undefined or unsupported form with the
// shared diagnostic.
// What this does not prove: anything about the other tiers
// (conformance/negatives/py-bytes-escape-parity.test.ts), or that the emitted
// script carries those bytes (the parity test compares script hex).
// ---------------------------------------------------------------------------

func f203Contract(lit string) string {
	return "from runar import SmartContract, ByteString, public, assert_\n\n\n" +
		"class Esc(SmartContract):\n" +
		"    def __init__(self):\n" +
		"        super().__init__()\n\n" +
		"    @public\n" +
		"    def unlock(self, x: ByteString):\n" +
		"        assert_(x == " + lit + ")\n"
}

// f203Literal returns the right-hand ByteStringLiteral of unlock's assert.
func f203Literal(t *testing.T, r *ParseResult) string {
	t.Helper()
	if r.Contract == nil {
		t.Fatalf("no contract")
	}
	for _, m := range r.Contract.Methods {
		if m.Name != "unlock" || len(m.Body) == 0 {
			continue
		}
		es, ok := m.Body[0].(ExpressionStmt)
		if !ok {
			t.Fatalf("unexpected stmt %T", m.Body[0])
		}
		call, ok := es.Expr.(CallExpr)
		if !ok || len(call.Args) != 1 {
			t.Fatalf("unexpected expr %#v", es.Expr)
		}
		bin, ok := call.Args[0].(BinaryExpr)
		if !ok {
			t.Fatalf("unexpected arg %#v", call.Args[0])
		}
		lit, ok := bin.Right.(ByteStringLiteral)
		if !ok {
			t.Fatalf("unexpected rhs %#v", bin.Right)
		}
		return lit.Value
	}
	t.Fatalf("unlock not found")
	return ""
}

func TestF203_PyBytesEscapesDecodeLikeCPython(t *testing.T) {
	cases := []struct{ body, hex string }{
		{`\0`, "00"},
		{`\00`, "00"},
		{`\000`, "00"},
		{`\7`, "07"},
		{`\101`, "41"},
		{`\377`, "ff"},
		{`\1234`, "5334"},
		{`a\0b`, "610062"},
		{`\08`, "0038"},
		{`\n`, "0a"},
		{`\t`, "09"},
		{`\r`, "0d"},
		{`\\`, "5c"},
		{`\'`, "27"},
		{`\"`, "22"},
		{`\a`, "07"},
		{`\b`, "08"},
		{`\f`, "0c"},
		{`\v`, "0b"},
		{`\xde\xad`, "dead"},
		{`\x00\x6a`, "006a"},
		{`ab`, "6162"},
		{`\\n`, "5c6e"},
		{`x\ty\nz`, "7809790a7a"},
	}
	for _, c := range cases {
		r := ParsePython([]byte(f203Contract("b'"+c.body+"'")), "Esc.runar.py")
		if len(r.Errors) != 0 {
			t.Errorf("b'%s': unexpected errors %v", c.body, r.Errors)
			continue
		}
		if got := strings.ToLower(f203Literal(t, r)); got != c.hex {
			t.Errorf("b'%s': got %s, want %s", c.body, got, c.hex)
		}
	}

	// Both escaped quotes inside double quotes.
	r := ParsePython([]byte(f203Contract(`b"\'\""`)), "Esc.runar.py")
	if len(r.Errors) != 0 || f203Literal(t, r) != "2722" {
		t.Errorf(`b"\'\"": errors %v`, r.Errors)
	}

	// A plain hex-text string decodes CPython escapes: "\x61\x62" is "ab".
	r = ParsePython([]byte(f203Contract(`"\x61\x62"`)), "Esc.runar.py")
	if len(r.Errors) != 0 || f203Literal(t, r) != "ab" {
		t.Errorf(`"\x61\x62": errors %v`, r.Errors)
	}
}

func TestF203_PyBytesEscapeRefusals(t *testing.T) {
	if got := InvalidEscapeSequenceMsg(`\q`); got != `invalid escape sequence '\q'` {
		t.Fatalf("diagnostic text: %q", got)
	}
	if PyBytesNonASCIIMsg != "bytes can only contain ASCII literal characters" {
		t.Fatalf("diagnostic text: %q", PyBytesNonASCIIMsg)
	}
	cases := []struct{ lit, msg string }{
		{`b'\q'`, InvalidEscapeSequenceMsg(`\q`)},
		{`b'\x4'`, InvalidEscapeSequenceMsg(`\x`)},
		{`b'\xg0'`, InvalidEscapeSequenceMsg(`\x`)},
		{`b'\400'`, InvalidEscapeSequenceMsg(`\400`)},
		{`b'\N{DIGIT ONE}'`, InvalidEscapeSequenceMsg(`\N`)},
		{"b'\\u0041'", InvalidEscapeSequenceMsg(`\u`)},
		{`b'\U00000041'`, InvalidEscapeSequenceMsg(`\U`)},
		{`"\q"`, InvalidEscapeSequenceMsg(`\q`)},
		{"\"\\u0061\"", InvalidEscapeSequenceMsg(`\u`)},
		{"b'é'", PyBytesNonASCIIMsg},
	}
	for _, c := range cases {
		r := ParsePython([]byte(f203Contract(c.lit)), "Esc.runar.py")
		if f011Find(r, c.msg) == nil {
			t.Errorf("%s: want %q, got %v", c.lit, c.msg, r.Errors)
		}
	}
	// Prefix forms and a backslash-newline continuation stay refused.
	for _, lit := range []string{`rb'\n'`, `br'\n'`, `B'\n'`, "b'ab\\\ncd'"} {
		if r := ParseSource([]byte(f203Contract(lit)), "Esc.runar.py"); len(r.Errors) == 0 {
			t.Errorf("%q: accepted, want a refusal", lit)
		}
	}
}
