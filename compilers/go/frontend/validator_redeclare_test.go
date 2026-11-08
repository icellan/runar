package frontend

import (
	"strings"
	"testing"
)

// N-509: a local cannot be re-declared in the same scope (spec/grammar.md).
// One scope = one statement list; a method's parameters belong to its body's
// top-level list. Shadowing in a NESTED list is not a re-declaration.
// Mirrors packages/runar-compiler/src/__tests__/02-validate.test.ts (N-509).

func redeclSource(body, ctor string) string {
	if ctor == "" {
		ctor = "super(k);\n    this.k = k;"
	}
	return `
class R extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) {
    ` + ctor + `
  }
  public unlock(p: bigint, c: boolean) {
    ` + body + `
  }
}
`
}

func redeclMsg(name string) string {
	return "'" + name + "' is already declared in this scope and cannot be re-declared"
}

func redeclErrors(t *testing.T, src string) []Diagnostic {
	t.Helper()
	return Validate(mustParseTS(t, src)).Errors
}

func TestValidate_N509_RefusesSameScopeRedeclaration(t *testing.T) {
	cases := []struct{ name, body, id, ctor string }{
		{"const/const", "const a = 1n; const a = 2n; assert(a == p);", "a", ""},
		{"let/let", "let x = 1n; let x = 2n; assert(x == p);", "x", ""},
		{"const/let", "const a = 1n; let a = 2n; a = 3n; assert(a == p);", "a", ""},
		{"if branch", "if (c) { let y = 1n; let y = 2n; assert(y == p); } assert(c);", "y", ""},
		{"else branch", "if (c) { assert(c); } else { let y = 1n; let y = 2n; assert(y == p); }", "y", ""},
		{"loop body", "let s = 0n; for (let i = 0n; i < 2n; i++) { let t = i; let t = i; s = s + t; } assert(s == p);", "t", ""},
		{"method parameter", "let p = 5n; assert(p == this.k && c);", "p", ""},
		{"constructor parameter", "assert(p == this.k && c);", "k", "super(k);\n    this.k = k;\n    const k = 2n;\n    assert(k > 0n);"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			for _, d := range redeclErrors(t, redeclSource(tc.body, tc.ctor)) {
				if d.Message == redeclMsg(tc.id) {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("want exactly one %q, got %d", redeclMsg(tc.id), n)
			}
		})
	}
}

func TestValidate_N509_ReportsSecondDeclaration(t *testing.T) {
	for _, d := range redeclErrors(t, redeclSource("const a = 1n;\n    const a = 2n;\n    assert(a == p);", "")) {
		if d.Message == redeclMsg("a") {
			if d.Loc == nil || d.Loc.Line != 10 {
				t.Fatalf("want line 10, got %+v", d.Loc)
			}
			return
		}
	}
	t.Fatal("no re-declaration error")
}

func TestValidate_N509_AcceptsShadowingAndSiblings(t *testing.T) {
	cases := []struct{ name, body string }{
		{"nested if shadows local", "let x = 1n; if (c) { let x = 2n; assert(x == 2n); } assert(x == p);"},
		{"nested if shadows param", "if (c) { let p = 5n; assert(p == 5n); } assert(p == this.k);"},
		{"local named like property", "const k = 5n; assert(k == p + this.k && c);"},
		{"loop body shadows iterator", "let s = 0n; for (let i = 0n; i < 2n; i++) { let i = 7n; s = s + i; } assert(s == p && c);"},
		{"sibling branches", "if (c) { let y = 1n; assert(y == p); } else { let y = 2n; assert(y == p); }"},
		{"after the block ended", "if (c) { let y = 1n; assert(y == p); } let y = 2n; assert(y == p);"},
		{"two loops same iterator", "let s = 0n; for (let i = 0n; i < 2n; i++) { s = s + i; } for (let i = 0n; i < 3n; i++) { s = s + i; } assert(s == p && c);"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, d := range redeclErrors(t, redeclSource(tc.body, "")) {
				if strings.Contains(d.Message, "already declared") {
					t.Fatalf("unexpected: %s", d.Message)
				}
			}
		})
	}
}
