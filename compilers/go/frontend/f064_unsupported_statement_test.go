package frontend

import (
	"strings"
	"testing"
)

// F-064. parseStatement's default case returned nil for every tree-sitter
// statement node it did not recognise, and parseStatements drops nil — so a
// syntactically valid `while`, `switch`, `try`, bare block, ... VANISHED from
// the method body and compilation carried on. `while (c) { assert(false) }`
// compiled to a script without the guard: a spend the source forbids.
//
// The TS reference refuses each of these with
// "Unsupported statement kind: <SyntaxKind name>"; every tier now emits that
// same diagnostic.
//
// Proves: the .runar.ts surface refuses each statement kind outside
// spec/grammar.md §9 (in a method body, nested in if/else and in a for body),
// and the diagnostic names the TS SyntaxKind. Does not prove: other Go-tier
// surfaces (.runar.go/.sol/.move/...) — those have their own dispatchers.

func f064Wrap(stmt string) string {
	return `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public unlock(x: bigint) {
    ` + stmt + `
    assert(x > this.a);
  }
}
`
}

var f064Cases = []struct{ stmt, kind string }{
	{"while (x > 0n) { assert(false); }", "WhileStatement"},
	{"do { assert(false); } while (x > 0n);", "DoStatement"},
	{"switch (x) { case 1n: assert(false); break; default: assert(false); }", "SwitchStatement"},
	{"outer: for (let i = 0n; i < 2n; i++) { assert(false); }", "LabeledStatement"},
	{"try { assert(false); } catch (e) { assert(false); }", "TryStatement"},
	{"throw x;", "ThrowStatement"},
	{"for (const k in this) { assert(false); }", "ForInStatement"},
	{"for (const k of [x]) { assert(false); }", "ForOfStatement"},
	{"{ assert(false); }", "Block"},
	{";", "EmptyStatement"},
	{"assert(x > 1n);;", "EmptyStatement"},
	{"const y = x;;", "EmptyStatement"},
	{"class Inner { }", "ClassDeclaration"},
	{"function inner(): void { assert(false); }", "FunctionDeclaration"},
	{"debugger;", "DebuggerStatement"},
	{"with (x) { assert(false); }", "WithStatement"},
	{"break;", "BreakStatement"},
	{"continue;", "ContinueStatement"},
}

func f064Has(errs []Diagnostic, kind string) bool {
	want := "Unsupported statement kind: " + kind
	for _, e := range errs {
		if strings.Contains(e.Message, want) {
			return true
		}
	}
	return false
}

func TestF064_RefusesUnsupportedStatementKinds(t *testing.T) {
	for _, c := range f064Cases {
		for _, ctx := range []struct{ name, stmt string }{
			{"top", c.stmt},
			{"if-then", "if (x > 0n) { " + c.stmt + " }"},
			{"else", "if (x > 0n) { assert(true); } else { " + c.stmt + " }"},
			{"for-body", "for (let j = 0n; j < 2n; j++) { " + c.stmt + " }"},
		} {
			t.Run(c.kind+"/"+ctx.name, func(t *testing.T) {
				res := ParseSource([]byte(f064Wrap(ctx.stmt)), "Probe.runar.ts")
				if !f064Has(res.Errors, c.kind) {
					t.Fatalf("`%s` was not refused with \"Unsupported statement kind: %s\"; errors: %v",
						ctx.stmt, c.kind, res.Errors)
				}
			})
		}
	}
}

// The punctuation and comment children of a statement_block are not
// statements and must still parse clean.
func TestF064_CommentsAndBracesStillAccepted(t *testing.T) {
	src := f064Wrap("// a comment\n    /* block */ assert(x > 0n);")
	res := ParseSource([]byte(src), "Probe.runar.ts")
	if len(res.Errors) != 0 {
		t.Fatalf("well-formed source rejected: %v", res.Errors)
	}
}

// The same drop through the OTHER nil path: a supported statement kind whose
// expression the Go parser cannot build. parseExpression returns nil for a
// sequence_expression, so `assert(x > 5n), assert(x > 6n);` vanished whole —
// both guards gone — while the TS reference refuses it ("Unsupported binary
// operator: ','"). Pre-fix the Go CLI accepted every source below (probe log
// remediation-logs/F-064/probes3). Proves: no statement-level nil is dropped
// without a diagnostic. Does not prove: that nested sub-expressions which
// parse to nil inside an otherwise-built expression are refused.
func TestF064_UnparseableExpressionStatementIsRefused(t *testing.T) {
	for _, stmt := range []string{
		"assert(x > 5n), assert(x > 6n);",
		"(assert(x > 5n), 1n);",
		"new Foo();",
		"() => 1n;",
		"x satisfies bigint;",
		"({ a: 1n });",
		"/abc/;",
		"await x;",
	} {
		res := ParseSource([]byte(f064Wrap(stmt)), "Probe.runar.ts")
		if len(res.Errors) == 0 {
			t.Errorf("`%s` was accepted with the statement silently dropped", stmt)
		}
	}
}
