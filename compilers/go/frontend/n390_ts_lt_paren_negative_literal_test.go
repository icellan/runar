package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// N-390. tree-sitter-typescript reads `a < (-93n & -95n)` as the start of
// type arguments (`a<(-93n & -95n)>`, `-93n` being a valid literal type), so
// the Go .runar.ts parser refused a comparison whose right operand is a
// parenthesised expression made only of negative literals joined by `&`/`|`
// with "syntax error ... unparseable > near". The TS reference (the real
// TypeScript parser) and the other six tiers accept it.
//
// Proves: each shape parses with no error and yields the comparison AST the
// reference yields (operator, operand order, precedence against the
// surrounding expression), for `<` and the shapes around it. Does not prove:
// byte-identical hex against the other tiers (that is the cross-tier IR fuzz
// and the conformance runner), nor that sources with a genuine syntax error
// are repaired (the last test pins that they are still refused).
func n390Wrap(expr string) string {
	return `import { SmartContract, assert, abs } from 'runar-lang';

class C extends SmartContract {
  readonly p: bigint;
  constructor(p: bigint) { super(p); this.p = p; }
  public m(a: bigint, x: bigint, b: bigint): void {
    assert(` + expr + `);
  }
}
`
}

func n390Render(e Expression) string {
	switch v := e.(type) {
	case BinaryExpr:
		return "(" + n390Render(v.Left) + " " + v.Op + " " + n390Render(v.Right) + ")"
	case UnaryExpr:
		return v.Op + n390Render(v.Operand)
	case BigIntLiteral:
		return v.Value.String() + "n"
	case Identifier:
		return v.Name
	case PropertyAccessExpr:
		return "this." + v.Property
	case CallExpr:
		args := make([]string, len(v.Args))
		for i, a := range v.Args {
			args[i] = n390Render(a)
		}
		return n390Render(v.Callee) + "(" + strings.Join(args, ", ") + ")"
	default:
		return fmt.Sprintf("?%T", e)
	}
}

func TestN390_ComparisonWithParenthesisedNegativeLiteralRightOperand(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"((a < (-93n & -95n)) && (a <= a))", "((a < (-93n & -95n)) && (a <= a))"},
		{"a < (-93n & -95n)", "(a < (-93n & -95n))"},
		{"a < (-33836n << 7n)", "(a < (-33836n << 7n))"},
		{"abs(this.p) < (-53988n | -26372n)", "(abs(this.p) < (-53988n | -26372n))"},
		{"a < (-1n)", "(a < -1n)"},
		{"a < (-x)", "(a < -x)"},
		{"a < (- x)", "(a < -x)"},
		{"a > (-1n)", "(a > -1n)"},
		{"a <= (-1n)", "(a <= -1n)"},
		{"a >= (-1n | 2n)", "(a >= (-1n | 2n))"},
		{"a < (2n & -1n)", "(a < (2n & -1n))"},
		{"x + a < (-1n | -2n)", "((x + a) < (-1n | -2n))"},
		{"a < (-1n | -2n) + b", "(a < ((-1n | -2n) + b))"},
		{"a < (-1n & -2n) && b < (-3n | -4n)", "((a < (-1n & -2n)) && (b < (-3n | -4n)))"},
	} {
		res := ParseSource([]byte(n390Wrap(c.src)), "Probe.runar.ts")
		if len(res.Errors) > 0 {
			t.Errorf("%s: unexpected parse errors: %v", c.src, res.Errors)
			continue
		}
		stmt, ok := res.Contract.Methods[0].Body[0].(ExpressionStmt)
		if !ok {
			t.Errorf("%s: first statement is %T", c.src, res.Contract.Methods[0].Body[0])
			continue
		}
		call, ok := stmt.Expr.(CallExpr)
		if !ok || len(call.Args) != 1 {
			t.Errorf("%s: not an assert call: %T", c.src, stmt.Expr)
			continue
		}
		if got := n390Render(call.Args[0]); got != c.want {
			t.Errorf("%s: AST %s, want %s", c.src, got, c.want)
		}
	}
}

// A genuine syntax error next to the ambiguous shape stays refused: the repair
// is accepted only when the repaired source parses clean.
func TestN390_GenuineSyntaxErrorStillRefused(t *testing.T) {
	for _, src := range []string{"a < (-1n & -2n", "a < (-1n & ) && b", "a < (-1n & -2n) +"} {
		res := ParseSource([]byte(n390Wrap(src)), "Probe.runar.ts")
		if len(res.Errors) == 0 {
			t.Errorf("%s: malformed source was accepted", src)
		}
	}
}

// N-390 attempt 2. The repair inserts parentheses into the source it parses,
// so every location reported for a repaired line must be mapped back to the
// original text. The AST carries locations on statements, so a second and
// third statement on the same line stand for "a node after the repaired
// literal" (one and two repairs earlier on the line).
//
// Proves: statement columns after one and after two repairs on a line equal
// the columns of the original text. Does not prove: columns of nodes that the
// AST does not record a location for (expressions).
func TestN390_RepairedLineKeepsOriginalColumns(t *testing.T) {
	line := "    assert(a < (-1n & -2n)); assert(x === a); assert(b > (-3n | -4n)); assert(x === b);"
	src := n390Wrap2(line)
	res := ParseSource([]byte(src), "Probe.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	body := res.Contract.Methods[0].Body
	if len(body) != 4 {
		t.Fatalf("want 4 statements, got %d", len(body))
	}
	wantLine := strings.Count(src[:strings.Index(src, line)], "\n") + 1
	for i, needle := range []string{"assert(a <", "assert(x === a)", "assert(b >", "assert(x === b)"} {
		got := body[i].(ExpressionStmt).SourceLocation
		want := strings.Index(line, needle)
		if got.Column != want || got.Line != wantLine {
			t.Errorf("statement %d: got line %d col %d, want col %d (line %d)", i, got.Line, got.Column, want, wantLine)
		}
	}
}

func n390Wrap2(line string) string {
	return `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly p: bigint;
  constructor(p: bigint) { super(p); this.p = p; }
  public m(a: bigint, x: bigint, b: bigint): void {
` + line + `
  }
}
`
}

// A diagnostic raised on a repaired line, after the repaired literals, reports
// the original column (here the invalid numeric literal `012n` and the optional
// chain, both reported from tree-sitter positions).
func TestN390_DiagnosticOnRepairedLineKeepsOriginalColumn(t *testing.T) {
	line := "    assert(a < (-1n & -2n)); assert(b > (-3n | -4n) && x < 012n);"
	res := ParseSource([]byte(n390Wrap2(line)), "Probe.runar.ts")
	want := strings.Index(line, "012n")
	for _, e := range res.Errors {
		if e.Loc != nil && strings.Contains(e.Message, "012") {
			if e.Loc.Column != want {
				t.Errorf("diagnostic column %d, want %d (%s)", e.Loc.Column, want, e.Message)
			}
			return
		}
	}
	t.Fatalf("no diagnostic for the invalid literal; errors: %v", res.Errors)
}
