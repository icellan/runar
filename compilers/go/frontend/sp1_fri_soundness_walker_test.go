package frontend

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"sort"
	"testing"
)

// The SP1 FRI refusal (sp1_fri_soundness_warning.go) is only as strong as the
// walker that decides whether a contract reaches the built-in. `exprCallsSP1Fri`
// used to handle three of the fourteen declared Expression types — CallExpr,
// BinaryExpr and UnaryExpr — so ANY other expression form was a silent bypass:
// the refusal never fired and the contract compiled clean into the ~248 KB
// known-unsound verifier.
//
// Every case below is a form the REAL TypeScript frontend parser produces (they
// are compiled through ParseSource, not hand-built ASTs), so each one was a
// reachable hole rather than a theoretical one.

// sp1RefusedFromSource parses a full contract through the real frontend parser
// and reports whether Validate refused it. Validate runs before typecheck, so a
// case only has to PARSE — it does not have to typecheck — which is exactly the
// threat model: the refusal must fire before any later pass gets a say.
func sp1RefusedFromSource(t *testing.T, methodBody string) bool {
	t.Helper()
	src := fmt.Sprintf(`
import { SmartContract, ByteString, FixedArray, assert, verifySP1FRI } from 'runar-lang';

export class Bypass extends SmartContract {
  constructor() { super(); }
  public spend(proof: ByteString, pv: ByteString, vk: ByteString, flag: boolean) {
%s
  }
}
`, methodBody)
	res := ParseSource([]byte(src), "Bypass.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("fixture must parse cleanly, otherwise the case proves nothing; got %v", res.Errors)
	}
	for _, d := range Validate(res.Contract).Errors {
		if d.Severity == SeverityError && containsSubstr(d.Message, "REFUSING") {
			return true
		}
	}
	return false
}

func TestSP1FriRefusal_NotBypassableByExpressionForm(t *testing.T) {
	cases := []struct{ name, body string }{
		// CL-BUG-094's two EXECUTED bypasses. The second is the worse one: the
		// argument walk in callExprIsSP1Fri reaches the TernaryExpr and then
		// refused to descend into it.
		{"ternary/branch position", `    const ok: boolean = true ? verifySP1FRI(proof, pv, vk) : false;
    assert(ok);`},
		{"ternary/call argument", `    assert(flag ? verifySP1FRI(proof, pv, vk) : false);`},
		{"ternary/condition position", `    assert((verifySP1FRI(proof, pv, vk) ? 1n : 0n) === 1n);`},

		{"index access/index position", `    const xs: FixedArray<bigint, 2> = [1n, 2n];
    assert(xs[verifySP1FRI(proof, pv, vk)] === 1n);`},
		{"index access/object position", `    assert(verifySP1FRI(proof, pv, vk)[0n] === 1n);`},

		{"array literal/element", `    const xs: FixedArray<boolean, 2> = [verifySP1FRI(proof, pv, vk), false];
    assert(xs[0n]);`},

		{"member access/object position", `    assert(verifySP1FRI(proof, pv, vk).x === 1n);`},

		// Postfix ++/-- accept an arbitrary operand in the TS, Solidity, Move
		// and Java frontends (parser.go parsePostfix), so these are reachable,
		// not vacuous.
		{"increment/operand", `    verifySP1FRI(proof, pv, vk)++;
    assert(flag);`},
		{"decrement/operand", `    verifySP1FRI(proof, pv, vk)--;
    assert(flag);`},

		// The statement walker visited ForStmt.Condition and ForStmt.Body only.
		{"for/init", `    for (let i: bigint = verifySP1FRI(proof, pv, vk); i < 2n; i++) { assert(flag); }`},
		{"for/update", `    for (let i: bigint = 0n; i < 2n; verifySP1FRI(proof, pv, vk)++) { assert(flag); }`},

		// AssignmentStmt.Target is an Expression and was never walked.
		{"assignment/target", `    let xs: FixedArray<bigint, 2> = [1n, 2n];
    xs[verifySP1FRI(proof, pv, vk)] = 1n;
    assert(flag);`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !sp1RefusedFromSource(t, tc.body) {
				t.Fatalf("verifySP1FRI reached through %s and the compiler did NOT refuse; "+
					"this contract compiles clean into the known-unsound verifier that accepts "+
					"forged Merkle openings", tc.name)
			}
		})
	}
}

// ForStmt.Update is typed as a bare `Statement`, so it can hold an
// AssignmentStmt. No frontend produces that shape today — the TS parser routes
// the update through parseExpression, which returns nil for `i = expr` and
// substitutes a literal, and every other frontend wraps the update in an
// ExpressionStmt — so this case is built at the AST level and is deliberately
// forward-looking rather than a currently-exploitable hole. It is here because
// the walker's contract is "handle whatever Statement lands in Update", and a
// walker that only handles ExpressionStmt there would satisfy the source-level
// cases above while still being wrong.
func TestSP1FriRefusal_ForUpdateAssignment_ASTLevel(t *testing.T) {
	contract := &ContractNode{
		Name: "ForUpdateAssign",
		Methods: []MethodNode{{
			Name:       "spend",
			Visibility: "public",
			Body: []Statement{ForStmt{
				Init:      VariableDeclStmt{Name: "i", Mutable: true, Init: BigIntLiteral{Value: big.NewInt(0)}},
				Condition: BinaryExpr{Op: "<", Left: Identifier{Name: "i"}, Right: BigIntLiteral{Value: big.NewInt(2)}},
				Update: AssignmentStmt{
					Target: Identifier{Name: "i"},
					Value: CallExpr{
						Callee: Identifier{Name: "verifySP1FRI"},
						Args:   []Expression{Identifier{Name: "proof"}, Identifier{Name: "pv"}, Identifier{Name: "vk"}},
					},
				},
				Body: []Statement{},
			}},
		}},
	}
	refused := false
	for _, d := range Validate(contract).Errors {
		if containsSubstr(d.Message, "REFUSING") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("verifySP1FRI in ForStmt.Update was not refused")
	}
}

// The control that isolates the failure: the walk DOES cover private helper
// bodies, so a fix that broadens the expression walk is fixing the right thing.
// This passed before the fix and must keep passing.
func TestSP1FriRefusal_PrivateHelperControl(t *testing.T) {
	src := `
import { SmartContract, ByteString, assert, verifySP1FRI } from 'runar-lang';

export class ViaHelper extends SmartContract {
  constructor() { super(); }
  private check(proof: ByteString, pv: ByteString, vk: ByteString): boolean {
    return verifySP1FRI(proof, pv, vk);
  }
  public spend(proof: ByteString, pv: ByteString, vk: ByteString) {
    assert(this.check(proof, pv, vk));
  }
}
`
	res := ParseSource([]byte(src), "ViaHelper.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("parse: %v", res.Errors)
	}
	refused := false
	for _, d := range Validate(res.Contract).Errors {
		if containsSubstr(d.Message, "REFUSING") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the private-helper path must stay refused")
	}
}

// Negative control. Without this, `exprCallsSP1Fri` returning true
// unconditionally would satisfy every case above.
func TestSP1FriRefusal_NegativeControl_NoFalseRefusal(t *testing.T) {
	// Deliberately exercises every expression and statement form the positive
	// cases use — ternary, index, array literal, member, ++/--, for-init,
	// for-update, assignment target — with no verifySP1FRI anywhere.
	src := `
import { SmartContract, ByteString, FixedArray, assert } from 'runar-lang';

export class Clean extends SmartContract {
  constructor() { super(); }
  private helper(a: bigint): bigint {
    return a + 1n;
  }
  public spend(flag: boolean, a: bigint) {
    let xs: FixedArray<bigint, 2> = [a, a + 1n];
    const pick: bigint = flag ? 0n : 1n;
    xs[pick] = this.helper(a);
    let n: bigint = xs[0n];
    n++;
    n--;
    for (let i: bigint = this.helper(a); i < 2n; i = i + 1n) {
      n = n + i;
    }
    assert(n >= 0n);
  }
}
`
	res := ParseSource([]byte(src), "Clean.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("parse: %v", res.Errors)
	}
	v := Validate(res.Contract)
	for _, d := range append(append([]Diagnostic{}, v.Errors...), v.Warnings...) {
		if containsSubstr(d.Message, "verifySP1FRI") {
			t.Fatalf("SP1 FRI diagnostic fired for a contract that never calls the built-in: %s", d.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// Exhaustiveness
// ---------------------------------------------------------------------------
//
// Go has no compile-time exhaustiveness checking on a type switch, and a
// fail-closed `default` is not an option here: defaulting to "calls SP1 FRI"
// would refuse every contract that used a newly-added expression form. So the
// guarantee is enforced by source inspection instead — this test reads the
// declared Expression/Statement types out of ast.go and fails if any of them is
// missing from the walker's type switch. Adding a new AST node without teaching
// the walker about it breaks the build here rather than silently reopening the
// bypass.

// markerImplementers returns the type names T for which ast.go declares
// `func (T) <marker>() {}`.
func markerImplementers(t *testing.T, marker string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "ast.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ast.go: %v", err)
	}
	var names []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != marker {
			continue
		}
		if id, ok := fn.Recv.List[0].Type.(*ast.Ident); ok {
			names = append(names, id.Name)
		}
	}
	sort.Strings(names)
	return names
}

// switchCaseTypes returns the set of type names appearing as `case` types in
// the type switch inside the named function of the named file, recording
// whether the value form, the pointer form, or both appear.
func switchCaseTypes(t *testing.T, file, funcName string) map[string]struct{ value, pointer bool } {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	got := map[string]struct{ value, pointer bool }{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				switch te := e.(type) {
				case *ast.Ident:
					entry := got[te.Name]
					entry.value = true
					got[te.Name] = entry
				case *ast.StarExpr:
					if id, ok := te.X.(*ast.Ident); ok {
						entry := got[id.Name]
						entry.pointer = true
						got[id.Name] = entry
					}
				}
			}
			return true
		})
	}
	return got
}

func TestSP1FriWalker_HandlesEveryDeclaredExpressionType(t *testing.T) {
	declared := markerImplementers(t, "exprMarker")
	if len(declared) < 10 {
		t.Fatalf("expected ast.go to declare many Expression types, found %v — "+
			"the source scan is probably broken, not the walker", declared)
	}
	handled := switchCaseTypes(t, "sp1_fri_soundness_warning.go", "exprCallsSP1Fri")
	for _, name := range declared {
		e, ok := handled[name]
		if !ok {
			t.Errorf("Expression type %s is declared in ast.go but exprCallsSP1Fri does not handle it: "+
				"a contract can reach verifySP1FRI through it and the refusal will not fire", name)
			continue
		}
		if !e.value {
			t.Errorf("exprCallsSP1Fri handles *%s but not the value form %s", name, name)
		}
		if !e.pointer {
			t.Errorf("exprCallsSP1Fri handles %s but not the pointer form *%s", name, name)
		}
	}
}

func TestSP1FriWalker_HandlesEveryDeclaredStatementType(t *testing.T) {
	declared := markerImplementers(t, "stmtMarker")
	if len(declared) < 5 {
		t.Fatalf("expected ast.go to declare many Statement types, found %v", declared)
	}
	handled := switchCaseTypes(t, "sp1_fri_soundness_warning.go", "statementsCallSP1Fri")
	for _, name := range declared {
		e, ok := handled[name]
		if !ok {
			t.Errorf("Statement type %s is declared in ast.go but statementsCallSP1Fri does not handle it", name)
			continue
		}
		if !e.value || !e.pointer {
			t.Errorf("statementsCallSP1Fri must handle both %s and *%s (value=%v pointer=%v)",
				name, name, e.value, e.pointer)
		}
	}
}
