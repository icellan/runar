package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Java P2PKH contract
// ---------------------------------------------------------------------------

func TestParseJava_P2PKH(t *testing.T) {
	source := `
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class P2PKH extends SmartContract {

    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("expected non-nil contract")
	}

	c := result.Contract
	if c.Name != "P2PKH" {
		t.Errorf("expected contract name P2PKH, got %s", c.Name)
	}
	if c.ParentClass != "SmartContract" {
		t.Errorf("expected parentClass SmartContract, got %s", c.ParentClass)
	}
	if c.SourceFile != "P2PKH.runar.java" {
		t.Errorf("expected sourceFile P2PKH.runar.java, got %s", c.SourceFile)
	}

	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	pkh := c.Properties[0]
	if pkh.Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", pkh.Name)
	}
	if !pkh.Readonly {
		t.Errorf("expected property readonly=true")
	}
	if pt, ok := pkh.Type.(PrimitiveType); !ok || pt.Name != "Addr" {
		t.Errorf("expected Addr primitive type, got %T %+v", pkh.Type, pkh.Type)
	}

	// Constructor
	if c.Constructor.Name != "constructor" {
		t.Errorf("expected constructor name 'constructor', got %s", c.Constructor.Name)
	}
	if len(c.Constructor.Params) != 1 {
		t.Fatalf("expected 1 constructor param, got %d", len(c.Constructor.Params))
	}
	if len(c.Constructor.Body) != 2 {
		t.Fatalf("expected 2 constructor body stmts, got %d", len(c.Constructor.Body))
	}
	// stmt 0: super(pubKeyHash)
	superStmt, ok := c.Constructor.Body[0].(ExpressionStmt)
	if !ok {
		t.Fatalf("body[0] should be ExpressionStmt, got %T", c.Constructor.Body[0])
	}
	superCall, ok := superStmt.Expr.(CallExpr)
	if !ok {
		t.Fatalf("super stmt should wrap CallExpr, got %T", superStmt.Expr)
	}
	if id, ok := superCall.Callee.(Identifier); !ok || id.Name != "super" {
		t.Errorf("expected super() callee Identifier{super}, got %T %+v", superCall.Callee, superCall.Callee)
	}

	// stmt 1: this.pubKeyHash = pubKeyHash
	assignStmt, ok := c.Constructor.Body[1].(AssignmentStmt)
	if !ok {
		t.Fatalf("body[1] should be AssignmentStmt, got %T", c.Constructor.Body[1])
	}
	if pa, ok := assignStmt.Target.(PropertyAccessExpr); !ok || pa.Property != "pubKeyHash" {
		t.Errorf("expected PropertyAccessExpr{pubKeyHash}, got %T %+v", assignStmt.Target, assignStmt.Target)
	}

	// Method
	if len(c.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(c.Methods))
	}
	unlock := c.Methods[0]
	if unlock.Name != "unlock" {
		t.Errorf("expected method name unlock, got %s", unlock.Name)
	}
	if unlock.Visibility != "public" {
		t.Errorf("expected public method, got %s", unlock.Visibility)
	}
	if len(unlock.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(unlock.Params))
	}
	if pt, ok := unlock.Params[0].Type.(PrimitiveType); !ok || pt.Name != "Sig" {
		t.Errorf("expected Sig, got %+v", unlock.Params[0].Type)
	}
	if pt, ok := unlock.Params[1].Type.(PrimitiveType); !ok || pt.Name != "PubKey" {
		t.Errorf("expected PubKey, got %+v", unlock.Params[1].Type)
	}
	if len(unlock.Body) != 2 {
		t.Fatalf("expected 2 unlock body stmts, got %d", len(unlock.Body))
	}

	// First stmt: assertThat(hash160(pubKey).equals(pubKeyHash)). The peer
	// parser rewrites the static-imported `assertThat` to `assert` so the
	// shared typechecker (which only knows `assert`) accepts the call.
	first, ok := unlock.Body[0].(ExpressionStmt)
	if !ok {
		t.Fatalf("unlock body[0] should be ExpressionStmt, got %T", unlock.Body[0])
	}
	assertCall, ok := first.Expr.(CallExpr)
	if !ok {
		t.Fatalf("expected assert call, got %T", first.Expr)
	}
	if id, ok := assertCall.Callee.(Identifier); !ok || id.Name != "assert" {
		t.Errorf("expected assert callee, got %+v", assertCall.Callee)
	}
	if len(assertCall.Args) != 1 {
		t.Fatalf("expected 1 assert arg, got %d", len(assertCall.Args))
	}
	equalsCall, ok := assertCall.Args[0].(CallExpr)
	if !ok {
		t.Fatalf("expected equals call arg, got %T", assertCall.Args[0])
	}
	equalsCallee, ok := equalsCall.Callee.(MemberExpr)
	if !ok {
		t.Fatalf("expected MemberExpr callee, got %T", equalsCall.Callee)
	}
	if equalsCallee.Property != "equals" {
		t.Errorf("expected .equals, got .%s", equalsCallee.Property)
	}
	hash160Call, ok := equalsCallee.Object.(CallExpr)
	if !ok {
		t.Fatalf("expected hash160 call receiver, got %T", equalsCallee.Object)
	}
	if id, ok := hash160Call.Callee.(Identifier); !ok || id.Name != "hash160" {
		t.Errorf("expected hash160 callee, got %+v", hash160Call.Callee)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Java stateful contract without @Readonly field
// ---------------------------------------------------------------------------

func TestParseJava_StatefulCounter(t *testing.T) {
	source := `
class Counter extends StatefulSmartContract {
    Bigint count;
    Counter(Bigint count) {
        super(count);
        this.count = count;
    }
}
`
	result := ParseSource([]byte(source), "Counter.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if c.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected StatefulSmartContract, got %s", c.ParentClass)
	}
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	if c.Properties[0].Readonly {
		t.Errorf("expected count to be mutable (not readonly)")
	}
	if pt, ok := c.Properties[0].Type.(PrimitiveType); !ok || pt.Name != "bigint" {
		t.Errorf("expected bigint, got %+v", c.Properties[0].Type)
	}
}

// ---------------------------------------------------------------------------
// Test: Property initializer via BigInteger.ZERO
// ---------------------------------------------------------------------------

func TestParseJava_PropertyInitializer(t *testing.T) {
	source := `
class Counter extends StatefulSmartContract {
    BigInteger count = BigInteger.ZERO;
    @Readonly PubKey owner;
    Counter(PubKey owner) { super(owner); this.owner = owner; }
}
`
	result := ParseSource([]byte(source), "Counter.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(c.Properties))
	}
	var count *PropertyNode
	for i := range c.Properties {
		if c.Properties[i].Name == "count" {
			count = &c.Properties[i]
			break
		}
	}
	if count == nil {
		t.Fatal("count property not found")
	}
	if count.Initializer == nil {
		t.Fatal("count should carry its initializer")
	}
	lit, ok := count.Initializer.(BigIntLiteral)
	if !ok {
		t.Fatalf("expected BigIntLiteral initializer, got %T", count.Initializer)
	}
	if lit.Value.Sign() != 0 {
		t.Errorf("expected BigIntLiteral(0), got %s", lit.Value.String())
	}
}

// ---------------------------------------------------------------------------
// Test: Unknown parent class rejected
// ---------------------------------------------------------------------------

func TestParseJava_UnknownParent_Error(t *testing.T) {
	source := `
class Bad extends Frobulator { }
`
	result := ParseSource([]byte(source), "Bad.runar.java")
	if len(result.Errors) == 0 {
		t.Fatal("expected error for unknown parent class")
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "Frobulator") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error referencing Frobulator, got %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Missing extends clause rejected
// ---------------------------------------------------------------------------

func TestParseJava_MissingExtends_Error(t *testing.T) {
	source := `
class Bad { }
`
	result := ParseSource([]byte(source), "Bad.runar.java")
	if len(result.Errors) == 0 {
		t.Fatal("expected error for missing extends clause")
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "extend") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error referencing extend, got %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: ByteString.fromHex("deadbeef") → ByteStringLiteral
// ---------------------------------------------------------------------------

func TestParseJava_ByteStringFromHex(t *testing.T) {
	source := `
class C extends SmartContract {
    @Readonly ByteString magic;
    @Public void check() {
        assertThat(magic.equals(ByteString.fromHex("deadbeef")));
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(c.Methods))
	}
	stmt, ok := c.Methods[0].Body[0].(ExpressionStmt)
	if !ok {
		t.Fatalf("expected ExpressionStmt, got %T", c.Methods[0].Body[0])
	}
	assertCall, ok := stmt.Expr.(CallExpr)
	if !ok {
		t.Fatalf("expected CallExpr, got %T", stmt.Expr)
	}
	equalsCall, ok := assertCall.Args[0].(CallExpr)
	if !ok {
		t.Fatalf("expected equalsCall, got %T", assertCall.Args[0])
	}
	if len(equalsCall.Args) != 1 {
		t.Fatalf("expected 1 arg to equals(), got %d", len(equalsCall.Args))
	}
	lit, ok := equalsCall.Args[0].(ByteStringLiteral)
	if !ok {
		t.Fatalf("expected ByteStringLiteral, got %T", equalsCall.Args[0])
	}
	if lit.Value != "deadbeef" {
		t.Errorf("expected deadbeef, got %q", lit.Value)
	}
}

// ---------------------------------------------------------------------------
// Test: BigInteger.valueOf(7) → BigIntLiteral(7)
// ---------------------------------------------------------------------------

func TestParseJava_BigIntegerValueOfLiteral(t *testing.T) {
	source := `
class C extends SmartContract {
    @Readonly Bigint threshold;
    @Public void check(Bigint x) {
        assertThat(x == BigInteger.valueOf(7));
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	stmt, ok := c.Methods[0].Body[0].(ExpressionStmt)
	if !ok {
		t.Fatalf("expected ExpressionStmt, got %T", c.Methods[0].Body[0])
	}
	assertCall, ok := stmt.Expr.(CallExpr)
	if !ok {
		t.Fatalf("expected CallExpr, got %T", stmt.Expr)
	}
	cmp, ok := assertCall.Args[0].(BinaryExpr)
	if !ok {
		t.Fatalf("expected BinaryExpr arg, got %T", assertCall.Args[0])
	}
	// Java's == maps to === in the AST — same convention as every other parser.
	if cmp.Op != "===" {
		t.Errorf("expected Op ===, got %q", cmp.Op)
	}
	if id, ok := cmp.Left.(Identifier); !ok || id.Name != "x" {
		t.Errorf("expected LHS Identifier{x}, got %+v", cmp.Left)
	}
	lit, ok := cmp.Right.(BigIntLiteral)
	if !ok {
		t.Fatalf("expected RHS BigIntLiteral (not CallExpr), got %T", cmp.Right)
	}
	if lit.Value.Int64() != 7 {
		t.Errorf("expected BigIntLiteral(7), got %s", lit.Value.String())
	}
}

// ---------------------------------------------------------------------------
// Test: Static-imported identifier resolves as a free call
// ---------------------------------------------------------------------------

func TestParseJava_StaticImportedCall(t *testing.T) {
	source := `
import static runar.lang.Builtins.hash160;

class C extends SmartContract {
    @Readonly Addr h;
    @Public void check(PubKey pk) {
        assertThat(hash160(pk).equals(h));
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	stmt, _ := c.Methods[0].Body[0].(ExpressionStmt)
	assertCall, _ := stmt.Expr.(CallExpr)
	equalsCall, _ := assertCall.Args[0].(CallExpr)
	equalsCallee, _ := equalsCall.Callee.(MemberExpr)
	hash160Call, ok := equalsCallee.Object.(CallExpr)
	if !ok {
		t.Fatalf("expected hash160 call, got %T", equalsCallee.Object)
	}
	// Key assertion: static-imported hash160 resolves as a bare Identifier
	// call (like every other parser does), not a MemberExpr call.
	id, ok := hash160Call.Callee.(Identifier)
	if !ok {
		t.Fatalf("expected Identifier callee for static-imported call, got %T", hash160Call.Callee)
	}
	if id.Name != "hash160" {
		t.Errorf("expected hash160, got %s", id.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Binary operator mapping
// ---------------------------------------------------------------------------

func TestParseJava_BinaryOperatorMapping(t *testing.T) {
	// Every Java operator the spec requires us to handle, wrapped in a
	// single method body. The ASCII order of operators below follows a
	// bottom-up evaluation so each assertion gets its own statement.
	source := `
class C extends SmartContract {
    @Public void run(Bigint a, Bigint b) {
        assertThat(a + b == b + a);
        assertThat(a - b != b - a);
        assertThat(a * b == b * a);
        assertThat(a / b == a / b);
        assertThat(a % b == a % b);
        assertThat(a < b);
        assertThat(a <= b);
        assertThat(a > b);
        assertThat(a >= b);
        assertThat((a & b) == (b & a));
        assertThat((a | b) == (b | a));
        assertThat((a ^ b) == (b ^ a));
        assertThat((a << 1) != 0);
        assertThat((a >> 1) != 0);
        assertThat(true && false);
        assertThat(true || false);
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	body := c.Methods[0].Body
	if len(body) != 16 {
		t.Fatalf("expected 16 assert stmts, got %d", len(body))
	}

	// Helpers to extract the outermost BinaryExpr from an
	// `assertThat(<binExpr>)` statement. Some statements wrap in a
	// comparison — peel one level.
	outerBinOp := func(stmt Statement) string {
		es, ok := stmt.(ExpressionStmt)
		if !ok {
			return ""
		}
		call, ok := es.Expr.(CallExpr)
		if !ok || len(call.Args) == 0 {
			return ""
		}
		if be, ok := call.Args[0].(BinaryExpr); ok {
			return be.Op
		}
		return ""
	}

	// Peel the equality wrapper off statements that were framed as
	// `assertThat((a OP b) == (b OP a))`.
	innerArithOp := func(stmt Statement) string {
		es, ok := stmt.(ExpressionStmt)
		if !ok {
			return ""
		}
		call, ok := es.Expr.(CallExpr)
		if !ok || len(call.Args) == 0 {
			return ""
		}
		eq, ok := call.Args[0].(BinaryExpr)
		if !ok {
			return ""
		}
		left, ok := eq.Left.(BinaryExpr)
		if !ok {
			return ""
		}
		return left.Op
	}

	// a + b == b + a
	if op := innerArithOp(body[0]); op != "+" {
		t.Errorf("stmt 0 inner op: expected +, got %q", op)
	}
	// a - b != b - a
	if op := innerArithOp(body[1]); op != "-" {
		t.Errorf("stmt 1 inner op: expected -, got %q", op)
	}
	// a * b ==
	if op := innerArithOp(body[2]); op != "*" {
		t.Errorf("stmt 2 inner op: expected *, got %q", op)
	}
	// a / b ==
	if op := innerArithOp(body[3]); op != "/" {
		t.Errorf("stmt 3 inner op: expected /, got %q", op)
	}
	// a % b ==
	if op := innerArithOp(body[4]); op != "%" {
		t.Errorf("stmt 4 inner op: expected %%, got %q", op)
	}
	// comparisons
	if op := outerBinOp(body[5]); op != "<" {
		t.Errorf("stmt 5: expected <, got %q", op)
	}
	if op := outerBinOp(body[6]); op != "<=" {
		t.Errorf("stmt 6: expected <=, got %q", op)
	}
	if op := outerBinOp(body[7]); op != ">" {
		t.Errorf("stmt 7: expected >, got %q", op)
	}
	if op := outerBinOp(body[8]); op != ">=" {
		t.Errorf("stmt 8: expected >=, got %q", op)
	}
	// bitwise
	if op := innerArithOp(body[9]); op != "&" {
		t.Errorf("stmt 9 inner op: expected &, got %q", op)
	}
	if op := innerArithOp(body[10]); op != "|" {
		t.Errorf("stmt 10 inner op: expected |, got %q", op)
	}
	if op := innerArithOp(body[11]); op != "^" {
		t.Errorf("stmt 11 inner op: expected ^, got %q", op)
	}
	if op := innerArithOp(body[12]); op != "<<" {
		t.Errorf("stmt 12 inner op: expected <<, got %q", op)
	}
	if op := innerArithOp(body[13]); op != ">>" {
		t.Errorf("stmt 13 inner op: expected >>, got %q", op)
	}
	// logical — Java's && maps to the AST '&&'
	if op := outerBinOp(body[14]); op != "&&" {
		t.Errorf("stmt 14: expected &&, got %q", op)
	}
	if op := outerBinOp(body[15]); op != "||" {
		t.Errorf("stmt 15: expected ||, got %q", op)
	}
}

// ---------------------------------------------------------------------------
// Test: Java's `==` becomes the AST's `===` equality operator (same
// convention as the Python, Rust macro, and other parsers).
// ---------------------------------------------------------------------------

func TestParseJava_EqualityOperatorIsTripleEq(t *testing.T) {
	source := `
class C extends SmartContract {
    @Public void run(Bigint a, Bigint b) {
        assertThat(a == b);
        assertThat(a != b);
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	body := c.Methods[0].Body

	extract := func(stmt Statement) BinaryExpr {
		es := stmt.(ExpressionStmt)
		return es.Expr.(CallExpr).Args[0].(BinaryExpr)
	}

	eq := extract(body[0])
	if eq.Op != "===" {
		t.Errorf("expected === for `==`, got %q", eq.Op)
	}
	ne := extract(body[1])
	if ne.Op != "!==" {
		t.Errorf("expected !== for `!=`, got %q", ne.Op)
	}
}

// ---------------------------------------------------------------------------
// Test: Unary operators
// ---------------------------------------------------------------------------

func TestParseJava_UnaryOperators(t *testing.T) {
	source := `
class C extends SmartContract {
    @Public void run(Bigint a) {
        assertThat(!(a == a));
        assertThat(-a == -a);
        assertThat(~a == ~a);
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if len(c.Methods[0].Body) != 3 {
		t.Fatalf("expected 3 stmts, got %d", len(c.Methods[0].Body))
	}
	// stmt 0: !(a == a) — unary !
	st0 := c.Methods[0].Body[0].(ExpressionStmt)
	call0 := st0.Expr.(CallExpr)
	un0, ok := call0.Args[0].(UnaryExpr)
	if !ok || un0.Op != "!" {
		t.Errorf("expected unary !, got %+v", call0.Args[0])
	}
	// stmt 1: (-a) == (-a) — BinaryExpr with UnaryExpr left
	st1 := c.Methods[0].Body[1].(ExpressionStmt)
	call1 := st1.Expr.(CallExpr)
	eq1 := call1.Args[0].(BinaryExpr)
	left1, ok := eq1.Left.(UnaryExpr)
	if !ok || left1.Op != "-" {
		t.Errorf("expected unary -, got %+v", eq1.Left)
	}
	// stmt 2: (~a) == (~a)
	st2 := c.Methods[0].Body[2].(ExpressionStmt)
	call2 := st2.Expr.(CallExpr)
	eq2 := call2.Args[0].(BinaryExpr)
	left2, ok := eq2.Left.(UnaryExpr)
	if !ok || left2.Op != "~" {
		t.Errorf("expected unary ~, got %+v", eq2.Left)
	}
}

// ---------------------------------------------------------------------------
// Test: for-loop, ternary, array access, array literal via new T[]{...}
// ---------------------------------------------------------------------------

func TestParseJava_ForTernaryArray(t *testing.T) {
	source := `
class C extends SmartContract {
    @Public void run(Bigint n) {
        Bigint sum = BigInteger.ZERO;
        for (Bigint i = BigInteger.ZERO; i < n; i++) {
            sum = sum + i;
        }
        Bigint pick = (n > BigInteger.ZERO) ? sum : BigInteger.ZERO;
        Bigint[] xs = new Bigint[] { BigInteger.ONE, BigInteger.TWO };
        assertThat(xs[0] == BigInteger.ONE);
        assertThat(pick == sum);
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	body := c.Methods[0].Body
	// body[0] sum decl; body[1] for; body[2] pick decl; body[3] xs decl;
	// body[4..5] two assertions.
	if len(body) < 6 {
		t.Fatalf("expected at least 6 stmts, got %d", len(body))
	}
	if _, ok := body[1].(ForStmt); !ok {
		t.Errorf("expected ForStmt at body[1], got %T", body[1])
	}
	pickDecl, ok := body[2].(VariableDeclStmt)
	if !ok {
		t.Fatalf("expected VariableDeclStmt, got %T", body[2])
	}
	if _, ok := pickDecl.Init.(TernaryExpr); !ok {
		t.Errorf("expected TernaryExpr initializer, got %T", pickDecl.Init)
	}
	xsDecl, ok := body[3].(VariableDeclStmt)
	if !ok {
		t.Fatalf("expected VariableDeclStmt for xs, got %T", body[3])
	}
	arr, ok := xsDecl.Init.(ArrayLiteralExpr)
	if !ok {
		t.Fatalf("expected ArrayLiteralExpr, got %T", xsDecl.Init)
	}
	if len(arr.Elements) != 2 {
		t.Errorf("expected 2 elements, got %d", len(arr.Elements))
	}
	// body[4] is the xs[0] access assert
	st4 := body[4].(ExpressionStmt)
	call4 := st4.Expr.(CallExpr)
	eq4 := call4.Args[0].(BinaryExpr)
	if _, ok := eq4.Left.(IndexAccessExpr); !ok {
		t.Errorf("expected IndexAccessExpr LHS, got %T", eq4.Left)
	}
}

// ---------------------------------------------------------------------------
// Test: Prefix and postfix ++/--
// ---------------------------------------------------------------------------

func TestParseJava_IncrementDecrement(t *testing.T) {
	source := `
class C extends SmartContract {
    @Public void run(Bigint a) {
        Bigint b = a;
        b++;
        ++b;
        b--;
        --b;
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	body := result.Contract.Methods[0].Body
	if len(body) != 5 {
		t.Fatalf("expected 5 stmts, got %d", len(body))
	}
	// body[1]: b++ — ExpressionStmt wrapping IncrementExpr{Prefix: false}
	inc1 := body[1].(ExpressionStmt).Expr.(IncrementExpr)
	if inc1.Prefix {
		t.Errorf("expected postfix ++")
	}
	// body[2]: ++b
	inc2 := body[2].(ExpressionStmt).Expr.(IncrementExpr)
	if !inc2.Prefix {
		t.Errorf("expected prefix ++")
	}
	// body[3]: b--
	dec1 := body[3].(ExpressionStmt).Expr.(DecrementExpr)
	if dec1.Prefix {
		t.Errorf("expected postfix --")
	}
	// body[4]: --b
	dec2 := body[4].(ExpressionStmt).Expr.(DecrementExpr)
	if !dec2.Prefix {
		t.Errorf("expected prefix --")
	}
}

// ---------------------------------------------------------------------------
// Test: Private helper method (no @Public)
// ---------------------------------------------------------------------------

func TestParseJava_PrivateHelper(t *testing.T) {
	source := `
class C extends SmartContract {
    @Readonly Bigint threshold;
    @Public void run(Bigint x) {
        assertThat(isBig(x));
    }
    boolean isBig(Bigint x) {
        return x > threshold;
    }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if len(c.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(c.Methods))
	}
	var run, isBig *MethodNode
	for i := range c.Methods {
		if c.Methods[i].Name == "run" {
			run = &c.Methods[i]
		}
		if c.Methods[i].Name == "isBig" {
			isBig = &c.Methods[i]
		}
	}
	if run == nil || isBig == nil {
		t.Fatal("missing method")
	}
	if run.Visibility != "public" {
		t.Errorf("expected run public, got %s", run.Visibility)
	}
	if isBig.Visibility != "private" {
		t.Errorf("expected isBig private, got %s", isBig.Visibility)
	}
	// isBig body has one ReturnStmt
	if _, ok := isBig.Body[0].(ReturnStmt); !ok {
		t.Errorf("expected ReturnStmt in isBig body, got %T", isBig.Body[0])
	}
}

// ---------------------------------------------------------------------------
// Test: FixedArray<T, N>
// ---------------------------------------------------------------------------

func TestParseJava_FixedArray(t *testing.T) {
	source := `
class C extends SmartContract {
    @Readonly FixedArray<Bigint, 4> xs;
    C(FixedArray<Bigint, 4> xs) { super(xs); this.xs = xs; }
}
`
	result := ParseSource([]byte(source), "C.runar.java")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	fa, ok := c.Properties[0].Type.(FixedArrayType)
	if !ok {
		t.Fatalf("expected FixedArrayType, got %T", c.Properties[0].Type)
	}
	if fa.Length != 4 {
		t.Errorf("expected length 4, got %d", fa.Length)
	}
	if elem, ok := fa.Element.(PrimitiveType); !ok || elem.Name != "bigint" {
		t.Errorf("expected bigint element, got %+v", fa.Element)
	}
}
