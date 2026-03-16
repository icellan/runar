package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: parse TypeScript source and return the ContractNode
// ---------------------------------------------------------------------------

func mustParseTS(t *testing.T, source string) *ContractNode {
	t.Helper()
	result := ParseSource([]byte(source), "test.runar.ts")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.Errors, "; "))
	}
	if result.Contract == nil {
		t.Fatal("parse returned nil contract")
	}
	return result.Contract
}

// ---------------------------------------------------------------------------
// Test: Valid P2PKH contract passes validation
// ---------------------------------------------------------------------------

func TestValidate_ValidP2PKH(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if len(result.Errors) > 0 {
		t.Errorf("expected no validation errors, got: %s", strings.Join(result.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Constructor missing super() call produces error
// ---------------------------------------------------------------------------

func TestValidate_ConstructorMissingSuperCall(t *testing.T) {
	// Build a ContractNode manually with a constructor that doesn't start with super()
	contract := &ContractNode{
		Name:        "Bad",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				// Missing super() — jump straight to assignment
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "val", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								BinaryExpr{
									Op:    "===",
									Left:  Identifier{Name: "val"},
									Right: PropertyAccessExpr{Property: "x"},
								},
							},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	foundSuperError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "super()") {
			foundSuperError = true
			break
		}
	}
	if !foundSuperError {
		t.Errorf("expected validation error about missing super() call, got errors: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Public method not ending with assert produces error
// ---------------------------------------------------------------------------

func TestValidate_PublicMethodMissingFinalAssert(t *testing.T) {
	contract := &ContractNode{
		Name:        "NoAssert",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{
						Callee: Identifier{Name: "super"},
						Args:   []Expression{Identifier{Name: "x"}},
					},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "val", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					// Does NOT end with assert — just a bare expression
					ExpressionStmt{
						Expr: BinaryExpr{
							Op:    "+",
							Left:  Identifier{Name: "val"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	foundAssertError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "assert()") {
			foundAssertError = true
			break
		}
	}
	if !foundAssertError {
		t.Errorf("expected validation error about public method not ending with assert(), got errors: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Direct recursion is detected
// ---------------------------------------------------------------------------

func TestValidate_DirectRecursion(t *testing.T) {
	contract := &ContractNode{
		Name:        "Recursive",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{
						Callee: Identifier{Name: "super"},
						Args:   nil,
					},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "recurse",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "n", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					// this.recurse(n - 1) — direct self-call
					ExpressionStmt{
						Expr: CallExpr{
							Callee: PropertyAccessExpr{Property: "recurse"},
							Args: []Expression{
								BinaryExpr{
									Op:    "-",
									Left:  Identifier{Name: "n"},
									Right: BigIntLiteral{Value: 1},
								},
							},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	foundRecursionError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "recursion") {
			foundRecursionError = true
			break
		}
	}
	if !foundRecursionError {
		t.Errorf("expected validation error about recursion, got errors: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Valid P2PKH parsed from source passes validation (integration)
// ---------------------------------------------------------------------------

func TestValidate_P2PKHFromSource(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if len(result.Errors) > 0 {
		t.Errorf("P2PKH should validate without errors, got: %s", strings.Join(result.Errors, "; "))
	}
	if len(result.Warnings) > 0 {
		t.Logf("validation warnings: %s", strings.Join(result.Warnings, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: StatefulSmartContract public method without trailing assert is OK
// (the compiler auto-injects it)
// ---------------------------------------------------------------------------

func TestValidate_StatefulNoFinalAssertOK(t *testing.T) {
	contract := &ContractNode{
		Name:        "Counter",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{
						Callee: Identifier{Name: "super"},
						Args:   []Expression{Identifier{Name: "count"}},
					},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "increment",
				Visibility: "public",
				Params:     []ParamNode{},
				Body: []Statement{
					// this.count = this.count + 1 — no trailing assert
					AssignmentStmt{
						Target: PropertyAccessExpr{Property: "count"},
						Value: BinaryExpr{
							Op:    "+",
							Left:  PropertyAccessExpr{Property: "count"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	// StatefulSmartContract methods should NOT require a trailing assert
	for _, e := range result.Errors {
		if strings.Contains(e, "must end with an assert()") {
			t.Errorf("StatefulSmartContract public method should not require trailing assert, got error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: super() not as first statement → error
// ---------------------------------------------------------------------------

func TestValidate_SuperNotFirstStatement(t *testing.T) {
	contract := &ContractNode{
		Name:        "Bad",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				// Assignment first, super() second — should fail
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
				ExpressionStmt{
					Expr: CallExpr{
						Callee: Identifier{Name: "super"},
						Args:   []Expression{Identifier{Name: "x"}},
					},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "super()") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about super() not being first statement, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Property not assigned in constructor → error
// ---------------------------------------------------------------------------

func TestValidate_PropertyNotAssignedInConstructor(t *testing.T) {
	contract := &ContractNode{
		Name:        "Missing",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
			{Name: "y", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
				{Name: "y", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{
						Callee: Identifier{Name: "super"},
						Args:   []Expression{Identifier{Name: "x"}, Identifier{Name: "y"}},
					},
				},
				// Only assign x, not y
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "'y'") && strings.Contains(e, "assigned") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about property 'y' not assigned in constructor, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: For-loop with non-constant bound → error
// ---------------------------------------------------------------------------

func TestValidate_ForLoopNonConstantBound(t *testing.T) {
	contract := &ContractNode{
		Name:        "BadLoop",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "run",
				Visibility: "public",
				Params:     []ParamNode{{Name: "limit", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// for (let i = 0n; i < a + b; i++) — a + b is a runtime expression, not constant
					ForStmt{
						Init: VariableDeclStmt{
							Name: "i",
							Init: BigIntLiteral{Value: 0},
						},
						Condition: BinaryExpr{
							Op:   "<",
							Left: Identifier{Name: "i"},
							Right: BinaryExpr{ // non-constant: runtime arithmetic
								Op:    "+",
								Left:  Identifier{Name: "limit"},
								Right: BigIntLiteral{Value: 1},
							},
						},
						Update: ExpressionStmt{
							Expr: IncrementExpr{
								Operand: Identifier{Name: "i"},
							},
						},
						Body: []Statement{},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "constant") || strings.Contains(e, "bound") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about non-constant for loop bound, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: void property type → error
// ---------------------------------------------------------------------------

func TestValidate_VoidPropertyType(t *testing.T) {
	contract := &ContractNode{
		Name:        "BadVoid",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{
				Name:           "x",
				Type:           PrimitiveType{Name: "void"},
				Readonly:       true,
				SourceLocation: SourceLocation{File: "test.ts", Line: 3},
			},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "void"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "x"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "void") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about 'void' property type, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: SmartContract with non-readonly property → error
// (TS and Rust compilers enforce this; Go validator should too)
// ---------------------------------------------------------------------------

func TestValidate_SmartContractNonReadonlyProperty(t *testing.T) {
	contract := &ContractNode{
		Name:        "MutableStateless",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			// Non-readonly property on a SmartContract — should be an error
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "count"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "readonly") || strings.Contains(e, "mutable") || strings.Contains(e, "StatefulSmartContract") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected validation error about non-readonly property in SmartContract, got errors: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: StatefulSmartContract non-readonly property is allowed
// ---------------------------------------------------------------------------

func TestValidate_StatefulSmartContractNonReadonlyAllowed(t *testing.T) {
	contract := &ContractNode{
		Name:        "Counter",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			// Non-readonly on StatefulSmartContract — must be allowed
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "count"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "increment",
				Visibility: "public",
				Params:     []ParamNode{},
				Body: []Statement{
					AssignmentStmt{
						Target: PropertyAccessExpr{Property: "count"},
						Value: BinaryExpr{
							Op:    "+",
							Left:  PropertyAccessExpr{Property: "count"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	// Must not produce any error specifically about non-readonly properties
	for _, e := range result.Errors {
		if strings.Contains(e, "readonly") || strings.Contains(e, "mutable") {
			t.Errorf("StatefulSmartContract non-readonly property should be allowed, but got error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Indirect recursion (A calls B, B calls A) → error
// ---------------------------------------------------------------------------

func TestValidate_IndirectRecursion(t *testing.T) {
	contract := &ContractNode{
		Name:        "IndirectRec",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "methodA",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// this.methodB(v) — calls B
					ExpressionStmt{
						Expr: CallExpr{
							Callee: PropertyAccessExpr{Property: "methodB"},
							Args:   []Expression{Identifier{Name: "v"}},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BoolLiteral{Value: true}},
						},
					},
				},
			},
			{
				Name:       "methodB",
				Visibility: "private",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// this.methodA(v) — calls A back
					ExpressionStmt{
						Expr: CallExpr{
							Callee: PropertyAccessExpr{Property: "methodA"},
							Args:   []Expression{Identifier{Name: "v"}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "recursion") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recursion error for indirect cycle A→B→A, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test V3: validate — multiple public methods allowed → no errors
// ---------------------------------------------------------------------------

func TestValidate_MultiplePublicMethodsAllowed(t *testing.T) {
	contract := &ContractNode{
		Name:        "MultiMethod",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "x"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "spend1",
				Visibility: "public",
				Params:     []ParamNode{{Name: "a", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BinaryExpr{Op: "===", Left: Identifier{Name: "a"}, Right: PropertyAccessExpr{Property: "x"}}},
						},
					},
				},
			},
			{
				Name:       "spend2",
				Visibility: "public",
				Params:     []ParamNode{{Name: "b", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{BinaryExpr{Op: ">", Left: Identifier{Name: "b"}, Right: BigIntLiteral{Value: 0}}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	if len(result.Errors) > 0 {
		t.Errorf("expected no validation errors for contract with 2 public methods, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test V4: validate — if/else where both branches end in assert → no errors
// ---------------------------------------------------------------------------

func TestValidate_IfElseBothBranchesAssert_OK(t *testing.T) {
	contract := &ContractNode{
		Name:        "BranchAssert",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "cond", Type: PrimitiveType{Name: "boolean"}},
					{Name: "a", Type: PrimitiveType{Name: "bigint"}},
					{Name: "b", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					IfStmt{
						Condition: Identifier{Name: "cond"},
						Then: []Statement{
							ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BinaryExpr{Op: ">", Left: Identifier{Name: "a"}, Right: BigIntLiteral{Value: 0}}}}},
						},
						Else: []Statement{
							ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BinaryExpr{Op: ">", Left: Identifier{Name: "b"}, Right: BigIntLiteral{Value: 0}}}}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	for _, e := range result.Errors {
		if strings.Contains(e, "assert()") {
			t.Errorf("expected no assert-related errors for if/else both ending in assert, got: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test V6: validate — public method ending with non-assert call rejected
// ---------------------------------------------------------------------------

func TestValidate_PublicMethodEndingWithNonAssertCall_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "NonAssertEnd",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "spend",
				Visibility: "public",
				Params:     []ParamNode{{Name: "x", Type: PrimitiveType{Name: "ByteString"}}},
				Body: []Statement{
					// Last statement is hash160(x), not assert
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "hash160"},
							Args:   []Expression{Identifier{Name: "x"}},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "assert()") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected validation error about public method not ending with assert(), got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test V7: validate — private method without assert is OK
// ---------------------------------------------------------------------------

func TestValidate_PrivateMethodWithoutAssert_OK(t *testing.T) {
	contract := &ContractNode{
		Name:        "PrivNoAssert",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "helper",
				Visibility: "private",
				Params:     []ParamNode{{Name: "x", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// Private method with no assert — should be OK
					ExpressionStmt{
						Expr: BinaryExpr{Op: "+", Left: Identifier{Name: "x"}, Right: BigIntLiteral{Value: 1}},
					},
				},
			},
			{
				Name:       "spend",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BoolLiteral{Value: true}}}},
				},
			},
		},
	}

	result := Validate(contract)

	// Private method without assert should not produce an error
	for _, e := range result.Errors {
		if strings.Contains(e, "helper") && strings.Contains(e, "assert()") {
			t.Errorf("expected private method without assert to be OK, but got error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test V8: validate — empty public method body rejected
// ---------------------------------------------------------------------------

func TestValidate_EmptyPublicMethodBody_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "EmptyMethod",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "spend",
				Visibility: "public",
				Params:     []ParamNode{},
				Body:       []Statement{}, // empty
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "assert()") || strings.Contains(e, "spend") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected validation error for empty public method body, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test V11: validate — identifier for-loop bound (treated as possibly const) accepted
// ---------------------------------------------------------------------------

func TestValidate_ForLoopIdentifierBound_OK(t *testing.T) {
	contract := &ContractNode{
		Name:        "IdentBound",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "run",
				Visibility: "public",
				Params:     []ParamNode{{Name: "N", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// for (let i = 0n; i < N; i++) where N is an identifier → treated as const
					ForStmt{
						Init:      VariableDeclStmt{Name: "i", Init: BigIntLiteral{Value: 0}},
						Condition: BinaryExpr{Op: "<", Left: Identifier{Name: "i"}, Right: Identifier{Name: "N"}},
						Update:    ExpressionStmt{Expr: IncrementExpr{Operand: Identifier{Name: "i"}}},
						Body:      []Statement{},
					},
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BoolLiteral{Value: true}}}},
				},
			},
		},
	}

	result := Validate(contract)

	// Identifier bound should not produce a "constant bound" error
	for _, e := range result.Errors {
		if strings.Contains(e, "constant") || strings.Contains(e, "bound") {
			t.Errorf("expected identifier for-loop bound to be accepted (treated as const), but got error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test V15: validate — all properties assigned in constructor → no error
// ---------------------------------------------------------------------------

func TestValidate_AllPropertiesAssignedInConstructor_OK(t *testing.T) {
	contract := &ContractNode{
		Name:        "AllAssigned",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
			{Name: "y", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
				{Name: "y", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "x"}, Identifier{Name: "y"}}},
				},
				AssignmentStmt{Target: PropertyAccessExpr{Property: "x"}, Value: Identifier{Name: "x"}},
				AssignmentStmt{Target: PropertyAccessExpr{Property: "y"}, Value: Identifier{Name: "y"}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BoolLiteral{Value: true}}}},
				},
			},
		},
	}

	result := Validate(contract)

	// No property-assignment errors should be produced
	for _, e := range result.Errors {
		if strings.Contains(e, "assigned") {
			t.Errorf("expected no assignment errors when all properties are assigned, but got: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test V21: validate — non-recursive method calls not flagged
// ---------------------------------------------------------------------------

func TestValidate_NonRecursiveMethodCalls_NoError(t *testing.T) {
	contract := &ContractNode{
		Name:        "NonRecursive",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "methodA",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// methodA calls methodB (helper), but methodB does NOT call methodA
					ExpressionStmt{
						Expr: CallExpr{
							Callee: PropertyAccessExpr{Property: "methodB"},
							Args:   []Expression{Identifier{Name: "v"}},
						},
					},
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BoolLiteral{Value: true}}}},
				},
			},
			{
				Name:       "methodB",
				Visibility: "private",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// methodB does NOT call methodA
					ExpressionStmt{
						Expr: BinaryExpr{Op: "+", Left: Identifier{Name: "v"}, Right: BigIntLiteral{Value: 1}},
					},
				},
			},
		},
	}

	result := Validate(contract)

	for _, e := range result.Errors {
		if strings.Contains(e, "recursion") {
			t.Errorf("expected no recursion error for non-recursive A→B call chain, but got: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test V23: validate — regular SmartContract still needs trailing assert
// ---------------------------------------------------------------------------

func TestValidate_SmartContractPublicMethodNeedsAssert(t *testing.T) {
	contract := &ContractNode{
		Name:        "NeedsAssert",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:   "constructor",
			Params: []ParamNode{},
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: nil}},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "spend",
				Visibility: "public",
				Params:     []ParamNode{{Name: "x", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// No trailing assert
					VariableDeclStmt{Name: "r", Init: BinaryExpr{Op: "+", Left: Identifier{Name: "x"}, Right: BigIntLiteral{Value: 1}}},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "assert()") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SmartContract public method without trailing assert should produce error, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: StatefulSmartContract method that manually calls checkPreimage() →
// warning/error
// TODO: not yet implemented in Go validator
// ---------------------------------------------------------------------------

func TestValidate_ManualCheckPreimage_Warning(t *testing.T) {

	contract := &ContractNode{
		Name:        "ManualPreimage",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "count"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "increment",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "preimage", Type: PrimitiveType{Name: "SigHashPreimage"}},
				},
				Body: []Statement{
					// Manually calling checkPreimage — StatefulSmartContract auto-injects this,
					// so calling it manually is an error/warning
					VariableDeclStmt{
						Name: "ok",
						Init: CallExpr{
							Callee: Identifier{Name: "checkPreimage"},
							Args:   []Expression{Identifier{Name: "preimage"}},
						},
					},
					AssignmentStmt{
						Target: PropertyAccessExpr{Property: "count"},
						Value: BinaryExpr{
							Op:    "+",
							Left:  PropertyAccessExpr{Property: "count"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range append(result.Errors, result.Warnings...) {
		if strings.Contains(e, "checkPreimage") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning/error about manual checkPreimage() in StatefulSmartContract, got errors: %v, warnings: %v", result.Errors, result.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Test: Manually calling getStateScript() → warning/error
// TODO: not yet implemented in Go validator
// ---------------------------------------------------------------------------

func TestValidate_ManualGetStateScript_Warning(t *testing.T) {

	contract := &ContractNode{
		Name:        "ManualStateScript",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "count"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "update",
				Visibility: "public",
				Params:     []ParamNode{},
				Body: []Statement{
					// Manually calling getStateScript() — should warn
					VariableDeclStmt{
						Name: "script",
						Init: CallExpr{
							Callee: PropertyAccessExpr{Property: "getStateScript"},
							Args:   []Expression{},
						},
					},
					AssignmentStmt{
						Target: PropertyAccessExpr{Property: "count"},
						Value: BinaryExpr{
							Op:    "+",
							Left:  PropertyAccessExpr{Property: "count"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range append(result.Errors, result.Warnings...) {
		if strings.Contains(e, "getStateScript") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning/error about manual getStateScript() call, got errors: %v, warnings: %v", result.Errors, result.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Test: StatefulSmartContract with no mutable properties → warning
// TODO: not yet implemented in Go validator
// ---------------------------------------------------------------------------

func TestValidate_StatefulNoMutableProperties_Warning(t *testing.T) {

	contract := &ContractNode{
		Name:        "NoMutableProps",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			// All readonly — makes no sense for StatefulSmartContract
			{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "x", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "x"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "x"},
					Value:  Identifier{Name: "x"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "doNothing",
				Visibility: "public",
				Params:     []ParamNode{},
				Body:       []Statement{},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "mutable") || strings.Contains(w, "property") || strings.Contains(w, "StatefulSmartContract") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about no mutable properties in StatefulSmartContract, got warnings: %v", result.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Test: Declaring 'txPreimage' as an explicit property → error
// TODO: not yet implemented in Go validator
// ---------------------------------------------------------------------------

func TestValidate_TxPreimageExplicitProperty_Error(t *testing.T) {

	contract := &ContractNode{
		Name:        "ExplicitPreimage",
		ParentClass: "StatefulSmartContract",
		Properties: []PropertyNode{
			{Name: "count", Type: PrimitiveType{Name: "bigint"}, Readonly: false},
			// Declaring txPreimage explicitly — should be an error since it's auto-injected
			{Name: "txPreimage", Type: PrimitiveType{Name: "SigHashPreimage"}, Readonly: true},
		},
		Constructor: MethodNode{
			Name: "constructor",
			Params: []ParamNode{
				{Name: "count", Type: PrimitiveType{Name: "bigint"}},
			},
			Body: []Statement{
				ExpressionStmt{
					Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "count"}}},
				},
				AssignmentStmt{
					Target: PropertyAccessExpr{Property: "count"},
					Value:  Identifier{Name: "count"},
				},
			},
		},
		Methods: []MethodNode{
			{
				Name:       "increment",
				Visibility: "public",
				Params:     []ParamNode{},
				Body: []Statement{
					AssignmentStmt{
						Target: PropertyAccessExpr{Property: "count"},
						Value: BinaryExpr{
							Op:    "+",
							Left:  PropertyAccessExpr{Property: "count"},
							Right: BigIntLiteral{Value: 1},
						},
					},
				},
			},
		},
	}

	result := Validate(contract)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "txPreimage") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about explicit txPreimage property declaration, got: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Row 98: Empty contract name → error
// ---------------------------------------------------------------------------

func TestValidate_EmptyContractName(t *testing.T) {
	// Build a ContractNode with an empty name directly
	contract := &ContractNode{
		Name:        "",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{},
		Constructor: MethodNode{
			Name:       "constructor",
			Visibility: "private",
			Body:       []Statement{ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{}}}},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "x", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					ExpressionStmt{Expr: CallExpr{
						Callee: Identifier{Name: "assert"},
						Args:   []Expression{BoolLiteral{Value: true}},
					}},
				},
			},
		},
	}

	result := Validate(contract)
	if len(result.Errors) == 0 {
		t.Fatal("expected error for empty contract name")
	}
}
