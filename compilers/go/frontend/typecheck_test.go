package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Valid P2PKH passes type check
// ---------------------------------------------------------------------------

func TestTypeCheck_ValidP2PKH(t *testing.T) {
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

	// Validate first (prerequisite for type check)
	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type check errors for P2PKH, got: %s", strings.Join(tcResult.Errors, "; "))
	}
	if tcResult.Contract == nil {
		t.Error("expected non-nil contract in type check result")
	}
}

// ---------------------------------------------------------------------------
// Test: Unknown function call (Math.floor) produces error
// ---------------------------------------------------------------------------

func TestTypeCheck_UnknownFunction_MathFloor(t *testing.T) {
	// Build an AST that calls Math.floor — this should be rejected
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
					// const result = Math.floor(val) — should be rejected
					VariableDeclStmt{
						Name: "result",
						Init: CallExpr{
							Callee: MemberExpr{
								Object:   Identifier{Name: "Math"},
								Property: "floor",
							},
							Args: []Expression{Identifier{Name: "val"}},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								BinaryExpr{
									Op:    "===",
									Left:  Identifier{Name: "result"},
									Right: PropertyAccessExpr{Property: "x"},
								},
							},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	foundUnknownError := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "unknown function") || strings.Contains(e, "Math.floor") {
			foundUnknownError = true
			break
		}
	}
	if !foundUnknownError {
		t.Errorf("expected type check error about unknown function 'Math.floor', got errors: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Unknown function call (console.log) produces error
// ---------------------------------------------------------------------------

func TestTypeCheck_UnknownFunction_ConsoleLog(t *testing.T) {
	contract := &ContractNode{
		Name:        "Bad",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "val", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					// console.log(val)
					ExpressionStmt{
						Expr: CallExpr{
							Callee: MemberExpr{
								Object:   Identifier{Name: "console"},
								Property: "log",
							},
							Args: []Expression{Identifier{Name: "val"}},
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

	tcResult := TypeCheck(contract)

	foundError := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "unknown function") || strings.Contains(e, "console.log") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("expected type check error about unknown function 'console.log', got errors: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Type mismatch in binary arithmetic operator
// ---------------------------------------------------------------------------

func TestTypeCheck_TypeMismatch_ArithmeticOnBoolean(t *testing.T) {
	contract := &ContractNode{
		Name:        "Mismatch",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "flag", Type: PrimitiveType{Name: "boolean"}},
				},
				Body: []Statement{
					// const result = flag + 1n — boolean + bigint should error
					VariableDeclStmt{
						Name: "result",
						Init: BinaryExpr{
							Op:    "+",
							Left:  Identifier{Name: "flag"},
							Right: BigIntLiteral{Value: 1},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								BinaryExpr{
									Op:    "===",
									Left:  Identifier{Name: "result"},
									Right: BigIntLiteral{Value: 2},
								},
							},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	foundTypeError := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "must be bigint") || strings.Contains(e, "boolean") {
			foundTypeError = true
			break
		}
	}
	if !foundTypeError {
		t.Errorf("expected type check error about type mismatch (boolean used in arithmetic), got errors: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Arithmetic contract passes type check
// ---------------------------------------------------------------------------

func TestTypeCheck_ValidArithmetic(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class Arithmetic extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    const sum: bigint = a + b;
    const diff: bigint = a - b;
    const prod: bigint = a * b;
    const quot: bigint = a / b;
    const result: bigint = sum + diff + prod + quot;
    assert(result === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type check errors for Arithmetic, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Boolean logic contract passes type check
// ---------------------------------------------------------------------------

func TestTypeCheck_ValidBooleanLogic(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BoolLogic extends SmartContract {
  readonly threshold: bigint;

  constructor(threshold: bigint) {
    super(threshold);
    this.threshold = threshold;
  }

  public verify(a: bigint, b: bigint, flag: boolean): void {
    const aAbove: boolean = a > this.threshold;
    const bAbove: boolean = b > this.threshold;
    const bothAbove: boolean = aAbove && bAbove;
    const eitherAbove: boolean = aAbove || bAbove;
    const notFlag: boolean = !flag;
    assert(bothAbove || (eitherAbove && notFlag));
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type check errors for BoolLogic, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Valid StatefulSmartContract passes type check
// ---------------------------------------------------------------------------

func TestTypeCheck_ValidStateful(t *testing.T) {
	source := `
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(): void {
    this.count = this.count + 1n;
    this.addOutput(1000n, this.count);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected valid StatefulSmartContract to pass type checking, got errors: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Built-in function with wrong argument count produces error
// ---------------------------------------------------------------------------

func TestTypeCheck_BuiltinWrongArgCount(t *testing.T) {
	source := `
import { SmartContract, assert, sha256 } from 'runar-lang';

class BadArgs extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(a: ByteString, b: ByteString): void {
    const h = sha256(a, b);
    assert(this.x > 0n);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for sha256 called with wrong number of args, got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test: Subtype compatibility (PubKey assignable to ByteString parameter)
// ---------------------------------------------------------------------------

func TestTypeCheck_SubtypeCompatibility(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, sha256 } from 'runar-lang';

class HashCheck extends SmartContract {
  readonly expectedHash: Sha256;

  constructor(expectedHash: Sha256) {
    super(expectedHash);
    this.expectedHash = expectedHash;
  }

  public verify(pubKey: PubKey): void {
    assert(sha256(pubKey) === this.expectedHash);
  }
}
`
	contract := mustParseTS(t, source)

	// PubKey should be assignable to ByteString (sha256's parameter type)
	tcResult := TypeCheck(contract)
	// Filter out errors that are NOT about subtype/argument type issues
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "argument") && strings.Contains(e, "PubKey") {
			t.Errorf("PubKey should be assignable to ByteString, but got error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Unknown standalone function call → error
// ---------------------------------------------------------------------------

func TestTypeCheck_UnknownStandaloneFunction(t *testing.T) {
	contract := &ContractNode{
		Name:        "Bad",
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
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "v", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// unknownFunc(v) — an entirely unknown top-level function
					VariableDeclStmt{
						Name: "result",
						Init: CallExpr{
							Callee: Identifier{Name: "unknownFunc"},
							Args:   []Expression{Identifier{Name: "v"}},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								BinaryExpr{
									Op:    ">",
									Left:  Identifier{Name: "result"},
									Right: BigIntLiteral{Value: 0},
								},
							},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "unknown function") || strings.Contains(e, "unknownFunc") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type check error for unknown standalone function 'unknownFunc', got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: ByteString arithmetic subtraction produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_ByteStringArithmetic_Error(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BSArith extends SmartContract {
  readonly x: ByteString;

  constructor(x: ByteString) {
    super(x);
    this.x = x;
  }

  public check(): void {
    const diff = this.x - this.x;
    assert(diff === diff);
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "type") || strings.Contains(e, "ByteString") || strings.Contains(e, "bigint") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for ByteString used in arithmetic subtraction, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: ByteString concatenation (+) is allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_ByteStringConcat_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BSConcat extends SmartContract {
  readonly x: ByteString;
  readonly y: ByteString;

  constructor(x: ByteString, y: ByteString) {
    super(x, y);
    this.x = x;
    this.y = y;
  }

  public check(): void {
    const cat = this.x + this.y;
    assert(cat === cat);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type check errors for ByteString + ByteString (OP_CAT), got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: bigint + ByteString produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_BigintPlusByteString_Error(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BIPlusBs extends SmartContract {
  readonly n: bigint;
  readonly bs: ByteString;

  constructor(n: bigint, bs: ByteString) {
    super(n, bs);
    this.n = n;
    this.bs = bs;
  }

  public check(): void {
    const r = this.n + this.bs;
    assert(r === r);
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for bigint + ByteString, got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test: Sig used twice in checkSig produces affine type error
// ---------------------------------------------------------------------------

func TestTypeCheck_SigUsedTwice_Error(t *testing.T) {
	source := `
import { SmartContract, assert, Sig, PubKey, checkSig } from 'runar-lang';

class SigTwice extends SmartContract {
  readonly pubKeyHash: PubKey;

  constructor(pubKeyHash: PubKey) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public check(sig: Sig, pubKey: PubKey): void {
    assert(checkSig(sig, pubKey));
    assert(checkSig(sig, pubKey));
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "affine") || strings.Contains(e, "Sig") || strings.Contains(e, "once") || strings.Contains(e, "linear") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected affine/linear type error for Sig used twice, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: if condition that is bigint (non-boolean) produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_IfConditionNotBoolean_Error(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class IfNonBool extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public check(): void {
    if (this.n) {
      assert(true);
    } else {
      assert(true);
    }
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "boolean") || strings.Contains(e, "condition") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for non-boolean if condition, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: assert(bigint_expr) produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_AssertNonBoolean_Error(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class AssertBigint extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public check(): void {
    assert(this.n);
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for assert(bigint), got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test: checkSig with wrong argument count produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_CheckSigWrongArgCount_Error(t *testing.T) {
	source := `
import { SmartContract, assert, Sig, PubKey, checkSig } from 'runar-lang';

class BadCheckSig extends SmartContract {
  readonly pubKeyHash: PubKey;

  constructor(pubKeyHash: PubKey) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public check(sig: Sig): void {
    assert(checkSig(sig));
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for checkSig called with 1 argument (needs 2), got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test: Accessing non-existent property does not panic
// ---------------------------------------------------------------------------

func TestTypeCheck_NonExistentPropertyAccess(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class PropAccess extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(): void {
    assert(this.nonExistent === this.x);
  }
}
`
	contract := mustParseTS(t, source)

	// Should not panic — either returns an error or gracefully handles
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("TypeCheck panicked on non-existent property access: %v", r)
		}
	}()

	tcResult := TypeCheck(contract)
	// Either errors or no errors is acceptable — just no panic
	t.Logf("TypeCheck result for non-existent property: errors=%v", tcResult.Errors)
}

// ---------------------------------------------------------------------------
// Test: sha256 with wrong argument count → error
// ---------------------------------------------------------------------------

func TestTypeCheck_SHA256WrongArgCount(t *testing.T) {
	contract := &ContractNode{
		Name:        "BadSHA",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "a", Type: PrimitiveType{Name: "ByteString"}},
					{Name: "b", Type: PrimitiveType{Name: "ByteString"}},
				},
				Body: []Statement{
					// sha256(a, b) — sha256 takes exactly 1 arg
					VariableDeclStmt{
						Name: "h",
						Init: CallExpr{
							Callee: Identifier{Name: "sha256"},
							Args:   []Expression{Identifier{Name: "a"}, Identifier{Name: "b"}},
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

	tcResult := TypeCheck(contract)

	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for sha256 called with 2 args (expects 1), got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test: Bitwise AND on bigint operands is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_BitwiseOnBigint_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BitwiseBigint extends SmartContract {
  readonly mask: bigint;

  constructor(mask: bigint) {
    super(mask);
    this.mask = mask;
  }

  public check(a: bigint, b: bigint): void {
    const r = a & b;
    assert(r === this.mask);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for bigint & bigint, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Bitwise AND on boolean operands produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_BitwiseOnBoolean_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "BitwiseBool",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "a", Type: PrimitiveType{Name: "boolean"}},
					{Name: "b", Type: PrimitiveType{Name: "boolean"}},
				},
				Body: []Statement{
					// a & b where both are boolean — should be an error
					VariableDeclStmt{
						Name: "r",
						Init: BinaryExpr{
							Op:    "&",
							Left:  Identifier{Name: "a"},
							Right: Identifier{Name: "b"},
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

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "boolean") || strings.Contains(e, "bigint") || strings.Contains(e, "&") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for boolean & boolean (bitwise on boolean), got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Bitwise AND on ByteString operands is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_BitwiseOnByteString_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BitwiseBS extends SmartContract {
  readonly mask: ByteString;

  constructor(mask: ByteString) {
    super(mask);
    this.mask = mask;
  }

  public check(a: ByteString, b: ByteString): void {
    const r = a & b;
    assert(r === this.mask);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for ByteString & ByteString, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Bitwise NOT on ByteString is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_BitwiseNotOnByteString_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class BitwiseNotBS extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public check(a: ByteString): void {
    const r = ~a;
    assert(r === this.expected);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for ~ByteString, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Logical NOT on boolean is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_LogicalNotOnBoolean_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class LogicalNotBool extends SmartContract {
  readonly flag: boolean;

  constructor(flag: boolean) {
    super(flag);
    this.flag = flag;
  }

  public check(a: boolean): void {
    const r = !a;
    assert(r === this.flag);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for !boolean, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Logical NOT on bigint produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_LogicalNotOnBigint_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "LogicalNotBigint",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "a", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					// !a where a is bigint — should error
					VariableDeclStmt{
						Name: "r",
						Init: UnaryExpr{
							Op:      "!",
							Operand: Identifier{Name: "a"},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{Identifier{Name: "r"}},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "boolean") || strings.Contains(e, "bigint") || strings.Contains(e, "!") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for !bigint (logical not on non-boolean), got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test: Unary minus on bigint is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_UnaryMinusOnBigint_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class UnaryMinus extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public check(a: bigint): void {
    const r = -a;
    assert(r === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for -bigint, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: assert with 2 args (condition + message) is OK
// ---------------------------------------------------------------------------

func TestTypeCheck_AssertWithMessage_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class AssertMsg extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public check(val: bigint): void {
    assert(val === this.n, "values must match");
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for assert(cond, msg), got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test: Comparing bigint === ByteString produces type error
// ---------------------------------------------------------------------------

func TestTypeCheck_IncompatibleEquality_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "IncompatEq",
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
				Name:       "check",
				Visibility: "public",
				Params: []ParamNode{
					{Name: "n", Type: PrimitiveType{Name: "bigint"}},
					{Name: "bs", Type: PrimitiveType{Name: "ByteString"}},
				},
				Body: []Statement{
					// n === bs — comparing bigint with ByteString
					VariableDeclStmt{
						Name: "r",
						Init: BinaryExpr{
							Op:    "===",
							Left:  Identifier{Name: "n"},
							Right: Identifier{Name: "bs"},
						},
					},
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args:   []Expression{Identifier{Name: "r"}},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "compare") || strings.Contains(e, "bigint") || strings.Contains(e, "ByteString") || strings.Contains(e, "===") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for bigint === ByteString, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test T4: typecheck — valid hash function calls pass
// ---------------------------------------------------------------------------

func TestTypeCheck_ValidHashFunctionCalls(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, sha256 } from 'runar-lang';

class HashTest extends SmartContract {
  readonly expected: Sha256;

  constructor(expected: Sha256) {
    super(expected);
    this.expected = expected;
  }

  public verify(pk: PubKey): void {
    const h = sha256(pk);
    assert(h === this.expected);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for sha256(pk), got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T5: typecheck — checkSig: wrong first arg type rejected
// ---------------------------------------------------------------------------

func TestTypeCheck_CheckSigWrongFirstArgType_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "BadCheckSigFirst",
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
					{Name: "someBytes", Type: PrimitiveType{Name: "ByteString"}},
					{Name: "pubkey", Type: PrimitiveType{Name: "PubKey"}},
				},
				Body: []Statement{
					// checkSig(someBytes, pubkey) — first arg is ByteString, not Sig
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								CallExpr{
									Callee: Identifier{Name: "checkSig"},
									Args:   []Expression{Identifier{Name: "someBytes"}, Identifier{Name: "pubkey"}},
								},
							},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "Sig") || strings.Contains(e, "argument") || strings.Contains(e, "type") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for checkSig(ByteString, PubKey) — first arg must be Sig, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test T6: typecheck — checkSig: second arg not PubKey rejected
// ---------------------------------------------------------------------------

func TestTypeCheck_CheckSigWrongSecondArgType_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "BadCheckSigSecond",
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
					{Name: "sig", Type: PrimitiveType{Name: "Sig"}},
					{Name: "bytes", Type: PrimitiveType{Name: "ByteString"}},
				},
				Body: []Statement{
					// checkSig(sig, bytes) — second arg is ByteString, not PubKey
					ExpressionStmt{
						Expr: CallExpr{
							Callee: Identifier{Name: "assert"},
							Args: []Expression{
								CallExpr{
									Callee: Identifier{Name: "checkSig"},
									Args:   []Expression{Identifier{Name: "sig"}, Identifier{Name: "bytes"}},
								},
							},
						},
					},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "PubKey") || strings.Contains(e, "argument") || strings.Contains(e, "type") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for checkSig(Sig, ByteString) — second arg must be PubKey, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test T10: typecheck — bigint subtraction allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_BigintSubtraction_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class SubTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    const diff: bigint = a - b;
    assert(diff === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for bigint subtraction, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T11: typecheck — bigint multiplication and division allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_BigintMulDiv_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class MulDivTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    const prod: bigint = a * b;
    const quot: bigint = a / b;
    assert(prod === this.target);
    assert(quot === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for bigint * and /, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T16: typecheck — mixed bigint & ByteString in bitwise op rejected
// ---------------------------------------------------------------------------

func TestTypeCheck_MixedBitwiseBigintByteString_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "MixedBitwise",
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
					{Name: "n", Type: PrimitiveType{Name: "bigint"}},
					{Name: "bs", Type: PrimitiveType{Name: "ByteString"}},
				},
				Body: []Statement{
					// 1n & bs — bigint & ByteString is an error
					VariableDeclStmt{
						Name: "r",
						Init: BinaryExpr{
							Op:    "&",
							Left:  Identifier{Name: "n"},
							Right: Identifier{Name: "bs"},
						},
					},
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{BoolLiteral{Value: true}}}},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for bigint & ByteString (mixed bitwise types), got no errors")
	}
}

// ---------------------------------------------------------------------------
// Test T18: typecheck — PubKey + ByteString (byte subtype concat) allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_PubKeyPlusByteString_OK(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey } from 'runar-lang';

class ConcatTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(pubkey: PubKey, extra: ByteString): void {
    const cat = pubkey + extra;
    assert(cat === this.expected);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for PubKey + ByteString (subtype concat), got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T20: typecheck — comparison operators return boolean (usable in assert)
// ---------------------------------------------------------------------------

func TestTypeCheck_ComparisonInAssert_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class CmpTest extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public verify(a: bigint, b: bigint): void {
    assert(a > b);
    assert(a >= b);
    assert(a < b);
    assert(a <= b);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for comparison operators in assert, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T21: typecheck — equality === returns boolean
// ---------------------------------------------------------------------------

func TestTypeCheck_EqualityInAssert_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class EqTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint): void {
    assert(a === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for a === b in assert, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T24: typecheck — bigint in logical operator rejected
// ---------------------------------------------------------------------------

func TestTypeCheck_BigintInLogicalAnd_Error(t *testing.T) {
	contract := &ContractNode{
		Name:        "LogicalBigint",
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
					{Name: "a", Type: PrimitiveType{Name: "bigint"}},
					{Name: "b", Type: PrimitiveType{Name: "bigint"}},
				},
				Body: []Statement{
					// 1n && 2n — bigints in logical && should be an error
					VariableDeclStmt{
						Name: "r",
						Init: BinaryExpr{
							Op:    "&&",
							Left:  Identifier{Name: "a"},
							Right: Identifier{Name: "b"},
						},
					},
					ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{Identifier{Name: "r"}}}},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "boolean") || strings.Contains(e, "&&") || strings.Contains(e, "bigint") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for bigint && bigint (logical op requires boolean), got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test T29: typecheck — assigning wrong type to declared variable rejected
// ---------------------------------------------------------------------------

func TestTypeCheck_WrongTypeAssignment_Error(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class WrongAssign extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(): void {
    const y: bigint = true;
    assert(y === this.x);
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "boolean") || strings.Contains(e, "bigint") || strings.Contains(e, "type") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected type error for const x: bigint = true (type mismatch), got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Test T32: typecheck — this.x resolves to property type (no error)
// ---------------------------------------------------------------------------

func TestTypeCheck_ThisPropertyResolves_OK(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class PropAccess extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig): void {
    assert(checkSig(sig, this.pk));
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for this.pk access, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T39: typecheck — non-affine type (PubKey) can be reused freely
// ---------------------------------------------------------------------------

func TestTypeCheck_PubKeyReused_OK(t *testing.T) {
	source := `
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class ReuseKey extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig1: Sig, sig2: Sig): void {
    assert(checkSig(sig1, this.pk));
    assert(checkSig(sig2, this.pk));
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)

	// PubKey is not an affine type — it can be used multiple times
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "affine") || strings.Contains(e, "once") || (strings.Contains(e, "PubKey") && strings.Contains(e, "consumed")) {
			t.Errorf("expected PubKey to be reusable, but got affine/linear error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test T43: typecheck — known Rúnar builtins allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_KnownBuiltinsAllowed(t *testing.T) {
	source := `
import { SmartContract, assert, abs, min } from 'runar-lang';

class BuiltinTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    const absA = abs(a);
    const minVal = min(a, b);
    assert(absA === this.target);
    assert(minVal === this.target);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for known Rúnar builtins abs/min, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Test T44: typecheck — split builtin allowed on ByteString
// NOTE: split is not in builtinFunctions map → this test documents expected
// behavior. It currently fails (source bug — T44 source bug).
// ---------------------------------------------------------------------------

func TestTypeCheck_SplitBuiltinOnByteString_OK(t *testing.T) {
	source := `
import { SmartContract, assert, ByteString } from 'runar-lang';

class SplitTest extends SmartContract {
  readonly data: ByteString;

  constructor(data: ByteString) {
    super(data);
    this.data = data;
  }

  public check(pos: bigint): void {
    const left = split(this.data, pos);
    assert(left === this.data);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)

	// split() must not produce an "unknown function" error
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "split") && strings.Contains(e, "unknown") {
			t.Errorf("split() was rejected as unknown function: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test T45: typecheck — private contract method calls allowed
// ---------------------------------------------------------------------------

func TestTypeCheck_PrivateMethodCallAllowed(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class PrivateMethod extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  private helper(a: bigint): bigint {
    return a + 1n;
  }

  public check(val: bigint): void {
    const r = this.helper(val);
    assert(r === this.x);
  }
}
`
	contract := mustParseTS(t, source)

	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}

	tcResult := TypeCheck(contract)

	// Calling a private method should not produce an "unknown function" error
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "unknown") && (strings.Contains(e, "helper") || strings.Contains(e, "method")) {
			t.Errorf("expected private method call to be allowed, but got unknown-function error: %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: SigHashPreimage used in two checkPreimage calls → affine error
// ---------------------------------------------------------------------------

func TestTypeCheck_SigHashPreimageUsedTwice_Error(t *testing.T) {
	source := `
import { SmartContract, assert, SigHashPreimage, checkPreimage } from 'runar-lang';

class PreimageTwice extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(preimage: SigHashPreimage): void {
    assert(checkPreimage(preimage));
    assert(checkPreimage(preimage));
  }
}
`
	contract := mustParseTS(t, source)

	tcResult := TypeCheck(contract)

	found := false
	for _, e := range tcResult.Errors {
		if strings.Contains(e, "affine") || strings.Contains(e, "consumed") || strings.Contains(e, "SigHashPreimage") || strings.Contains(e, "once") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected affine/linear type error for SigHashPreimage used twice in checkPreimage, got: %v", tcResult.Errors)
	}
}

// ---------------------------------------------------------------------------
// Row 110: Inequality (!==) returns boolean → no errors
// ---------------------------------------------------------------------------

func TestTypeCheck_Inequality_OK(t *testing.T) {
	source := `
import { SmartContract, assert } from 'runar-lang';

class Test extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public check(v: bigint): void {
    assert(v !== this.x);
  }
}
`
	contract := mustParseTS(t, source)
	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}
	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for !==, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Row 122: Sig used once → valid (no affine error)
// ---------------------------------------------------------------------------

func TestTypeCheck_SigUsedOnce_OK(t *testing.T) {
	source := `
import { SmartContract, assert, Sig, PubKey, checkSig } from 'runar-lang';

class Test extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(sig: Sig): void {
    assert(checkSig(sig, this.pk));
  }
}
`
	contract := mustParseTS(t, source)
	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}
	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for Sig used once, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Row 126: sha256 with wrong argument type → error
// ---------------------------------------------------------------------------

func TestTypeCheck_SHA256WrongArgType_Error(t *testing.T) {
	// sha256 expects ByteString, not bigint
	contract := &ContractNode{
		Name:        "Bad",
		ParentClass: "SmartContract",
		Properties:  []PropertyNode{{Name: "x", Type: PrimitiveType{Name: "bigint"}, Readonly: true}},
		Constructor: MethodNode{
			Name:       "constructor",
			Visibility: "private",
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{Callee: Identifier{Name: "super"}, Args: []Expression{Identifier{Name: "x"}}}},
				AssignmentStmt{Target: PropertyAccessExpr{Property: "x"}, Value: Identifier{Name: "x"}},
			},
			Params: []ParamNode{{Name: "x", Type: PrimitiveType{Name: "bigint"}}},
		},
		Methods: []MethodNode{
			{
				Name:       "check",
				Visibility: "public",
				Params:     []ParamNode{{Name: "n", Type: PrimitiveType{Name: "bigint"}}},
				Body: []Statement{
					// const h = sha256(n) — n is bigint, sha256 expects ByteString
					VariableDeclStmt{
						Name: "h",
						Type: PrimitiveType{Name: "Sha256"},
						Init: CallExpr{
							Callee: Identifier{Name: "sha256"},
							Args:   []Expression{Identifier{Name: "n"}},
						},
					},
					ExpressionStmt{Expr: CallExpr{
						Callee: Identifier{Name: "assert"},
						Args:   []Expression{BoolLiteral{Value: true}},
					}},
				},
			},
		},
	}

	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) == 0 {
		t.Error("expected type error for sha256(bigint), got no errors")
	}
}

// ---------------------------------------------------------------------------
// Row 145: num2bin argument types pass type check
// ---------------------------------------------------------------------------

func TestTypeCheck_Num2Bin_OK(t *testing.T) {
	source := `
import { SmartContract, assert, ByteString, num2bin } from 'runar-lang';

class Test extends SmartContract {
  readonly expected: ByteString;
  constructor(e: ByteString) { super(e); this.expected = e; }
  public check(n: bigint, size: bigint): void {
    const result: ByteString = num2bin(n, size);
    assert(result === this.expected);
  }
}
`
	contract := mustParseTS(t, source)
	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}
	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for num2bin(bigint, bigint), got: %s", strings.Join(tcResult.Errors, "; "))
	}
}

// ---------------------------------------------------------------------------
// Row 146: Different Sigs (sig1, sig2) each used once → no affine error
// ---------------------------------------------------------------------------

func TestTypeCheck_DifferentSigs_OK(t *testing.T) {
	source := `
import { SmartContract, assert, Sig, PubKey, checkSig } from 'runar-lang';

class MultiSig extends SmartContract {
  readonly pk1: PubKey;
  readonly pk2: PubKey;
  constructor(pk1: PubKey, pk2: PubKey) { super(pk1, pk2); this.pk1 = pk1; this.pk2 = pk2; }
  public unlock(sig1: Sig, sig2: Sig): void {
    assert(checkSig(sig1, this.pk1));
    assert(checkSig(sig2, this.pk2));
  }
}
`
	contract := mustParseTS(t, source)
	valResult := Validate(contract)
	if len(valResult.Errors) > 0 {
		t.Fatalf("validation failed: %s", strings.Join(valResult.Errors, "; "))
	}
	tcResult := TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		t.Errorf("expected no type errors for two distinct Sigs used once each, got: %s", strings.Join(tcResult.Errors, "; "))
	}
}
