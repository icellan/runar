package frontend

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeTestANFProgram(methods []ir.ANFMethod) *ir.ANFProgram {
	return &ir.ANFProgram{
		ContractName: "Test",
		Properties:   nil,
		Methods:      methods,
	}
}

func makeTestMethod(name string, body []ir.ANFBinding) ir.ANFMethod {
	return ir.ANFMethod{
		Name:     name,
		Params:   nil,
		Body:     body,
		IsPublic: true,
	}
}

func mkInt(val int64) ir.ANFValue  { return makeLoadConstInt(val) }
func mkBool(val bool) ir.ANFValue  { return makeLoadConstBool(val) }
func mkStr(val string) ir.ANFValue { return makeLoadConstString(val) }
func binOp(op, left, right string) ir.ANFValue {
	return ir.ANFValue{Kind: "bin_op", Op: op, Left: left, Right: right}
}
func unaryOp(op, operand string) ir.ANFValue {
	return ir.ANFValue{Kind: "unary_op", Op: op, Operand: operand}
}
func loadParam(name string) ir.ANFValue {
	return ir.ANFValue{Kind: "load_param", Name: name}
}
func loadProp(name string) ir.ANFValue {
	return ir.ANFValue{Kind: "load_prop", Name: name}
}
func callFunc(funcName string, args []string) ir.ANFValue {
	return ir.ANFValue{Kind: "call", Func: funcName, Args: args}
}
func b(name string, value ir.ANFValue) ir.ANFBinding {
	return ir.ANFBinding{Name: name, Value: value}
}

func assertLoadConstBigInt(t *testing.T, binding ir.ANFBinding, expected int64) {
	t.Helper()
	if binding.Value.Kind != "load_const" {
		t.Fatalf("expected load_const, got %s", binding.Value.Kind)
	}
	if binding.Value.ConstBigInt == nil {
		t.Fatal("ConstBigInt is nil")
	}
	if binding.Value.ConstBigInt.Int64() != expected {
		t.Fatalf("expected %d, got %d", expected, binding.Value.ConstBigInt.Int64())
	}
}

func assertLoadConstBool(t *testing.T, binding ir.ANFBinding, expected bool) {
	t.Helper()
	if binding.Value.Kind != "load_const" {
		t.Fatalf("expected load_const, got %s", binding.Value.Kind)
	}
	if binding.Value.ConstBool == nil {
		t.Fatal("ConstBool is nil")
	}
	if *binding.Value.ConstBool != expected {
		t.Fatalf("expected %v, got %v", expected, *binding.Value.ConstBool)
	}
}

func assertLoadConstString(t *testing.T, binding ir.ANFBinding, expected string) {
	t.Helper()
	if binding.Value.Kind != "load_const" {
		t.Fatalf("expected load_const, got %s", binding.Value.Kind)
	}
	if binding.Value.ConstString == nil {
		t.Fatal("ConstString is nil")
	}
	if *binding.Value.ConstString != expected {
		t.Fatalf("expected %q, got %q", expected, *binding.Value.ConstString)
	}
}

func assertNotFolded(t *testing.T, binding ir.ANFBinding, expectedKind string) {
	t.Helper()
	if binding.Value.Kind != expectedKind {
		t.Fatalf("expected kind %s, got %s", expectedKind, binding.Value.Kind)
	}
}

// ---------------------------------------------------------------------------
// Binary operations on bigints
// ---------------------------------------------------------------------------

func TestFoldConstants_Addition(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(20)),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 30)
}

func TestFoldConstants_Subtraction(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(50)),
			b("t1", mkInt(20)),
			b("t2", binOp("-", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 30)
}

func TestFoldConstants_Multiplication(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(6)),
			b("t1", mkInt(7)),
			b("t2", binOp("*", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 42)
}

func TestFoldConstants_Division(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(100)),
			b("t1", mkInt(4)),
			b("t2", binOp("/", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 25)
}

func TestFoldConstants_DivByZero(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(100)),
			b("t1", mkInt(0)),
			b("t2", binOp("/", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

func TestFoldConstants_Modulo(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(3)),
			b("t2", binOp("%", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 1)
}

func TestFoldConstants_ModByZero(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(100)),
			b("t1", mkInt(0)),
			b("t2", binOp("%", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

func TestFoldConstants_Comparisons(t *testing.T) {
	tests := []struct {
		op       string
		left     int64
		right    int64
		expected bool
	}{
		{"===", 5, 5, true},
		{"===", 5, 6, false},
		{"!==", 5, 6, true},
		{"<", 3, 5, true},
		{"<", 5, 3, false},
		{">", 5, 3, true},
		{"<=", 5, 5, true},
		{">=", 5, 5, true},
	}
	for _, tc := range tests {
		p := makeTestANFProgram([]ir.ANFMethod{
			makeTestMethod("m", []ir.ANFBinding{
				b("t0", mkInt(tc.left)),
				b("t1", mkInt(tc.right)),
				b("t2", binOp(tc.op, "t0", "t1")),
			}),
		})
		result := foldConstantsOnly(p)
		assertLoadConstBool(t, result.Methods[0].Body[2], tc.expected)
	}
}

// ---------------------------------------------------------------------------
// Shift operators
// ---------------------------------------------------------------------------

func TestFoldConstants_LeftShift(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(1)),
			b("t1", mkInt(3)),
			b("t2", binOp("<<", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 8)
}

func TestFoldConstants_RightShiftNonNegative(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(16)),
			b("t1", mkInt(2)),
			b("t2", binOp(">>", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 4)
}

func TestFoldConstants_RightShiftNegativeNotFolded(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(-8)),
			b("t1", mkInt(1)),
			b("t2", binOp(">>", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

// ---------------------------------------------------------------------------
// Bitwise operators
// ---------------------------------------------------------------------------

func TestFoldConstants_BitwiseOps(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0b1100)),
			b("t1", mkInt(0b1010)),
			b("t2", binOp("&", "t0", "t1")),
			b("t3", binOp("|", "t0", "t1")),
			b("t4", binOp("^", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 0b1000)
	assertLoadConstBigInt(t, result.Methods[0].Body[3], 0b1110)
	assertLoadConstBigInt(t, result.Methods[0].Body[4], 0b0110)
}

// ---------------------------------------------------------------------------
// Boolean operations
// ---------------------------------------------------------------------------

func TestFoldConstants_BooleanAndOr(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", mkBool(false)),
			b("t2", binOp("&&", "t0", "t1")),
			b("t3", binOp("||", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[2], false)
	assertLoadConstBool(t, result.Methods[0].Body[3], true)
}

func TestFoldConstants_BooleanEquality(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", mkBool(true)),
			b("t2", binOp("===", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[2], true)
}

// ---------------------------------------------------------------------------
// String (ByteString) operations
// ---------------------------------------------------------------------------

func TestFoldConstants_HexConcat(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkStr("ab")),
			b("t1", mkStr("cd")),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstString(t, result.Methods[0].Body[2], "abcd")
}

func TestFoldConstants_InvalidHexNotFolded(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkStr("aabb")),
			b("t1", mkStr("zzzz")),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

func TestFoldConstants_InvalidHexLeftNotFolded(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkStr("xyz1")),
			b("t1", mkStr("aabb")),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

func TestFoldConstants_StringEquality(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkStr("abc")),
			b("t1", mkStr("abc")),
			b("t2", binOp("===", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[2], true)
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

func TestFoldConstants_BoolNegation(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", unaryOp("!", "t0")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[1], false)
}

func TestFoldConstants_BigIntNegation(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(42)),
			b("t1", unaryOp("-", "t0")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], -42)
}

func TestFoldConstants_BitwiseComplement(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0)),
			b("t1", unaryOp("~", "t0")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], -1)
}

func TestFoldConstants_NotOnBigIntZero(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0)),
			b("t1", unaryOp("!", "t0")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[1], true)
}

// ---------------------------------------------------------------------------
// Constant propagation
// ---------------------------------------------------------------------------

func TestFoldConstants_PropagatesThroughChains(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(20)),
			b("t2", binOp("+", "t0", "t1")),
			b("t3", mkInt(12)),
			b("t4", binOp("+", "t2", "t3")),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[4], 42)
}

func TestFoldConstants_DoesNotFoldWithParam(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("x")),
			b("t1", mkInt(5)),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "bin_op")
}

// ---------------------------------------------------------------------------
// If-branch folding
// ---------------------------------------------------------------------------

func TestFoldConstants_FoldsAwayFalseBranch(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", ir.ANFValue{
				Kind: "if",
				Cond: "t0",
				Then: []ir.ANFBinding{b("t2", mkInt(42))},
				Else: []ir.ANFBinding{b("t3", mkInt(99))},
			}),
		}),
	})
	result := foldConstantsOnly(p)
	ifVal := result.Methods[0].Body[1].Value
	if ifVal.Kind != "if" {
		t.Fatalf("expected if, got %s", ifVal.Kind)
	}
	if len(ifVal.Then) != 1 {
		t.Fatalf("expected 1 then binding, got %d", len(ifVal.Then))
	}
	if len(ifVal.Else) != 0 {
		t.Fatalf("expected 0 else bindings, got %d", len(ifVal.Else))
	}
}

func TestFoldConstants_FoldsAwayTrueBranch(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(false)),
			b("t1", ir.ANFValue{
				Kind: "if",
				Cond: "t0",
				Then: []ir.ANFBinding{b("t2", mkInt(42))},
				Else: []ir.ANFBinding{b("t3", mkInt(99))},
			}),
		}),
	})
	result := foldConstantsOnly(p)
	ifVal := result.Methods[0].Body[1].Value
	if len(ifVal.Then) != 0 {
		t.Fatalf("expected 0 then bindings, got %d", len(ifVal.Then))
	}
	if len(ifVal.Else) != 1 {
		t.Fatalf("expected 1 else binding, got %d", len(ifVal.Else))
	}
}

func TestFoldConstants_FoldsInsideBothBranches(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("flag")),
			b("c1", mkInt(5)),
			b("c2", mkInt(3)),
			b("t1", ir.ANFValue{
				Kind: "if",
				Cond: "t0",
				Then: []ir.ANFBinding{b("t2", binOp("+", "c1", "c2"))},
				Else: []ir.ANFBinding{b("t3", binOp("-", "c1", "c2"))},
			}),
		}),
	})
	result := foldConstantsOnly(p)
	ifVal := result.Methods[0].Body[3].Value
	assertLoadConstBigInt(t, ifVal.Then[0], 8)
	assertLoadConstBigInt(t, ifVal.Else[0], 2)
}

// ---------------------------------------------------------------------------
// Loop folding
// ---------------------------------------------------------------------------

func TestFoldConstants_FoldsInsideLoopBody(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("c1", mkInt(10)),
			b("c2", mkInt(20)),
			b("t0", ir.ANFValue{
				Kind:    "loop",
				Count:   5,
				IterVar: "i",
				Body:    []ir.ANFBinding{b("t1", binOp("+", "c1", "c2"))},
			}),
		}),
	})
	result := foldConstantsOnly(p)
	loopVal := result.Methods[0].Body[2].Value
	if loopVal.Kind != "loop" {
		t.Fatalf("expected loop, got %s", loopVal.Kind)
	}
	assertLoadConstBigInt(t, loopVal.Body[0], 30)
}

// ---------------------------------------------------------------------------
// Non-foldable values pass through
// ---------------------------------------------------------------------------

func TestFoldConstants_LoadParamUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("x")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[0], "load_param")
}

func TestFoldConstants_LoadPropUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadProp("pk")),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[0], "load_prop")
}

func TestFoldConstants_CallUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("x")),
			b("t1", callFunc("hash160", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[1], "call")
}

func TestFoldConstants_AssertUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", ir.ANFValue{Kind: "assert", ValueRef: "t0"}),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[1], "assert")
}

func TestFoldConstants_UpdatePropUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0)),
			b("t1", ir.ANFValue{Kind: "update_prop", Name: "count", ValueRef: "t0"}),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[1], "update_prop")
}

func TestFoldConstants_CheckPreimageUnchanged(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("preimage")),
			b("t1", ir.ANFValue{Kind: "check_preimage", Preimage: "t0"}),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[1], "check_preimage")
}

// ---------------------------------------------------------------------------
// Pure math builtin folding
// ---------------------------------------------------------------------------

func TestFoldConstants_Abs(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(-5)),
			b("t1", callFunc("abs", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], 5)
}

func TestFoldConstants_Min(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(3)),
			b("t1", mkInt(7)),
			b("t2", callFunc("min", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 3)
}

func TestFoldConstants_Max(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(3)),
			b("t1", mkInt(7)),
			b("t2", callFunc("max", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 7)
}

func TestFoldConstants_Safediv(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(3)),
			b("t2", callFunc("safediv", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 3)
}

func TestFoldConstants_SafedivByZero(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(0)),
			b("t2", callFunc("safediv", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertNotFolded(t, result.Methods[0].Body[2], "call")
}

func TestFoldConstants_Safemod(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(3)),
			b("t2", callFunc("safemod", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 1)
}

func TestFoldConstants_Clamp(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(15)),
			b("t1", mkInt(0)),
			b("t2", mkInt(10)),
			b("t3", callFunc("clamp", []string{"t0", "t1", "t2"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[3], 10)
}

func TestFoldConstants_Sign(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(-42)),
			b("t1", callFunc("sign", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], -1)
}

func TestFoldConstants_Pow(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(2)),
			b("t1", mkInt(10)),
			b("t2", callFunc("pow", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 1024)
}

func TestFoldConstants_MulDiv(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(20)),
			b("t2", mkInt(3)),
			b("t3", callFunc("mulDiv", []string{"t0", "t1", "t2"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[3], 66)
}

func TestFoldConstants_PercentOf(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(1000)),
			b("t1", mkInt(500)),
			b("t2", callFunc("percentOf", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 50)
}

func TestFoldConstants_Sqrt(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(144)),
			b("t1", callFunc("sqrt", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], 12)
}

func TestFoldConstants_Gcd(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(12)),
			b("t1", mkInt(8)),
			b("t2", callFunc("gcd", []string{"t0", "t1"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[2], 4)
}

func TestFoldConstants_Log2(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(256)),
			b("t1", callFunc("log2", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBigInt(t, result.Methods[0].Body[1], 8)
}

func TestFoldConstants_Bool(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0)),
			b("t1", callFunc("bool", []string{"t0"})),
		}),
	})
	result := foldConstantsOnly(p)
	assertLoadConstBool(t, result.Methods[0].Body[1], false)
}

// ---------------------------------------------------------------------------
// Dead binding elimination (tested via eliminateDeadBindings after fold)
// ---------------------------------------------------------------------------

// foldAndEliminate is a test helper that folds constants then eliminates dead bindings,
// mirroring the full pipeline behavior (FoldConstants + EC optimizer's DCE).
func foldAndEliminate(p *ir.ANFProgram) *ir.ANFProgram {
	result := FoldConstants(p)
	for i := range result.Methods {
		eliminateDeadBindings(&result.Methods[i])
	}
	return result
}

func TestFoldConstants_RemovesUnusedBindings(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(42)), // unused
			b("t1", mkBool(true)),
			b("t2", ir.ANFValue{Kind: "assert", ValueRef: "t1"}),
		}),
	})
	result := foldAndEliminate(p)
	for _, binding := range result.Methods[0].Body {
		if binding.Name == "t0" {
			t.Fatal("expected t0 to be removed")
		}
	}
}

func TestFoldConstants_KeepsSideEffects(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkBool(true)),
			b("t1", ir.ANFValue{Kind: "assert", ValueRef: "t0"}),
			b("t2", mkInt(99)), // unused
		}),
	})
	result := foldAndEliminate(p)
	found := false
	for _, binding := range result.Methods[0].Body {
		if binding.Name == "t1" {
			found = true
		}
		if binding.Name == "t2" {
			t.Fatal("expected t2 to be removed")
		}
	}
	if !found {
		t.Fatal("expected t1 (assert) to be kept")
	}
}

func TestFoldConstants_RemovesTransitivelyDead(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(10)),
			b("t1", mkInt(20)),
			b("t2", binOp("+", "t0", "t1")), // unused
			b("t3", mkBool(true)),
			b("t4", ir.ANFValue{Kind: "assert", ValueRef: "t3"}),
		}),
	})
	result := foldAndEliminate(p)
	for _, binding := range result.Methods[0].Body {
		if binding.Name == "t0" || binding.Name == "t1" || binding.Name == "t2" {
			t.Fatalf("expected %s to be removed", binding.Name)
		}
	}
}

func TestFoldConstants_PreservesAllWhenUsed(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", loadParam("x")),
			b("t1", mkInt(5)),
			b("t2", binOp("===", "t0", "t1")),
			b("t3", ir.ANFValue{Kind: "assert", ValueRef: "t2"}),
		}),
	})
	result := foldAndEliminate(p)
	if len(result.Methods[0].Body) != 4 {
		t.Fatalf("expected 4 bindings, got %d", len(result.Methods[0].Body))
	}
}

func TestFoldConstants_KeepsUpdateProp(t *testing.T) {
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			b("t0", mkInt(0)),
			b("t1", ir.ANFValue{Kind: "update_prop", Name: "count", ValueRef: "t0"}),
		}),
	})
	result := foldAndEliminate(p)
	if len(result.Methods[0].Body) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(result.Methods[0].Body))
	}
}

// Ensure big.Int is used for non-int64 range values
func TestFoldConstants_LargeBigInt(t *testing.T) {
	largeVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(100), nil)
	raw := []byte(`"` + largeVal.String() + `"`)
	p := makeTestANFProgram([]ir.ANFMethod{
		makeTestMethod("m", []ir.ANFBinding{
			{Name: "t0", Value: ir.ANFValue{
				Kind: "load_const", RawValue: raw, ConstBigInt: largeVal,
			}},
			b("t1", mkInt(1)),
			b("t2", binOp("+", "t0", "t1")),
		}),
	})
	result := foldConstantsOnly(p)
	binding := result.Methods[0].Body[2]
	if binding.Value.Kind != "load_const" {
		t.Fatalf("expected load_const, got %s", binding.Value.Kind)
	}
	expected := new(big.Int).Add(largeVal, big.NewInt(1))
	if binding.Value.ConstBigInt.Cmp(expected) != 0 {
		t.Fatalf("expected %s, got %s", expected.String(), binding.Value.ConstBigInt.String())
	}
}
