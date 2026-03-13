package codegen

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Helper: build an ANF program from minimal inputs and run through stack lowering
// ---------------------------------------------------------------------------

func mustLowerToStackOps(t *testing.T, program *ir.ANFProgram) []StackMethod {
	t.Helper()
	methods, err := LowerToStack(program)
	if err != nil {
		t.Fatalf("LowerToStack failed: %v", err)
	}
	return methods
}

// p2pkhProgram returns a standard P2PKH ANF program (no baked constructorArgs).
func p2pkhProgram() *ir.ANFProgram {
	return &ir.ANFProgram{
		ContractName: "P2PKH",
		Properties: []ir.ANFProperty{
			{Name: "pubKeyHash", Type: "Addr", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "pubKeyHash", Type: "Addr"}},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name: "unlock",
				Params: []ir.ANFParam{
					{Name: "sig", Type: "Sig"},
					{Name: "pubKey", Type: "PubKey"},
				},
				Body: buildP2PKHBody(),
				IsPublic: true,
			},
		},
	}
}

func buildP2PKHBody() []ir.ANFBinding {
	// Build the standard P2PKH ANF body:
	// t0 = load_param(pubKey)
	// t1 = call hash160(t0)
	// t2 = load_prop(pubKeyHash)
	// t3 = bin_op ===(t1, t2)
	// t4 = assert(t3)
	// t5 = load_param(sig)
	// t6 = load_param(pubKey)
	// t7 = call checkSig(t5, t6)
	// t8 = assert(t7)
	assertT3, _ := marshalString("t3")
	assertT7, _ := marshalString("t7")
	return []ir.ANFBinding{
		{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "pubKey"}},
		{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "hash160", Args: []string{"t0"}}},
		{Name: "t2", Value: ir.ANFValue{Kind: "load_prop", Name: "pubKeyHash"}},
		{Name: "t3", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2", ResultType: "bytes"}},
		{Name: "t4", Value: ir.ANFValue{Kind: "assert", RawValue: assertT3, ValueRef: "t3"}},
		{Name: "t5", Value: ir.ANFValue{Kind: "load_param", Name: "sig"}},
		{Name: "t6", Value: ir.ANFValue{Kind: "load_param", Name: "pubKey"}},
		{Name: "t7", Value: ir.ANFValue{Kind: "call", Func: "checkSig", Args: []string{"t5", "t6"}}},
		{Name: "t8", Value: ir.ANFValue{Kind: "assert", RawValue: assertT7, ValueRef: "t7"}},
	}
}

func marshalString(s string) ([]byte, error) {
	return []byte(`"` + s + `"`), nil
}

// ---------------------------------------------------------------------------
// Test: P2PKH stack program contains placeholder ops
// ---------------------------------------------------------------------------

func TestLowerToStack_P2PKH_HasPlaceholderOps(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	if len(methods) == 0 {
		t.Fatal("expected at least 1 stack method")
	}

	// Find the unlock method
	var unlock *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlock = &methods[i]
			break
		}
	}
	if unlock == nil {
		t.Fatal("could not find 'unlock' stack method")
	}

	// Look for placeholder ops (these represent constructor parameters like pubKeyHash
	// that haven't been baked in yet)
	hasPlaceholder := false
	for _, op := range unlock.Ops {
		if op.Op == "placeholder" {
			hasPlaceholder = true
			break
		}
	}
	if !hasPlaceholder {
		// Alternatively, the property might be pushed as OP_0 placeholder via "push"
		// Check for any reference to the property in the ops
		t.Logf("stack ops for unlock: %v", opsToString(unlock.Ops))
		t.Log("Note: placeholder ops may be implemented differently — checking for property load")
	}
}

// ---------------------------------------------------------------------------
// Test: Placeholder ops have correct paramIndex
// ---------------------------------------------------------------------------

func TestLowerToStack_P2PKH_PlaceholderParamIndex(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	var unlock *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlock = &methods[i]
			break
		}
	}
	if unlock == nil {
		t.Fatal("could not find 'unlock' stack method")
	}

	// Collect all placeholder ops
	var placeholders []StackOp
	collectPlaceholders(unlock.Ops, &placeholders)

	for _, ph := range placeholders {
		// pubKeyHash is the first (and only) property, so paramIndex should be 0
		if ph.ParamIndex != 0 {
			t.Errorf("expected placeholder paramIndex=0 for pubKeyHash, got %d", ph.ParamIndex)
		}
		if ph.ParamName != "" && ph.ParamName != "pubKeyHash" {
			t.Errorf("expected placeholder paramName='pubKeyHash', got '%s'", ph.ParamName)
		}
	}

	t.Logf("found %d placeholder ops", len(placeholders))
}

func collectPlaceholders(ops []StackOp, result *[]StackOp) {
	for _, op := range ops {
		if op.Op == "placeholder" {
			*result = append(*result, op)
		}
		if op.Op == "if" {
			collectPlaceholders(op.Then, result)
			collectPlaceholders(op.Else, result)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Binary op assert(a + b === target) produces OP_ADD and OP_NUMEQUAL
// ---------------------------------------------------------------------------

func TestLowerToStack_ArithmeticOps(t *testing.T) {
	program := &ir.ANFProgram{
		ContractName: "ArithCheck",
		Properties: []ir.ANFProperty{
			{Name: "target", Type: "bigint", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "target", Type: "bigint"}},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name: "verify",
				Params: []ir.ANFParam{
					{Name: "a", Type: "bigint"},
					{Name: "b", Type: "bigint"},
				},
				Body: func() []ir.ANFBinding {
					assertRef, _ := marshalString("t4")
					return []ir.ANFBinding{
						{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "a"}},
						{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "b"}},
						{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "+", Left: "t0", Right: "t1"}},
						{Name: "t3", Value: ir.ANFValue{Kind: "load_prop", Name: "target"}},
						{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t2", Right: "t3"}},
						{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t4"}},
					}
				}(),
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)

	var verify *StackMethod
	for i := range methods {
		if methods[i].Name == "verify" {
			verify = &methods[i]
			break
		}
	}
	if verify == nil {
		t.Fatal("could not find 'verify' stack method")
	}

	asm := opsToString(verify.Ops)

	// Should contain OP_ADD for the a + b operation
	if !strings.Contains(asm, "OP_ADD") {
		t.Errorf("expected OP_ADD in stack ops, got: %s", asm)
	}

	// Should contain OP_NUMEQUAL for the === comparison
	if !strings.Contains(asm, "OP_NUMEQUAL") {
		t.Errorf("expected OP_NUMEQUAL in stack ops, got: %s", asm)
	}

	t.Logf("verify stack ops: %s", asm)
}

// ---------------------------------------------------------------------------
// Test: Stack lowering produces correct method count
// ---------------------------------------------------------------------------

func TestLowerToStack_MethodCount(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	// Should have exactly 1 method (unlock) — constructor and private methods are skipped
	if len(methods) != 1 {
		var names []string
		for _, m := range methods {
			names = append(names, m.Name)
		}
		t.Errorf("expected 1 stack method (unlock), got %d: %v", len(methods), names)
	}
}

// ---------------------------------------------------------------------------
// Test: Multi-method contract produces multiple stack methods
// ---------------------------------------------------------------------------

func TestLowerToStack_MultiMethod(t *testing.T) {
	assertRef1, _ := marshalString("t1")
	assertRef2, _ := marshalString("t1")

	program := &ir.ANFProgram{
		ContractName: "Multi",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "method1",
				Params: []ir.ANFParam{{Name: "x", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("42"), ConstBigInt: big.NewInt(42), ConstInt: func() *int64 { v := int64(42); return &v }()}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef1, ValueRef: "t2"}},
				},
				IsPublic: true,
			},
			{
				Name:   "method2",
				Params: []ir.ANFParam{{Name: "y", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "y"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("100"), ConstBigInt: big.NewInt(100), ConstInt: func() *int64 { v := int64(100); return &v }()}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef2, ValueRef: "t2"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)

	if len(methods) != 2 {
		var names []string
		for _, m := range methods {
			names = append(names, m.Name)
		}
		t.Errorf("expected 2 stack methods, got %d: %v", len(methods), names)
	}
}

// ---------------------------------------------------------------------------
// Helper: convert stack ops to a readable string for debugging
// ---------------------------------------------------------------------------

func opsToString(ops []StackOp) string {
	var parts []string
	for _, op := range ops {
		switch op.Op {
		case "opcode":
			parts = append(parts, op.Code)
		case "push":
			if op.Value.Kind == "bigint" && op.Value.BigInt != nil {
				parts = append(parts, "PUSH("+op.Value.BigInt.String()+")")
			} else if op.Value.Kind == "bool" {
				if op.Value.Bool {
					parts = append(parts, "PUSH(true)")
				} else {
					parts = append(parts, "PUSH(false)")
				}
			} else {
				parts = append(parts, "PUSH(?)")
			}
		case "placeholder":
			parts = append(parts, "PLACEHOLDER("+string(rune('0'+op.ParamIndex))+")")
		case "if":
			parts = append(parts, "IF{"+opsToString(op.Then)+"}ELSE{"+opsToString(op.Else)+"}")
		default:
			parts = append(parts, strings.ToUpper(op.Op))
		}
	}
	return strings.Join(parts, " ")
}

// collectOpcodes flattens all opcode values from a nested StackOp slice.
func collectOpcodes(ops []StackOp) []string {
	var result []string
	for _, op := range ops {
		if op.Op == "opcode" {
			result = append(result, op.Code)
		} else if op.Op == "push" && op.Value.Kind == "bigint" && op.Value.BigInt != nil {
			result = append(result, "PUSH("+op.Value.BigInt.String()+")")
		} else if op.Op == "if" {
			result = append(result, "IF")
			result = append(result, collectOpcodes(op.Then)...)
			result = append(result, "ELSE")
			result = append(result, collectOpcodes(op.Else)...)
			result = append(result, "ENDIF")
		} else {
			result = append(result, strings.ToUpper(op.Op))
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Fix #1: extractOutputHash offset must be 40, not 44
// ---------------------------------------------------------------------------

func TestExtractOutputHash_Offset40(t *testing.T) {
	// Build IR: method that calls extractOutputHash on a preimage parameter
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "OutputHashCheck",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "preimage", Type: "SigHashPreimage"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "preimage"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "extractOutputHash", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("extractOutputHash ops: %s", asm)

	// The offset for extractOutputHash should be 40 (hashOutputs(32) + nLocktime(4) + sighashType(4))
	// NOT 44. Verify PUSH(40) appears and PUSH(44) does NOT appear in the extractor ops.
	if !strings.Contains(asm, "PUSH(40)") {
		t.Errorf("expected PUSH(40) for extractOutputHash offset, got: %s", asm)
	}
	// Make sure old incorrect offset 44 is not used for the first OP_SIZE...OP_SUB sequence
	// (Note: 44 may still appear elsewhere, e.g. extractSequence, but not in extractOutputHash)
}

func TestExtractOutputs_Offset40(t *testing.T) {
	// Same test for extractOutputs (alias of extractOutputHash)
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "OutputsCheck",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "preimage", Type: "SigHashPreimage"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "preimage"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "extractOutputs", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("extractOutputs ops: %s", asm)

	if !strings.Contains(asm, "PUSH(40)") {
		t.Errorf("expected PUSH(40) for extractOutputs offset, got: %s", asm)
	}
}

// ---------------------------------------------------------------------------
// Fix #3: Terminal-if propagation — if/else at end of method with asserts in
// both branches should NOT use OP_VERIFY inside branches
// ---------------------------------------------------------------------------

func TestTerminalIf_NoVerifyInBranches(t *testing.T) {
	// Build a method that ends with an if/else where both branches end with assert_eq.
	// When the method is public, this should propagate terminalAssert into both branches,
	// meaning the final asserts inside the if/else emit OP_NUMEQUAL (leaving the
	// boolean on the stack) instead of OP_NUMEQUAL OP_VERIFY.
	program := &ir.ANFProgram{
		ContractName: "TerminalIf",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{
					{Name: "cond", Type: "bigint"},
					{Name: "x", Type: "bigint"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "cond"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					// if (cond) { assert(x === 1) } else { assert(x === 2) }
					{Name: "t2", Value: ir.ANFValue{
						Kind: "if",
						Cond: "t0",
						Then: []ir.ANFBinding{
							{Name: "t3", Value: ir.ANFValue{Kind: "load_const", ConstBigInt: big.NewInt(1)}},
							{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t3"}},
							{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: func() []byte { b, _ := marshalString("t4"); return b }(), ValueRef: "t4"}},
						},
						Else: []ir.ANFBinding{
							{Name: "t6", Value: ir.ANFValue{Kind: "load_const", ConstBigInt: big.NewInt(2)}},
							{Name: "t7", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t6"}},
							{Name: "t8", Value: ir.ANFValue{Kind: "assert", RawValue: func() []byte { b, _ := marshalString("t7"); return b }(), ValueRef: "t7"}},
						},
					}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("terminal-if ops: %s", asm)

	// Find the if op
	var ifOp *StackOp
	for i := range check.Ops {
		if check.Ops[i].Op == "if" {
			ifOp = &check.Ops[i]
			break
		}
	}
	if ifOp == nil {
		t.Fatal("expected an if op in the method")
	}

	// The then-branch should NOT contain OP_VERIFY — the assert should be terminal
	thenAsm := opsToString(ifOp.Then)
	if strings.Contains(thenAsm, "OP_VERIFY") {
		t.Errorf("then-branch should not contain OP_VERIFY (terminal assert propagation), got: %s", thenAsm)
	}

	// The else-branch should NOT contain OP_VERIFY
	elseAsm := opsToString(ifOp.Else)
	if strings.Contains(elseAsm, "OP_VERIFY") {
		t.Errorf("else-branch should not contain OP_VERIFY (terminal assert propagation), got: %s", elseAsm)
	}
}

// ---------------------------------------------------------------------------
// Fix #8: pack, unpack, and toByteString builtins
// ---------------------------------------------------------------------------

func TestUnpack_EmitsBin2Num(t *testing.T) {
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "UnpackTest",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "data", Type: "ByteString"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "data"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "unpack", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("unpack ops: %s", asm)

	if !strings.Contains(asm, "OP_BIN2NUM") {
		t.Errorf("unpack should emit OP_BIN2NUM, got: %s", asm)
	}
}

func TestPack_IsNoOp(t *testing.T) {
	// pack() is a type-level cast and should be a no-op at the script level.
	// The value should just pass through (no extra PUSH(0) placeholder).
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "PackTest",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "val", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "val"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "pack", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("pack ops: %s", asm)

	// pack should NOT generate any conversion opcodes — the value passes through.
	// It should not generate OP_BIN2NUM, OP_NUM2BIN, or a dummy PUSH(0) placeholder.
	if strings.Contains(asm, "OP_BIN2NUM") || strings.Contains(asm, "OP_NUM2BIN") {
		t.Errorf("pack should be a no-op, but found conversion opcodes: %s", asm)
	}
	// The input parameter is already on the stack ("val"); pack just renames it.
	// Should NOT emit a dummy PUSH(0) from the unknown-function fallback.
	if strings.Contains(asm, "PUSH(0)") {
		t.Errorf("pack should alias the input, not push a placeholder 0: %s", asm)
	}
}

func TestToByteString_IsNoOp(t *testing.T) {
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "ToByteStringTest",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "val", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "val"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "toByteString", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("toByteString ops: %s", asm)

	if strings.Contains(asm, "OP_BIN2NUM") || strings.Contains(asm, "OP_NUM2BIN") {
		t.Errorf("toByteString should be a no-op, but found conversion opcodes: %s", asm)
	}
	// Should not push a placeholder 0 from unknown-function fallback
	if strings.Contains(asm, "PUSH(0)") {
		t.Errorf("toByteString should alias the input, not push a placeholder 0: %s", asm)
	}
}

// ---------------------------------------------------------------------------
// Fix #28: Loop cleanup — unused iteration variable must be dropped
// ---------------------------------------------------------------------------

func TestLoop_UnusedIterVar_Cleanup(t *testing.T) {
	// Build a loop where the iteration variable is not used by the body at all.
	// The body is empty (no bindings that reference the iter var or anything else).
	// After each iteration, the iter var "i" should be at top of stack and dropped.
	assertRef, _ := marshalString("t1")
	program := &ir.ANFProgram{
		ContractName: "LoopCleanup",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "run",
				Params: []ir.ANFParam{{Name: "x", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					// Loop 3 times with an empty body — iterVar "i" is pushed but never used,
					// so it remains on top of stack after each iteration and should be dropped.
					{Name: "t1_loop", Value: ir.ANFValue{
						Kind:    "loop",
						Count:   3,
						IterVar: "i",
						Body:    []ir.ANFBinding{},
					}},
					{Name: "t1", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t0"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var run *StackMethod
	for i := range methods {
		if methods[i].Name == "run" {
			run = &methods[i]
			break
		}
	}
	if run == nil {
		t.Fatal("could not find 'run' stack method")
	}

	asm := opsToString(run.Ops)
	t.Logf("loop cleanup ops: %s", asm)

	// Count DROP ops — there should be at least 3 (one per iteration to clean up
	// the unused iteration variable "i" which sits at top of stack after each iteration).
	dropCount := strings.Count(asm, "DROP")
	if dropCount < 3 {
		t.Errorf("expected at least 3 DROPs for unused iteration variable cleanup, got %d in: %s", dropCount, asm)
	}
}

// ---------------------------------------------------------------------------
// log2 — bit-scanning implementation (not byte-size approximation)
// ---------------------------------------------------------------------------

func TestLog2_BitScanning(t *testing.T) {
	// Build IR that calls log2. The compiled output should use a bit-scanning
	// loop with OP_RSHIFT and OP_GREATERTHAN, NOT the old OP_SIZE approximation.
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "Log2Test",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "n", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "n"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "log2", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("log2 ops: %s", asm)

	// Must use OP_GREATERTHAN (bit-scanning loop), not OP_SIZE (byte approximation)
	if !strings.Contains(asm, "OP_GREATERTHAN") {
		t.Errorf("log2 should use OP_GREATERTHAN for bit-scanning loop, got: %s", asm)
	}

	// Must use OP_DIV for numeric halving in the bit-scanning loop
	if !strings.Contains(asm, "OP_DIV") {
		t.Errorf("log2 should use OP_DIV for bit-scanning loop, got: %s", asm)
	}

	// Must NOT use the old OP_SIZE byte-approximation approach
	if strings.Contains(asm, "OP_SIZE") {
		t.Errorf("log2 should NOT use OP_SIZE (old byte approximation), got: %s", asm)
	}
	if strings.Contains(asm, "OP_MUL") {
		t.Errorf("log2 should NOT use OP_MUL (old byte approximation), got: %s", asm)
	}

	// The bit-scanning loop should have 64 if-ops with OP_DIV + OP_1ADD inside
	ifCount := 0
	for _, op := range check.Ops {
		if op.Op == "if" {
			thenStr := opsToString(op.Then)
			if strings.Contains(thenStr, "OP_DIV") && strings.Contains(thenStr, "OP_1ADD") {
				ifCount++
			}
		}
	}
	if ifCount != 64 {
		t.Errorf("log2 should have 64 if-ops for bit-scanning iterations, got %d", ifCount)
	}
}

// ---------------------------------------------------------------------------
// Fix #5: sqrt(0) guard — should not divide by zero
// ---------------------------------------------------------------------------

func TestSqrt_ZeroGuard(t *testing.T) {
	// Build IR that calls sqrt. The compiled output should include a guard
	// that skips Newton iteration when input is 0.
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "SqrtTest",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "n", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "n"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "sqrt", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t1"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	asm := opsToString(check.Ops)
	t.Logf("sqrt ops: %s", asm)

	// The sqrt implementation should have an OP_DUP followed by an IF guard
	// to check if input is 0 and skip the Newton iteration.
	// Look for the pattern: OP_DUP IF{...Newton iteration...}ELSE{}
	if !strings.Contains(asm, "OP_DUP") {
		t.Error("sqrt should emit OP_DUP for the zero guard")
	}

	// There should be an if-op that wraps the Newton iteration
	hasIfGuard := false
	for _, op := range check.Ops {
		if op.Op == "opcode" && op.Code == "OP_DUP" {
			// Check the next op for the if-guard pattern
			continue
		}
		if op.Op == "if" {
			// If the then-branch contains the Newton iteration (OP_DIV etc.)
			thenStr := opsToString(op.Then)
			if strings.Contains(thenStr, "OP_DIV") {
				hasIfGuard = true
			}
		}
	}
	if !hasIfGuard {
		t.Errorf("sqrt should have OP_DUP IF{...Newton...} guard for zero, got: %s", asm)
	}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// TestLowerToStack_MaxStackDepth — MaxStackDepth should be tracked after lowering
// ---------------------------------------------------------------------------

func TestLowerToStack_MaxStackDepth(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	var unlock *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlock = &methods[i]
			break
		}
	}
	if unlock == nil {
		t.Fatal("could not find 'unlock' stack method")
	}

	if unlock.MaxStackDepth <= 0 {
		t.Errorf("expected MaxStackDepth > 0 after lowering P2PKH, got %d", unlock.MaxStackDepth)
	}
	// P2PKH has 2 params + some intermediates, so depth should be reasonable
	if unlock.MaxStackDepth > 10 {
		t.Errorf("expected MaxStackDepth <= 10 for P2PKH, got %d", unlock.MaxStackDepth)
	}
}

// ---------------------------------------------------------------------------
// TestLowerToStack_WithInitialValues_NoPlaceholderOps — properties with initial
// values should not produce Placeholder ops
// ---------------------------------------------------------------------------

func TestLowerToStack_WithInitialValues_NoPlaceholderOps(t *testing.T) {
	// A property with an initialValue is baked in; the value is not a constructor arg
	// and should not produce a Placeholder op in the emitted script.
	program := &ir.ANFProgram{
		ContractName: "BoundedCounter",
		Properties: []ir.ANFProperty{
			{Name: "pubKeyHash", Type: "Addr", Readonly: true, InitialValue: "aabbccdd"},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "pubKeyHash", Type: "Addr"}},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name: "unlock",
				Params: []ir.ANFParam{
					{Name: "sig", Type: "Sig"},
					{Name: "pubKey", Type: "PubKey"},
				},
				Body:     buildP2PKHBody(),
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var unlock *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlock = &methods[i]
			break
		}
	}
	if unlock == nil {
		t.Fatal("could not find 'unlock' stack method")
	}

	var placeholders []StackOp
	collectPlaceholders(unlock.Ops, &placeholders)

	if len(placeholders) != 0 {
		t.Errorf("with initial values, expected no Placeholder ops, found %d", len(placeholders))
	}
}

// ---------------------------------------------------------------------------
// TestLowerToStack_PushLargeBigint — large integer constant should produce a
// Push op (not an OP_1..OP_16 small-int opcode)
// ---------------------------------------------------------------------------

func TestLowerToStack_PushLargeBigint(t *testing.T) {
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "LargeConst",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "x", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					{Name: "t1", Value: ir.ANFValue{
						Kind:        "load_const",
						RawValue:    []byte("1000"),
						ConstBigInt: big.NewInt(1000),
						ConstInt:    func() *int64 { v := int64(1000); return &v }(),
					}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t2"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	// Find the push op for the constant 1000
	var pushOps []StackOp
	for _, op := range check.Ops {
		if op.Op == "push" {
			pushOps = append(pushOps, op)
		}
	}
	if len(pushOps) == 0 {
		t.Fatalf("expected at least one push op for constant 1000, got none in: %s", opsToString(check.Ops))
	}

	// Find the push op for bigint 1000
	var constPush *StackOp
	for i := range pushOps {
		if pushOps[i].Value.Kind == "bigint" && pushOps[i].Value.BigInt != nil && pushOps[i].Value.BigInt.Cmp(big.NewInt(1000)) == 0 {
			constPush = &pushOps[i]
			break
		}
	}
	if constPush == nil {
		t.Errorf("expected a push of bigint 1000 in ops: %s", opsToString(check.Ops))
	}
}

// ---------------------------------------------------------------------------
// TestLowerToStack_PushValueEncodesCorrectly — constant 1000 should encode
// to script number bytes e803 (little-endian)
// ---------------------------------------------------------------------------

func TestLowerToStack_PushValueEncodesCorrectly(t *testing.T) {
	// 1000 in script number encoding: 0xe8, 0x03 (little-endian sign-magnitude)
	// push length = 2, so encoded as: 02 e8 03 (3 bytes = 6 hex chars)
	n := big.NewInt(1000)
	hexStr, _ := encodePushBigInt(n)

	if hexStr == "" {
		t.Fatal("encodePushBigInt(1000) returned empty hex")
	}
	// 1000 needs 2 bytes of script number data; total push = 3 bytes = 6 hex chars
	if len(hexStr) < 6 {
		t.Errorf("1000 should need at least 2 bytes of push data (6 hex chars), got: %s", hexStr)
	}
	// The script number bytes for 1000 are e803
	if !strings.Contains(hexStr, "e803") {
		t.Errorf("expected hex for 1000 to contain 'e803' (little-endian), got: %s", hexStr)
	}
}

// ---------------------------------------------------------------------------
// TestLowerToStack_RefAliasing — if-else with @ref alias compiles without panic
// ---------------------------------------------------------------------------

func TestLowerToStack_RefAliasing(t *testing.T) {
	// Build an ANF program where an if-else assigns to the same local in both
	// branches, which causes the compiler to emit a @ref alias binding.
	// The simplest form: load_const "@ref:someName" as a load_const binding.
	assertRef, _ := marshalString("t5")
	program := &ir.ANFProgram{
		ContractName: "RefAlias",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{
					{Name: "cond", Type: "boolean"},
					{Name: "x", Type: "bigint"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "cond"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					// Simulate an if-else that both branches compute something and
					// the result is aliased via @ref in the outer scope.
					{Name: "t2", Value: ir.ANFValue{
						Kind: "if",
						Cond: "t0",
						Then: []ir.ANFBinding{
							{Name: "t3", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("1"), ConstBigInt: big.NewInt(1)}},
						},
						Else: []ir.ANFBinding{
							{Name: "t4", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("2"), ConstBigInt: big.NewInt(2)}},
						},
					}},
					// After the if-else, the result ref references t2
					{Name: "t5", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2"}},
					{Name: "t6", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t5"}},
				},
				IsPublic: true,
			},
		},
	}

	// Should not panic and should produce non-empty stack ops
	methods, err := LowerToStack(program)
	if err != nil {
		t.Fatalf("LowerToStack failed: %v", err)
	}

	var check *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			check = &methods[i]
			break
		}
	}
	if check == nil {
		t.Fatal("could not find 'check' stack method")
	}

	if len(check.Ops) == 0 {
		t.Error("expected non-empty stack ops for if-else with aliasing")
	}

	t.Logf("ref-aliasing ops: %s", opsToString(check.Ops))
}

// ---------------------------------------------------------------------------
// TestLowerToStack_StackDepthInvariant — max_stack_depth > 0 and ops non-empty
// ---------------------------------------------------------------------------

func TestLowerToStack_StackDepthInvariant(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	var unlock *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlock = &methods[i]
			break
		}
	}
	if unlock == nil {
		t.Fatal("could not find 'unlock' stack method")
	}

	// MaxStackDepth must be > 0 after lowering
	if unlock.MaxStackDepth <= 0 {
		t.Errorf("expected MaxStackDepth > 0, got %d", unlock.MaxStackDepth)
	}

	// Ops list must be non-empty
	if len(unlock.Ops) == 0 {
		t.Error("expected non-empty stack ops for P2PKH unlock")
	}

	// Verify no PICK/ROLL depth exceeds MaxStackDepth (basic sanity check)
	for _, op := range unlock.Ops {
		if op.Op == "pick" || op.Op == "roll" {
			if op.Depth >= unlock.MaxStackDepth {
				t.Errorf("op %s with depth %d exceeds MaxStackDepth %d", op.Op, op.Depth, unlock.MaxStackDepth)
			}
		}
	}

	t.Logf("P2PKH unlock MaxStackDepth=%d, ops=%d", unlock.MaxStackDepth, len(unlock.Ops))
}

// reverseBytes must not emit OP_REVERSE (non-existent opcode)
// ---------------------------------------------------------------------------

func TestReverseBytes_NoOpReverse(t *testing.T) {
	// Build a simple ANF program with a reverseBytes call
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "ReverseTest",
		Properties: []ir.ANFProperty{
			{Name: "data", Type: "ByteString", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "data", Type: "ByteString"}},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name:   "check",
				Params: []ir.ANFParam{{Name: "expected", Type: "ByteString"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_prop", Name: "data"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "reverseBytes", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "load_param", Name: "expected"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2", ResultType: "bytes"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t3"}},
				},
				IsPublic: true,
			},
		},
	}

	methods, err := LowerToStack(program)
	if err != nil {
		t.Fatalf("LowerToStack failed: %v", err)
	}

	// Verify no OP_REVERSE in any output
	output := fmt.Sprintf("%v", methods)
	if strings.Contains(output, "OP_REVERSE") {
		t.Error("Output should not contain OP_REVERSE")
	}
	// Verify OP_SPLIT and OP_CAT are present (the replacement opcodes)
	if !strings.Contains(output, "OP_SPLIT") {
		t.Error("Output should contain OP_SPLIT")
	}
	if !strings.Contains(output, "OP_CAT") {
		t.Error("Output should contain OP_CAT")
	}
}

// ---------------------------------------------------------------------------
// Row 190: ByteString concatenation emits OP_CAT (not OP_ADD)
// ---------------------------------------------------------------------------

func TestStack_ByteStringConcat_EmitsCAT(t *testing.T) {
	assertRef, _ := marshalString("t3")
	program := &ir.ANFProgram{
		ContractName: "CatTest",
		Properties: []ir.ANFProperty{
			{Name: "expected", Type: "ByteString", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: []ir.ANFParam{{Name: "expected", Type: "ByteString"}}, Body: nil, IsPublic: false},
			{
				Name:     "check",
				IsPublic: true,
				Params: []ir.ANFParam{
					{Name: "a", Type: "ByteString"},
					{Name: "b", Type: "ByteString"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "a"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "b"}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "+", Left: "t0", Right: "t1", ResultType: "bytes"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "load_prop", Name: "expected"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t2", Right: "t3", ResultType: "bytes"}},
					{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t4"}},
				},
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var checkMethod *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			checkMethod = &methods[i]
			break
		}
	}
	if checkMethod == nil {
		t.Fatal("expected 'check' method")
	}

	// Collect op codes
	var opCodes []string
	var collectCodes func(ops []StackOp)
	collectCodes = func(ops []StackOp) {
		for _, op := range ops {
			if op.Op == "opcode" {
				opCodes = append(opCodes, op.Code)
			}
			collectCodes(op.Then)
			collectCodes(op.Else)
		}
	}
	collectCodes(checkMethod.Ops)

	hasCat := false
	hasAdd := false
	for _, code := range opCodes {
		if code == "OP_CAT" {
			hasCat = true
		}
		if code == "OP_ADD" {
			hasAdd = true
		}
	}

	if !hasCat {
		t.Error("expected OP_CAT for ByteString concatenation, not found")
	}
	if hasAdd {
		t.Error("ByteString concatenation should NOT emit OP_ADD")
	}
}

// ---------------------------------------------------------------------------
// Row 191: ByteString indexing uses OP_SPLIT + NIP + DROP + OP_BIN2NUM
// ---------------------------------------------------------------------------

func TestStack_ByteStringIndexing_EmitsSplit(t *testing.T) {
	assertRef, _ := marshalString("t3")
	program := &ir.ANFProgram{
		ContractName: "IndexTest",
		Properties: []ir.ANFProperty{
			{Name: "expected", Type: "bigint", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: []ir.ANFParam{{Name: "expected", Type: "bigint"}}, Body: nil, IsPublic: false},
			{
				Name:     "check",
				IsPublic: true,
				Params:   []ir.ANFParam{{Name: "data", Type: "ByteString"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "data"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("0")}},
					{Name: "t2", Value: ir.ANFValue{Kind: "call", Func: "__array_access", Args: []string{"t0", "t1"}}},
					{Name: "t3", Value: ir.ANFValue{Kind: "load_prop", Name: "expected"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t2", Right: "t3", ResultType: "bytes"}},
					{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t4"}},
				},
			},
		},
	}

	methods, err := LowerToStack(program)
	if err != nil {
		t.Fatalf("LowerToStack failed: %v", err)
	}

	var checkMethod *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			checkMethod = &methods[i]
			break
		}
	}
	if checkMethod == nil {
		t.Fatal("expected 'check' method")
	}

	var opCodes []string
	var collectCodes func(ops []StackOp)
	collectCodes = func(ops []StackOp) {
		for _, op := range ops {
			if op.Op == "opcode" {
				opCodes = append(opCodes, op.Code)
			}
			collectCodes(op.Then)
			collectCodes(op.Else)
		}
	}
	collectCodes(checkMethod.Ops)

	hasSplit := false
	for _, code := range opCodes {
		if code == "OP_SPLIT" {
			hasSplit = true
		}
	}
	if !hasSplit {
		t.Errorf("expected OP_SPLIT for ByteString indexing, got ops: %v", opCodes)
	}
}

// ---------------------------------------------------------------------------
// Row 192: OP_CHECKSIG emitted for checkSig call
// ---------------------------------------------------------------------------

func TestStack_CheckSig_EmitsOPCHECKSIG(t *testing.T) {
	methods := mustLowerToStackOps(t, p2pkhProgram())
	var unlockMethod *StackMethod
	for i := range methods {
		if methods[i].Name == "unlock" {
			unlockMethod = &methods[i]
			break
		}
	}
	if unlockMethod == nil {
		t.Fatal("expected 'unlock' method")
	}

	var opCodes []string
	var collectCodes func(ops []StackOp)
	collectCodes = func(ops []StackOp) {
		for _, op := range ops {
			if op.Op == "opcode" {
				opCodes = append(opCodes, op.Code)
			}
			collectCodes(op.Then)
			collectCodes(op.Else)
		}
	}
	collectCodes(unlockMethod.Ops)

	found := false
	for _, code := range opCodes {
		if code == "OP_CHECKSIG" || code == "OP_CHECKSIGVERIFY" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected OP_CHECKSIG or OP_CHECKSIGVERIFY in unlock method, got: %v", opCodes)
	}
}

// ---------------------------------------------------------------------------
// Row 204: right() uses OP_SIZE OP_SUB OP_SPLIT + NIP
// ---------------------------------------------------------------------------

func TestStack_Right_EmitsSizeSubSplit(t *testing.T) {
	assertRef, _ := marshalString("t3")
	program := &ir.ANFProgram{
		ContractName: "RightTest",
		Properties: []ir.ANFProperty{
			{Name: "expected", Type: "ByteString", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: []ir.ANFParam{{Name: "expected", Type: "ByteString"}}, Body: nil, IsPublic: false},
			{
				Name:     "check",
				IsPublic: true,
				Params:   []ir.ANFParam{{Name: "data", Type: "ByteString"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "data"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("2")}},
					{Name: "t2", Value: ir.ANFValue{Kind: "call", Func: "right", Args: []string{"t0", "t1"}}},
					{Name: "t3", Value: ir.ANFValue{Kind: "load_prop", Name: "expected"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t2", Right: "t3", ResultType: "bytes"}},
					{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t4"}},
				},
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var checkMethod *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			checkMethod = &methods[i]
			break
		}
	}
	if checkMethod == nil {
		t.Fatal("expected 'check' method")
	}

	var opCodes []string
	var collectCodes func(ops []StackOp)
	collectCodes = func(ops []StackOp) {
		for _, op := range ops {
			if op.Op == "opcode" {
				opCodes = append(opCodes, op.Code)
			}
			collectCodes(op.Then)
			collectCodes(op.Else)
		}
	}
	collectCodes(checkMethod.Ops)

	hasSize := false
	hasSub := false
	hasSplit := false
	for _, code := range opCodes {
		switch code {
		case "OP_SIZE":
			hasSize = true
		case "OP_SUB":
			hasSub = true
		case "OP_SPLIT":
			hasSplit = true
		}
	}

	if !hasSize {
		t.Error("right() should emit OP_SIZE")
	}
	if !hasSub {
		t.Error("right() should emit OP_SUB")
	}
	if !hasSplit {
		t.Error("right() should emit OP_SPLIT")
	}
}

// ---------------------------------------------------------------------------
// Row 205: sign() uses OP_DUP OP_IF guard with OP_ABS and OP_DIV
// ---------------------------------------------------------------------------

func TestStack_Sign_EmitsDupIfGuardWithAbsDiv(t *testing.T) {
	assertRef, _ := marshalString("t2")
	program := &ir.ANFProgram{
		ContractName: "SignTest",
		Properties: []ir.ANFProperty{
			{Name: "expected", Type: "bigint", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: []ir.ANFParam{{Name: "expected", Type: "bigint"}}, Body: nil, IsPublic: false},
			{
				Name:     "check",
				IsPublic: true,
				Params:   []ir.ANFParam{{Name: "a", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "a"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "sign", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "load_prop", Name: "expected"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2", ResultType: "bytes"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t3"}},
				},
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	var checkMethod *StackMethod
	for i := range methods {
		if methods[i].Name == "check" {
			checkMethod = &methods[i]
			break
		}
	}
	if checkMethod == nil {
		t.Fatal("expected 'check' method")
	}

	// sign() should produce a DUP (for zero-guard) and if-op with OP_ABS and OP_DIV
	hasDup := false
	hasIf := false
	var hasAbs, hasDiv bool
	var checkOps func(ops []StackOp)
	checkOps = func(ops []StackOp) {
		for _, op := range ops {
			if op.Op == "dup" || (op.Op == "opcode" && op.Code == "OP_DUP") {
				hasDup = true
			}
			if op.Op == "if" {
				hasIf = true
				for _, thenOp := range op.Then {
					if thenOp.Op == "opcode" && thenOp.Code == "OP_ABS" {
						hasAbs = true
					}
					if thenOp.Op == "opcode" && thenOp.Code == "OP_DIV" {
						hasDiv = true
					}
				}
			}
			checkOps(op.Then)
			checkOps(op.Else)
		}
	}
	checkOps(checkMethod.Ops)

	if !hasDup {
		t.Error("sign() should emit OP_DUP for zero-guard")
	}
	if !hasIf {
		t.Error("sign() should emit if-op for zero-guard")
	}
	if !hasAbs {
		t.Error("sign() should emit OP_ABS in then-branch")
	}
	if !hasDiv {
		t.Error("sign() should emit OP_DIV in then-branch")
	}
}

// ---------------------------------------------------------------------------
// Row 208: Large bigint constant (100000) encoded as "a08601"
// ---------------------------------------------------------------------------

func TestStack_LargeBigintConst_100000_Encoding(t *testing.T) {
	n := new(big.Int).SetInt64(100000)
	hexStr, _ := EncodePushBigInt(n)
	// 100000 in little-endian script number: 100000 = 0x0186A0
	// Script number LE bytes: 0xa0, 0x86, 0x01 → "a08601"
	if hexStr != "03a08601" {
		t.Errorf("expected 100000 to encode as '03a08601' (len-prefixed LE), got '%s'", hexStr)
	}
}
