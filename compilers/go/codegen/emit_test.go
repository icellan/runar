package codegen

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Test: Placeholder op produces ConstructorSlot with correct byte offset
// ---------------------------------------------------------------------------

func TestEmit_PlaceholderProducesConstructorSlot(t *testing.T) {
	// A minimal method with just a placeholder and an opcode
	method := &StackMethod{
		Name: "unlock",
		Ops: []StackOp{
			{Op: "placeholder", ParamIndex: 0, ParamName: "pubKeyHash"},
			{Op: "opcode", Code: "OP_CHECKSIG"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if len(result.ConstructorSlots) != 1 {
		t.Fatalf("expected 1 constructor slot, got %d", len(result.ConstructorSlots))
	}

	slot := result.ConstructorSlots[0]
	if slot.ParamIndex != 0 {
		t.Errorf("expected paramIndex=0, got %d", slot.ParamIndex)
	}
	// The placeholder is the first op, so byte offset should be 0
	if slot.ByteOffset != 0 {
		t.Errorf("expected byteOffset=0, got %d", slot.ByteOffset)
	}
}

// ---------------------------------------------------------------------------
// Test: Multiple placeholders have distinct byte offsets
// ---------------------------------------------------------------------------

func TestEmit_MultiplePlaceholdersDistinctOffsets(t *testing.T) {
	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			{Op: "placeholder", ParamIndex: 0, ParamName: "x"},
			{Op: "placeholder", ParamIndex: 1, ParamName: "y"},
			{Op: "opcode", Code: "OP_ADD"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if len(result.ConstructorSlots) != 2 {
		t.Fatalf("expected 2 constructor slots, got %d", len(result.ConstructorSlots))
	}

	slot0 := result.ConstructorSlots[0]
	slot1 := result.ConstructorSlots[1]

	if slot0.ParamIndex != 0 {
		t.Errorf("first slot: expected paramIndex=0, got %d", slot0.ParamIndex)
	}
	if slot1.ParamIndex != 1 {
		t.Errorf("second slot: expected paramIndex=1, got %d", slot1.ParamIndex)
	}

	// Byte offsets must be different
	if slot0.ByteOffset == slot1.ByteOffset {
		t.Errorf("expected distinct byte offsets, both are %d", slot0.ByteOffset)
	}

	// First placeholder at offset 0, second at offset 1 (each placeholder emits 1 byte: OP_0)
	if slot0.ByteOffset != 0 {
		t.Errorf("first slot: expected byteOffset=0, got %d", slot0.ByteOffset)
	}
	if slot1.ByteOffset != 1 {
		t.Errorf("second slot: expected byteOffset=1, got %d", slot1.ByteOffset)
	}
}

// ---------------------------------------------------------------------------
// Test: Byte offset accounts for preceding opcodes
// ---------------------------------------------------------------------------

func TestEmit_ByteOffsetAccountsForPrecedingOpcodes(t *testing.T) {
	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_DUP"},       // 1 byte (0x76)
			{Op: "opcode", Code: "OP_HASH160"},    // 1 byte (0xa9)
			{Op: "placeholder", ParamIndex: 0, ParamName: "pubKeyHash"}, // placeholder at byte 2
			{Op: "opcode", Code: "OP_EQUALVERIFY"}, // 1 byte (0x88)
			{Op: "opcode", Code: "OP_CHECKSIG"},    // 1 byte (0xac)
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if len(result.ConstructorSlots) != 1 {
		t.Fatalf("expected 1 constructor slot, got %d", len(result.ConstructorSlots))
	}

	slot := result.ConstructorSlots[0]
	// OP_DUP (1 byte) + OP_HASH160 (1 byte) = 2 bytes before the placeholder
	if slot.ByteOffset != 2 {
		t.Errorf("expected byteOffset=2 (after OP_DUP + OP_HASH160), got %d", slot.ByteOffset)
	}
}

// ---------------------------------------------------------------------------
// Test: Byte offset accounts for push data of varying sizes
// ---------------------------------------------------------------------------

func TestEmit_ByteOffsetWithPushData(t *testing.T) {
	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			// Push the number 17 — this uses 2 bytes (01 11)
			{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(17)}},
			{Op: "placeholder", ParamIndex: 0, ParamName: "x"},
			{Op: "opcode", Code: "OP_ADD"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if len(result.ConstructorSlots) != 1 {
		t.Fatalf("expected 1 constructor slot, got %d", len(result.ConstructorSlots))
	}

	slot := result.ConstructorSlots[0]
	// Push 17 takes 2 bytes (0x01 length + 0x11 value), so placeholder is at offset 2
	if slot.ByteOffset != 2 {
		t.Errorf("expected byteOffset=2 (after push 17), got %d", slot.ByteOffset)
	}
}

// ---------------------------------------------------------------------------
// Test: EmitMethod produces correct hex for a simple sequence
// ---------------------------------------------------------------------------

func TestEmit_SimpleSequenceHex(t *testing.T) {
	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_DUP"},
			{Op: "opcode", Code: "OP_HASH160"},
			{Op: "opcode", Code: "OP_SWAP"},
			{Op: "opcode", Code: "OP_EQUALVERIFY"},
			{Op: "opcode", Code: "OP_CHECKSIG"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	// OP_DUP=76, OP_HASH160=a9, OP_SWAP=7c, OP_EQUALVERIFY=88, OP_CHECKSIG=ac
	expected := "76a97c88ac"
	if result.ScriptHex != expected {
		t.Errorf("expected hex %s, got %s", expected, result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Test: Peephole optimization via OptimizeStackOps before Emit
// (CHECKSIG + VERIFY -> CHECKSIGVERIFY)
// ---------------------------------------------------------------------------

func TestEmit_PeepholeOptimization(t *testing.T) {
	// The real compiler pipeline calls OptimizeStackOps before Emit.
	methods := []StackMethod{
		{
			Name: "check",
			Ops: []StackOp{
				{Op: "opcode", Code: "OP_CHECKSIG"},
				{Op: "opcode", Code: "OP_VERIFY"},
				{Op: "opcode", Code: "OP_1"},
			},
		},
	}

	// Apply peephole optimization (as the compiler pipeline does before emit)
	for i := range methods {
		methods[i].Ops = OptimizeStackOps(methods[i].Ops)
	}

	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// After peephole: CHECKSIG + VERIFY -> CHECKSIGVERIFY, then OP_1
	// OP_CHECKSIGVERIFY=0xad, OP_1=0x51
	expected := "ad51"
	if result.ScriptHex != expected {
		t.Errorf("expected hex %s, got %s", expected, result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Test: Full P2PKH pipeline from ANF IR to emit
// ---------------------------------------------------------------------------

func TestEmit_FullP2PKH(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if result.ScriptHex == "" {
		t.Error("expected non-empty script hex for P2PKH")
	}
	if result.ScriptAsm == "" {
		t.Error("expected non-empty script ASM for P2PKH")
	}

	t.Logf("P2PKH hex: %s", result.ScriptHex)
	t.Logf("P2PKH asm: %s", result.ScriptAsm)
}

// ---------------------------------------------------------------------------
// Test: Multi-method dispatch produces OP_IF/OP_ELSE/OP_ENDIF
// ---------------------------------------------------------------------------

func TestEmit_MultiMethodDispatch(t *testing.T) {
	assertRef1, _ := marshalString("t1")
	assertRef2, _ := marshalString("t1")

	program := &ir.ANFProgram{
		ContractName: "Multi",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: nil, Body: nil, IsPublic: false},
			{
				Name:   "m1",
				Params: []ir.ANFParam{{Name: "x", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("1"), ConstBigInt: big.NewInt(1), ConstInt: func() *int64 { v := int64(1); return &v }()}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef1, ValueRef: "t2"}},
				},
				IsPublic: true,
			},
			{
				Name:   "m2",
				Params: []ir.ANFParam{{Name: "y", Type: "bigint"}},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "y"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_const", RawValue: []byte("2"), ConstBigInt: big.NewInt(2), ConstInt: func() *int64 { v := int64(2); return &v }()}},
					{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef2, ValueRef: "t2"}},
				},
				IsPublic: true,
			},
		},
	}

	methods := mustLowerToStackOps(t, program)
	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// Multi-method dispatch should contain OP_IF and OP_ELSE
	if result.ScriptAsm == "" {
		t.Fatal("expected non-empty ASM")
	}

	hasIF := false
	hasELSE := false
	hasENDIF := false
	for _, part := range []string{"OP_IF", "OP_ELSE", "OP_ENDIF"} {
		switch part {
		case "OP_IF":
			if containsSubstring(result.ScriptAsm, "OP_IF") {
				hasIF = true
			}
		case "OP_ELSE":
			if containsSubstring(result.ScriptAsm, "OP_ELSE") {
				hasELSE = true
			}
		case "OP_ENDIF":
			if containsSubstring(result.ScriptAsm, "OP_ENDIF") {
				hasENDIF = true
			}
		}
	}

	if !hasIF {
		t.Errorf("expected OP_IF in multi-method dispatch ASM, got: %s", result.ScriptAsm)
	}
	if !hasELSE {
		t.Errorf("expected OP_ELSE in multi-method dispatch ASM, got: %s", result.ScriptAsm)
	}
	if !hasENDIF {
		t.Errorf("expected OP_ENDIF in multi-method dispatch ASM, got: %s", result.ScriptAsm)
	}

	t.Logf("Multi-method hex: %s", result.ScriptHex)
	t.Logf("Multi-method asm: %s", result.ScriptAsm)
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstringHelper(s, sub))
}

func containsSubstringHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
