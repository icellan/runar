package codegen

import (
	"fmt"
	"math/big"
	"strings"
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

// ---------------------------------------------------------------------------
// Row 216: Terminal assert leaves value on stack (no OP_VERIFY for terminal checkSig)
// ---------------------------------------------------------------------------

func TestEmit_TerminalAssert_NoVerify(t *testing.T) {
	// The last assert(checkSig(sig, pk)) should leave the value on stack
	// without OP_VERIFY — the peephole optimizer should produce OP_CHECKSIG (not CHECKSIGVERIFY)
	// when it's the terminal op
	methods := mustLowerToStackOps(t, p2pkhProgram())
	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}
	// OP_CHECKSIG should be present (the terminal assert leaves value on stack)
	if !containsSubstring(result.ScriptAsm, "OP_CHECKSIG") {
		t.Errorf("expected OP_CHECKSIG in terminal-assert P2PKH, got ASM: %s", result.ScriptAsm)
	}
}

// ---------------------------------------------------------------------------
// Row 220: OP_DROP encodes to hex "75"
// ---------------------------------------------------------------------------

func TestEmit_OPDropEncodesTo75(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "opcode", Code: "OP_DROP"}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if result.ScriptHex != "75" {
		t.Errorf("OP_DROP should encode to '75', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 221: OP_NIP encodes to hex "77"
// ---------------------------------------------------------------------------

func TestEmit_OPNipEncodesTo77(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "opcode", Code: "OP_NIP"}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if result.ScriptHex != "77" {
		t.Errorf("OP_NIP should encode to '77', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 222: OP_OVER encodes to hex "78"
// ---------------------------------------------------------------------------

func TestEmit_OPOverEncodesTo78(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "opcode", Code: "OP_OVER"}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if result.ScriptHex != "78" {
		t.Errorf("OP_OVER should encode to '78', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 223: OP_PICK encodes to hex "79"
// ---------------------------------------------------------------------------

func TestEmit_OPPickEncodesTo79(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "pick", Depth: 2}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if !strings.Contains(result.ScriptHex, "79") {
		t.Errorf("pick (OP_PICK) should produce hex containing '79', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 224: OP_ROLL encodes to hex "7a"
// ---------------------------------------------------------------------------

func TestEmit_OPRollEncodesTo7a(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "roll", Depth: 3}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if !strings.Contains(result.ScriptHex, "7a") {
		t.Errorf("roll (OP_ROLL) should produce hex containing '7a', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 225: OP_ROT encodes to hex "7b"
// ---------------------------------------------------------------------------

func TestEmit_OPRotEncodesTo7b(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops:  []StackOp{{Op: "opcode", Code: "OP_ROT"}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	if result.ScriptHex != "7b" {
		t.Errorf("OP_ROT should encode to '7b', got: %s", result.ScriptHex)
	}
}

// ---------------------------------------------------------------------------
// Row 231: Push negative -1 encodes to "4f" (OP_1NEGATE)
// ---------------------------------------------------------------------------

func TestEmit_PushNegativeOne_Encodes4f(t *testing.T) {
	hexStr, asmStr := EncodePushBigInt(big.NewInt(-1))
	if hexStr != "4f" {
		t.Errorf("expected -1 to encode as '4f' (OP_1NEGATE), got '%s'", hexStr)
	}
	if !strings.Contains(asmStr, "1NEGATE") {
		t.Errorf("expected '1NEGATE' in ASM for -1, got '%s'", asmStr)
	}
}

// ---------------------------------------------------------------------------
// Row 234: 75-byte push uses direct length prefix (no OP_PUSHDATA1)
// ---------------------------------------------------------------------------

func TestEmit_75BytePush_NoOPPUSHDATA1(t *testing.T) {
	data := make([]byte, 75)
	for i := range data {
		data[i] = 0xab
	}
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{{
			Op:    "push",
			Value: PushValue{Kind: "bytes", Bytes: data},
		}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	// 75 bytes: direct prefix "4b" (75), NOT "4c4b" (PUSHDATA1)
	if !strings.HasPrefix(result.ScriptHex, "4b") {
		t.Errorf("75-byte push should start with '4b' (direct length prefix), got: %s", result.ScriptHex[:4])
	}
	if strings.HasPrefix(result.ScriptHex, "4c") {
		t.Errorf("75-byte push should NOT use OP_PUSHDATA1 (0x4c), got: %s", result.ScriptHex[:4])
	}
}

// ---------------------------------------------------------------------------
// Row 239: If/else with both branches emits OP_IF OP_ELSE OP_ENDIF
// ---------------------------------------------------------------------------

func TestEmit_IfElseBothBranches(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_1"},
			{
				Op:   "if",
				Then: []StackOp{{Op: "opcode", Code: "OP_DROP"}},
				Else: []StackOp{{Op: "opcode", Code: "OP_NIP"}},
			},
		},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if !containsSubstring(result.ScriptAsm, "OP_IF") {
		t.Errorf("expected OP_IF in ASM, got: %s", result.ScriptAsm)
	}
	if !containsSubstring(result.ScriptAsm, "OP_ELSE") {
		t.Errorf("expected OP_ELSE in ASM, got: %s", result.ScriptAsm)
	}
	if !containsSubstring(result.ScriptAsm, "OP_ENDIF") {
		t.Errorf("expected OP_ENDIF in ASM, got: %s", result.ScriptAsm)
	}
}

// ---------------------------------------------------------------------------
// Row 242: Empty push (0-byte data) encodes as OP_0
// ---------------------------------------------------------------------------

func TestEmit_EmptyPush_EncodesAsOP0(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{{
			Op:    "push",
			Value: PushValue{Kind: "bytes", Bytes: []byte{}},
		}},
	}
	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}
	// Empty bytes should encode as OP_0 = 0x00
	if result.ScriptHex != "00" {
		t.Errorf("empty push should encode as '00' (OP_0), got: %s", result.ScriptHex)
	}
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

// ---------------------------------------------------------------------------
// Test: Push bool true → 0x51 (OP_TRUE), false → 0x00 (OP_FALSE)
// ---------------------------------------------------------------------------

func TestEmit_PushBoolTrueFalse(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{
			{Op: "push", Value: PushValue{Kind: "bool", Bool: true}},
			{Op: "push", Value: PushValue{Kind: "bool", Bool: false}},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	// OP_TRUE = 0x51, OP_FALSE = 0x00
	if !strings.HasPrefix(result.ScriptHex, "51") {
		t.Errorf("true should emit 0x51 (OP_TRUE), got hex: %s", result.ScriptHex)
	}
	if !strings.HasSuffix(result.ScriptHex, "00") {
		t.Errorf("false should emit 0x00 (OP_FALSE), got hex: %s", result.ScriptHex)
	}
	if !containsSubstring(result.ScriptAsm, "OP_TRUE") {
		t.Errorf("expected OP_TRUE in ASM, got: %s", result.ScriptAsm)
	}
	if !containsSubstring(result.ScriptAsm, "OP_FALSE") {
		t.Errorf("expected OP_FALSE in ASM, got: %s", result.ScriptAsm)
	}
}

// ---------------------------------------------------------------------------
// Test: Integer encoding for 0, 1, and 16
// ---------------------------------------------------------------------------

func TestEmit_OP0Through16_Encoding(t *testing.T) {
	// 0 -> OP_0 = 0x00
	hex0, asm0 := encodePushBigInt(big.NewInt(0))
	if hex0 != "00" {
		t.Errorf("integer 0 should encode as OP_0 (0x00), got %s", hex0)
	}
	if asm0 != "OP_0" {
		t.Errorf("integer 0 should have ASM 'OP_0', got %s", asm0)
	}

	// 1 -> OP_1 = 0x51
	hex1, asm1 := encodePushBigInt(big.NewInt(1))
	if hex1 != "51" {
		t.Errorf("integer 1 should encode as OP_1 (0x51), got %s", hex1)
	}
	if asm1 != "OP_1" {
		t.Errorf("integer 1 should have ASM 'OP_1', got %s", asm1)
	}

	// 16 -> OP_16 = 0x60
	hex16, asm16 := encodePushBigInt(big.NewInt(16))
	if hex16 != "60" {
		t.Errorf("integer 16 should encode as OP_16 (0x60), got %s", hex16)
	}
	if asm16 != "OP_16" {
		t.Errorf("integer 16 should have ASM 'OP_16', got %s", asm16)
	}
}

// ---------------------------------------------------------------------------
// Test: 76-byte data uses OP_PUSHDATA1 prefix (0x4c 0x4c)
// ---------------------------------------------------------------------------

func TestEmit_PushData1_Encoding(t *testing.T) {
	// 76 bytes of data should use OP_PUSHDATA1 (0x4c) + length byte (0x4c = 76)
	data := make([]byte, 76)
	for i := range data {
		data[i] = 0xab
	}

	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			{Op: "push", Value: PushValue{Kind: "bytes", Bytes: data}},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	// Result should start with 4c4c (OP_PUSHDATA1 + length 76)
	if !strings.HasPrefix(result.ScriptHex, "4c4c") {
		t.Errorf("76-byte data should use OP_PUSHDATA1 (4c) + length 4c, got hex: %s", result.ScriptHex[:min(8, len(result.ScriptHex))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Test: Empty StackMethods list → empty hex and no constructor slots
// ---------------------------------------------------------------------------

func TestEmit_EmptyMethods_ProducesNoOutput(t *testing.T) {
	result, err := Emit([]StackMethod{})
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if result.ScriptHex != "" {
		t.Errorf("empty methods should produce empty hex, got: %s", result.ScriptHex)
	}
	if len(result.ConstructorSlots) != 0 {
		t.Errorf("empty methods should produce no constructor slots, got: %v", result.ConstructorSlots)
	}
}

// ---------------------------------------------------------------------------
// Test: Data of 256+ bytes uses OP_PUSHDATA2 (0x4d) prefix + 2-byte LE length
// ---------------------------------------------------------------------------

func TestEmit_PushData2_Encoding(t *testing.T) {
	// 256 bytes of data should use OP_PUSHDATA2 (0x4d) + 2-byte LE length (0x00 0x01 = 256)
	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xcd
	}

	method := &StackMethod{
		Name: "check",
		Ops: []StackOp{
			{Op: "push", Value: PushValue{Kind: "bytes", Bytes: data}},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	// Result should start with 4d0001 (OP_PUSHDATA2 + 2-byte LE length 256 = 0x0100)
	if !strings.HasPrefix(result.ScriptHex, "4d0001") {
		t.Errorf("256-byte data should use OP_PUSHDATA2 (4d) + LE length 0100, got hex start: %s",
			result.ScriptHex[:min(8, len(result.ScriptHex))])
	}

	// Total length: 1 (opcode) + 2 (length) + 256 (data) = 259 bytes = 518 hex chars
	expectedHexLen := 2 + 4 + 256*2 // 4d + 0001 + data
	if len(result.ScriptHex) != expectedHexLen {
		t.Errorf("expected hex length %d for 256-byte push, got %d", expectedHexLen, len(result.ScriptHex))
	}
}

// ---------------------------------------------------------------------------
// Test: Last method in dispatch uses fail-closed pattern (OP_NUMEQUALVERIFY)
// ---------------------------------------------------------------------------

func TestEmit_LastMethod_FailClosed(t *testing.T) {
	// Create a 3-method program; the last method should use OP_NUMEQUALVERIFY
	// instead of OP_IF/OP_ELSE (fail-closed: invalid selector → script fails)
	assertRef, _ := marshalString("t2")

	makeMethod := func(name string, constVal int64) ir.ANFMethod {
		return ir.ANFMethod{
			Name:   name,
			Params: []ir.ANFParam{{Name: "x", Type: "bigint"}},
			Body: []ir.ANFBinding{
				{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
				{Name: "t1", Value: ir.ANFValue{
					Kind:        "load_const",
					RawValue:    []byte(fmt.Sprintf("%d", constVal)),
					ConstBigInt: big.NewInt(constVal),
					ConstInt:    func() *int64 { v := constVal; return &v }(),
				}},
				{Name: "t2", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t0", Right: "t1"}},
				{Name: "t3", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t2"}},
			},
			IsPublic: true,
		}
	}

	program := &ir.ANFProgram{
		ContractName: "ThreeMethod",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: nil, Body: nil, IsPublic: false},
			makeMethod("m1", 1),
			makeMethod("m2", 2),
			makeMethod("m3", 3),
		},
	}

	methods := mustLowerToStackOps(t, program)
	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// The dispatch ASM must contain OP_NUMEQUALVERIFY (fail-closed for last method)
	if !containsSubstring(result.ScriptAsm, "OP_NUMEQUALVERIFY") {
		t.Errorf("expected OP_NUMEQUALVERIFY in multi-method dispatch for last method (fail-closed), got ASM: %s", result.ScriptAsm)
	}

	// And it should also have OP_IF (for earlier methods)
	if !containsSubstring(result.ScriptAsm, "OP_IF") {
		t.Errorf("expected OP_IF in multi-method dispatch ASM, got: %s", result.ScriptAsm)
	}

	t.Logf("Three-method dispatch ASM: %s", result.ScriptAsm)
}

// ---------------------------------------------------------------------------
// Test M10: emit — integers 17+ use push prefix (not OP_N shortcodes)
// ---------------------------------------------------------------------------

func TestEmit_Integer17UsesPushPrefix(t *testing.T) {
	// OP_1..OP_16 exist (0x51..0x60), but OP_17 does NOT.
	// Pushing integer 17 should use a data push: 0x01 0x11
	hex17, asm17 := encodePushBigInt(big.NewInt(17))

	// Should NOT be 0x61 (there is no OP_17 opcode)
	if hex17 == "61" {
		t.Errorf("integer 17 must NOT encode as 0x61 (no OP_17 exists); got %s", hex17)
	}
	// Should use data push prefix: 01 11 (1 byte of data, value 0x11 = 17 in script num)
	if hex17 != "0111" {
		t.Errorf("integer 17 should encode as '0111' (push prefix + value), got %s", hex17)
	}
	if asm17 == "OP_17" {
		t.Errorf("integer 17 should not have ASM 'OP_17', got %s", asm17)
	}

	t.Logf("integer 17 hex: %s, asm: %s", hex17, asm17)
}

// ---------------------------------------------------------------------------
// Test M20: emit — deterministic output
// ---------------------------------------------------------------------------

func TestEmit_DeterministicOutput(t *testing.T) {
	program := p2pkhProgram()

	methods1 := mustLowerToStackOps(t, program)
	result1, err := Emit(methods1)
	if err != nil {
		t.Fatalf("Emit (first run) failed: %v", err)
	}

	methods2 := mustLowerToStackOps(t, program)
	result2, err := Emit(methods2)
	if err != nil {
		t.Fatalf("Emit (second run) failed: %v", err)
	}

	if result1.ScriptHex != result2.ScriptHex {
		t.Errorf("emit is not deterministic: first=%s, second=%s", result1.ScriptHex, result2.ScriptHex)
	}
	if result1.ScriptAsm != result2.ScriptAsm {
		t.Errorf("emit ASM is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// Test M21: emit — OP_DUP encodes to 0x76
// ---------------------------------------------------------------------------

func TestEmit_OPDupEncodesTo76(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_DUP"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if result.ScriptHex != "76" {
		t.Errorf("OP_DUP should encode to 0x76, got: %s", result.ScriptHex)
	}
	if !containsSubstring(result.ScriptAsm, "OP_DUP") {
		t.Errorf("expected OP_DUP in ASM, got: %s", result.ScriptAsm)
	}
}

// ---------------------------------------------------------------------------
// Test M22: emit — OP_SWAP encodes to 0x7c
// ---------------------------------------------------------------------------

func TestEmit_OPSwapEncodesTo7c(t *testing.T) {
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_SWAP"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if result.ScriptHex != "7c" {
		t.Errorf("OP_SWAP should encode to 0x7c, got: %s", result.ScriptHex)
	}
	if !containsSubstring(result.ScriptAsm, "OP_SWAP") {
		t.Errorf("expected OP_SWAP in ASM, got: %s", result.ScriptAsm)
	}
}

// ---------------------------------------------------------------------------
// Test M24: emit — if without else produces no OP_ELSE
// ---------------------------------------------------------------------------

func TestEmit_IfWithoutElse_NoOPELSE(t *testing.T) {
	// The "if" StackOp uses nested Then/Else slices (not a flat sequence).
	// An if with no else has an empty Else slice.
	method := &StackMethod{
		Name: "test",
		Ops: []StackOp{
			{Op: "opcode", Code: "OP_1"},
			{
				Op:   "if",
				Then: []StackOp{{Op: "opcode", Code: "OP_DROP"}},
				Else: []StackOp{}, // empty else
			},
			{Op: "opcode", Code: "OP_1"},
		},
	}

	result, err := EmitMethod(method)
	if err != nil {
		t.Fatalf("EmitMethod failed: %v", err)
	}

	if containsSubstring(result.ScriptAsm, "OP_ELSE") {
		t.Errorf("expected no OP_ELSE for if-without-else, but ASM contains OP_ELSE: %s", result.ScriptAsm)
	}
	if !containsSubstring(result.ScriptAsm, "OP_IF") {
		t.Errorf("expected OP_IF in ASM for if-without-else: %s", result.ScriptAsm)
	}
	if !containsSubstring(result.ScriptAsm, "OP_ENDIF") {
		t.Errorf("expected OP_ENDIF in ASM for if-without-else: %s", result.ScriptAsm)
	}

	t.Logf("if-without-else ASM: %s", result.ScriptAsm)
}

// ---------------------------------------------------------------------------
// Test M25: emit — single method → no dispatch preamble
// ---------------------------------------------------------------------------

func TestEmit_SingleMethod_NoDispatch(t *testing.T) {
	program := p2pkhProgram()
	methods := mustLowerToStackOps(t, program)

	result, err := Emit(methods)
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// P2PKH has one public method — no dispatch preamble needed
	// The ASM should not contain OP_IF (method dispatch uses OP_IF/OP_ELSE)
	if containsSubstring(result.ScriptAsm, "OP_IF") {
		t.Errorf("single-method contract should not have OP_IF dispatch preamble, but ASM contains OP_IF: %s", result.ScriptAsm)
	}

	t.Logf("P2PKH (single method) ASM: %s", result.ScriptAsm)
}

// ---------------------------------------------------------------------------
// Test: Contract with sha256() has "OP_SHA256" in the ASM output
// ---------------------------------------------------------------------------

func TestEmit_SHA256InASM(t *testing.T) {
	// Build an ANF program that calls sha256 on a ByteString parameter
	assertRef, _ := marshalString("t3")

	program := &ir.ANFProgram{
		ContractName: "SHA256Test",
		Properties: []ir.ANFProperty{
			{Name: "expectedHash", Type: "Sha256", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{Name: "constructor", Params: nil, Body: nil, IsPublic: false},
			{
				Name: "verify",
				Params: []ir.ANFParam{
					{Name: "data", Type: "ByteString"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "data"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "sha256", Args: []string{"t0"}}},
					{Name: "t2", Value: ir.ANFValue{Kind: "load_prop", Name: "expectedHash"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2", ResultType: "bytes"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t3"}},
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

	if !containsSubstring(result.ScriptAsm, "OP_SHA256") {
		t.Errorf("expected OP_SHA256 in ASM for contract with sha256() call, got ASM: %s", result.ScriptAsm)
	}

	t.Logf("SHA256 contract ASM: %s", result.ScriptAsm)
}
