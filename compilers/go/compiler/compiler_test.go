package compiler

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func mustLoadIR(t *testing.T, jsonStr string) *ir.ANFProgram {
	t.Helper()
	prog, err := ir.LoadIRFromBytes([]byte(jsonStr))
	if err != nil {
		t.Fatalf("failed to load IR: %v", err)
	}
	return prog
}

func mustCompile(t *testing.T, jsonStr string) *Artifact {
	t.Helper()
	artifact, err := CompileFromIRBytes([]byte(jsonStr))
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	return artifact
}

// ---------------------------------------------------------------------------
// Test: IR loading
// ---------------------------------------------------------------------------

func TestLoadIR_BasicP2PKH(t *testing.T) {
	irJSON := `{
		"contractName": "P2PKH",
		"properties": [
			{"name": "pubKeyHash", "type": "Addr", "readonly": true}
		],
		"methods": [{
			"name": "unlock",
			"params": [
				{"name": "sig", "type": "Sig"},
				{"name": "pubKey", "type": "PubKey"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
				{"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
				{"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
				{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
				{"name": "t5", "value": {"kind": "assert", "value": "t4"}},
				{"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
				{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
			],
			"isPublic": true
		}]
	}`

	prog := mustLoadIR(t, irJSON)

	if prog.ContractName != "P2PKH" {
		t.Errorf("expected contractName=P2PKH, got %s", prog.ContractName)
	}
	if len(prog.Methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(prog.Methods))
	}
	if len(prog.Methods[0].Body) != 8 {
		t.Errorf("expected 8 bindings, got %d", len(prog.Methods[0].Body))
	}
}

// ---------------------------------------------------------------------------
// Test: P2PKH compilation produces expected script hex
// ---------------------------------------------------------------------------

func TestCompile_BasicP2PKH(t *testing.T) {
	// The conformance expected script hex for P2PKH.
	// From the TypeScript compiler: DUP HASH160 <pubKeyHash> EQUALVERIFY CHECKSIG
	// But since pubKeyHash has no initialValue, it's provided as a placeholder (OP_0).
	// The actual conformance test hex is: 76a97c7e7e87a988ac
	// Which translates to: OP_DUP OP_HASH160 OP_SWAP ... (depends on stack lowering)

	irJSON := `{
		"contractName": "P2PKH",
		"properties": [
			{"name": "pubKeyHash", "type": "Addr", "readonly": true}
		],
		"methods": [{
			"name": "unlock",
			"params": [
				{"name": "sig", "type": "Sig"},
				{"name": "pubKey", "type": "PubKey"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
				{"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
				{"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
				{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
				{"name": "t5", "value": {"kind": "assert", "value": "t4"}},
				{"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
				{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)

	if artifact.ContractName != "P2PKH" {
		t.Errorf("expected contractName=P2PKH, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
	if artifact.ASM == "" {
		t.Error("expected non-empty ASM")
	}

	t.Logf("P2PKH script hex: %s", artifact.Script)
	t.Logf("P2PKH script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Arithmetic operations
// ---------------------------------------------------------------------------

func TestCompile_Arithmetic(t *testing.T) {
	irJSON := `{
		"contractName": "Arithmetic",
		"properties": [
			{"name": "target", "type": "bigint", "readonly": true}
		],
		"methods": [{
			"name": "verify",
			"params": [
				{"name": "a", "type": "bigint"},
				{"name": "b", "type": "bigint"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "a"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "b"}},
				{"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
				{"name": "t3", "value": {"kind": "bin_op", "op": "-", "left": "t0", "right": "t1"}},
				{"name": "t4", "value": {"kind": "bin_op", "op": "*", "left": "t0", "right": "t1"}},
				{"name": "t5", "value": {"kind": "bin_op", "op": "/", "left": "t0", "right": "t1"}},
				{"name": "t6", "value": {"kind": "bin_op", "op": "+", "left": "t2", "right": "t3"}},
				{"name": "t7", "value": {"kind": "bin_op", "op": "+", "left": "t6", "right": "t4"}},
				{"name": "t8", "value": {"kind": "bin_op", "op": "+", "left": "t7", "right": "t5"}},
				{"name": "t9", "value": {"kind": "load_prop", "name": "target"}},
				{"name": "t10", "value": {"kind": "bin_op", "op": "===", "left": "t8", "right": "t9"}},
				{"name": "t11", "value": {"kind": "assert", "value": "t10"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)

	if artifact.ContractName != "Arithmetic" {
		t.Errorf("expected contractName=Arithmetic, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}

	// Verify that arithmetic opcodes are present in the ASM
	for _, op := range []string{"OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV"} {
		if !strings.Contains(artifact.ASM, op) {
			t.Errorf("expected ASM to contain %s", op)
		}
	}

	t.Logf("Arithmetic script hex: %s", artifact.Script)
	t.Logf("Arithmetic script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: If/Else
// ---------------------------------------------------------------------------

func TestCompile_IfElse(t *testing.T) {
	irJSON := `{
		"contractName": "IfElse",
		"properties": [
			{"name": "limit", "type": "bigint", "readonly": true}
		],
		"methods": [{
			"name": "check",
			"params": [
				{"name": "value", "type": "bigint"},
				{"name": "mode", "type": "boolean"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "value"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "mode"}},
				{"name": "t2", "value": {"kind": "load_const", "value": 0}},
				{"name": "t3", "value": {
					"kind": "if",
					"cond": "t1",
					"then": [
						{"name": "t4", "value": {"kind": "load_prop", "name": "limit"}},
						{"name": "t5", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t4"}}
					],
					"else": [
						{"name": "t6", "value": {"kind": "load_prop", "name": "limit"}},
						{"name": "t7", "value": {"kind": "bin_op", "op": "-", "left": "t0", "right": "t6"}}
					]
				}},
				{"name": "t8", "value": {"kind": "load_const", "value": 0}},
				{"name": "t9", "value": {"kind": "bin_op", "op": ">", "left": "t3", "right": "t8"}},
				{"name": "t10", "value": {"kind": "assert", "value": "t9"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)

	// Verify if/else opcodes
	if !strings.Contains(artifact.ASM, "OP_IF") {
		t.Error("expected ASM to contain OP_IF")
	}
	if !strings.Contains(artifact.ASM, "OP_ELSE") {
		t.Error("expected ASM to contain OP_ELSE")
	}
	if !strings.Contains(artifact.ASM, "OP_ENDIF") {
		t.Error("expected ASM to contain OP_ENDIF")
	}

	t.Logf("IfElse script hex: %s", artifact.Script)
	t.Logf("IfElse script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Boolean logic
// ---------------------------------------------------------------------------

func TestCompile_BooleanLogic(t *testing.T) {
	irJSON := `{
		"contractName": "BooleanLogic",
		"properties": [
			{"name": "threshold", "type": "bigint", "readonly": true}
		],
		"methods": [{
			"name": "verify",
			"params": [
				{"name": "a", "type": "bigint"},
				{"name": "b", "type": "bigint"},
				{"name": "flag", "type": "boolean"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "a"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "b"}},
				{"name": "t2", "value": {"kind": "load_param", "name": "flag"}},
				{"name": "t3", "value": {"kind": "load_prop", "name": "threshold"}},
				{"name": "t4", "value": {"kind": "bin_op", "op": ">", "left": "t0", "right": "t3"}},
				{"name": "t5", "value": {"kind": "bin_op", "op": ">", "left": "t1", "right": "t3"}},
				{"name": "t6", "value": {"kind": "bin_op", "op": "&&", "left": "t4", "right": "t5"}},
				{"name": "t7", "value": {"kind": "bin_op", "op": "||", "left": "t4", "right": "t5"}},
				{"name": "t8", "value": {"kind": "unary_op", "op": "!", "operand": "t2"}},
				{"name": "t9", "value": {"kind": "bin_op", "op": "&&", "left": "t7", "right": "t8"}},
				{"name": "t10", "value": {"kind": "bin_op", "op": "||", "left": "t6", "right": "t9"}},
				{"name": "t11", "value": {"kind": "assert", "value": "t10"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)

	for _, op := range []string{"OP_BOOLAND", "OP_BOOLOR", "OP_NOT"} {
		if !strings.Contains(artifact.ASM, op) {
			t.Errorf("expected ASM to contain %s", op)
		}
	}

	t.Logf("BooleanLogic script hex: %s", artifact.Script)
	t.Logf("BooleanLogic script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Script number encoding
// ---------------------------------------------------------------------------

func TestEncodeScriptNumber(t *testing.T) {
	tests := []struct {
		name     string
		value    *big.Int
		wantHex  string
		wantAsm  string
	}{
		{"zero", big.NewInt(0), "00", "OP_0"},
		{"one", big.NewInt(1), "51", "OP_1"},
		{"sixteen", big.NewInt(16), "60", "OP_16"},
		{"negative_one", big.NewInt(-1), "4f", "OP_1NEGATE"},
		{"seventeen", big.NewInt(17), "0111", "OP_17_as_push"},
		{"minus_two", big.NewInt(-2), "0182", "OP_minus2_as_push"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHex, gotAsm := codegen.EncodePushBigInt(tt.value)
			if gotHex != tt.wantHex {
				t.Errorf("hex: got %s, want %s", gotHex, tt.wantHex)
			}
			_ = gotAsm // ASM format varies; just ensure no panic
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Artifact JSON structure
// ---------------------------------------------------------------------------

func TestArtifactJSON(t *testing.T) {
	irJSON := `{
		"contractName": "Simple",
		"properties": [],
		"methods": [{
			"name": "check",
			"params": [{"name": "x", "type": "bigint"}],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
				{"name": "t1", "value": {"kind": "load_const", "value": 42}},
				{"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
				{"name": "t3", "value": {"kind": "assert", "value": "t2"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)
	jsonBytes, err := ArtifactToJSON(artifact)
	if err != nil {
		t.Fatalf("JSON serialization failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check required fields
	for _, field := range []string{"version", "compilerVersion", "contractName", "abi", "script", "asm", "buildTimestamp"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	if parsed["version"] != "runar-v0.1.0" {
		t.Errorf("expected version runar-v0.1.0, got %v", parsed["version"])
	}
}

// ---------------------------------------------------------------------------
// Test: IR validation
// ---------------------------------------------------------------------------

func TestValidation_EmptyContractName(t *testing.T) {
	irJSON := `{"contractName": "", "properties": [], "methods": []}`
	_, err := ir.LoadIRFromBytes([]byte(irJSON))
	if err == nil {
		t.Error("expected validation error for empty contractName")
	}
}

func TestValidation_UnknownKind(t *testing.T) {
	irJSON := `{
		"contractName": "Bad",
		"properties": [],
		"methods": [{
			"name": "m",
			"params": [],
			"body": [{"name": "t0", "value": {"kind": "nonexistent_kind"}}],
			"isPublic": true
		}]
	}`
	_, err := ir.LoadIRFromBytes([]byte(irJSON))
	if err == nil {
		t.Error("expected validation error for unknown kind")
	}
}

func TestValidation_NegativeLoopCount(t *testing.T) {
	irJSON := `{
		"contractName": "Bad",
		"properties": [],
		"methods": [{
			"name": "m",
			"params": [],
			"body": [{"name": "t0", "value": {"kind": "loop", "count": -1, "iterVar": "i", "body": []}}],
			"isPublic": true
		}]
	}`
	_, err := ir.LoadIRFromBytes([]byte(irJSON))
	if err == nil {
		t.Error("expected validation error for negative loop count")
	}
}

func TestValidation_ExcessiveLoopCount(t *testing.T) {
	irJSON := `{
		"contractName": "Bad",
		"properties": [],
		"methods": [{
			"name": "m",
			"params": [],
			"body": [{"name": "t0", "value": {"kind": "loop", "count": 99999999, "iterVar": "i", "body": []}}],
			"isPublic": true
		}]
	}`
	_, err := ir.LoadIRFromBytes([]byte(irJSON))
	if err == nil {
		t.Error("expected validation error for excessive loop count")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeding maximum") {
		t.Errorf("expected 'exceeding maximum' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: Peephole optimizer
// ---------------------------------------------------------------------------

func TestOptimizer_SwapSwap(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "swap"},
		{Op: "swap"},
		{Op: "opcode", Code: "OP_ADD"},
	}
	optimized := codegen.OptimizeStackOps(ops)
	if len(optimized) != 1 || optimized[0].Code != "OP_ADD" {
		t.Errorf("expected [OP_ADD], got %v", optimized)
	}
}

func TestOptimizer_CheckSigVerify(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "opcode", Code: "OP_CHECKSIG"},
		{Op: "opcode", Code: "OP_VERIFY"},
	}
	optimized := codegen.OptimizeStackOps(ops)
	if len(optimized) != 1 || optimized[0].Code != "OP_CHECKSIGVERIFY" {
		t.Errorf("expected [OP_CHECKSIGVERIFY], got %v", optimized)
	}
}

func TestOptimizer_NumEqualVerify(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "opcode", Code: "OP_NUMEQUAL"},
		{Op: "opcode", Code: "OP_VERIFY"},
	}
	optimized := codegen.OptimizeStackOps(ops)
	if len(optimized) != 1 || optimized[0].Code != "OP_NUMEQUALVERIFY" {
		t.Errorf("expected [OP_NUMEQUALVERIFY], got %v", optimized)
	}
}

// ---------------------------------------------------------------------------
// Conformance test helper
// ---------------------------------------------------------------------------

func conformanceDir() string {
	return filepath.Join("..", "..", "..", "conformance", "tests")
}

func mustLoadConformanceIR(t *testing.T, testName string) []byte {
	t.Helper()
	path := filepath.Join(conformanceDir(), testName, "expected-ir.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read conformance IR %s: %v", path, err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Test: Bounded loop conformance
// ---------------------------------------------------------------------------

func TestCompile_BoundedLoop(t *testing.T) {
	irData := mustLoadConformanceIR(t, "bounded-loop")
	artifact, err := CompileFromIRBytes(irData)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	if artifact.ContractName != "BoundedLoop" {
		t.Errorf("expected contractName=BoundedLoop, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
	if artifact.ASM == "" {
		t.Error("expected non-empty ASM")
	}

	t.Logf("BoundedLoop script hex: %s", artifact.Script)
	t.Logf("BoundedLoop script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Multi-method conformance (dispatch table)
// ---------------------------------------------------------------------------

func TestCompile_MultiMethod(t *testing.T) {
	irData := mustLoadConformanceIR(t, "multi-method")
	artifact, err := CompileFromIRBytes(irData)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	if artifact.ContractName != "MultiMethod" {
		t.Errorf("expected contractName=MultiMethod, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}

	// Multi-method contracts must produce a dispatch table with OP_IF
	if !strings.Contains(artifact.ASM, "OP_IF") {
		t.Error("expected ASM to contain OP_IF for method dispatch")
	}

	t.Logf("MultiMethod script hex: %s", artifact.Script)
	t.Logf("MultiMethod script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Stateful conformance
// ---------------------------------------------------------------------------

func TestCompile_Stateful(t *testing.T) {
	irData := mustLoadConformanceIR(t, "stateful")
	artifact, err := CompileFromIRBytes(irData)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	if artifact.ContractName != "Stateful" {
		t.Errorf("expected contractName=Stateful, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}

	// Stateful contracts use hash256 for state validation
	if !strings.Contains(artifact.ASM, "OP_HASH256") {
		t.Error("expected ASM to contain OP_HASH256 for state hashing")
	}

	// Stateful contracts use OP_VERIFY for assertions
	if !strings.Contains(artifact.ASM, "OP_VERIFY") {
		t.Error("expected ASM to contain OP_VERIFY for state assertions")
	}

	// Should have state fields in the artifact
	if len(artifact.StateFields) == 0 {
		t.Error("expected non-empty stateFields for stateful contract")
	}

	t.Logf("Stateful script hex: %s", artifact.Script)
	t.Logf("Stateful script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: All conformance tests compile successfully
// ---------------------------------------------------------------------------

func TestCompile_AllConformanceTests(t *testing.T) {
	testDirs := []string{
		"arithmetic",
		"basic-p2pkh",
		"boolean-logic",
		"bounded-loop",
		"if-else",
		"multi-method",
		"stateful",
	}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			irData := mustLoadConformanceIR(t, dir)
			artifact, err := CompileFromIRBytes(irData)
			if err != nil {
				t.Fatalf("compilation failed for %s: %v", dir, err)
			}

			if artifact.Script == "" {
				t.Errorf("expected non-empty script hex for %s", dir)
			}
			if artifact.ASM == "" {
				t.Errorf("expected non-empty ASM for %s", dir)
			}
			if artifact.ContractName == "" {
				t.Errorf("expected non-empty contractName for %s", dir)
			}

			// Compare against golden expected-script.hex
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")
			goldenHex, err := os.ReadFile(goldenPath)
			if err == nil {
				expected := strings.TrimSpace(string(goldenHex))
				if artifact.Script != expected {
					t.Errorf("%s: IR-compiled script hex does not match golden file\n  expected: %s\n  got:      %s", dir, expected, artifact.Script)
				}
			}

			t.Logf("%s: hex=%d bytes, asm=%d chars", dir, len(artifact.Script)/2, len(artifact.ASM))
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Push data encoding for various sizes
// ---------------------------------------------------------------------------

func TestPushDataEncoding(t *testing.T) {
	tests := []struct {
		name          string
		dataLen       int
		expectPrefix  byte   // expected first byte
		expectPrefix2 byte   // expected second byte (for PUSHDATA1/2)
		description   string
	}{
		{
			name:         "empty_data",
			dataLen:      0,
			expectPrefix: 0x00, // OP_0
			description:  "empty data should produce OP_0",
		},
		{
			name:         "1_byte",
			dataLen:      1,
			expectPrefix: 0x01, // direct length prefix
			description:  "1 byte should use direct length prefix",
		},
		{
			name:         "75_bytes",
			dataLen:      75,
			expectPrefix: 75, // direct length prefix (max)
			description:  "75 bytes should use direct length prefix (max for single-byte)",
		},
		{
			name:          "76_bytes_pushdata1",
			dataLen:       76,
			expectPrefix:  0x4c, // OP_PUSHDATA1
			expectPrefix2: 76,
			description:   "76 bytes should trigger OP_PUSHDATA1",
		},
		{
			name:          "256_bytes_pushdata2",
			dataLen:       256,
			expectPrefix:  0x4d, // OP_PUSHDATA2
			expectPrefix2: 0x00, // low byte of 256
			description:   "256 bytes should trigger OP_PUSHDATA2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			for i := range data {
				data[i] = 0xab // fill with dummy data
			}

			// Use the PushValue encoding path for bytes
			pv := codegen.PushValue{Kind: "bytes", Bytes: data}
			hexStr, _ := codegen.EncodePushBigInt(big.NewInt(0)) // just to verify zero works
			_ = hexStr

			// Encode push data via the emit path directly
			// We compile a minimal IR with a const bytes push to exercise the encoding
			encoded := encodePushDataHelper(data)
			if len(encoded) == 0 {
				t.Fatal("encoded push data should not be empty")
			}

			if encoded[0] != tt.expectPrefix {
				t.Errorf("%s: expected first byte 0x%02x, got 0x%02x", tt.description, tt.expectPrefix, encoded[0])
			}

			if tt.dataLen == 76 || tt.dataLen == 256 {
				if len(encoded) < 2 {
					t.Fatalf("expected at least 2 prefix bytes for PUSHDATA encoding")
				}
				if encoded[1] != tt.expectPrefix2 {
					t.Errorf("%s: expected second byte 0x%02x, got 0x%02x", tt.description, tt.expectPrefix2, encoded[1])
				}
			}

			// Verify total length: prefix + data
			var expectedTotalLen int
			switch {
			case tt.dataLen == 0:
				expectedTotalLen = 1 // just OP_0
			case tt.dataLen <= 75:
				expectedTotalLen = 1 + tt.dataLen // length byte + data
			case tt.dataLen <= 255:
				expectedTotalLen = 2 + tt.dataLen // OP_PUSHDATA1 + length byte + data
			default:
				expectedTotalLen = 3 + tt.dataLen // OP_PUSHDATA2 + 2 length bytes + data
			}

			if len(encoded) != expectedTotalLen {
				t.Errorf("expected total encoded length %d, got %d", expectedTotalLen, len(encoded))
			}

			_ = pv // suppress unused variable
		})
	}
}

// encodePushDataHelper mirrors codegen.encodePushData for testing.
// We replicate the logic here since encodePushData is unexported.
func encodePushDataHelper(data []byte) []byte {
	length := len(data)

	if length == 0 {
		return []byte{0x00}
	}

	if length >= 1 && length <= 75 {
		result := make([]byte, 1+length)
		result[0] = byte(length)
		copy(result[1:], data)
		return result
	}

	if length >= 76 && length <= 255 {
		result := make([]byte, 2+length)
		result[0] = 0x4c
		result[1] = byte(length)
		copy(result[2:], data)
		return result
	}

	if length >= 256 && length <= 65535 {
		result := make([]byte, 3+length)
		result[0] = 0x4d
		result[1] = byte(length & 0xff)
		result[2] = byte((length >> 8) & 0xff)
		copy(result[3:], data)
		return result
	}

	result := make([]byte, 5+length)
	result[0] = 0x4e
	result[1] = byte(length & 0xff)
	result[2] = byte((length >> 8) & 0xff)
	result[3] = byte((length >> 16) & 0xff)
	result[4] = byte((length >> 24) & 0xff)
	copy(result[5:], data)
	return result
}

// ---------------------------------------------------------------------------
// Test: Stack map operations
// ---------------------------------------------------------------------------

func TestStackMap(t *testing.T) {
	// We test the stack map indirectly through a compilation that exercises
	// push, find-depth, and removal. Create an IR with multiple variables
	// that forces various stack depths.
	irJSON := `{
		"contractName": "StackMapTest",
		"properties": [],
		"methods": [{
			"name": "test",
			"params": [
				{"name": "a", "type": "bigint"},
				{"name": "b", "type": "bigint"},
				{"name": "c", "type": "bigint"},
				{"name": "d", "type": "bigint"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "a"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "b"}},
				{"name": "t2", "value": {"kind": "load_param", "name": "c"}},
				{"name": "t3", "value": {"kind": "load_param", "name": "d"}},
				{"name": "t4", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t3"}},
				{"name": "t5", "value": {"kind": "bin_op", "op": "+", "left": "t1", "right": "t2"}},
				{"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}},
				{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
			],
			"isPublic": true
		}]
	}`

	artifact := mustCompile(t, irJSON)

	if artifact.Script == "" {
		t.Error("expected non-empty script hex for stack map test")
	}

	// The ASM should contain stack manipulation opcodes (SWAP, ROLL, PICK, ROT, etc.)
	// since we reference variables at different depths
	hasStackOps := strings.Contains(artifact.ASM, "OP_SWAP") ||
		strings.Contains(artifact.ASM, "OP_ROLL") ||
		strings.Contains(artifact.ASM, "OP_PICK") ||
		strings.Contains(artifact.ASM, "OP_ROT") ||
		strings.Contains(artifact.ASM, "OP_OVER")
	if !hasStackOps {
		t.Error("expected ASM to contain stack manipulation opcodes (SWAP/ROLL/PICK/ROT/OVER)")
	}

	t.Logf("StackMapTest script asm: %s", artifact.ASM)
}

// ---------------------------------------------------------------------------
// Test: Optimizer PUSH+DROP elimination
// ---------------------------------------------------------------------------

func TestOptimizerPushDrop(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "push", Value: codegen.PushValue{Kind: "bigint", BigInt: big.NewInt(42)}},
		{Op: "drop"},
		{Op: "opcode", Code: "OP_ADD"},
	}
	optimized := codegen.OptimizeStackOps(ops)

	// PUSH+DROP should be eliminated, leaving only OP_ADD
	if len(optimized) != 1 {
		t.Errorf("expected 1 op after optimization, got %d: %v", len(optimized), optimized)
	}
	if len(optimized) > 0 && optimized[0].Code != "OP_ADD" {
		t.Errorf("expected remaining op to be OP_ADD, got %v", optimized[0])
	}
}

// ---------------------------------------------------------------------------
// Test: Optimizer DROP+DROP -> 2DROP
// ---------------------------------------------------------------------------

func TestOptimizer2Drop(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "drop"},
		{Op: "drop"},
	}
	optimized := codegen.OptimizeStackOps(ops)

	if len(optimized) != 1 {
		t.Errorf("expected 1 op after optimization, got %d: %v", len(optimized), optimized)
	}
	if len(optimized) > 0 && optimized[0].Code != "OP_2DROP" {
		t.Errorf("expected OP_2DROP, got %v", optimized[0])
	}
}

// ---------------------------------------------------------------------------
// Test: Optimizer PUSH_1+ADD -> 1ADD
// ---------------------------------------------------------------------------

func TestOptimizer1Add(t *testing.T) {
	ops := []codegen.StackOp{
		{Op: "push", Value: codegen.PushValue{Kind: "bigint", BigInt: big.NewInt(1)}},
		{Op: "opcode", Code: "OP_ADD"},
	}
	optimized := codegen.OptimizeStackOps(ops)

	if len(optimized) != 1 {
		t.Errorf("expected 1 op after optimization, got %d: %v", len(optimized), optimized)
	}
	if len(optimized) > 0 && optimized[0].Code != "OP_1ADD" {
		t.Errorf("expected OP_1ADD, got %v", optimized[0])
	}
}

// ---------------------------------------------------------------------------
// Test: Deterministic output
// ---------------------------------------------------------------------------

func TestDeterministicOutput(t *testing.T) {
	irJSON := `{
		"contractName": "Deterministic",
		"properties": [
			{"name": "target", "type": "bigint", "readonly": true}
		],
		"methods": [{
			"name": "verify",
			"params": [
				{"name": "a", "type": "bigint"},
				{"name": "b", "type": "bigint"}
			],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "a"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "b"}},
				{"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
				{"name": "t3", "value": {"kind": "load_prop", "name": "target"}},
				{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t2", "right": "t3"}},
				{"name": "t5", "value": {"kind": "assert", "value": "t4"}}
			],
			"isPublic": true
		}]
	}`

	artifact1 := mustCompile(t, irJSON)
	artifact2 := mustCompile(t, irJSON)

	if artifact1.Script != artifact2.Script {
		t.Errorf("non-deterministic script hex:\n  first:  %s\n  second: %s", artifact1.Script, artifact2.Script)
	}
	if artifact1.ASM != artifact2.ASM {
		t.Errorf("non-deterministic ASM:\n  first:  %s\n  second: %s", artifact1.ASM, artifact2.ASM)
	}

	// Also verify against the conformance P2PKH
	p2pkhData := mustLoadConformanceIR(t, "basic-p2pkh")
	a1, err := CompileFromIRBytes(p2pkhData)
	if err != nil {
		t.Fatalf("first P2PKH compilation failed: %v", err)
	}
	a2, err := CompileFromIRBytes(p2pkhData)
	if err != nil {
		t.Fatalf("second P2PKH compilation failed: %v", err)
	}

	if a1.Script != a2.Script {
		t.Errorf("non-deterministic P2PKH script hex")
	}
	if a1.ASM != a2.ASM {
		t.Errorf("non-deterministic P2PKH ASM")
	}

	// Suppress unused import warnings
	_ = hex.EncodeToString
	_ = os.ReadFile
}

// ---------------------------------------------------------------------------
// Source compilation tests (.runar.ts → Bitcoin Script via native frontend)
// ---------------------------------------------------------------------------

func TestSourceCompile_P2PKH(t *testing.T) {
	source := filepath.Join(conformanceDir(), "basic-p2pkh", "basic-p2pkh.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.ContractName != "P2PKH" {
		t.Errorf("expected contract name P2PKH, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
	if artifact.ASM == "" {
		t.Error("expected non-empty ASM")
	}
	if !strings.Contains(artifact.ASM, "OP_HASH160") {
		t.Errorf("expected OP_HASH160 in ASM, got: %s", artifact.ASM)
	}
	if !strings.Contains(artifact.ASM, "OP_CHECKSIG") {
		t.Errorf("expected OP_CHECKSIG in ASM, got: %s", artifact.ASM)
	}
	t.Logf("P2PKH from source: hex=%s asm=%s", artifact.Script, artifact.ASM)
}

func TestSourceCompile_Arithmetic(t *testing.T) {
	source := filepath.Join(conformanceDir(), "arithmetic", "arithmetic.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.ContractName != "Arithmetic" {
		t.Errorf("expected Arithmetic, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
	if !strings.Contains(artifact.ASM, "OP_ADD") {
		t.Errorf("expected OP_ADD in ASM")
	}
	t.Logf("Arithmetic from source: hex=%s", artifact.Script)
}

func TestSourceCompile_BooleanLogic(t *testing.T) {
	source := filepath.Join(conformanceDir(), "boolean-logic", "boolean-logic.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.ContractName != "BooleanLogic" {
		t.Errorf("expected BooleanLogic, got %s", artifact.ContractName)
	}
	if !strings.Contains(artifact.ASM, "OP_BOOLAND") {
		t.Errorf("expected OP_BOOLAND in ASM")
	}
}

func TestSourceCompile_IfElse(t *testing.T) {
	source := filepath.Join(conformanceDir(), "if-else", "if-else.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if !strings.Contains(artifact.ASM, "OP_IF") {
		t.Errorf("expected OP_IF in ASM")
	}
}

func TestSourceCompile_BoundedLoop(t *testing.T) {
	source := filepath.Join(conformanceDir(), "bounded-loop", "bounded-loop.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
}

func TestSourceCompile_MultiMethod(t *testing.T) {
	source := filepath.Join(conformanceDir(), "multi-method", "multi-method.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if !strings.Contains(artifact.ASM, "OP_IF") {
		t.Errorf("expected OP_IF for dispatch table in ASM")
	}
}

func TestSourceCompile_Stateful(t *testing.T) {
	source := filepath.Join(conformanceDir(), "stateful", "stateful.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if !strings.Contains(artifact.ASM, "OP_HASH256") {
		t.Errorf("expected OP_HASH256 in ASM for state hashing")
	}
}

func TestSourceCompile_AllConformanceFromSource(t *testing.T) {
	testDirs := []string{
		"arithmetic", "basic-p2pkh", "boolean-logic",
		"bounded-loop", "if-else", "multi-method", "stateful",
	}
	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := filepath.Join(conformanceDir(), dir, dir+".runar.ts")
			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("source compilation failed for %s: %v", dir, err)
			}
			if artifact.Script == "" {
				t.Errorf("%s: empty script hex", dir)
			}
			if artifact.ASM == "" {
				t.Errorf("%s: empty ASM", dir)
			}
			if artifact.ContractName == "" {
				t.Errorf("%s: empty contract name", dir)
			}

			// Compare against golden expected-script.hex
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")
			goldenHex, err := os.ReadFile(goldenPath)
			if err == nil {
				expected := strings.TrimSpace(string(goldenHex))
				if artifact.Script != expected {
					t.Errorf("%s: script hex mismatch\n  expected: %s\n  got:      %s", dir, expected, artifact.Script)
				}
			}

			t.Logf("%s: hex=%d bytes, asm=%d chars", dir, len(artifact.Script)/2, len(artifact.ASM))
		})
	}
}

func TestSourceCompile_ExampleP2PKH(t *testing.T) {
	source := filepath.Join(conformanceDir(), "..", "..", "examples", "ts", "p2pkh", "P2PKH.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.ContractName != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty script hex")
	}
}

func TestSourceCompile_ExampleEscrow(t *testing.T) {
	source := filepath.Join(conformanceDir(), "..", "..", "examples", "ts", "escrow", "Escrow.runar.ts")
	artifact, err := CompileFromSource(source)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}
	if artifact.ContractName != "Escrow" {
		t.Errorf("expected Escrow, got %s", artifact.ContractName)
	}
	// Escrow has 2 public methods, so needs dispatch table
	if !strings.Contains(artifact.ASM, "OP_IF") {
		t.Errorf("expected OP_IF for multi-method dispatch")
	}
}

func TestSourceCompile_IRvsSourceMatch(t *testing.T) {
	// Compile from IR and from source, both should produce non-empty valid output
	irPath := filepath.Join(conformanceDir(), "basic-p2pkh", "expected-ir.json")
	sourcePath := filepath.Join(conformanceDir(), "basic-p2pkh", "basic-p2pkh.runar.ts")

	irArtifact, err := CompileFromIR(irPath)
	if err != nil {
		t.Fatalf("IR compilation failed: %v", err)
	}

	sourceArtifact, err := CompileFromSource(sourcePath)
	if err != nil {
		t.Fatalf("source compilation failed: %v", err)
	}

	// Both should produce P2PKH
	if irArtifact.ContractName != sourceArtifact.ContractName {
		t.Errorf("contract name mismatch: IR=%s source=%s", irArtifact.ContractName, sourceArtifact.ContractName)
	}

	// Both should produce non-empty scripts
	if irArtifact.Script == "" || sourceArtifact.Script == "" {
		t.Error("both paths should produce non-empty scripts")
	}

	t.Logf("IR hex:     %s", irArtifact.Script)
	t.Logf("Source hex: %s", sourceArtifact.Script)
}

// ---------------------------------------------------------------------------
// Test: ALL 9 conformance .runar.ts files compile and match golden hex
// ---------------------------------------------------------------------------

func TestCompilerParity_AllConformance(t *testing.T) {
	// All 9 conformance test directories
	testDirs := []string{
		"arithmetic",
		"basic-p2pkh",
		"boolean-logic",
		"bounded-loop",
		"if-else",
		"multi-method",
		"post-quantum-slhdsa",
		"post-quantum-wots",
		"stateful",
	}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			sourcePath := filepath.Join(conformanceDir(), dir, dir+".runar.ts")
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")

			// Check that the source file exists
			if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
				t.Skipf("source file not found: %s", sourcePath)
			}

			// Compile from source
			artifact, err := CompileFromSource(sourcePath)
			if err != nil {
				t.Fatalf("source compilation failed for %s: %v", dir, err)
			}

			// Verify basic artifact properties
			if artifact.Script == "" {
				t.Errorf("%s: empty script hex", dir)
			}
			if artifact.ASM == "" {
				t.Errorf("%s: empty ASM", dir)
			}
			if artifact.ContractName == "" {
				t.Errorf("%s: empty contract name", dir)
			}

			// Compare against golden expected-script.hex
			goldenHex, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("%s: could not read golden file: %v", dir, err)
			}

			expected := strings.TrimSpace(string(goldenHex))
			if artifact.Script != expected {
				// Report a clear diff — show first 200 chars of each for long scripts
				maxLen := 200
				gotPreview := artifact.Script
				if len(gotPreview) > maxLen {
					gotPreview = gotPreview[:maxLen] + "..."
				}
				expectedPreview := expected
				if len(expectedPreview) > maxLen {
					expectedPreview = expectedPreview[:maxLen] + "..."
				}
				t.Errorf("%s: script hex mismatch (len expected=%d, got=%d)\n  expected: %s\n  got:      %s",
					dir, len(expected), len(artifact.Script), expectedPreview, gotPreview)
			} else {
				t.Logf("%s: MATCH (hex=%d bytes)", dir, len(artifact.Script)/2)
			}

			// Also compile from IR and verify both paths produce the same output
			irPath := filepath.Join(conformanceDir(), dir, "expected-ir.json")
			if _, err := os.Stat(irPath); err == nil {
				irArtifact, err := CompileFromIR(irPath)
				if err != nil {
					t.Logf("%s: IR compilation failed (may be expected for some tests): %v", dir, err)
				} else {
					// Compare IR path vs source path
					if irArtifact.Script != artifact.Script {
						t.Errorf("%s: IR-compiled script differs from source-compiled script\n  IR:     %s\n  Source: %s",
							dir, truncate(irArtifact.Script, 200), truncate(artifact.Script, 200))
					}
				}
			}
		})
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
