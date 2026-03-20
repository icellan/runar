package runar

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeArtifact(script string, abi ABI, overrides ...func(*RunarArtifact)) *RunarArtifact {
	a := &RunarArtifact{
		Version:         "runar-v0.1.0",
		CompilerVersion: "0.1.0",
		ContractName:    "Test",
		ABI:             abi,
		Script:          script,
		ASM:             "",
		BuildTimestamp:   "2026-03-02T00:00:00.000Z",
	}
	for _, override := range overrides {
		override(a)
	}
	return a
}

func makeUtxo(satoshis int64, outputIndex int) UTXO {
	return UTXO{
		Txid:        strings.Repeat("ab", 32), // 64 hex chars = 32 bytes
		OutputIndex: outputIndex,
		Satoshis:    satoshis,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	}
}

func makeTx(txid string, outputs []TxOutput) *TransactionData {
	return &TransactionData{
		Txid:    txid,
		Version: 1,
		Inputs: []TxInput{
			{
				Txid:        strings.Repeat("00", 32),
				OutputIndex: 0,
				Script:      "",
				Sequence:    0xffffffff,
			},
		},
		Outputs:  outputs,
		Locktime: 0,
	}
}

// parseTxHex parses a raw transaction hex for verification purposes.
func parseTxHex(hex string) struct {
	version     int
	inputCount  int
	inputs      []parsedInput
	outputCount int
	outputs     []parsedOutput
	locktime    int
} {
	type result struct {
		version     int
		inputCount  int
		inputs      []parsedInput
		outputCount int
		outputs     []parsedOutput
		locktime    int
	}

	offset := 0

	readBytes := func(n int) string {
		r := hex[offset : offset+n*2]
		offset += n * 2
		return r
	}

	readUint32LE := func() int {
		h := readBytes(4)
		b0 := hexVal(h[0:2])
		b1 := hexVal(h[2:4])
		b2 := hexVal(h[4:6])
		b3 := hexVal(h[6:8])
		return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
	}

	readUint64LE := func() int64 {
		lo := readBytes(4)
		hi := readBytes(4)
		loVal := hexVal(lo[0:2]) | (hexVal(lo[2:4]) << 8) | (hexVal(lo[4:6]) << 16) | (hexVal(lo[6:8]) << 24)
		hiVal := hexVal(hi[0:2]) | (hexVal(hi[2:4]) << 8) | (hexVal(hi[4:6]) << 16) | (hexVal(hi[6:8]) << 24)
		return int64(hiVal)*0x100000000 + int64(loVal)
	}

	readVarInt := func() int {
		first := hexVal(readBytes(1))
		if first < 0xfd {
			return first
		}
		if first == 0xfd {
			h := readBytes(2)
			lo := hexVal(h[0:2])
			hi := hexVal(h[2:4])
			return lo | (hi << 8)
		}
		panic("unsupported varint")
	}

	version := readUint32LE()
	inputCount := readVarInt()

	var inputs []parsedInput
	for i := 0; i < inputCount; i++ {
		prevTxid := readBytes(32)
		prevIndex := readUint32LE()
		scriptLen := readVarInt()
		script := readBytes(scriptLen)
		sequence := readUint32LE()
		inputs = append(inputs, parsedInput{prevTxid, prevIndex, script, uint32(sequence)})
	}

	outputCount := readVarInt()
	var outputs []parsedOutput
	for i := 0; i < outputCount; i++ {
		satoshis := readUint64LE()
		scriptLen := readVarInt()
		script := readBytes(scriptLen)
		outputs = append(outputs, parsedOutput{satoshis, script})
	}

	locktime := readUint32LE()

	return struct {
		version     int
		inputCount  int
		inputs      []parsedInput
		outputCount int
		outputs     []parsedOutput
		locktime    int
	}{version, inputCount, inputs, outputCount, outputs, locktime}
}

type parsedInput struct {
	prevTxid  string
	prevIndex int
	script    string
	sequence  uint32
}

type parsedOutput struct {
	satoshis int64
	script   string
}

func hexVal(s string) int {
	var v int
	for _, c := range s {
		v <<= 4
		if c >= '0' && c <= '9' {
			v |= int(c - '0')
		} else if c >= 'a' && c <= 'f' {
			v |= int(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			v |= int(c - 'A' + 10)
		}
	}
	return v
}

// ---------------------------------------------------------------------------
// Contract construction
// ---------------------------------------------------------------------------

func TestNewRunarContract_CorrectArgCount(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "x", Type: "bigint"}},
		},
		Methods: []ABIMethod{},
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
}

func TestNewRunarContract_WrongArgCount(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "x", Type: "bigint"}},
		},
		Methods: []ABIMethod{},
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for wrong arg count")
		}
		msg := fmt.Sprintf("%v", r)
		if !strings.Contains(msg, "expected 1 constructor args") {
			t.Fatalf("unexpected panic message: %s", msg)
		}
	}()

	NewRunarContract(artifact, []interface{}{})
}

func TestNewRunarContract_InitializesState(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "count", Type: "bigint"}},
		},
		Methods: []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "count", Type: "bigint", Index: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	state := c.GetState()
	if state["count"] != int64(42) {
		t.Errorf("expected count=42, got %v", state["count"])
	}
}

func TestNewRunarContract_InitializesState_MismatchedNames(t *testing.T) {
	// Constructor param "initialHash" maps to state field "rollingHash" by index
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{
				{Name: "genesisOutpoint", Type: "ByteString"},
				{Name: "initialHash", Type: "ByteString"},
				{Name: "metadata", Type: "ByteString"},
			},
		},
		Methods: []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{
			{Name: "genesisOutpoint", Type: "ByteString", Index: 0},
			{Name: "rollingHash", Type: "ByteString", Index: 1},
			{Name: "metadata", Type: "ByteString", Index: 2},
		}
	})

	c := NewRunarContract(artifact, []interface{}{"aabb", "ccdd", "eeff"})
	state := c.GetState()
	if state["genesisOutpoint"] != "aabb" {
		t.Errorf("expected genesisOutpoint=aabb, got %v", state["genesisOutpoint"])
	}
	if state["rollingHash"] != "ccdd" {
		t.Errorf("expected rollingHash=ccdd, got %v", state["rollingHash"])
	}
	if state["metadata"] != "eeff" {
		t.Errorf("expected metadata=eeff, got %v", state["metadata"])
	}
}

// ---------------------------------------------------------------------------
// BigInt values from JSON without reviver ("0n" strings)
// ---------------------------------------------------------------------------

func TestNewRunarContract_BigIntJSON_Revives0n(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "count", Type: "bigint", Index: 0, InitialValue: "0n"}}
	})

	c := NewRunarContract(artifact, []interface{}{})
	state := c.GetState()
	if state["count"] != int64(0) {
		t.Errorf("expected count=0, got %v (type %T)", state["count"], state["count"])
	}
}

func TestNewRunarContract_BigIntJSON_Revives1000n(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "amount", Type: "bigint", Index: 0, InitialValue: "1000n"}}
	})

	c := NewRunarContract(artifact, []interface{}{})
	state := c.GetState()
	if state["amount"] != int64(1000) {
		t.Errorf("expected amount=1000, got %v (type %T)", state["amount"], state["amount"])
	}
}

func TestNewRunarContract_BigIntJSON_RevivesNegative(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "offset", Type: "bigint", Index: 0, InitialValue: "-42n"}}
	})

	c := NewRunarContract(artifact, []interface{}{})
	state := c.GetState()
	if state["offset"] != int64(-42) {
		t.Errorf("expected offset=-42, got %v (type %T)", state["offset"], state["offset"])
	}
}

func TestSerializeState_BigIntJSON_Handles0nString(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	// Simulate state containing unrevived "0n" string
	hex := SerializeState(fields, map[string]interface{}{"count": "0n"})
	if hex != "0000000000000000" {
		t.Errorf("expected 0000000000000000, got %s", hex)
	}
}

func TestSerializeState_BigIntJSON_Handles1000nString(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	hexFromString := SerializeState(fields, map[string]interface{}{"count": "1000n"})
	hexFromInt := SerializeState(fields, map[string]interface{}{"count": int64(1000)})
	if hexFromString != hexFromInt {
		t.Errorf("expected %s, got %s", hexFromInt, hexFromString)
	}
}

func TestGetLockingScript_BigIntJSON_InitialValue0n(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "count", Type: "bigint", Index: 0, InitialValue: "0n"}}
	})

	c := NewRunarContract(artifact, []interface{}{})
	script := c.GetLockingScript()
	// Should contain OP_RETURN separator
	if !strings.Contains(script, "6a") {
		t.Error("expected script to contain OP_RETURN (6a)")
	}
	// Should be valid hex (even length, only hex chars)
	if len(script)%2 != 0 {
		t.Error("expected even-length hex string")
	}
	for _, ch := range script {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("unexpected character in hex: %c", ch)
			break
		}
	}
}

func TestReviveJSONValue_Float64(t *testing.T) {
	// JSON numbers decode as float64 in Go — verify they're handled
	result := reviveJSONValue(float64(42), "bigint")
	if result != int64(42) {
		t.Errorf("expected int64(42), got %v (type %T)", result, result)
	}
}

func TestReviveJSONValue_NonBigintType(t *testing.T) {
	// Non-bigint types should pass through unchanged
	result := reviveJSONValue("hello", "ByteString")
	if result != "hello" {
		t.Errorf("expected 'hello', got %v", result)
	}
}

// ---------------------------------------------------------------------------
// getLockingScript with constructor slots
// ---------------------------------------------------------------------------

func TestGetLockingScript_P2PKH_ConstructorSlot(t *testing.T) {
	pubKeyHash := "18f5bdad6dac9a0a5044a970edf2897d67a7562d"
	artifact := makeArtifact("76a90088ac", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "pubKeyHash", Type: "Addr"}},
		},
		Methods: []ABIMethod{{Name: "unlock", Params: []ABIParam{
			{Name: "sig", Type: "Sig"},
			{Name: "pubKey", Type: "PubKey"},
		}, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.ContractName = "P2PKH"
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 2}}
	})

	c := NewRunarContract(artifact, []interface{}{pubKeyHash})
	lockingScript := c.GetLockingScript()

	// Expected: OP_DUP OP_HASH160 <push 20 bytes: pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
	expected := "76a914" + pubKeyHash + "88ac"
	if lockingScript != expected {
		t.Errorf("expected %s, got %s", expected, lockingScript)
	}
}

func TestGetLockingScript_MultipleConstructorSlots(t *testing.T) {
	pk1 := strings.Repeat("aa", 33)
	pk2 := strings.Repeat("bb", 33)
	artifact := makeArtifact("007c00ac", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{
				{Name: "pk1", Type: "PubKey"},
				{Name: "pk2", Type: "PubKey"},
			},
		},
		Methods: []ABIMethod{{Name: "unlock", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{
			{ParamIndex: 0, ByteOffset: 0},
			{ParamIndex: 1, ByteOffset: 2},
		}
	})

	c := NewRunarContract(artifact, []interface{}{pk1, pk2})
	lockingScript := c.GetLockingScript()

	// 21 = 33 in hex (length prefix for 33 bytes)
	expected := "21" + pk1 + "7c" + "21" + pk2 + "ac"
	if lockingScript != expected {
		t.Errorf("expected %s, got %s", expected, lockingScript)
	}
}

func TestGetLockingScript_FallbackAppend(t *testing.T) {
	pubKeyHash := strings.Repeat("ab", 20)
	artifact := makeArtifact("76a90088ac", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "pubKeyHash", Type: "Addr"}},
		},
		Methods: []ABIMethod{{Name: "unlock", Params: nil, IsPublic: true}},
	})
	// No constructorSlots — old artifact format

	c := NewRunarContract(artifact, []interface{}{pubKeyHash})
	lockingScript := c.GetLockingScript()

	// Old behavior: args appended to end of script
	encodedHash := "14" + pubKeyHash
	expected := "76a90088ac" + encodedHash
	if lockingScript != expected {
		t.Errorf("expected %s, got %s", expected, lockingScript)
	}
}

func TestGetLockingScript_BigintConstructorSlot(t *testing.T) {
	artifact := makeArtifact("009c69", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "threshold", Type: "bigint"}},
		},
		Methods: []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(1000)})
	lockingScript := c.GetLockingScript()

	// 1000 = 0x03E8, as script number (little-endian): e8 03
	// push-data encoding: 02 e8 03
	expected := "02e8039c69"
	if lockingScript != expected {
		t.Errorf("expected %s, got %s", expected, lockingScript)
	}
}

func TestGetLockingScript_DoesNotCorruptNonPlaceholderOP0(t *testing.T) {
	artifact := makeArtifact("00930088", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "x", Type: "bigint"}},
		},
		Methods: []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 2}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	lockingScript := c.GetLockingScript()

	// 42 = 0x2a, script number encoding: 01 2a
	expected := "0093" + "012a" + "88"
	if lockingScript != expected {
		t.Errorf("expected %s, got %s", expected, lockingScript)
	}
}

// ---------------------------------------------------------------------------
// State serialization/deserialization roundtrip
// ---------------------------------------------------------------------------

func TestStateRoundtrip_SingleBigint(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	values := map[string]interface{}{"count": int64(42)}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["count"] != int64(42) {
		t.Errorf("expected count=42, got %v", result["count"])
	}
}

func TestStateRoundtrip_ZeroBigint(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	values := map[string]interface{}{"count": int64(0)}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["count"] != int64(0) {
		t.Errorf("expected count=0, got %v", result["count"])
	}
}

func TestStateRoundtrip_NegativeBigint(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	values := map[string]interface{}{"count": int64(-42)}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["count"] != int64(-42) {
		t.Errorf("expected count=-42, got %v", result["count"])
	}
}

func TestStateRoundtrip_LargeBigint(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	values := map[string]interface{}{"count": int64(1000000000000)}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["count"] != int64(1000000000000) {
		t.Errorf("expected count=1000000000000, got %v", result["count"])
	}
}

func TestStateRoundtrip_MultipleFields(t *testing.T) {
	fields := []StateField{
		{Name: "a", Type: "bigint", Index: 0},
		{Name: "b", Type: "bigint", Index: 1},
		{Name: "c", Type: "bigint", Index: 2},
	}
	values := map[string]interface{}{"a": int64(1), "b": int64(2), "c": int64(3)}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["a"] != int64(1) || result["b"] != int64(2) || result["c"] != int64(3) {
		t.Errorf("unexpected state: %v", result)
	}
}

func TestStateRoundtrip_Boolean(t *testing.T) {
	fields := []StateField{{Name: "flag", Type: "bool", Index: 0}}

	hex := SerializeState(fields, map[string]interface{}{"flag": true})
	result := DeserializeState(fields, hex)
	if result["flag"] != true {
		t.Errorf("expected flag=true, got %v", result["flag"])
	}

	hex = SerializeState(fields, map[string]interface{}{"flag": false})
	result = DeserializeState(fields, hex)
	if result["flag"] != false {
		t.Errorf("expected flag=false, got %v", result["flag"])
	}
}

func TestStateRoundtrip_ByteString(t *testing.T) {
	fields := []StateField{{Name: "data", Type: "bytes", Index: 0}}
	values := map[string]interface{}{"data": "aabbccdd"}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["data"] != "aabbccdd" {
		t.Errorf("expected data=aabbccdd, got %v", result["data"])
	}
}

func TestStateRoundtrip_MixedTypes(t *testing.T) {
	fields := []StateField{
		{Name: "count", Type: "bigint", Index: 0},
		{Name: "active", Type: "bool", Index: 1},
	}
	values := map[string]interface{}{"count": int64(100), "active": true}
	hex := SerializeState(fields, values)
	result := DeserializeState(fields, hex)
	if result["count"] != int64(100) {
		t.Errorf("expected count=100, got %v", result["count"])
	}
	if result["active"] != true {
		t.Errorf("expected active=true, got %v", result["active"])
	}
}

// ---------------------------------------------------------------------------
// State encoding specifics
// ---------------------------------------------------------------------------

func TestStateEncode_Zero(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"v": int64(0)})
	// NUM2BIN(0, 8) → 8 zero bytes
	if hex != "0000000000000000" {
		t.Errorf("expected 0000000000000000, got %s", hex)
	}
}

func TestStateEncode_42(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"v": int64(42)})
	// 42 = 0x2a → LE 8 bytes
	if hex != "2a00000000000000" {
		t.Errorf("expected 2a00000000000000, got %s", hex)
	}
}

func TestStateEncode_1000(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"v": int64(1000)})
	// 1000 = 0x03E8 → LE 8 bytes
	if hex != "e803000000000000" {
		t.Errorf("expected e803000000000000, got %s", hex)
	}
}

func TestStateEncode_128(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"v": int64(128)})
	// 128 = 0x80 → LE 8 bytes, sign bit in byte[7] is 0x00 (positive)
	if hex != "8000000000000000" {
		t.Errorf("expected 8000000000000000, got %s", hex)
	}
}

func TestStateEncode_Neg128(t *testing.T) {
	fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"v": int64(-128)})
	// -128: magnitude=0x80, sign bit in byte[7]
	if hex != "8000000000000080" {
		t.Errorf("expected 8000000000000080, got %s", hex)
	}
}

func TestStateEncode_BoolTrue(t *testing.T) {
	fields := []StateField{{Name: "flag", Type: "bool", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"flag": true})
	// Raw byte 0x01
	if hex != "01" {
		t.Errorf("expected 01, got %s", hex)
	}
}

func TestStateEncode_BoolFalse(t *testing.T) {
	fields := []StateField{{Name: "flag", Type: "bool", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"flag": false})
	if hex != "00" {
		t.Errorf("expected 00, got %s", hex)
	}
}

func TestStateEncode_PubKey(t *testing.T) {
	pubkey := strings.Repeat("ff", 33)
	fields := []StateField{{Name: "pk", Type: "PubKey", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"pk": pubkey})
	// Raw 33 bytes, no push-data prefix
	if hex != pubkey {
		t.Errorf("expected %s, got %s", pubkey, hex)
	}
}

func TestStateEncode_Addr(t *testing.T) {
	addr := strings.Repeat("aa", 20)
	fields := []StateField{{Name: "a", Type: "Addr", Index: 0}}
	hex := SerializeState(fields, map[string]interface{}{"a": addr})
	// Raw 20 bytes, no push-data prefix
	if hex != addr {
		t.Errorf("expected %s, got %s", addr, hex)
	}
}

// ---------------------------------------------------------------------------
// ExtractStateFromScript
// ---------------------------------------------------------------------------

func TestExtractState_NoStateFields(t *testing.T) {
	artifact := makeArtifact("76a914"+strings.Repeat("00", 20)+"88ac", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "unlock", Params: nil, IsPublic: true}},
	})

	result := ExtractStateFromScript(artifact, "76a914"+strings.Repeat("00", 20)+"88ac")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestExtractState_EmptyStateFields(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "unlock", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{}
	})

	result := ExtractStateFromScript(artifact, "51")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestExtractState_NoOpReturn(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "count", Type: "bigint", Index: 0}}
	})

	// Script with no 0x6a anywhere
	result := ExtractStateFromScript(artifact, "5193885187")
	if result != nil {
		t.Errorf("expected nil for script without OP_RETURN, got %v", result)
	}
}

func TestExtractState_FindsLastOpReturn(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = fields
	})

	// Code with embedded 0x6a, then OP_RETURN, then state
	codeWithEmbedded6a := "016a93" // PUSH(0x6a) OP_ADD
	stateHex := SerializeState(fields, map[string]interface{}{"count": int64(42)})
	fullScript := codeWithEmbedded6a + "6a" + stateHex

	result := ExtractStateFromScript(artifact, fullScript)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["count"] != int64(42) {
		t.Errorf("expected count=42, got %v", result["count"])
	}
}

func TestExtractState_RoundtripBigint(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = fields
	})

	stateHex := SerializeState(fields, map[string]interface{}{"count": int64(999)})
	fullScript := "aabbcc" + "6a" + stateHex

	result := ExtractStateFromScript(artifact, fullScript)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["count"] != int64(999) {
		t.Errorf("expected count=999, got %v", result["count"])
	}
}

func TestExtractState_FieldOrdering(t *testing.T) {
	// Declare fields out of order
	fields := []StateField{
		{Name: "b", Type: "bigint", Index: 1},
		{Name: "a", Type: "bigint", Index: 0},
	}
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "check", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = fields
	})

	stateHex := SerializeState(fields, map[string]interface{}{"a": int64(10), "b": int64(20)})
	fullScript := "ac" + "6a" + stateHex

	result := ExtractStateFromScript(artifact, fullScript)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["a"] != int64(10) {
		t.Errorf("expected a=10, got %v", result["a"])
	}
	if result["b"] != int64(20) {
		t.Errorf("expected b=20, got %v", result["b"])
	}
}

// ---------------------------------------------------------------------------
// ExtractState — 0x6a inside state data (regression tests)
// ---------------------------------------------------------------------------

func TestExtractState_BigintValue106(t *testing.T) {
	fields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	artifact := makeArtifact("51ac", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	}, func(a *RunarArtifact) {
		a.StateFields = fields
	})

	// 106 = 0x6a → NUM2BIN(8): "6a00000000000000"
	stateHex := SerializeState(fields, map[string]interface{}{"count": int64(106)})
	if stateHex != "6a00000000000000" {
		t.Fatalf("expected state hex 6a00000000000000, got %s", stateHex)
	}
	fullScript := "51ac" + "6a" + stateHex

	result := ExtractStateFromScript(artifact, fullScript)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["count"] != int64(106) {
		t.Errorf("expected count=106, got %v", result["count"])
	}
}

func TestExtractState_PubKeyEndingWith6a(t *testing.T) {
	pubkey := strings.Repeat("ab", 32) + "6a" // 33 bytes, last byte is 0x6a
	fields := []StateField{
		{Name: "count", Type: "bigint", Index: 0},
		{Name: "owner", Type: "PubKey", Index: 1},
	}
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	}, func(a *RunarArtifact) {
		a.StateFields = fields
	})

	stateHex := SerializeState(fields, map[string]interface{}{"count": int64(42), "owner": pubkey})
	fullScript := "51" + "6a" + stateHex

	result := ExtractStateFromScript(artifact, fullScript)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["count"] != int64(42) {
		t.Errorf("expected count=42, got %v", result["count"])
	}
	if result["owner"] != pubkey {
		t.Errorf("expected owner=%s, got %v", pubkey, result["owner"])
	}
}

func TestFindLastOpReturn_Simple(t *testing.T) {
	// OP_1 OP_RETURN push(1 byte 0x2a)
	pos := FindLastOpReturn("516a012a")
	if pos != 2 {
		t.Errorf("expected 2, got %d", pos)
	}
}

func TestFindLastOpReturn_SkipsPushData(t *testing.T) {
	// push(1 byte: 0x6a) OP_ADD OP_RETURN push(1 byte: 0x2a)
	pos := FindLastOpReturn("016a936a012a")
	if pos != 6 {
		t.Errorf("expected 6, got %d", pos)
	}
}

func TestFindLastOpReturn_NoOpReturn(t *testing.T) {
	pos := FindLastOpReturn("5193885187")
	if pos != -1 {
		t.Errorf("expected -1, got %d", pos)
	}
}

// ---------------------------------------------------------------------------
// Deploy transaction structure
// ---------------------------------------------------------------------------

func TestBuildDeployTransaction_NonEmptyHex(t *testing.T) {
	lockingScript := "76a914" + strings.Repeat("00", 20) + "88ac"
	utxos := []UTXO{makeUtxo(100000, 0)}
	tx, inputCount, err := BuildDeployTransaction(
		lockingScript,
		utxos,
		50000,
		"testChangeAddress",
		"76a914"+strings.Repeat("ff", 20)+"88ac",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	txHex := tx.Hex()
	if txHex == "" {
		t.Fatal("expected non-empty txHex")
	}
	if inputCount != 1 {
		t.Errorf("expected 1 input, got %d", inputCount)
	}
	// All hex chars
	for _, c := range txHex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character in txHex: %c", c)
		}
	}
}

func TestBuildDeployTransaction_CorrectStructure(t *testing.T) {
	lockingScript := "51" // OP_1
	utxos := []UTXO{makeUtxo(100000, 0)}
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	tx, _, err := BuildDeployTransaction(lockingScript, utxos, 50000, "testChangeAddress", changeScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed := parseTxHex(tx.Hex())

	if parsed.version != 1 {
		t.Errorf("expected version 1, got %d", parsed.version)
	}
	if parsed.inputCount != 1 {
		t.Errorf("expected 1 input, got %d", parsed.inputCount)
	}
	if parsed.inputs[0].script != "" {
		t.Errorf("expected empty scriptSig, got %s", parsed.inputs[0].script)
	}
	if parsed.inputs[0].sequence != 0xffffffff {
		t.Errorf("expected sequence 0xffffffff, got %d", parsed.inputs[0].sequence)
	}
	if parsed.outputCount != 2 {
		t.Errorf("expected 2 outputs, got %d", parsed.outputCount)
	}
	if parsed.outputs[0].script != lockingScript {
		t.Errorf("expected contract script %s, got %s", lockingScript, parsed.outputs[0].script)
	}
	if parsed.outputs[1].script != changeScript {
		t.Errorf("expected change script %s, got %s", changeScript, parsed.outputs[1].script)
	}
	if parsed.locktime != 0 {
		t.Errorf("expected locktime 0, got %d", parsed.locktime)
	}
}

func TestBuildDeployTransaction_MultipleUtxos(t *testing.T) {
	utxos := []UTXO{makeUtxo(30000, 0), makeUtxo(40000, 1), makeUtxo(50000, 2)}
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	tx, inputCount, err := BuildDeployTransaction("51", utxos, 50000, "testChangeAddress", changeScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inputCount != 3 {
		t.Errorf("expected 3 inputs, got %d", inputCount)
	}

	parsed := parseTxHex(tx.Hex())
	if parsed.inputCount != 3 {
		t.Errorf("expected 3 inputs in parsed tx, got %d", parsed.inputCount)
	}
}

func TestBuildDeployTransaction_ErrorNoUtxos(t *testing.T) {
	_, _, err := BuildDeployTransaction("51", nil, 50000, "addr", "51")
	if err == nil {
		t.Fatal("expected error for no UTXOs")
	}
	if !strings.Contains(err.Error(), "no UTXOs provided") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestBuildDeployTransaction_ErrorInsufficientFunds(t *testing.T) {
	_, _, err := BuildDeployTransaction("51", []UTXO{makeUtxo(100, 0)}, 50000, "addr", "51")
	if err == nil {
		t.Fatal("expected error for insufficient funds")
	}
	if !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestBuildDeployTransaction_SingleOutputWhenZeroChange(t *testing.T) {
	// Fee: TX_OVERHEAD(10) + 1 input * P2PKH(148) + contract output(8+1+1) + change output(34) = 202 bytes
	// Fee = ceil(202 * 100 / 1000) = 21 sat
	utxos := []UTXO{makeUtxo(50021, 0)}
	tx, _, err := BuildDeployTransaction("51", utxos, 50000, "addr", "51")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed := parseTxHex(tx.Hex())
	if parsed.outputCount != 1 {
		t.Errorf("expected 1 output (no change), got %d", parsed.outputCount)
	}
}

// ---------------------------------------------------------------------------
// Call transaction structure
// ---------------------------------------------------------------------------

func TestBuildCallTransaction_BasicStructure(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	callTxObj, _, _ := BuildCallTransaction(utxo, "51", "", 0, "", "", nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.version != 1 {
		t.Errorf("expected version 1, got %d", parsed.version)
	}
	if parsed.locktime != 0 {
		t.Errorf("expected locktime 0, got %d", parsed.locktime)
	}
}

func TestBuildCallTransaction_UnlockingScriptInInput0(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	callTxObj, _, _ := BuildCallTransaction(utxo, "aabb", "", 0, "", "", nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.inputs[0].script != "aabb" {
		t.Errorf("expected unlocking script aabb in input 0, got %s", parsed.inputs[0].script)
	}
}

func TestBuildCallTransaction_SingleInput(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	callTxObj, inputCount, _ := BuildCallTransaction(utxo, "51", "", 0, "", "", nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if inputCount != 1 {
		t.Errorf("expected 1 input, got %d", inputCount)
	}
	if parsed.inputCount != 1 {
		t.Errorf("expected 1 input in parsed tx, got %d", parsed.inputCount)
	}
}

func TestBuildCallTransaction_AdditionalInputs(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	additional := []UTXO{makeUtxo(50000, 1), makeUtxo(30000, 2)}
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, inputCount, _ := BuildCallTransaction(utxo, "51", "", 0, "changeaddr", changeScript, additional, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if inputCount != 3 {
		t.Errorf("expected 3 inputs, got %d", inputCount)
	}
	if parsed.inputs[0].script != "51" {
		t.Errorf("expected unlocking script 51 in input 0, got %s", parsed.inputs[0].script)
	}
	// Additional inputs have empty scriptSig
	if parsed.inputs[1].script != "" {
		t.Errorf("expected empty scriptSig in input 1, got %s", parsed.inputs[1].script)
	}
	if parsed.inputs[2].script != "" {
		t.Errorf("expected empty scriptSig in input 2, got %s", parsed.inputs[2].script)
	}
}

func TestBuildCallTransaction_StatefulOutput(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	newLockingScript := "76a914" + strings.Repeat("dd", 20) + "88ac"
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, _, _ := BuildCallTransaction(utxo, "51", newLockingScript, 50000, "changeaddr", changeScript, nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.outputs[0].script != newLockingScript {
		t.Errorf("expected contract output script, got %s", parsed.outputs[0].script)
	}
	if parsed.outputs[0].satoshis != 50000 {
		t.Errorf("expected 50000 sats, got %d", parsed.outputs[0].satoshis)
	}
}

func TestBuildCallTransaction_DefaultSatoshis(t *testing.T) {
	utxo := makeUtxo(75000, 0)
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	// newSatoshis = 0 with newLockingScript set => defaults to currentUtxo.Satoshis
	callTxObj, _, _ := BuildCallTransaction(utxo, "00", "51", 0, "changeaddr", changeScript, nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.outputs[0].satoshis != 75000 {
		t.Errorf("expected 75000 sats (default from utxo), got %d", parsed.outputs[0].satoshis)
	}
}

func TestBuildCallTransaction_ChangeCalculation(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, _, _ := BuildCallTransaction(utxo, "00", "51", 50000, "changeaddr", changeScript, nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	// Fee: input0(32+4+1+1+4=42) + contractOut(8+1+1=10) + changeOut(34) + overhead(10) = 96 bytes
	// Fee = ceil(96 * 100 / 1000) = 10 sat
	// Change = 100000 - 50000 - 10 = 49990
	if parsed.outputCount != 2 {
		t.Fatalf("expected 2 outputs, got %d", parsed.outputCount)
	}
	if parsed.outputs[0].satoshis != 50000 {
		t.Errorf("expected 50000 sats for contract output, got %d", parsed.outputs[0].satoshis)
	}
	if parsed.outputs[1].satoshis != 49990 {
		t.Errorf("expected 49990 sats for change, got %d", parsed.outputs[1].satoshis)
	}
}

func TestBuildCallTransaction_NoChangeWhenZero(t *testing.T) {
	// Fee: input0(42) + contractOut(10) + changeOut(34) + overhead(10) = 96 bytes
	// Fee = ceil(96 * 100 / 1000) = 10 sat
	utxo := makeUtxo(50010, 0)
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, _, _ := BuildCallTransaction(utxo, "00", "51", 50000, "changeaddr", changeScript, nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.outputCount != 1 {
		t.Errorf("expected 1 output (no change), got %d", parsed.outputCount)
	}
}

func TestBuildCallTransaction_StatelessChangeOnly(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, _, _ := BuildCallTransaction(utxo, "51", "", 0, "changeaddr", changeScript, nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	// Fee: input0(42) + changeOut(34) + overhead(10) = 86 bytes
	// Fee = ceil(86 * 100 / 1000) = 9 sat
	// Change: 100000 - 0 - 9 = 99991
	if parsed.outputCount != 1 {
		t.Fatalf("expected 1 output, got %d", parsed.outputCount)
	}
	if parsed.outputs[0].script != changeScript {
		t.Errorf("expected change script, got %s", parsed.outputs[0].script)
	}
	if parsed.outputs[0].satoshis != 99991 {
		t.Errorf("expected 99991 sats, got %d", parsed.outputs[0].satoshis)
	}
}

func TestBuildCallTransaction_ReversedTxid(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	callTxObj, _, _ := BuildCallTransaction(utxo, "51", "", 0, "", "", nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	expected := reverseHex(utxo.Txid)
	if parsed.inputs[0].prevTxid != expected {
		t.Errorf("expected reversed txid %s, got %s", expected, parsed.inputs[0].prevTxid)
	}
}

func TestBuildCallTransaction_CorrectOutputIndex(t *testing.T) {
	utxo := makeUtxo(100000, 3)
	callTxObj, _, _ := BuildCallTransaction(utxo, "51", "", 0, "", "", nil, 100)
	parsed := parseTxHex(callTxObj.Hex())

	if parsed.inputs[0].prevIndex != 3 {
		t.Errorf("expected prevIndex 3, got %d", parsed.inputs[0].prevIndex)
	}
}

// ---------------------------------------------------------------------------
// UTXO selection
// ---------------------------------------------------------------------------

func TestSelectUtxos_LargestFirst(t *testing.T) {
	utxos := []UTXO{
		{Txid: "aa", Satoshis: 10000},
		{Txid: "bb", Satoshis: 50000},
		{Txid: "cc", Satoshis: 30000},
	}

	selected := SelectUtxos(utxos, 20000, 25)
	if len(selected) != 1 {
		t.Fatalf("expected 1 UTXO selected, got %d", len(selected))
	}
	if selected[0].Satoshis != 50000 {
		t.Errorf("expected largest UTXO (50000), got %d", selected[0].Satoshis)
	}
}

func TestSelectUtxos_MultipleNeeded(t *testing.T) {
	utxos := []UTXO{
		{Txid: "aa", Satoshis: 1000},
		{Txid: "bb", Satoshis: 2000},
		{Txid: "cc", Satoshis: 3000},
	}

	// Need enough for 5000 + fees
	selected := SelectUtxos(utxos, 5000, 25)
	if len(selected) != 3 {
		t.Errorf("expected 3 UTXOs, got %d", len(selected))
	}
}

// ---------------------------------------------------------------------------
// buildUnlockingScript — method selector encoding
// ---------------------------------------------------------------------------

func TestBuildUnlockingScript_NoSelectorSingleMethod(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "unlock", Params: []ABIParam{{Name: "sig", Type: "Sig"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	sig := strings.Repeat("aa", 72)
	script := c.BuildUnlockingScript("unlock", []interface{}{sig})

	// 72 = 0x48, direct push
	expected := "48" + sig
	if script != expected {
		t.Errorf("expected %s, got %s", expected, script)
	}
}

func TestBuildUnlockingScript_SelectorIndex0(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "release", Params: nil, IsPublic: true},
			{Name: "refund", Params: nil, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("release", nil)

	// Method index 0 encodes as OP_0 (0x00)
	if script != "00" {
		t.Errorf("expected 00, got %s", script)
	}
}

func TestBuildUnlockingScript_SelectorIndex1(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "release", Params: nil, IsPublic: true},
			{Name: "refund", Params: nil, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("refund", nil)

	// Method index 1 encodes as OP_1 (0x51)
	if script != "51" {
		t.Errorf("expected 51, got %s", script)
	}
}

func TestBuildUnlockingScript_SkipsPrivateMethods(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "release", Params: nil, IsPublic: true},
			{Name: "_helper", Params: nil, IsPublic: false},
			{Name: "refund", Params: nil, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("refund", nil)
	// 'refund' is public method index 1 (skipping _helper)
	if script != "51" {
		t.Errorf("expected 51, got %s", script)
	}
}

func TestBuildUnlockingScript_ThreePublicMethods(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "a", Params: nil, IsPublic: true},
			{Name: "b", Params: nil, IsPublic: true},
			{Name: "c", Params: nil, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	if c.BuildUnlockingScript("a", nil) != "00" {
		t.Error("method a should encode as 00 (OP_0)")
	}
	if c.BuildUnlockingScript("b", nil) != "51" {
		t.Error("method b should encode as 51 (OP_1)")
	}
	if c.BuildUnlockingScript("c", nil) != "52" {
		t.Error("method c should encode as 52 (OP_2)")
	}
}

// ---------------------------------------------------------------------------
// buildUnlockingScript — argument encoding
// ---------------------------------------------------------------------------

func TestBuildUnlockingScript_BigintZero(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "n", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("check", []interface{}{int64(0)})
	if script != "00" {
		t.Errorf("expected 00, got %s", script)
	}
}

func TestBuildUnlockingScript_BigintSmallNumbers(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "n", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	if c.BuildUnlockingScript("check", []interface{}{int64(1)}) != "51" {
		t.Error("1 should encode as 51 (OP_1)")
	}
	if c.BuildUnlockingScript("check", []interface{}{int64(5)}) != "55" {
		t.Error("5 should encode as 55 (OP_5)")
	}
	if c.BuildUnlockingScript("check", []interface{}{int64(16)}) != "60" {
		t.Error("16 should encode as 60 (OP_16)")
	}
}

func TestBuildUnlockingScript_BigintNeg1(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "n", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("check", []interface{}{int64(-1)})
	if script != "4f" {
		t.Errorf("expected 4f (OP_1NEGATE), got %s", script)
	}
}

func TestBuildUnlockingScript_Bigint1000(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "n", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("check", []interface{}{int64(1000)})
	// 1000 = 0x03E8, LE: e8 03, push 2 bytes: 02e803
	if script != "02e803" {
		t.Errorf("expected 02e803, got %s", script)
	}
}

func TestBuildUnlockingScript_NegativeBigint(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "n", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	script := c.BuildUnlockingScript("check", []interface{}{int64(-42)})
	// -42: abs=0x2a, sign bit not set, set high bit: 0xaa. Push 1 byte: 01aa
	if script != "01aa" {
		t.Errorf("expected 01aa, got %s", script)
	}
}

func TestBuildUnlockingScript_HexString(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "h", Type: "Addr"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	addr := strings.Repeat("aa", 20)
	script := c.BuildUnlockingScript("check", []interface{}{addr})
	// 20 bytes = 0x14 length prefix
	if script != "14"+addr {
		t.Errorf("expected 14%s, got %s", addr, script)
	}
}

func TestBuildUnlockingScript_BoolTrue(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "flag", Type: "bool"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	if c.BuildUnlockingScript("check", []interface{}{true}) != "51" {
		t.Error("true should encode as 51")
	}
}

func TestBuildUnlockingScript_BoolFalse(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "flag", Type: "bool"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	if c.BuildUnlockingScript("check", []interface{}{false}) != "00" {
		t.Error("false should encode as 00")
	}
}

func TestBuildUnlockingScript_ArgsWithSelector(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "release", Params: []ABIParam{{Name: "sig", Type: "Sig"}}, IsPublic: true},
			{Name: "refund", Params: []ABIParam{{Name: "sig", Type: "Sig"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, nil)
	sig := strings.Repeat("cc", 71)
	script := c.BuildUnlockingScript("release", []interface{}{sig})

	// 71 bytes = 0x47 push prefix, then method index 0 = OP_0
	expected := "47" + sig + "00"
	if script != expected {
		t.Errorf("expected %s, got %s", expected, script)
	}
}

// ---------------------------------------------------------------------------
// FromTxId
// ---------------------------------------------------------------------------

func TestFromTxId_StatefulContract(t *testing.T) {
	stateFields := []StateField{
		{Name: "count", Type: "bigint", Index: 0},
		{Name: "active", Type: "bool", Index: 1},
	}

	codeHex := "76a988ac"
	stateValues := map[string]interface{}{"count": int64(42), "active": true}
	stateHex := SerializeState(stateFields, stateValues)
	fullScript := codeHex + "6a" + stateHex

	fakeTxid := strings.Repeat("aa", 32)
	provider := NewMockProvider("testnet")
	provider.AddTransaction(makeTx(fakeTxid, []TxOutput{
		{Satoshis: 10000, Script: fullScript},
	}))

	artifact := makeArtifact(codeHex, ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{
				{Name: "count", Type: "bigint"},
				{Name: "active", Type: "bool"},
			},
		},
		Methods: nil,
	}, func(a *RunarArtifact) {
		a.StateFields = stateFields
	})

	contract, err := FromTxId(artifact, fakeTxid, 0, provider)
	if err != nil {
		t.Fatalf("FromTxId error: %v", err)
	}

	state := contract.GetState()
	if state["count"] != int64(42) {
		t.Errorf("expected count=42, got %v", state["count"])
	}
	if state["active"] != true {
		t.Errorf("expected active=true, got %v", state["active"])
	}
}

func TestFromTxId_StatelessContract(t *testing.T) {
	fakeTxid := strings.Repeat("aa", 32)
	provider := NewMockProvider("testnet")
	provider.AddTransaction(makeTx(fakeTxid, []TxOutput{
		{Satoshis: 5000, Script: "51"},
	}))

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "spend", Params: nil, IsPublic: true}},
	})

	contract, err := FromTxId(artifact, fakeTxid, 0, provider)
	if err != nil {
		t.Fatalf("FromTxId error: %v", err)
	}

	state := contract.GetState()
	if len(state) != 0 {
		t.Errorf("expected empty state for stateless contract, got %v", state)
	}
}

func TestFromTxId_PreservesCodeScript(t *testing.T) {
	stateFields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	codeHex := "76a988ac"
	stateHex := SerializeState(stateFields, map[string]interface{}{"count": int64(10)})
	fullScript := codeHex + "6a" + stateHex

	fakeTxid := strings.Repeat("aa", 32)
	provider := NewMockProvider("testnet")
	provider.AddTransaction(makeTx(fakeTxid, []TxOutput{
		{Satoshis: 10000, Script: fullScript},
	}))

	artifact := makeArtifact(codeHex, ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "count", Type: "bigint"}},
		},
		Methods: nil,
	}, func(a *RunarArtifact) {
		a.StateFields = stateFields
	})

	contract, err := FromTxId(artifact, fakeTxid, 0, provider)
	if err != nil {
		t.Fatalf("FromTxId error: %v", err)
	}

	// Update state and verify the locking script uses the preserved code
	contract.SetState(map[string]interface{}{"count": int64(99)})
	newScript := contract.GetLockingScript()
	newStateHex := SerializeState(stateFields, map[string]interface{}{"count": int64(99)})
	expected := codeHex + "6a" + newStateHex

	if newScript != expected {
		t.Errorf("expected %s, got %s", expected, newScript)
	}
}

func TestFromTxId_OutOfRange(t *testing.T) {
	fakeTxid := strings.Repeat("aa", 32)
	provider := NewMockProvider("testnet")
	provider.AddTransaction(makeTx(fakeTxid, []TxOutput{
		{Satoshis: 5000, Script: "51"},
	}))

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	})

	_, err := FromTxId(artifact, fakeTxid, 5, provider)
	if err == nil {
		t.Fatal("expected error for out-of-range output index")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFromTxId_UnknownTxid(t *testing.T) {
	provider := NewMockProvider("testnet")

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	})

	unknownTxid := strings.Repeat("ff", 32)
	_, err := FromTxId(artifact, unknownTxid, 0, provider)
	if err == nil {
		t.Fatal("expected error for unknown txid")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MockProvider
// ---------------------------------------------------------------------------

func TestMockProvider_AddAndGetTransaction(t *testing.T) {
	provider := NewMockProvider("testnet")
	txid := strings.Repeat("aa", 32)
	tx := makeTx(txid, []TxOutput{{Satoshis: 5000, Script: "51"}})
	provider.AddTransaction(tx)

	got, err := provider.GetTransaction(txid)
	if err != nil {
		t.Fatalf("GetTransaction error: %v", err)
	}
	if got.Txid != txid {
		t.Errorf("expected txid %s, got %s", txid, got.Txid)
	}
}

func TestMockProvider_GetTransactionNotFound(t *testing.T) {
	provider := NewMockProvider("testnet")
	_, err := provider.GetTransaction("deadbeef")
	if err == nil {
		t.Fatal("expected error for missing transaction")
	}
}

func TestMockProvider_AddAndGetUtxos(t *testing.T) {
	provider := NewMockProvider("testnet")
	utxo := UTXO{Txid: "aa", OutputIndex: 0, Satoshis: 10000, Script: "51"}
	provider.AddUtxo("myaddr", utxo)

	utxos, err := provider.GetUtxos("myaddr")
	if err != nil {
		t.Fatalf("GetUtxos error: %v", err)
	}
	if len(utxos) != 1 {
		t.Fatalf("expected 1 UTXO, got %d", len(utxos))
	}
	if utxos[0].Satoshis != 10000 {
		t.Errorf("expected 10000 sats, got %d", utxos[0].Satoshis)
	}
}

func TestMockProvider_Broadcast(t *testing.T) {
	provider := NewMockProvider("testnet")
	// Build a minimal transaction for broadcast
	bcastTx := transaction.NewTransaction()
	_ = bcastTx.AddInputFrom(strings.Repeat("00", 32), 0, "51", 100000, nil)
	outLS, _ := sdkscript.NewFromHex("51")
	bcastTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      50000,
		LockingScript: outLS,
	})
	txid, err := provider.Broadcast(bcastTx)
	if err != nil {
		t.Fatalf("Broadcast error: %v", err)
	}
	if len(txid) != 64 {
		t.Errorf("expected 64-char txid, got %d chars: %s", len(txid), txid)
	}

	txs := provider.GetBroadcastedTxs()
	if len(txs) != 1 {
		t.Fatalf("expected 1 broadcasted tx, got %d", len(txs))
	}
	if txs[0] != bcastTx.Hex() {
		t.Errorf("expected tx hex, got %s", txs[0])
	}
}

func TestMockProvider_GetNetwork(t *testing.T) {
	p := NewMockProvider("mainnet")
	if p.GetNetwork() != "mainnet" {
		t.Errorf("expected mainnet, got %s", p.GetNetwork())
	}

	p2 := NewMockProvider("")
	if p2.GetNetwork() != "testnet" {
		t.Errorf("expected default testnet, got %s", p2.GetNetwork())
	}
}

// ---------------------------------------------------------------------------
// Full deploy/call lifecycle with MockProvider
// ---------------------------------------------------------------------------

func TestDeployCallLifecycle(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "spend", Params: nil, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, nil)

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	// Add a UTXO for the mock address
	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	// Deploy
	txid, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}
	if txid == "" {
		t.Fatal("expected non-empty txid after deploy")
	}

	broadcasted := provider.GetBroadcastedTxs()
	if len(broadcasted) != 1 {
		t.Fatalf("expected 1 broadcasted tx, got %d", len(broadcasted))
	}
	// Verify it's valid hex
	for _, c := range broadcasted[0] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character in broadcasted tx: %c", c)
		}
	}

	// Call — should work because deploy tracked the UTXO
	txid2, _, err := contract.Call("spend", nil, provider, signer, nil)
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}
	if txid2 == "" {
		t.Fatal("expected non-empty txid after call")
	}
}

func TestDeployThrowsNoUtxos(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	})

	contract := NewRunarContract(artifact, nil)
	provider := NewMockProvider("testnet")
	signer := NewMockSigner("", strings.Repeat("00", 20))

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err == nil {
		t.Fatal("expected error for no UTXOs")
	}
	if !strings.Contains(err.Error(), "no UTXOs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallThrowsNotDeployed(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "spend", Params: nil, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, nil)
	provider := NewMockProvider("testnet")
	signer := NewMockSigner("", strings.Repeat("00", 20))

	_, _, err := contract.Call("spend", nil, provider, signer, nil)
	if err == nil {
		t.Fatal("expected error for undeployed contract")
	}
	if !strings.Contains(err.Error(), "not deployed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallThrowsUnknownMethod(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "spend", Params: nil, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, nil)
	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	// Deploy first
	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})
	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	_, _, err = contract.Call("nonexistent", nil, provider, signer, nil)
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallThrowsWrongArgCount(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{{
			Name: "transfer",
			Params: []ABIParam{
				{Name: "to", Type: "Addr"},
				{Name: "amount", Type: "bigint"},
			},
			IsPublic: true,
		}},
	})

	contract := NewRunarContract(artifact, nil)
	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})
	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	// Pass 1 arg when 2 are expected
	_, _, err = contract.Call("transfer", []interface{}{"deadbeef"}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected error for wrong arg count")
	}
	if !strings.Contains(err.Error(), "expects 2 args, got 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Stateful deploy/call lifecycle
// ---------------------------------------------------------------------------

func TestStatefulDeployCallLifecycle(t *testing.T) {
	stateFields := []StateField{{Name: "count", Type: "bigint", Index: 0}}
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "count", Type: "bigint"}},
		},
		Methods: []ABIMethod{{Name: "increment", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = stateFields
	})

	contract := NewRunarContract(artifact, []interface{}{int64(0)})

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	// Deploy with initial state count=0
	txid, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}
	if txid == "" {
		t.Fatal("expected non-empty txid")
	}

	// Verify initial state
	state := contract.GetState()
	if state["count"] != int64(0) {
		t.Errorf("expected count=0, got %v", state["count"])
	}

	// Call increment with updated state
	txid2, _, err := contract.Call("increment", nil, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	})
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}
	if txid2 == "" {
		t.Fatal("expected non-empty txid after call")
	}

	// Verify updated state
	state = contract.GetState()
	if state["count"] != int64(1) {
		t.Errorf("expected count=1, got %v", state["count"])
	}
}

// ---------------------------------------------------------------------------
// Bigint roundtrip edge cases (matching TS tests)
// ---------------------------------------------------------------------------

func TestBigintEdgeCases(t *testing.T) {
	testCases := []struct {
		label string
		value int64
	}{
		{"0", 0},
		{"1", 1},
		{"-1", -1},
		{"127", 127},
		{"128", 128},
		{"-128", -128},
		{"255", 255},
		{"256", 256},
		{"-256", -256},
		{"large positive", 9999999999},
		{"large negative", -9999999999},
	}

	for _, tc := range testCases {
		t.Run(tc.label, func(t *testing.T) {
			fields := []StateField{{Name: "v", Type: "bigint", Index: 0}}
			hex := SerializeState(fields, map[string]interface{}{"v": tc.value})
			result := DeserializeState(fields, hex)
			if result["v"] != tc.value {
				t.Errorf("roundtrip failed: expected %d, got %v", tc.value, result["v"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// InsertUnlockingScript
// ---------------------------------------------------------------------------

func TestInsertUnlockingScript_Basic(t *testing.T) {
	// Build a simple 1-input tx with empty scriptSig
	utxo := makeUtxo(100000, 0)
	deployTxObj, _, err := BuildDeployTransaction("51", []UTXO{utxo}, 50000, "addr",
		"76a914"+strings.Repeat("ff", 20)+"88ac")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Insert a mock unlocking script
	unlockScript := "48" + strings.Repeat("aa", 72) // 72-byte sig push
	modified := InsertUnlockingScript(deployTxObj.Hex(), 0, unlockScript)

	parsed := parseTxHex(modified)
	if parsed.inputs[0].script != unlockScript {
		t.Errorf("expected unlocking script in input 0, got %s", parsed.inputs[0].script)
	}
}

// ---------------------------------------------------------------------------
// MockSigner
// ---------------------------------------------------------------------------

func TestMockSigner_GetPublicKey(t *testing.T) {
	signer := NewMockSigner("", "")
	pk, err := signer.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey error: %v", err)
	}
	// Default is 02 + 32 zero bytes = 66 hex chars
	if len(pk) != 66 {
		t.Errorf("expected 66-char public key, got %d: %s", len(pk), pk)
	}
}

func TestMockSigner_Sign(t *testing.T) {
	signer := NewMockSigner("", "")
	sig, err := signer.Sign("aabb", 0, "51", 10000, nil)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	// DER prefix 0x30 + 70 zero bytes + sighash 0x41 = 144 hex chars
	if len(sig) != 144 {
		t.Errorf("expected 144-char signature, got %d: %s", len(sig), sig)
	}
}

// ---------------------------------------------------------------------------
// SetState
// ---------------------------------------------------------------------------

func TestSetState(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "count", Type: "bigint"}},
		},
		Methods: nil,
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{{Name: "count", Type: "bigint", Index: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(0)})
	c.SetState(map[string]interface{}{"count": int64(99)})

	state := c.GetState()
	if state["count"] != int64(99) {
		t.Errorf("expected count=99, got %v", state["count"])
	}
}

// ---------------------------------------------------------------------------
// LocalSigner
// ---------------------------------------------------------------------------

const testPrivKeyHex1 = "0000000000000000000000000000000000000000000000000000000000000001"
const testPrivKeyHex2 = "0000000000000000000000000000000000000000000000000000000000000002"
const testWifCompressed = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

func TestLocalSigner_ConstructorHex(t *testing.T) {
	signer, err := NewLocalSigner(testPrivKeyHex1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestLocalSigner_ConstructorWif(t *testing.T) {
	signer, err := NewLocalSigner(testWifCompressed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestLocalSigner_ConstructorInvalid(t *testing.T) {
	_, err := NewLocalSigner("not-a-key")
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestLocalSigner_GetPublicKey(t *testing.T) {
	signer, _ := NewLocalSigner(testPrivKeyHex1)
	pk, err := signer.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey error: %v", err)
	}
	// Private key 1 = secp256k1 generator point G
	expected := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	if pk != expected {
		t.Errorf("expected %s, got %s", expected, pk)
	}
}

func TestLocalSigner_GetPublicKey_66Chars(t *testing.T) {
	signer, _ := NewLocalSigner(testPrivKeyHex1)
	pk, err := signer.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey error: %v", err)
	}
	if len(pk) != 66 {
		t.Errorf("expected 66-char public key, got %d: %s", len(pk), pk)
	}
}

func TestLocalSigner_GetAddress(t *testing.T) {
	signer, _ := NewLocalSigner(testPrivKeyHex1)
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatalf("GetAddress error: %v", err)
	}
	if len(addr) == 0 {
		t.Fatal("expected non-empty address")
	}
	if addr[0] != '1' {
		t.Errorf("expected mainnet address starting with 1, got %s", addr)
	}
}

func TestLocalSigner_WifSameAsHex(t *testing.T) {
	fromHex, _ := NewLocalSigner(testPrivKeyHex1)
	fromWif, _ := NewLocalSigner(testWifCompressed)

	pkHex, _ := fromHex.GetPublicKey()
	pkWif, _ := fromWif.GetPublicKey()
	if pkHex != pkWif {
		t.Errorf("WIF and hex should produce same pubkey: %s vs %s", pkHex, pkWif)
	}

	addrHex, _ := fromHex.GetAddress()
	addrWif, _ := fromWif.GetAddress()
	if addrHex != addrWif {
		t.Errorf("WIF and hex should produce same address: %s vs %s", addrHex, addrWif)
	}
}

func TestLocalSigner_Sign(t *testing.T) {
	signer, _ := NewLocalSigner(testPrivKeyHex1)

	// Minimal valid transaction: version(4) + 1 input(41 bytes) + 1 output(10 bytes) + locktime(4)
	txHex := "01000000" + // version 1
		"01" + // 1 input
		strings.Repeat("00", 32) + // prevTxid
		"00000000" + // prevIndex 0
		"00" + // empty scriptSig
		"ffffffff" + // sequence
		"01" + // 1 output
		"5000000000000000" + // 80 satoshis (LE)
		"01" + // script length 1
		"51" + // OP_1
		"00000000" // locktime 0

	sig, err := signer.Sign(txHex, 0, "51", 100, nil)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Should be valid hex
	for _, c := range sig {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character in signature: %c", c)
		}
	}

	// Should end with sighash byte 0x41
	if sig[len(sig)-2:] != "41" {
		t.Errorf("expected signature ending with 41, got %s", sig[len(sig)-2:])
	}

	// Should start with DER prefix 30
	if sig[:2] != "30" {
		t.Errorf("expected DER signature starting with 30, got %s", sig[:2])
	}
}

func TestLocalSigner_SignDeterministic(t *testing.T) {
	signer, _ := NewLocalSigner(testPrivKeyHex1)

	txHex := "01000000" +
		"01" +
		strings.Repeat("00", 32) +
		"00000000" +
		"00" +
		"ffffffff" +
		"01" +
		"5000000000000000" +
		"01" +
		"51" +
		"00000000"

	sig1, _ := signer.Sign(txHex, 0, "51", 100, nil)
	sig2, _ := signer.Sign(txHex, 0, "51", 100, nil)
	if sig1 != sig2 {
		t.Errorf("expected deterministic signatures, got %s vs %s", sig1, sig2)
	}
}

func TestLocalSigner_DifferentKeysDifferentSigs(t *testing.T) {
	signer1, _ := NewLocalSigner(testPrivKeyHex1)
	signer2, _ := NewLocalSigner(testPrivKeyHex2)

	txHex := "01000000" +
		"01" +
		strings.Repeat("00", 32) +
		"00000000" +
		"00" +
		"ffffffff" +
		"01" +
		"5000000000000000" +
		"01" +
		"51" +
		"00000000"

	sig1, _ := signer1.Sign(txHex, 0, "51", 100, nil)
	sig2, _ := signer2.Sign(txHex, 0, "51", 100, nil)
	if sig1 == sig2 {
		t.Error("different keys should produce different signatures")
	}
}

// ---------------------------------------------------------------------------
// BuildUnlockingScript
// ---------------------------------------------------------------------------

func TestBuildUnlockingScript_SingleMethod_NoSelector(t *testing.T) {
	artifact := makeArtifact("009c", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "target", Type: "bigint"}},
		},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "x", Type: "bigint"}}, IsPublic: true},
		},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	unlock := c.BuildUnlockingScript("check", []interface{}{int64(7)})

	// Single-method contract: no method selector, only the arg
	// 7 → OP_7 = 0x57
	expected := "57"
	if unlock != expected {
		t.Errorf("expected unlocking script %q, got %q", expected, unlock)
	}
}

func TestBuildUnlockingScript_MultiMethod_HasSelector(t *testing.T) {
	artifact := makeArtifact("009c", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "target", Type: "bigint"}},
		},
		Methods: []ABIMethod{
			{Name: "methodA", Params: []ABIParam{{Name: "x", Type: "bigint"}}, IsPublic: true},
			{Name: "methodB", Params: nil, IsPublic: true},
		},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	unlock := c.BuildUnlockingScript("methodB", []interface{}{})

	// Multi-method: method selector for index 1 (methodB) = OP_1 = 0x51
	expected := "51"
	if unlock != expected {
		t.Errorf("expected unlocking script %q, got %q", expected, unlock)
	}
}

// ---------------------------------------------------------------------------
// buildCodeScript must NOT duplicate constructor args
// ---------------------------------------------------------------------------

func TestBuildCodeScript_WithSlots_NoFallbackAppend(t *testing.T) {
	// Script: OP_0 (placeholder at offset 0) + OP_NUMEQUAL
	// After splicing target=42: should be "012a" + "9c"
	artifact := makeArtifact("009c", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "target", Type: "bigint"}},
		},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "x", Type: "bigint"}}, IsPublic: true},
		},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	lockingScript := c.GetLockingScript()

	// 42 = 0x2a → script number push: 01 2a
	// Then OP_NUMEQUAL = 9c
	expected := "012a9c"
	if lockingScript != expected {
		t.Errorf("expected locking script %q, got %q\nlength: expected %d, got %d",
			expected, lockingScript, len(expected), len(lockingScript))
	}
}

func TestBuildCodeScript_WithoutSlots_FallbackAppends(t *testing.T) {
	// Old artifact format: no constructor slots, args appended to script
	artifact := makeArtifact("009c", ABI{
		Constructor: ABIConstructor{
			Params: []ABIParam{{Name: "target", Type: "bigint"}},
		},
		Methods: []ABIMethod{
			{Name: "check", Params: []ABIParam{{Name: "x", Type: "bigint"}}, IsPublic: true},
		},
	})

	c := NewRunarContract(artifact, []interface{}{int64(42)})
	lockingScript := c.GetLockingScript()

	// Fallback: "009c" + encoded(42) = "009c" + "012a"
	expected := "009c" + "012a"
	if lockingScript != expected {
		t.Errorf("expected locking script %q, got %q", expected, lockingScript)
	}
}

// ---------------------------------------------------------------------------
// Terminal method call tests
// ---------------------------------------------------------------------------

func TestTerminalCall_SetsUtxoToNil(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "cancel", Params: nil, IsPublic: true},
		},
	})

	contract := NewRunarContract(artifact, nil)

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	payoutScript := "76a914" + strings.Repeat("bb", 20) + "88ac"
	txid, _, err := contract.Call("cancel", nil, provider, signer, &CallOptions{
		TerminalOutputs: []TerminalOutput{
			{ScriptHex: payoutScript, Satoshis: 49000},
		},
	})
	if err != nil {
		t.Fatalf("Terminal call error: %v", err)
	}
	if len(txid) != 64 {
		t.Errorf("expected 64-char txid, got %d", len(txid))
	}
	if contract.GetCurrentUtxo() != nil {
		t.Error("expected currentUtxo to be nil after terminal call")
	}
}

func TestTerminalCall_SubsequentCallFails(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "spend", Params: nil, IsPublic: true},
		},
	})

	contract := NewRunarContract(artifact, nil)

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	_, _, err = contract.Call("spend", nil, provider, signer, &CallOptions{
		TerminalOutputs: []TerminalOutput{
			{ScriptHex: "76a914" + strings.Repeat("cc", 20) + "88ac", Satoshis: 9000},
		},
	})
	if err != nil {
		t.Fatalf("Terminal call error: %v", err)
	}

	// Subsequent call should fail with "not deployed"
	_, _, err = contract.Call("spend", nil, provider, signer, nil)
	if err == nil {
		t.Fatal("expected error after terminal call")
	}
	if !strings.Contains(err.Error(), "not deployed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerminalCall_MultipleOutputs(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "settle", Params: nil, IsPublic: true},
		},
	})

	contract := NewRunarContract(artifact, nil)

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 20000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	txid, _, err := contract.Call("settle", nil, provider, signer, &CallOptions{
		TerminalOutputs: []TerminalOutput{
			{ScriptHex: "76a914" + strings.Repeat("aa", 20) + "88ac", Satoshis: 10000},
			{ScriptHex: "76a914" + strings.Repeat("bb", 20) + "88ac", Satoshis: 9000},
		},
	})
	if err != nil {
		t.Fatalf("Terminal call error: %v", err)
	}
	if len(txid) != 64 {
		t.Errorf("expected 64-char txid, got %d", len(txid))
	}
	if contract.GetCurrentUtxo() != nil {
		t.Error("expected currentUtxo to be nil after terminal call")
	}
}

func TestTerminalCall_TxStructure(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods: []ABIMethod{
			{Name: "cancel", Params: nil, IsPublic: true},
		},
	})

	contract := NewRunarContract(artifact, nil)

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("Deploy error: %v", err)
	}

	payoutScript := "76a914" + strings.Repeat("dd", 20) + "88ac"
	_, _, err = contract.Call("cancel", nil, provider, signer, &CallOptions{
		TerminalOutputs: []TerminalOutput{
			{ScriptHex: payoutScript, Satoshis: 49000},
		},
	})
	if err != nil {
		t.Fatalf("Terminal call error: %v", err)
	}

	broadcastedTxs := provider.GetBroadcastedTxs()
	// Deploy is first broadcast, terminal call is second
	if len(broadcastedTxs) != 2 {
		t.Fatalf("expected 2 broadcasts, got %d", len(broadcastedTxs))
	}

	termTxHex := broadcastedTxs[1]
	parsed := parseTxHex(termTxHex)

	// Should have version 1
	if parsed.version != 1 {
		t.Errorf("expected version 1, got %d", parsed.version)
	}

	// Should have 1 input (no funding inputs)
	if parsed.inputCount != 1 {
		t.Errorf("expected 1 input, got %d", parsed.inputCount)
	}
}

// ---------------------------------------------------------------------------
// Row 353: All input sequences are 0xffffffff in call transaction
// ---------------------------------------------------------------------------

func TestBuildCallTransaction_AllSequences(t *testing.T) {
	utxo := makeUtxo(100000, 0)
	additional := []UTXO{makeUtxo(50000, 1), makeUtxo(30000, 2)}
	changeScript := "76a914" + strings.Repeat("ff", 20) + "88ac"

	callTxObj, _, _ := BuildCallTransaction(utxo, "51", "", 0, "changeaddr", changeScript, additional, 100)
	parsed := parseTxHex(callTxObj.Hex())

	for i, inp := range parsed.inputs {
		if inp.sequence != 0xffffffff {
			t.Errorf("input %d: expected sequence 0xffffffff, got %d", i, inp.sequence)
		}
	}
}

// ---------------------------------------------------------------------------
// Row 363: InsertUnlockingScript with out-of-range input index panics
// ---------------------------------------------------------------------------

func TestInsertUnlockingScript_OutOfRange(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for out-of-range input index")
		}
	}()

	utxo := makeUtxo(100000, 0)
	deployTxObj, _, err := BuildDeployTransaction("51", []UTXO{utxo}, 50000, "addr",
		"76a914"+strings.Repeat("ff", 20)+"88ac")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// index 5 is out of range (tx has 1 input)
	InsertUnlockingScript(deployTxObj.Hex(), 5, "51")
}

// ---------------------------------------------------------------------------
// Row 372: encode_state_value for PubKey encodes as raw hex (no push prefix)
// ---------------------------------------------------------------------------

func TestEncodeStateValue_PubKey(t *testing.T) {
	// A 33-byte compressed PubKey state field serializes as raw hex (no push prefix).
	// Test via round-trip: serialize state with a PubKey field, then verify bytes.
	pubKeyHex := "02" + strings.Repeat("ab", 32) // 33-byte compressed pubkey
	fields := []StateField{
		{Name: "pk", Type: "PubKey", Index: 0},
	}
	stateMap := map[string]interface{}{"pk": pubKeyHex}
	encoded := SerializeState(fields, stateMap)
	// Encoded state should contain the raw pubkey hex without extra push prefix length
	if !strings.Contains(encoded, strings.Repeat("ab", 32)) {
		t.Errorf("PubKey state encoding should contain raw bytes, got: %s", encoded)
	}
}

// ---------------------------------------------------------------------------
// Row 378: extract_state_from_script returns nil when no state fields defined
// ---------------------------------------------------------------------------

func TestExtractState_NoStateFieldsDefined(t *testing.T) {
	// A contract with no stateFields → ExtractStateFromScript returns nil
	artifact := makeArtifact("76a914"+strings.Repeat("00", 20)+"88ac", ABI{})
	// artifact.StateFields is empty/nil

	script := "76a914" + strings.Repeat("00", 20) + "88ac"
	state := ExtractStateFromScript(artifact, script)
	if state != nil {
		t.Errorf("expected nil state for contract with no stateFields, got: %v", state)
	}
}

// ---------------------------------------------------------------------------
// Row 382: push_data encode/decode — small data (< 76 bytes) round-trips
// ---------------------------------------------------------------------------

func TestPushData_SmallData_RoundTrip(t *testing.T) {
	// Encode 4-byte hex "deadbeef" as push data
	data := "deadbeef"
	encoded := EncodePushData(data)
	// Should start with "04" (length = 4)
	if !strings.HasPrefix(encoded, "04") {
		t.Errorf("expected 4-byte push to start with '04', got: %s", encoded)
	}
	// Decode should recover original
	decoded, _ := DecodePushData(encoded, 0)
	if decoded != data {
		t.Errorf("push_data round-trip failed: expected %s, got %s", data, decoded)
	}
}

// ---------------------------------------------------------------------------
// Row 383: push_data encode — 76+ bytes triggers OP_PUSHDATA1 (prefix 0x4c)
// ---------------------------------------------------------------------------

func TestPushData_76Bytes_UsesPUSHDATA1(t *testing.T) {
	// 76 bytes = 152 hex chars
	data := strings.Repeat("ab", 76)
	encoded := EncodePushData(data)
	if !strings.HasPrefix(encoded, "4c") {
		t.Errorf("expected 76-byte push to start with '4c' (OP_PUSHDATA1), got: %s", encoded[:4])
	}
}

// ---------------------------------------------------------------------------
// Row 387: MockSigner.sign() is deterministic
// ---------------------------------------------------------------------------

func TestMockSigner_Sign_Deterministic(t *testing.T) {
	signer := NewMockSigner("", "")
	txHex := "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100000000000000001976a914000000000000000000000000000000000000000088ac00000000"

	sig1, err1 := signer.Sign(txHex, 0, "", 0, nil)
	sig2, err2 := signer.Sign(txHex, 0, "", 0, nil)

	if err1 != nil || err2 != nil {
		t.Fatalf("sign errors: %v, %v", err1, err2)
	}
	if sig1 != sig2 {
		t.Errorf("MockSigner sign is not deterministic: %s != %s", sig1, sig2)
	}
}

// ---------------------------------------------------------------------------
// Row 388: MockSigner returns address (40 hex chars)
// ---------------------------------------------------------------------------

func TestMockSigner_GetAddress(t *testing.T) {
	signer := NewMockSigner("", "")
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatalf("GetAddress error: %v", err)
	}
	if len(addr) != 40 {
		t.Errorf("expected 40-char address, got %d: %s", len(addr), addr)
	}
}

// ---------------------------------------------------------------------------
// Row 400: ExternalSigner delegates GetPublicKey to callback
// ---------------------------------------------------------------------------

func TestExternalSigner_GetPublicKey(t *testing.T) {
	expectedPK := "03" + strings.Repeat("ab", 32)
	signer := NewExternalSigner(expectedPK, "addr", func(tx string, idx int, script string, sats int64, ht *int) (string, error) {
		return "", nil
	})
	pk, err := signer.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey error: %v", err)
	}
	if pk != expectedPK {
		t.Errorf("expected pubkey %s, got %s", expectedPK, pk)
	}
}

// ---------------------------------------------------------------------------
// Row 401: ExternalSigner delegates GetAddress to callback
// ---------------------------------------------------------------------------

func TestExternalSigner_GetAddress(t *testing.T) {
	expectedAddr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na"
	signer := NewExternalSigner("03"+ strings.Repeat("ab", 32), expectedAddr, func(tx string, idx int, script string, sats int64, ht *int) (string, error) {
		return "", nil
	})
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatalf("GetAddress error: %v", err)
	}
	if addr != expectedAddr {
		t.Errorf("expected address %s, got %s", expectedAddr, addr)
	}
}

// ---------------------------------------------------------------------------
// Row 402: ExternalSigner delegates sign() to callback with correct args
// ---------------------------------------------------------------------------

func TestExternalSigner_Sign_DelegatesToCallback(t *testing.T) {
	var capturedTx string
	var capturedIdx int
	expectedSig := "3045022100" + strings.Repeat("aa", 32) + "0220" + strings.Repeat("bb", 32) + "41"

	signer := NewExternalSigner("03"+strings.Repeat("ab", 32), "addr",
		func(tx string, idx int, script string, sats int64, ht *int) (string, error) {
			capturedTx = tx
			capturedIdx = idx
			return expectedSig, nil
		},
	)

	txHex := "0100000001" + strings.Repeat("00", 32) + "00000000ffffffff00ffffffff0100000000000000001976a914" + strings.Repeat("00", 20) + "88ac00000000"
	sig, err := signer.Sign(txHex, 2, "", 50000, nil)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if sig != expectedSig {
		t.Errorf("expected sig %s, got %s", expectedSig, sig)
	}
	if capturedTx != txHex {
		t.Errorf("callback received wrong tx: %s", capturedTx)
	}
	if capturedIdx != 2 {
		t.Errorf("callback received wrong input index: %d", capturedIdx)
	}
}

// ---------------------------------------------------------------------------
// Row 407: MockProvider unknown address → empty UTXO slice
// ---------------------------------------------------------------------------

func TestMockProvider_UnknownAddress_EmptySlice(t *testing.T) {
	provider := NewMockProvider("mainnet")
	// Don't add any UTXOs
	utxos, err := provider.GetUtxos("unknown-address")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(utxos) != 0 {
		t.Errorf("expected empty UTXO slice for unknown address, got %d UTXOs", len(utxos))
	}
}

// ---------------------------------------------------------------------------
// Row 408: MockProvider broadcast() is all-lowercase hex txid
// ---------------------------------------------------------------------------

func TestMockProvider_Broadcast_TxidAllHexLower(t *testing.T) {
	provider := NewMockProvider("mainnet")
	bcastTx := transaction.NewTransaction()
	_ = bcastTx.AddInputFrom(strings.Repeat("aa", 32), 0, "51", 100000, nil)
	outLS, _ := sdkscript.NewFromHex("51")
	bcastTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      50000,
		LockingScript: outLS,
	})

	txid, err := provider.Broadcast(bcastTx)
	if err != nil {
		t.Fatalf("broadcast error: %v", err)
	}
	if len(txid) != 64 {
		t.Errorf("expected 64-char txid, got %d: %s", len(txid), txid)
	}
	// All hex chars
	for _, c := range txid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("txid contains non-hex character: %c", c)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Row 433: RunarArtifact deserialization parses version, contractName, etc.
// ---------------------------------------------------------------------------

func TestRunarArtifact_Deserialization(t *testing.T) {
	artifactJSON := `{
		"version": "runar-v0.1.0",
		"compilerVersion": "0.1.0",
		"contractName": "P2PKH",
		"abi": {
			"constructor": {"params": [{"name": "pubKeyHash", "type": "Addr"}]},
			"methods": [{"name": "unlock", "params": [{"name": "sig", "type": "Sig"}, {"name": "pubKey", "type": "PubKey"}], "isPublic": true}]
		},
		"script": "76a914",
		"asm": "OP_DUP OP_HASH160",
		"buildTimestamp": "2026-01-01T00:00:00Z"
	}`

	var artifact RunarArtifact
	if err := json.Unmarshal([]byte(artifactJSON), &artifact); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if artifact.Version != "runar-v0.1.0" {
		t.Errorf("expected version 'runar-v0.1.0', got '%s'", artifact.Version)
	}
	if artifact.ContractName != "P2PKH" {
		t.Errorf("expected contractName 'P2PKH', got '%s'", artifact.ContractName)
	}
	if artifact.Script != "76a914" {
		t.Errorf("expected script '76a914', got '%s'", artifact.Script)
	}
	if len(artifact.ABI.Constructor.Params) != 1 {
		t.Errorf("expected 1 constructor param, got %d", len(artifact.ABI.Constructor.Params))
	}
	if len(artifact.ABI.Methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(artifact.ABI.Methods))
	}
}

// ---------------------------------------------------------------------------
// Row 434: constructorSlots and codeSeparatorIndex parsed from artifact JSON
// ---------------------------------------------------------------------------

func TestRunarArtifact_ConstructorSlots(t *testing.T) {
	sep := 5
	artifactJSON := fmt.Sprintf(`{
		"version": "runar-v0.1.0",
		"compilerVersion": "0.1.0",
		"contractName": "P2PKH",
		"abi": {"constructor": {"params": []}, "methods": []},
		"script": "76a914",
		"asm": "",
		"buildTimestamp": "2026-01-01T00:00:00Z",
		"constructorSlots": [{"paramIndex": 0, "byteOffset": 3}],
		"codeSeparatorIndex": %d
	}`, sep)

	var artifact RunarArtifact
	if err := json.Unmarshal([]byte(artifactJSON), &artifact); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if len(artifact.ConstructorSlots) != 1 {
		t.Fatalf("expected 1 constructor slot, got %d", len(artifact.ConstructorSlots))
	}
	if artifact.ConstructorSlots[0].ParamIndex != 0 {
		t.Errorf("expected slot paramIndex=0, got %d", artifact.ConstructorSlots[0].ParamIndex)
	}
	if artifact.ConstructorSlots[0].ByteOffset != 3 {
		t.Errorf("expected slot byteOffset=3, got %d", artifact.ConstructorSlots[0].ByteOffset)
	}
	if artifact.CodeSeparatorIndex == nil || *artifact.CodeSeparatorIndex != sep {
		t.Errorf("expected codeSeparatorIndex=%d, got %v", sep, artifact.CodeSeparatorIndex)
	}
}

// ---------------------------------------------------------------------------
// Row 457: ANF interpreter — Counter increment: count 0→1
// ---------------------------------------------------------------------------

func TestComputeNewState_Counter_Increment(t *testing.T) {
	anf := &ANFProgram{
		ContractName: "Counter",
		Properties: []ANFProperty{
			{Name: "count", Type: "bigint", Readonly: false},
		},
		Methods: []ANFMethod{
			{
				Name:     "constructor",
				Params:   []ANFParam{{Name: "count", Type: "bigint"}},
				Body:     []ANFBinding{},
				IsPublic: false,
			},
			{
				Name:     "increment",
				Params:   []ANFParam{{Name: "txPreimage", Type: "SigHashPreimage"}, {Name: "_changePKH", Type: "Addr"}, {Name: "_changeAmount", Type: "bigint"}},
				IsPublic: true,
				Body: []ANFBinding{
					{Name: "t0", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
					{Name: "t1", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
					{Name: "t2", Value: map[string]interface{}{"kind": "bin_op", "op": "+", "left": "t0", "right": "t1", "resultType": "bigint"}},
					{Name: "t3", Value: map[string]interface{}{"kind": "update_prop", "name": "count", "value": "t2"}},
				},
			},
		},
	}

	currentState := map[string]interface{}{"count": big.NewInt(0)}
	newState, err := ComputeNewState(anf, "increment", currentState, nil)
	if err != nil {
		t.Fatalf("ComputeNewState failed: %v", err)
	}

	countVal, ok := newState["count"]
	if !ok {
		t.Fatal("expected 'count' in new state")
	}
	countBig, ok := countVal.(*big.Int)
	if !ok {
		t.Fatalf("expected *big.Int for count, got %T", countVal)
	}
	if countBig.Int64() != 1 {
		t.Errorf("expected count=1, got %d", countBig.Int64())
	}
}

// ---------------------------------------------------------------------------
// Row 462: ANF interpreter — unknown method → error
// ---------------------------------------------------------------------------

func TestComputeNewState_UnknownMethod_Error(t *testing.T) {
	anf := &ANFProgram{
		ContractName: "Counter",
		Properties:   []ANFProperty{{Name: "count", Type: "bigint"}},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false, Body: []ANFBinding{}},
		},
	}

	_, err := ComputeNewState(anf, "nonexistent", map[string]interface{}{"count": big.NewInt(0)}, nil)
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}
