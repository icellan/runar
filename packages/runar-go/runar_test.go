package runar

import (
	"testing"
)

func TestAssert_True(t *testing.T) {
	Assert(true) // should not panic
}

func TestAssert_False(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Assert(false) to panic")
		}
	}()
	Assert(false)
}

func TestCheckSig_RealECDSA(t *testing.T) {
	sig := SignTestMessage(Alice.PrivKey)
	if !CheckSig(sig, Alice.PubKey) {
		t.Error("CheckSig should return true for valid ECDSA signature")
	}
}

func TestCheckSig_WrongKey(t *testing.T) {
	sig := SignTestMessage(Alice.PrivKey)
	if CheckSig(sig, Bob.PubKey) {
		t.Error("CheckSig should return false when sig doesn't match pubkey")
	}
}

func TestCheckMultiSig_RealECDSA(t *testing.T) {
	sigA := SignTestMessage(Alice.PrivKey)
	sigB := SignTestMessage(Bob.PrivKey)
	if !CheckMultiSig([]Sig{sigA, sigB}, []PubKey{Alice.PubKey, Bob.PubKey}) {
		t.Error("CheckMultiSig should return true for valid ordered signatures")
	}
}

func TestCheckMultiSig_WrongOrder(t *testing.T) {
	sigA := SignTestMessage(Alice.PrivKey)
	sigB := SignTestMessage(Bob.PrivKey)
	// Signatures in wrong order relative to pubkeys
	if CheckMultiSig([]Sig{sigB, sigA}, []PubKey{Alice.PubKey, Bob.PubKey}) {
		t.Error("CheckMultiSig should return false for wrong signature order")
	}
}

func TestCheckPreimage_AlwaysTrue(t *testing.T) {
	if !CheckPreimage(MockPreimage()) {
		t.Error("CheckPreimage should always return true in test mode")
	}
}

func TestHash160_Produces20Bytes(t *testing.T) {
	result := Hash160("hello")
	if len(result) != 20 {
		t.Errorf("Hash160 should produce 20 bytes, got %d", len(result))
	}
}

func TestHash160_Deterministic(t *testing.T) {
	a := Hash160("test data")
	b := Hash160("test data")
	if a != b {
		t.Error("Hash160 should be deterministic")
	}
}

func TestHash160_Comparable(t *testing.T) {
	pk := Alice.PubKey
	h1 := Hash160(pk)
	h2 := Hash160(pk)
	// This is the key test: == must work on Addr (string-backed)
	if h1 != h2 {
		t.Error("Addr values should be comparable with ==")
	}
}

func TestHash256_Produces32Bytes(t *testing.T) {
	result := Hash256("hello")
	if len(result) != 32 {
		t.Errorf("Hash256 should produce 32 bytes, got %d", len(result))
	}
}

func TestHash256_Deterministic(t *testing.T) {
	a := Hash256("test data")
	b := Hash256("test data")
	if a != b {
		t.Error("Hash256 should be deterministic")
	}
}

func TestSha256Hash_Produces32Bytes(t *testing.T) {
	result := Sha256Hash("hello")
	if len(result) != 32 {
		t.Errorf("Sha256Hash should produce 32 bytes, got %d", len(result))
	}
}

func TestRipemd160Func_Produces20Bytes(t *testing.T) {
	result := Ripemd160Func("hello")
	if len(result) != 20 {
		t.Errorf("Ripemd160Func should produce 20 bytes, got %d", len(result))
	}
}

func TestStatefulSmartContract_AddOutput(t *testing.T) {
	s := &StatefulSmartContract{}
	s.AddOutput(1000, "alice", int64(50))

	outputs := s.Outputs()
	if len(outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(outputs))
	}
	if outputs[0].Satoshis != 1000 {
		t.Errorf("expected satoshis=1000, got %d", outputs[0].Satoshis)
	}
	if len(outputs[0].Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(outputs[0].Values))
	}
}

func TestStatefulSmartContract_MultipleOutputs(t *testing.T) {
	s := &StatefulSmartContract{}
	s.AddOutput(1000, "alice", int64(30))
	s.AddOutput(1000, "bob", int64(70))

	if len(s.Outputs()) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(s.Outputs()))
	}
}

func TestStatefulSmartContract_ResetOutputs(t *testing.T) {
	s := &StatefulSmartContract{}
	s.AddOutput(1000, "alice")
	s.ResetOutputs()

	if len(s.Outputs()) != 0 {
		t.Errorf("expected 0 outputs after reset, got %d", len(s.Outputs()))
	}
}

func TestNum2Bin(t *testing.T) {
	result := Num2Bin(0, 4)
	if len(result) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(result))
	}

	result = Num2Bin(42, 4)
	if result[0] != 42 {
		t.Errorf("expected first byte 42, got %d", result[0])
	}
}

func TestLen(t *testing.T) {
	if Len(ByteString("\x01\x02\x03")) != 3 {
		t.Error("Len should return 3")
	}
}

func TestCat(t *testing.T) {
	result := Cat(ByteString("\x01"), ByteString("\x02\x03"))
	expected := ByteString("\x01\x02\x03")
	if result != expected {
		t.Errorf("Cat: expected %x, got %x", expected, result)
	}
}

func TestReverseBytes(t *testing.T) {
	result := ReverseBytes(ByteString("\x01\x02\x03"))
	expected := ByteString("\x03\x02\x01")
	if result != expected {
		t.Errorf("ReverseBytes: expected %x, got %x", expected, result)
	}
}

func TestSignTestMessage(t *testing.T) {
	sig := SignTestMessage(Alice.PrivKey)
	if len(sig) == 0 {
		t.Error("SignTestMessage should produce a non-empty signature")
	}
	// DER signatures start with 0x30
	if sig[0] != 0x30 {
		t.Errorf("DER signature should start with 0x30, got 0x%02x", sig[0])
	}
}

func TestTestKeys_PubKeyLength(t *testing.T) {
	if len(Alice.PubKey) != 33 {
		t.Errorf("Alice.PubKey should be 33 bytes, got %d", len(Alice.PubKey))
	}
	if len(Bob.PubKey) != 33 {
		t.Errorf("Bob.PubKey should be 33 bytes, got %d", len(Bob.PubKey))
	}
	if len(Charlie.PubKey) != 33 {
		t.Errorf("Charlie.PubKey should be 33 bytes, got %d", len(Charlie.PubKey))
	}
}

func TestTestKeys_PubKeyHashLength(t *testing.T) {
	if len(Alice.PubKeyHash) != 20 {
		t.Errorf("Alice.PubKeyHash should be 20 bytes, got %d", len(Alice.PubKeyHash))
	}
}

func TestTestKeys_Hash160Matches(t *testing.T) {
	computed := Hash160(Alice.PubKey)
	if computed != Alice.PubKeyHash {
		t.Error("Hash160(Alice.PubKey) should equal Alice.PubKeyHash")
	}
}

func TestTestKeys_PubKeyFromPrivKey(t *testing.T) {
	pk := PubKeyFromPrivKey(Alice.PrivKey)
	if pk != Alice.PubKey {
		t.Error("PubKeyFromPrivKey should produce Alice.PubKey")
	}
}

func TestMockPreimage(t *testing.T) {
	p := MockPreimage()
	if len(p) != 181 {
		t.Errorf("MockPreimage should be 181 bytes, got %d", len(p))
	}
}

func TestAbs(t *testing.T) {
	if Abs(-5) != 5 { t.Error("Abs(-5) should be 5") }
	if Abs(5) != 5 { t.Error("Abs(5) should be 5") }
	if Abs(0) != 0 { t.Error("Abs(0) should be 0") }
}

func TestMinMax(t *testing.T) {
	if Min(3, 5) != 3 { t.Error("Min(3,5) should be 3") }
	if Max(3, 5) != 5 { t.Error("Max(3,5) should be 5") }
}

func TestWithin(t *testing.T) {
	if !Within(5, 0, 10) { t.Error("5 should be within [0,10)") }
	if Within(10, 0, 10) { t.Error("10 should NOT be within [0,10)") }
	if Within(-1, 0, 10) { t.Error("-1 should NOT be within [0,10)") }
}

func TestSafediv_Positive(t *testing.T) {
	if got := Safediv(10, 3); got != 3 {
		t.Errorf("Safediv(10, 3): expected 3, got %d", got)
	}
}

func TestSafediv_TruncatesTowardZero(t *testing.T) {
	// Go integer division truncates toward zero, so -7/2 == -3.
	if got := Safediv(-7, 2); got != -3 {
		t.Errorf("Safediv(-7, 2): expected -3, got %d", got)
	}
}

func TestSafediv_ByZeroPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Safediv(1, 0) to panic")
		}
	}()
	Safediv(1, 0)
}

func TestSafemod_Positive(t *testing.T) {
	if got := Safemod(10, 3); got != 1 {
		t.Errorf("Safemod(10, 3): expected 1, got %d", got)
	}
}

func TestSafemod_Negative(t *testing.T) {
	// Go's % operator preserves the sign of the dividend: -7 % 3 == -1.
	if got := Safemod(-7, 3); got != -1 {
		t.Errorf("Safemod(-7, 3): expected -1, got %d", got)
	}
}

func TestSafemod_ByZeroPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Safemod(1, 0) to panic")
		}
	}()
	Safemod(1, 0)
}

func TestClamp_WithinRange(t *testing.T) {
	if got := Clamp(5, 0, 10); got != 5 {
		t.Errorf("Clamp(5, 0, 10): expected 5, got %d", got)
	}
}

func TestClamp_Below(t *testing.T) {
	if got := Clamp(-1, 0, 10); got != 0 {
		t.Errorf("Clamp(-1, 0, 10): expected 0, got %d", got)
	}
}

func TestClamp_Above(t *testing.T) {
	if got := Clamp(15, 0, 10); got != 10 {
		t.Errorf("Clamp(15, 0, 10): expected 10, got %d", got)
	}
}

func TestSign_Positive(t *testing.T) {
	if got := Sign(42); got != 1 {
		t.Errorf("Sign(42): expected 1, got %d", got)
	}
}

func TestSign_Negative(t *testing.T) {
	if got := Sign(-42); got != -1 {
		t.Errorf("Sign(-42): expected -1, got %d", got)
	}
}

func TestSign_Zero(t *testing.T) {
	if got := Sign(0); got != 0 {
		t.Errorf("Sign(0): expected 0, got %d", got)
	}
}

func TestSqrt_PerfectSquare(t *testing.T) {
	if got := Sqrt(9); got != 3 {
		t.Errorf("Sqrt(9): expected 3, got %d", got)
	}
}

func TestSqrt_NonPerfect(t *testing.T) {
	if got := Sqrt(10); got != 3 {
		t.Errorf("Sqrt(10): expected 3 (floor), got %d", got)
	}
}

func TestLog2_PowerOfTwo(t *testing.T) {
	if got := Log2(8); got != 3 {
		t.Errorf("Log2(8): expected 3, got %d", got)
	}
}

func TestLog2_NonPower(t *testing.T) {
	if got := Log2(9); got != 3 {
		t.Errorf("Log2(9): expected 3 (floor), got %d", got)
	}
}
