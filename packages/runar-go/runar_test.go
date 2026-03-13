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

func TestCheckSig_AlwaysTrue(t *testing.T) {
	if !CheckSig(MockSig(), MockPubKey()) {
		t.Error("CheckSig should always return true in test mode")
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
	pk := MockPubKey()
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

func TestMockSig(t *testing.T) {
	sig := MockSig()
	if len(sig) != 72 {
		t.Errorf("MockSig should be 72 bytes, got %d", len(sig))
	}
}

func TestMockPubKey(t *testing.T) {
	pk := MockPubKey()
	if len(pk) != 33 {
		t.Errorf("MockPubKey should be 33 bytes, got %d", len(pk))
	}
	if pk[0] != 0x02 {
		t.Errorf("MockPubKey should start with 0x02, got 0x%02x", pk[0])
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
