package runar

import (
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"
)

// d12MustRefuse asserts that fn panics with *ScriptOpcodeError (the SDK
// interpreter's "the script aborts here" signal) instead of returning a value.
func d12MustRefuse(t *testing.T, label string, fn func() interface{}) {
	t.Helper()
	var got interface{}
	defer func() {
		t.Helper()
		rec := recover()
		if rec == nil {
			t.Fatalf("%s: returned %v, want a refusal (the compiled script aborts)", label, got)
		}
		if _, ok := rec.(*ScriptOpcodeError); !ok {
			t.Fatalf("%s: panicked with %T (%v), want *ScriptOpcodeError", label, rec, rec)
		}
	}()
	got = fn()
}

// D12 BM-F3 / reverseBytes: the compiled script reverses only the first 520
// bytes, so the SDK must refuse longer inputs rather than reverse them fully.
func TestD12_ReverseBytesOver520Refused(t *testing.T) {
	ok := anfEvalCall("reverseBytes", []interface{}{strings.Repeat("ab", 519) + "cd"}, nil, nil, "m")
	if ok != "cd"+strings.Repeat("ab", 519) {
		t.Fatalf("reverseBytes(520 B) wrong: %v", ok)
	}
	d12MustRefuse(t, "reverseBytes(521 B)", func() interface{} {
		return anfEvalCall("reverseBytes", []interface{}{strings.Repeat("ab", 521)}, nil, nil, "m")
	})
}

// D12 BM-F4: ByteString & | ^ follow OP_AND/OP_OR/OP_XOR (equal lengths,
// byte-wise; a length mismatch aborts) instead of inventing "".
func TestD12_BytesBitwiseMatchesScript(t *testing.T) {
	cases := []struct{ op, a, b, want string }{
		{"&", "ff0f", "0ff0", "0f00"},
		{"|", "ff0f", "0ff0", "ffff"},
		{"^", "ff0f", "0ff0", "f0ff"},
		{"&", "", "", ""},
	}
	for _, tc := range cases {
		if got := anfEvalBinOp(tc.op, tc.a, tc.b, "bytes"); got != tc.want {
			t.Errorf("%s %s %s = %v, want %s", tc.a, tc.op, tc.b, got, tc.want)
		}
	}
	d12MustRefuse(t, "ff & 0f0f (length mismatch)", func() interface{} {
		return anfEvalBinOp("&", "ff", "0f0f", "bytes")
	})
}

// D12 BM-F4: int2str compiles to OP_NUM2BIN; it must not fall through to nil.
func TestD12_Int2strIsNum2bin(t *testing.T) {
	if got := anfEvalCall("int2str", []interface{}{big.NewInt(5), big.NewInt(2)}, nil, nil, "m"); got != "0500" {
		t.Fatalf("int2str(5, 2) = %v, want 0500", got)
	}
}

// D12 BM-F5: OP_NUM2BIN aborts when the width is negative or too narrow for
// the value's minimal encoding; the SDK must refuse, not truncate.
func TestD12_Num2binNarrowWidthRefused(t *testing.T) {
	for _, fn := range []string{"num2bin", "int2str"} {
		for _, tc := range []struct{ v, w int64 }{{40000, 2}, {128, 1}, {1, 0}, {5, -1}, {-1, 0}} {
			fn, tc := fn, tc
			d12MustRefuse(t, fn, func() interface{} {
				return anfEvalCall(fn, []interface{}{big.NewInt(tc.v), big.NewInt(tc.w)}, nil, nil, "m")
			})
		}
		if got := anfEvalCall(fn, []interface{}{big.NewInt(0), big.NewInt(0)}, nil, nil, "m"); got != "" {
			t.Fatalf("%s(0, 0) = %v, want empty", fn, got)
		}
		if got := anfEvalCall(fn, []interface{}{big.NewInt(255), big.NewInt(2)}, nil, nil, "m"); got != "ff00" {
			t.Fatalf("%s(255, 2) = %v, want ff00", fn, got)
		}
	}
}

// D12 NIST-F2: the compiled script reduces the scalar mod n, so a negative
// scalar negates the point. big.Int.Bytes() dropped the sign.
func TestD12_NistMocksNegativeScalar(t *testing.T) {
	g256 := P256MulGen(big.NewInt(1))
	if got, want := P256Mul(g256, big.NewInt(-1)), P256Negate(g256); got != want {
		t.Errorf("P256Mul(G, -1) != -G")
	}
	if got, want := P256MulGen(big.NewInt(-2)), P256Negate(P256MulGen(big.NewInt(2))); got != want {
		t.Errorf("P256MulGen(-2) != -2G")
	}
	n256 := elliptic.P256().Params().N
	if got, want := P256MulGen(new(big.Int).Sub(big.NewInt(-1), n256)), P256Negate(g256); got != want {
		t.Errorf("P256MulGen(-1-n) != -G")
	}
	g384 := P384MulGen(big.NewInt(1))
	if got, want := P384Mul(g384, big.NewInt(-1)), P384Negate(g384); got != want {
		t.Errorf("P384Mul(G, -1) != -G")
	}
	if got, want := P384MulGen(big.NewInt(-2)), P384Negate(P384MulGen(big.NewInt(2))); got != want {
		t.Errorf("P384MulGen(-2) != -2G")
	}
}

// D12 SECP-F1: the compiled script computes ((v tmod m) + m) tmod m and aborts
// on m == 0 (ec-codegen.ts emitEcModReduce). Expected values are the script's
// outputs on Spend from the D12 secp256k1 battery.
func TestD12_EcModReduceMatchesScript(t *testing.T) {
	for _, tc := range []struct{ v, m, want int64 }{
		{7, -3, -2}, {-7, -3, -1}, {-5, 3, 1}, {17, 5, 2}, {-3, 5, 2}, {0, 7, 0},
		{9223372036854775806, 9223372036854775807, 9223372036854775806},
	} {
		if got := EcModReduce(tc.v, tc.m); got != tc.want {
			t.Errorf("EcModReduce(%d, %d) = %d, want %d", tc.v, tc.m, got, tc.want)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("EcModReduce(5, 0) must abort like OP_MOD by zero")
			}
		}()
		EcModReduce(5, 0)
	}()
}

// D12 NIST-F3: every P-256/P-384/EC/stateful script uses OP_2MUL, a
// post-Chronicle opcode. The public ScriptVM ran pre-Chronicle and aborted.
func TestD12_ScriptVMRunsChronicleOpcodes(t *testing.T) {
	res, err := NewScriptVM(VMOptions{}).ExecuteHex("518d529c") // OP_1 OP_2MUL OP_2 OP_NUMEQUAL
	if err != nil {
		t.Fatalf("ExecuteHex: %v", err)
	}
	if !res.Success {
		t.Fatalf("OP_1 OP_2MUL OP_2 OP_NUMEQUAL failed: %+v", res)
	}
}
