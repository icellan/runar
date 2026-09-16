package runar

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BIN2NUM DOES NOT NARROW SILENTLY.
//
// OP_BIN2NUM reinterprets a push of any width as a Script number. Bin2Num
// returns int64, which cannot represent every such number, and for four years
// it handled that by returning the low 64 bits — "graceful truncation", in the
// doc comment. Graceful is the wrong word for it: the caller gets a number, it
// is the wrong number, and nothing says so. Bin2Num(Num2BinBig(
// 123456789012345678901234567890, 16)) came back as -4362896299872285998.
//
// It panics now. Callers whose value can exceed int64 use Bin2NumBig, which
// returns *big.Int and is what the .runar.go parser maps to the same `bin2num`
// builtin (see parser_gocontract.go mapGoBuiltin), so contract source can reach
// the wide answer without a different script.
//
// The reason the truncation survived is in the agreement table: there WAS a
// bin2num row, and it decoded 1000. A row that only exercises the in-range case
// is not coverage of a narrowing function. The rows here run on both sides of
// the boundary, and TestBin2Num_AcceptsAWidePushOfAnInRangeValue is the control
// that stops the new guard from degenerating into "16 bytes, therefore panic".
// ---------------------------------------------------------------------------

func wideTestVal(t *testing.T) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString("123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("bad literal")
	}
	return v
}

func TestBin2Num_RefusesAValueWiderThanInt64(t *testing.T) {
	encoded := Num2BinBig(wideTestVal(t), 16)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Bin2Num returned a value for a 16-byte number that does not " +
				"fit int64. It used to return its low 64 bits (-4362896299872285998) " +
				"while OP_BIN2NUM left the whole number on the stack.")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "123456789012345678901234567890") {
			t.Fatalf("the panic does not name the value it refused: %v", r)
		}
	}()
	_ = Bin2Num(encoded)
}

// The wide form has to decode what the narrow form refuses, or the refusal is
// just a lost capability.
func TestBin2NumBig_DecodesWhatBin2NumRefuses(t *testing.T) {
	want := wideTestVal(t)
	got := Bin2NumBig(Num2BinBig(want, 16))
	if got.Cmp(want) != 0 {
		t.Fatalf("Bin2NumBig round-trip = %s, want %s", got, want)
	}
}

// NON-VACUITY CONTROL. A guard that panicked on any push wider than 8 bytes
// would pass the refusal test above and be wrong: Script numbers are not
// minimally encoded by requirement, and a 16-byte push of 1000 is a 16-byte
// push of 1000. The emitted opcodes accept it; so must the mock.
func TestBin2Num_AcceptsAWidePushOfAnInRangeValue(t *testing.T) {
	rows := []struct {
		name   string
		value  int64
		length int64
	}{
		{name: "1000 in 16 bytes", value: 1000, length: 16},
		{name: "-1000 in 16 bytes", value: -1000, length: 16},
		{name: "0 in 16 bytes", value: 0, length: 16},
		{name: "MaxInt64 in 9 bytes", value: math.MaxInt64, length: 9},
		{name: "MinInt64 in 9 bytes", value: math.MinInt64, length: 9},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := Bin2Num(Num2BinBig(big.NewInt(r.value), r.length))
			if got != r.value {
				t.Fatalf("Bin2Num(Num2BinBig(%d, %d)) = %d, want %d",
					r.value, r.length, got, r.value)
			}
		})
	}
}

// The exact boundary in both directions. MaxInt64 must decode; MaxInt64+1 must
// not.
func TestBin2Num_BoundaryIsInt64AndNotByteWidth(t *testing.T) {
	maxOK := Bin2Num(Num2BinBig(big.NewInt(math.MaxInt64), 9))
	if maxOK != math.MaxInt64 {
		t.Fatalf("Bin2Num(MaxInt64) = %d, want %d", maxOK, int64(math.MaxInt64))
	}

	over := new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("Bin2Num accepted 2^63, which is one past what int64 holds")
			}
		}()
		_ = Bin2Num(Num2BinBig(over, 9))
	}()

	under := new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("Bin2Num accepted -2^63-1, which is one past what int64 holds")
			}
		}()
		_ = Bin2Num(Num2BinBig(under, 9))
	}()
}

// ---------------------------------------------------------------------------
// NUM2BIN DOES NOT NARROW SILENTLY EITHER.
//
// Num2BinBig padded or TRUNCATED to the requested length, with the comment
// "matches int64 wrap-around semantics". OP_NUM2BIN has no such semantics: it
// FAILS when the number does not fit the requested size. So a mock asked for a
// field too narrow produced bytes the script would never have produced, and
// the caller learned nothing.
// ---------------------------------------------------------------------------

func TestNum2BinBig_RefusesAFieldTooNarrowForTheValue(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Num2BinBig(2^70, 4) returned bytes. OP_NUM2BIN fails on a " +
				"size that cannot hold the number; truncating to the low 4 bytes " +
				"is a value the emitted script never produces.")
		}
	}()
	v := new(big.Int).Lsh(big.NewInt(1), 70)
	_ = Num2BinBig(v, 4)
}

func TestNum2BinBig_FitsExactlyAndPads(t *testing.T) {
	// 0xFF needs a sign byte: 8 bits of magnitude plus the sign do not fit in
	// one byte, so two is the minimum and one must be refused.
	if got := Num2BinBig(big.NewInt(255), 2); ByteString([]byte{0xff, 0x00}) != got {
		t.Fatalf("Num2BinBig(255, 2) = %x, want ff00", got)
	}
	if got := Num2BinBig(big.NewInt(255), 8); len(got) != 8 || got[0] != 0xff {
		t.Fatalf("Num2BinBig(255, 8) = %x, want ff then zeroes", got)
	}
	if got := Num2BinBig(big.NewInt(-255), 2); ByteString([]byte{0xff, 0x80}) != got {
		t.Fatalf("Num2BinBig(-255, 2) = %x, want ff80", got)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Num2BinBig(255, 1) returned bytes; 255 needs a sign byte")
			}
		}()
		_ = Num2BinBig(big.NewInt(255), 1)
	}()
}

// ---------------------------------------------------------------------------
// THE REFUSAL IS CHECKED AGAINST THE EMITTED OPCODES, NOT AGAINST A SECOND
// READING OF THE RULE.
//
// Num2Bin(math.MinInt64, 8) used to return 0000000000000080 and a test named
// TestNum2Bin_MinInt64_DoesNotPanic pinned those bytes. They are not MinInt64:
// the sign bit and the top magnitude bit are the same bit, so clearing the
// sign leaves a magnitude of zero and the push decodes as 0. The package
// comment on Num2Bin claimed "all valid int64 inputs (including
// math.MinInt64) round-trip correctly through Bin2Num", which was checkable
// and false.
//
// Whether -2^63 fits in 8 bytes is a question about OP_NUM2BIN, so this asks
// OP_NUM2BIN. It compiles `num2bin(p0, 8)`, spends it with -2^63, and requires
// the go-sdk consensus interpreter to refuse — which is what the mock's panic
// now mirrors. The 9-byte case is the control: same opcode, same value, one
// more byte, and it has to succeed, or this would prove only that the script
// dislikes large numbers.
// ---------------------------------------------------------------------------

func TestNum2Bin_MinInt64_TheScriptRefusesEightBytesAndAcceptsNine(t *testing.T) {
	minI64 := big.NewInt(math.MinInt64)

	narrow := agreementCase{
		builtin: "num2bin", mock: "Num2Bin", argTys: []string{"bigint"},
		args: [][]byte{numB(minI64)}, retTy: "ByteString",
		callExtra: []string{"8"},
		// Any 8-byte string: the script must fail at OP_NUM2BIN before it
		// ever compares. The old mock's answer is used on purpose — if the
		// script accepted anything here, it would accept exactly this.
		want:   []byte{0, 0, 0, 0, 0, 0, 0, 0x80},
		tamper: []byte{1, 0, 0, 0, 0, 0, 0, 0x80},
	}
	lock := compileAgreement(t, narrow)
	if err := runAgreement(t, lock, narrow, narrow.want); err == nil {
		t.Fatal("the compiled num2bin(-2^63, 8) ACCEPTED 0000000000000080. " +
			"Those bytes decode as 0, and the mock used to return them.")
	}

	wide := agreementCase{
		builtin: "num2bin", mock: "Num2Bin", argTys: []string{"bigint"},
		args: [][]byte{numB(minI64)}, retTy: "ByteString",
		callExtra: []string{"9"},
		want:      bs(Num2BinBig(minI64, 9)),
		tamper:    bs(Num2BinBig(big.NewInt(math.MinInt64+1), 9)),
	}
	checkAgreement(t, wide)

	// And the mock refuses the width the script refuses.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Num2Bin(MinInt64, 8) returned bytes the script will not produce")
			}
		}()
		_ = Num2Bin(math.MinInt64, 8)
	}()

	// Round-trip at the width that works, which is the claim the old doc
	// comment made about the width that does not.
	if got := Bin2Num(Num2Bin(math.MinInt64, 9)); got != math.MinInt64 {
		t.Fatalf("Bin2Num(Num2Bin(MinInt64, 9)) = %d, want %d", got, int64(math.MinInt64))
	}
}
