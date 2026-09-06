package runar

import (
	"math/big"
	"testing"
)

// NEW-013 — `num2bin` sign-bit placement.
//
// The ANF interpreter models what the DEPLOYED SCRIPT computes. For negative
// values it used to set the sign bit on the last MAGNITUDE byte and pad zeros
// AFTER it, so num2bin(-1, 2) came out 8100 where OP_NUM2BIN yields 0180. Those
// bytes go into the call transaction, so a legal method built a continuation
// the script rejects.
//
// Every expectation below is the output of OP_NUM2BIN on the real @bsv/sdk
// Spend interpreter, derived by
// `conformance/anf-interpreter/num2bin-engine-parity.test.ts`, which re-runs the
// engine live rather than trusting a table. Do NOT re-stamp these from this
// implementation's own output — that is precisely how six of seven SDKs agreed
// on the wrong answer.
func TestAnfNum2binHex_MatchesOpNum2Bin(t *testing.T) {
	cases := []struct {
		n       int64
		byteLen int
		want    string
		why     string
	}{
		// Negative, padded — the NEW-013 corner. The sign bit belongs on the
		// byte that is most significant AFTER padding, not before it.
		{-1, 2, "0180", "negative padded"},
		{-1, 4, "01000080", "negative padded"},
		{-1, 8, "0100000000000080", "negative padded"},
		{-5, 4, "05000080", "negative padded"},
		{-1000, 4, "e8030080", "negative padded"},
		{-1000, 8, "e803000000000080", "negative padded"},
		{-255, 3, "ff0080", "negative padded"},
		{-256, 3, "000180", "negative padded"},

		// Negative, exact width — the minimal encoding already fills the field,
		// so it is pushed unchanged and the sign bit does not move.
		{-1, 1, "81", "negative exact width"},
		{-127, 1, "ff", "negative exact width"},
		{-1000, 2, "e883", "negative exact width"},
		{-256, 2, "0081", "negative exact width"},

		// Negative, sign-bit carry — the top magnitude byte already uses bit 7,
		// so the minimal encoding grows a byte before any padding happens.
		{-128, 2, "8080", "negative carry, exact width"},
		{-128, 3, "800080", "negative carry, padded"},
		{-128, 8, "8000000000000080", "negative carry, padded"},
		{-32768, 3, "008080", "negative carry, exact width"},
		{-32768, 4, "00800080", "negative carry, padded"},

		// Positive at the same widths — must be untouched by the fix.
		{1, 1, "01", "positive exact width"},
		{1, 2, "0100", "positive padded"},
		{1, 8, "0100000000000000", "positive padded"},
		{1000, 2, "e803", "positive exact width"},
		{1000, 4, "e8030000", "positive padded"},
		{1000, 8, "e803000000000000", "positive padded"},
		{127, 1, "7f", "positive exact width"},
		{128, 2, "8000", "positive carry, exact width"},
		{128, 3, "800000", "positive carry, padded"},
		{255, 2, "ff00", "positive carry, exact width"},

		// Zero — an all-zero field, no sign bit anywhere.
		{0, 1, "00", "zero"},
		{0, 4, "00000000", "zero"},
		{0, 8, "0000000000000000", "zero"},
	}

	for _, tc := range cases {
		got := anfNum2binHex(big.NewInt(tc.n), tc.byteLen)
		if got != tc.want {
			t.Errorf("anfNum2binHex(%d, %d) = %q, want %q (%s)",
				tc.n, tc.byteLen, got, tc.want, tc.why)
		}
	}

	// Non-vacuity: this table only earns its keep if it can see the pre-fix
	// answer. `8100` is exactly what this function used to return.
	if anfNum2binHex(big.NewInt(-1), 2) == "8100" {
		t.Fatal("anfNum2binHex regressed to the pre-fix sign-bit placement")
	}
}

// bin2num is the interpreter's own inverse, so a round-trip proves only
// self-consistency — it held throughout the bug. It is kept as a smoke test and
// is explicitly NOT the evidence: the table above is.
func TestAnfNum2binHex_RoundTripIsSmokeTestOnly(t *testing.T) {
	for _, n := range []int64{-1000, -128, -1, 0, 1, 128, 1000} {
		hexStr := anfNum2binHex(big.NewInt(n), 8)
		if got := anfBin2numBigInt(hexStr).Int64(); got != n {
			t.Errorf("round trip of %d through %q gave %d", n, hexStr, got)
		}
	}
}
