package runar

import (
	"testing"
)

// TestEstimateCallFee_Formula validates that EstimateCallFee computes the same
// fee as the hand-rolled formula from the TS SDK (packages/runar-sdk/src/calling.ts).
// It mirrors the TS implementation exactly so all SDKs quote identical fees.
func TestEstimateCallFee_Formula(t *testing.T) {
	cases := []struct {
		name                  string
		lockingScriptByteLen  int
		unlockingScriptByteLen int
		numFundingInputs      int
		feeRate               int64
		want                  int64
	}{
		{
			name:                  "small_stateful_one_funding_input",
			lockingScriptByteLen:  100,
			unlockingScriptByteLen: 50,
			numFundingInputs:      1,
			feeRate:               100,
			want: func() int64 {
				// contractInput = 32+4+1+50+4 = 91
				// fundingInputs = 1*148 = 148
				// contractOutput = 8+1+100 = 109
				// changeOutput   = 34
				// tx             = 10 + 91 + 148 + 109 + 34 = 392
				// fee            = ceil(392 * 100 / 1000) = 40
				return 40
			}(),
		},
		{
			name:                  "no_funding_inputs_default_rate",
			lockingScriptByteLen:  200,
			unlockingScriptByteLen: 107,
			numFundingInputs:      0,
			feeRate:               0, // defaults to 100
			want: func() int64 {
				// contractInput  = 32+4+1+107+4 = 148
				// fundingInputs  = 0
				// contractOutput = 8+varIntByteSize(200)+200 = 8+1+200 = 209
				// changeOutput   = 34
				// tx             = 10+148+0+209+34 = 401
				// fee            = ceil(401*100/1000) = 41
				return 41
			}(),
		},
		{
			name:                  "large_locking_script_custom_rate",
			lockingScriptByteLen:  500,
			unlockingScriptByteLen: 300,
			numFundingInputs:      2,
			feeRate:               500,
			want: func() int64 {
				// contractInput  = 32+4+varIntByteSize(300)+300+4 = 32+4+3+300+4 = 343
				// fundingInputs  = 2*148 = 296
				// contractOutput = 8+varIntByteSize(500)+500 = 8+3+500 = 511
				// changeOutput   = 34
				// tx             = 10+343+296+511+34 = 1194
				// fee            = ceil(1194*500/1000) = 597
				return 597
			}(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var got int64
			if tc.feeRate == 0 {
				got = EstimateCallFee(tc.lockingScriptByteLen, tc.unlockingScriptByteLen, tc.numFundingInputs)
			} else {
				got = EstimateCallFee(tc.lockingScriptByteLen, tc.unlockingScriptByteLen, tc.numFundingInputs, tc.feeRate)
			}
			if got != tc.want {
				t.Errorf("EstimateCallFee(%d, %d, %d, rate=%d) = %d, want %d",
					tc.lockingScriptByteLen, tc.unlockingScriptByteLen, tc.numFundingInputs,
					tc.feeRate, got, tc.want)
			}
		})
	}
}

// TestEstimateCallFee_MonotonicInScriptSize ensures fee grows with script size.
// A trivial round-trip sanity test that catches obvious regressions in the
// fee-scaling math without depending on a live provider.
func TestEstimateCallFee_MonotonicInScriptSize(t *testing.T) {
	a := EstimateCallFee(100, 50, 1)
	b := EstimateCallFee(500, 50, 1)
	c := EstimateCallFee(500, 250, 1)

	if !(a < b) {
		t.Errorf("fee should grow with locking script size: a=%d b=%d", a, b)
	}
	if !(b < c) {
		t.Errorf("fee should grow with unlocking script size: b=%d c=%d", b, c)
	}
}

// TestEstimateCallFee_MockProviderRoundTrip exercises EstimateCallFee against
// artifact byte lengths drawn from a MockProvider-backed flow. The MockProvider
// is not strictly needed for a closed-form formula, but this test pins the
// expected shape: EstimateCallFee(locking, unlocking, fundingInputs) returns a
// positive int64 for realistic contract sizes.
func TestEstimateCallFee_MockProviderRoundTrip(t *testing.T) {
	// A minimal stateful locking script hex (not actually executed — we only
	// need the byte length for fee estimation).
	lockingScriptHex := "76a914" + "00000000000000000000000000000000000000" + "0088ac" // ~25 bytes
	lockingBytes := len(lockingScriptHex) / 2

	// A plausible unlocking script: signature (~71) + pubkey (~33) + method
	// selector + some args ~= 200 bytes.
	unlockingBytes := 200

	provider := NewMockProvider("testnet")
	// Seed a funding UTXO so the provider state matches a realistic flow.
	provider.AddUtxo("mockAddress", UTXO{
		Txid:        "abababababababababababababababababababababababababababababababab",
		OutputIndex: 0,
		Satoshis:    100_000,
		Script:      "76a914000000000000000000000000000000000000000088ac",
	})
	_ = provider

	fee := EstimateCallFee(lockingBytes, unlockingBytes, 1)
	if fee <= 0 {
		t.Errorf("EstimateCallFee returned non-positive fee: %d", fee)
	}
	// Sanity bound: at 100 sat/KB, a <1 KB transaction should be well under
	// 1000 sats.
	if fee > 1000 {
		t.Errorf("EstimateCallFee unexpectedly high for small tx: %d", fee)
	}
}
