package runar

import (
	"fmt"
	"strings"
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

// TestBuildP2PKHScript_F043 pins the input contract every SDK shares, using a
// real key: the secp256k1 generator G.
//
// PROVES: a 40-char hash, a 66-char compressed and a 130-char uncompressed
// pubkey (hashed with HASH160), and the mainnet/testnet addresses of G all map
// to the expected P2PKH script; the Genesis address with its last character
// flipped (still 25 decoded bytes, bad SHA256d checksum) panics, as do a P2SH
// address, a short address and a non-Base58 character.
// DOES NOT PROVE: that a pubkey is a valid curve point (no SDK checks it).
func TestBuildP2PKHScript_F043(t *testing.T) {
	const gPKH = "751e76e8199196d454941c45d1b3a323f1433bd6"
	ok := map[string]string{
		gPKH: "76a914" + gPKH + "88ac",
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798": "76a914" + gPKH + "88ac",
		"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8": "76a91491b24bf9f5288532960ac687abb035127b1d28a588ac",
		"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH": "76a914" + gPKH + "88ac",
		"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r": "76a914" + gPKH + "88ac",
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
	}
	for in, want := range ok {
		if got := BuildP2PKHScript(in); got != want {
			t.Errorf("BuildP2PKHScript(%q) = %s, want %s", in, got, want)
		}
	}
	bad := map[string]string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb": "checksum",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "not supported",
		"1Badx":                              "length",
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a": "bad char",
	}
	for in, want := range bad {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("BuildP2PKHScript(%q) did not panic", in)
					return
				}
				if msg := fmt.Sprint(r); !strings.Contains(msg, want) {
					t.Errorf("BuildP2PKHScript(%q) panic %q, want it to mention %q", in, msg, want)
				}
			}()
			BuildP2PKHScript(in)
		}()
	}
}
