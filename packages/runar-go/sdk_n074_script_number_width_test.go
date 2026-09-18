package runar

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// N-074 — a Bitcoin Script number is ARBITRARY PRECISION.
//
// Rúnar contracts routinely carry 256-bit EC scalars and 1024-bit+ Rabin moduli
// as plain `bigint` constructor args. `decodeScriptNumber` returned int64, so
// every value past 2^63 came back silently WRONG (Go's `<<` on a signed int
// wraps, it does not trap) — and feeding that wrong value back into a call
// rebuilds a locking script that no longer matches what is on chain.
//
// This is type-INDEPENDENT. It bites `bigint`, `int`, `RabinSig` and
// `RabinPubKey` identically; nothing about it is Rabin-specific.
//
// The ENCODE direction was already arbitrary-precision
// (`encodeBigIntScriptNumber`, sdk_contract.go). The asymmetry WAS the bug, so
// every case below is an encode -> decode round trip through the real
// `encodeArg` / `ExtractConstructorArgs` pair.
// ---------------------------------------------------------------------------

// Single-slot template: <value@0> ac
func n074Artifact(typeName string) *RunarArtifact {
	return &RunarArtifact{
		Script: "00" + "ac",
		ConstructorSlots: []ConstructorSlot{
			{ParamIndex: 0, ByteOffset: 0},
		},
		ABI: ABI{Constructor: ABIConstructor{Params: []ABIParam{
			{Name: "value", Type: typeName},
		}}},
	}
}

func n074MustBig(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad decimal literal %q", s)
	}
	return n
}

// secp256k1 group order — a real 256-bit EC scalar.
const n074SecpN = "115792089237316195423570985008687907852837564279074904382605163141518161494337"

// A deterministic 1024-bit odd modulus with the top bit set: the shape of a
// real Rabin public key (128 bytes).
const n074Rabin1024 = "99068719171432002146137311586819387646033673282442268174774782671999562801264502320230697368056122056037887996485526845789822730341467216601217971743412906058452632946239858722327898748234874221141359423697249054724716242045815478148675575955849558861539174810221469540865911313499616042524201320198581026695"

func n074Magnitudes(t *testing.T) []struct {
	name string
	v    *big.Int
} {
	t.Helper()
	return []struct {
		name string
		v    *big.Int
	}{
		{"small", big.NewInt(1234567890123456789)},
		{"2^63-1", n074MustBig(t, "9223372036854775807")},
		{"2^63", n074MustBig(t, "9223372036854775808")},
		{"2^64", n074MustBig(t, "18446744073709551616")},
		{"secp256k1 N (256-bit)", n074MustBig(t, n074SecpN)},
		{"Rabin modulus (1024-bit)", n074MustBig(t, n074Rabin1024)},
	}
}

// extractOneAsBig runs the real encode -> extract path and normalises whatever
// concrete type comes back into a *big.Int for comparison.
func n074Extract(t *testing.T, typeName string, v *big.Int) *big.Int {
	t.Helper()
	scriptHex := encodeArg(v) + "ac"
	args := ExtractConstructorArgs(n074Artifact(typeName), scriptHex)
	switch got := args["value"].(type) {
	case *big.Int:
		return got
	case int64:
		return big.NewInt(got)
	default:
		t.Fatalf("%s: value extracted as %T (%v), want a script number", typeName, args["value"], args["value"])
		return nil
	}
}

func TestN074_PositiveRoundTripAtEveryMagnitude(t *testing.T) {
	for _, typeName := range []string{"bigint", "int", "RabinPubKey", "RabinSig"} {
		for _, m := range n074Magnitudes(t) {
			got := n074Extract(t, typeName, m.v)
			if got.Cmp(m.v) != 0 {
				t.Errorf("%s / %s: round trip = %s, want %s", typeName, m.name, got, m.v)
			}
		}
	}
}

// Bitcoin script numbers are SIGN-MAGNITUDE, not two's complement: the sign
// lives in the high bit of the most-significant byte. This is where a naive
// bignum port breaks.
func TestN074_NegativeRoundTripAtEveryMagnitude(t *testing.T) {
	for _, typeName := range []string{"bigint", "RabinPubKey"} {
		for _, m := range n074Magnitudes(t) {
			neg := new(big.Int).Neg(m.v)
			got := n074Extract(t, typeName, neg)
			if got.Cmp(neg) != 0 {
				t.Errorf("%s / -%s: round trip = %s, want %s", typeName, m.name, got, neg)
			}
		}
	}
}

// CONTROL: small values must stay byte-identical on the wire AND keep their
// existing concrete Go type (int64), so no caller that type-asserts breaks.
func TestN074_ControlSmallValuesUnchanged(t *testing.T) {
	cases := []struct {
		v    int64
		want string // full push element
	}{
		{0, "00"},
		{1, "51"},
		{16, "60"},
		{-1, "4f"},
		{17, "0111"},
		{127, "017f"},
		{128, "028000"},
		{-128, "028080"},
		{1234567890123456789, "081581e97df4102211"},
		{-1234567890123456789, "081581e97df4102291"},
	}
	for _, c := range cases {
		if got := encodeArg(c.v); got != c.want {
			t.Errorf("encodeArg(%d) = %s, want %s", c.v, got, c.want)
		}
		args := ExtractConstructorArgs(n074Artifact("bigint"), c.want+"ac")
		got, ok := args["value"].(int64)
		if !ok {
			t.Fatalf("%d: extracted as %T (%v), want int64", c.v, args["value"], args["value"])
		}
		if got != c.v {
			t.Errorf("%d: extracted %d", c.v, got)
		}
	}
}
