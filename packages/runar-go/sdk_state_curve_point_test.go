package runar

import (
	"strings"
	"testing"
)

// P256Point (64) and P384Point (96) are FIXED-WIDTH RAW state fields.
//
// All seven compilers emit them as fixed raw slices in the state tail, and
// runar-lang's cast constructors hard-assert exactly those widths. The seven
// SDKs used to omit both from their width tables, so they fell through to the
// push-data default and deployed a state section 1 byte (0x40 direct push) or
// 2 bytes (OP_PUSHDATA1 0x60) longer than the script's own on-chain reader
// expects. The deploy succeeded and the FIRST spend failed with
// "OP_NUMEQUALVERIFY requires the top stack item to be truthy" — funds locked.
//
// crossSdkGolden is byte-identical across all seven SDKs; every tier carries
// the same literal and the same field list.

func rep(s string, n int) string { return strings.Repeat(s, n) }

func curvePointFields() []StateField {
	return []StateField{
		{Name: "n", Type: "bigint", Index: 0},
		{Name: "flag", Type: "bool", Index: 1},
		{Name: "pk", Type: "PubKey", Index: 2},
		{Name: "h", Type: "Sha256", Index: 3},
		{Name: "ad", Type: "Addr", Index: 4},
		{Name: "pt", Type: "Point", Index: 5},
		{Name: "p256", Type: "P256Point", Index: 6},
		{Name: "p384", Type: "P384Point", Index: 7},
		{Name: "sig", Type: "Sig", Index: 8},
		{Name: "rab", Type: "RabinSig", Index: 9},
		{Name: "bs", Type: "ByteString", Index: 10},
	}
}

func curvePointValues() map[string]interface{} {
	return map[string]interface{}{
		"n":    int64(1),
		"flag": true,
		"pk":   "02" + rep("aa", 32),
		"h":    rep("bb", 32),
		"ad":   rep("cc", 20),
		"pt":   rep("dd", 64),
		"p256": rep("11", 64),
		"p384": rep("22", 96),
		"sig":  "3044" + rep("ee", 66),
		"rab":  rep("ff", 8),
		"bs":   "0011",
	}
}

// crossSdkGolden — the one wire record every tier must reproduce byte for byte.
func crossSdkGolden() string {
	return "0100000000000000" + // bigint 1, NUM2BIN 8
		"01" + //                  bool true
		"02" + rep("aa", 32) + //  PubKey    33 raw
		rep("bb", 32) + //         Sha256    32 raw
		rep("cc", 20) + //         Addr      20 raw
		rep("dd", 64) + //         Point     64 raw
		rep("11", 64) + //         P256Point 64 raw   <- was framed "40" + 64
		rep("22", 96) + //         P384Point 96 raw   <- was framed "4c60" + 96
		"44" + "3044" + rep("ee", 66) + // Sig        framed <len><data>
		"08" + rep("ff", 8) + //           RabinSig   framed <len><data>
		"02" + "0011" //                   ByteString framed <len><data>
}

func TestCurvePointCrossSdkGoldenSerialize(t *testing.T) {
	want := crossSdkGolden()
	if len(want)/2 != 399 {
		t.Fatalf("golden is %d bytes, want 399", len(want)/2)
	}
	if got := SerializeState(curvePointFields(), curvePointValues()); got != want {
		t.Errorf("cross-SDK state record mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestCurvePointCrossSdkGoldenDeserialize(t *testing.T) {
	back := mustDeserializeState(t, curvePointFields(), crossSdkGolden())
	if n, _ := back["n"].(int64); n != 1 {
		t.Errorf("n: got %v, want 1", back["n"])
	}
	if b, _ := back["flag"].(bool); !b {
		t.Errorf("flag: got %v, want true", back["flag"])
	}
	in := curvePointValues()
	for _, k := range []string{"pk", "h", "ad", "pt", "p256", "p384", "sig", "rab", "bs"} {
		if got, _ := back[k].(string); got != in[k] {
			t.Errorf("%s: got %q, want %q", k, got, in[k])
		}
	}
}

func TestCurvePointLoneFieldRoundTrip(t *testing.T) {
	cases := []struct {
		fieldType string
		size      int
		fill      string
	}{
		{"P256Point", 64, "11"},
		{"P384Point", 96, "22"},
	}
	for _, c := range cases {
		fields := []StateField{{Name: "v", Type: c.fieldType, Index: 0}}
		v := rep(c.fill, c.size)
		hex := SerializeState(fields, map[string]interface{}{"v": v})
		if hex != v {
			t.Errorf("%s serialize: got %q, want raw %q", c.fieldType, hex, v)
		}
		if len(hex)/2 != c.size {
			t.Errorf("%s: got %d bytes, want %d", c.fieldType, len(hex)/2, c.size)
		}
		if back, _ := mustDeserializeState(t, fields, hex)["v"].(string); back != v {
			t.Errorf("%s deserialize: got %q, want %q", c.fieldType, back, v)
		}
	}
}

func TestCurvePointControlsUnchanged(t *testing.T) {
	raw := []struct {
		fieldType string
		size      int
	}{{"Point", 64}, {"PubKey", 33}, {"Sha256", 32}}
	for _, c := range raw {
		v := rep("ab", c.size)
		got := SerializeState([]StateField{{Name: "v", Type: c.fieldType, Index: 0}},
			map[string]interface{}{"v": v})
		if got != v {
			t.Errorf("%s control: got %q, want raw %q", c.fieldType, got, v)
		}
	}
	for _, ft := range []string{"ByteString", "Sig", "RabinSig"} {
		v := rep("ab", 64)
		got := SerializeState([]StateField{{Name: "v", Type: ft, Index: 0}},
			map[string]interface{}{"v": v})
		if got != "40"+v {
			t.Errorf("%s control: got %q, want framed %q", ft, got, "40"+v)
		}
	}
}
