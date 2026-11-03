package runar

import "testing"

// N-448 (R177): HexToBytes is the explicit hex spelling of a ByteString
// literal in a .runar.go contract. The compiler reads runar.HexToBytes("006a")
// as the two bytes 00 6a, so the native package must decode it the same way;
// the bare literal "006a" natively is four ASCII bytes, which is the divergence
// this helper replaces.
//
// Proves: valid hex decodes to the bytes it spells (including the empty string
// and mixed-case digits), and odd length or a non-hex digit panics.
// Does not prove: that the compiler tiers read the helper the same way (the
// conformance/negatives/n448 test covers that).
func TestHexToBytes_Decodes(t *testing.T) {
	cases := []struct {
		in   string
		want ByteString
	}{
		{"", ""},
		{"006a", "\x00\x6a"},
		{"1976a914", "\x19\x76\xa9\x14"},
		{"88AC", "\x88\xac"},
	}
	for _, c := range cases {
		if got := HexToBytes(c.in); got != c.want {
			t.Errorf("HexToBytes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if HexToBytes("006a") == ByteString("006a") {
		t.Error("HexToBytes must decode hex, not keep the ASCII text")
	}
}

func TestHexToBytes_PanicsOnBadHex(t *testing.T) {
	for _, in := range []string{"abc", "zz", "0x00"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("HexToBytes(%q) did not panic", in)
				}
			}()
			HexToBytes(in)
		}()
	}
}
