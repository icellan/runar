package runar

// N-329: a ByteString-family constructor arg that is not an even-length hex
// string must be refused at construction with a typed error, not spliced into
// the locking script as raw text (which silently produced a corrupt script:
// a push header sized for the raw bytes followed by non-hex characters).
//
// PROVES: NewRunarContract panics with *InvalidConstructorArgError for a raw
// (non-hex) Addr, an odd-length hex ByteString, and a non-hex leaf inside a
// FixedArray<Addr,2>; the same args as valid hex, and a runar.ByteString hex
// value, are accepted and GetLockingScript contains only hex characters.
// DOES NOT PROVE: width checks (a 3-byte Addr is still accepted here; state
// width is N-045's checkFixedWidthValue) or on-chain spendability.

import (
	"errors"
	"testing"
)

func n329Artifact(paramType string, fixed *ABIFixedArray) *RunarArtifact {
	return &RunarArtifact{
		ContractName: "N329",
		Script:       "00",
		ABI: ABI{Constructor: ABIConstructor{Params: []ABIParam{
			{Name: "owner", Type: paramType, FixedArray: fixed},
		}}},
		ConstructorSlots: []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}},
	}
}

func n329Construct(a *RunarArtifact, arg interface{}) (c *RunarContract, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(error)
			if !ok {
				panic(r)
			}
			err = e
		}
	}()
	c = NewRunarContract(a, []interface{}{arg})
	return c, nil
}

func TestN329_NonHexByteStringCtorArgIsRefused(t *testing.T) {
	raw := string([]byte{0x9a, 0x1c, 0x78, 0xa5, 0x07, 0x68, 0x9f, 0x6f, 0x54, 0xb8, 0x47, 0xad, 0x1c, 0xef, 0x1e, 0x61, 0x4e, 0xe2, 0x3f, 0x1e})
	for name, tc := range map[string]struct {
		typ string
		arg interface{}
	}{
		"raw Addr bytes":      {"Addr", raw},
		"raw ByteString type": {"Addr", ByteString(raw)},
		"odd-length hex":      {"ByteString", "abc"},
		"non-hex text":        {"PubKey", "zz"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := n329Construct(n329Artifact(tc.typ, nil), tc.arg)
			var bad *InvalidConstructorArgError
			if !errors.As(err, &bad) {
				t.Fatalf("want *InvalidConstructorArgError, got %v", err)
			}
		})
	}
}

func TestN329_NonHexFixedArrayLeafIsRefused(t *testing.T) {
	a := n329Artifact("FixedArray<Addr, 2>", &ABIFixedArray{ElementType: "Addr", Length: 2})
	_, err := n329Construct(a, []interface{}{"aabb", "not-hex!"})
	var bad *InvalidConstructorArgError
	if !errors.As(err, &bad) {
		t.Fatalf("want *InvalidConstructorArgError, got %v", err)
	}
}

func TestN329_HexByteStringCtorArgIsAccepted(t *testing.T) {
	for name, arg := range map[string]interface{}{
		"string":     "9a1c78a5",
		"ByteString": ByteString("9a1c78a5"),
		"[]byte":     []byte{0x9a, 0x1c, 0x78, 0xa5},
		"empty":      "",
		"upper hex":  "9A1C78A5",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := n329Construct(n329Artifact("ByteString", nil), arg)
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if !isHexBytes(c.GetLockingScript()) {
				t.Fatalf("locking script is not hex: %q", c.GetLockingScript())
			}
		})
	}
}
