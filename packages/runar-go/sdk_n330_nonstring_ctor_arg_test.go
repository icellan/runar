package runar

// N-330: a non-string ByteString-family constructor arg must be encoded as the
// raw bytes it is ([]byte) or refused with *InvalidConstructorArgError. Before,
// encodeArg's default arm did fmt.Sprintf("%v", v), so an untyped nil became
// "<nil>" and an int/bool/struct was spliced in as stringified text or as a
// script number.
//
// PROVES: untyped nil, int, int64, *big.Int, bool, float64 and a struct as a
// ByteString / FixedArray<Addr,2> leaf panic with *InvalidConstructorArgError;
// a []byte leaf yields the same locking script as the equivalent hex string.
// DOES NOT PROVE: width checks, method-call args, or on-chain spendability.

import (
	"errors"
	"math/big"
	"testing"
)

func TestN330_NonStringByteStringCtorArgIsRefused(t *testing.T) {
	for name, arg := range map[string]interface{}{
		"nil":      nil,
		"int":      5,
		"int64":    int64(5),
		"big.Int":  big.NewInt(5),
		"bool":     true,
		"float64":  1.5,
		"struct":   struct{ A int }{1},
		"[]string": []string{"aa"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := n329Construct(n329Artifact("ByteString", nil), arg)
			var bad *InvalidConstructorArgError
			if !errors.As(err, &bad) {
				t.Fatalf("want *InvalidConstructorArgError, got %v", err)
			}
		})
	}
}

func TestN330_NilFixedArrayLeafIsRefused(t *testing.T) {
	a := n329Artifact("FixedArray<Addr, 2>", &ABIFixedArray{ElementType: "Addr", Length: 2})
	_, err := n329Construct(a, []interface{}{"aabb", nil})
	var bad *InvalidConstructorArgError
	if !errors.As(err, &bad) {
		t.Fatalf("want *InvalidConstructorArgError, got %v", err)
	}
}

func TestN330_RawBytesEncodeAsThoseBytes(t *testing.T) {
	viaBytes, err := n329Construct(n329Artifact("ByteString", nil), []byte{0x9a, 0x1c, 0x78, 0xa5})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	viaHex, err := n329Construct(n329Artifact("ByteString", nil), "9a1c78a5")
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if viaBytes.GetLockingScript() != viaHex.GetLockingScript() {
		t.Fatalf("[]byte script %q != hex script %q", viaBytes.GetLockingScript(), viaHex.GetLockingScript())
	}
}
