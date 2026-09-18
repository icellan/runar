package runar

import (
	"math/big"
	"testing"
)

// TestAnfEvalCall_SubstrNegativeLength_NoPanic pins the W8 merge walk:
// extractScriptCode is empty in the Go SDK mock, so
// substr(sc, 0, len(sc)-49) has length -49. Go's h[lo:hi] panics on a
// negative hi (`slice bounds out of range [:-98]`); Bitcoin Script and
// the TS interpreter's String.slice yield empty instead.
func TestAnfEvalCall_SubstrNegativeLength_NoPanic(t *testing.T) {
	got := anfEvalCall("substr", []interface{}{"", big.NewInt(0), big.NewInt(-49)}, nil, nil, "merge")
	s, ok := got.(string)
	if !ok {
		t.Fatalf("substr: got %T, want string", got)
	}
	if s != "" {
		t.Fatalf("substr empty/-49 = %q, want empty", s)
	}
}

func TestAnfEvalCall_SubstrNegativeStart_NoPanic(t *testing.T) {
	got := anfEvalCall("substr", []interface{}{"aabb", big.NewInt(-1), big.NewInt(1)}, nil, nil, "merge")
	s, ok := got.(string)
	if !ok {
		t.Fatalf("substr: got %T, want string", got)
	}
	if s != "" {
		t.Fatalf("substr start=-1 = %q, want empty", s)
	}
}
