package runar

import (
	"math/big"
	"testing"
)

// R67: these two used to pin the W8 merge walk's historical clamp —
// extractScriptCode was empty in the Go SDK mock, so substr(sc, 0,
// len(sc)-49) had a negative length, and the OLD substr clamped that to ""
// instead of aborting. That was ITSELF the bug (N-171): OP_SPLIT aborts on a
// negative or past-the-end position, it does not clamp. extractScriptCode
// now returns the contract's own REAL codePart (sdk_contract.go's
// PrepareCall), so `merge`'s own scriptCode reads no longer go negative in
// practice -- but substr(data, start, length) with a literal negative
// start/length, as pinned directly here, must still abort on its own terms
// regardless of where the data came from.
func TestAnfEvalCall_SubstrNegativeLength_Panics(t *testing.T) {
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatalf("substr with negative length must panic, not return a value")
		}
		if _, ok := rec.(*ScriptOpcodeError); !ok {
			t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", rec, rec)
		}
	}()
	anfEvalCall("substr", []interface{}{"", big.NewInt(0), big.NewInt(-49)}, nil, nil, "merge")
}

func TestAnfEvalCall_SubstrNegativeStart_Panics(t *testing.T) {
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatalf("substr with negative start must panic, not return a value")
		}
		if _, ok := rec.(*ScriptOpcodeError); !ok {
			t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", rec, rec)
		}
	}()
	anfEvalCall("substr", []interface{}{"aabb", big.NewInt(-1), big.NewInt(1)}, nil, nil, "merge")
}
