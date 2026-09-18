package codegen

import (
	"math/big"
	"strings"
	"testing"
)

// R-174 / CL-BUG-153 — an unrecognised push kind silently became OP_0.
//
// `encodePushValue`'s switch covers "bool", "bigint" and "bytes" and its
// default returned ("00", "OP_0") — a ZERO. Any push whose Kind is unset or
// unrecognised was therefore emitted as false / empty, with no error, and the
// script was wrong in the one way nothing downstream can notice: it is valid
// script that computes something else.
//
// The sibling switch two hundred lines below already fails closed
// (`default: return fmt.Errorf("unknown stack op: %s", op.Op)`), and so do
// `HasSideEffect` and `collectValueRefs` in frontend/, whose comments say why:
// a silent fall-through lets a newly-added variant change the emitted program
// without anyone noticing.
//
// Unreachable from the current code — every in-repo `PushValue{...}` sets a
// Kind, checked by grep — which is exactly the state in which a fail-open
// default survives review. It is one zero-valued struct away from being live.

func TestR174_UnknownPushKindIsRefusedNotZeroed(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("an unknown push kind was encoded instead of refused; " +
				"a silent OP_0 is valid script computing the wrong thing")
		}
		if !strings.Contains(strings.ToLower(toString(r)), "push kind") {
			t.Errorf("panic should name the offending kind, got: %v", r)
		}
	}()
	_, _ = encodePushValue(PushValue{Kind: "totally_made_up_kind"})
}

func TestR174_ZeroValuedPushValueIsRefused(t *testing.T) {
	// The shape a future caller is most likely to produce by accident.
	defer func() {
		if recover() == nil {
			t.Fatal("a PushValue with no Kind was encoded instead of refused")
		}
	}()
	_, _ = encodePushValue(PushValue{})
}

// Controls: the three real kinds still encode, and still encode the same bytes.
// Without these the tests above would pass against a function that refuses
// everything.
func TestR174_KnownPushKindsStillEncode(t *testing.T) {
	cases := []struct {
		name    string
		value   PushValue
		wantHex string
		wantAsm string
	}{
		{"bool true", PushValue{Kind: "bool", Bool: true}, "51", "OP_TRUE"},
		{"bool false", PushValue{Kind: "bool", Bool: false}, "00", "OP_FALSE"},
		{"bigint 0", PushValue{Kind: "bigint", BigInt: big.NewInt(0)}, "00", "OP_0"},
		{"bigint 1", PushValue{Kind: "bigint", BigInt: big.NewInt(1)}, "51", "OP_1"},
		{"empty bytes", PushValue{Kind: "bytes", Bytes: []byte{}}, "00", "OP_0"},
		{"one byte", PushValue{Kind: "bytes", Bytes: []byte{0xab}}, "01ab", "<ab>"},
	}
	for _, c := range cases {
		gotHex, gotAsm := encodePushValue(c.value)
		if gotHex != c.wantHex || gotAsm != c.wantAsm {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, gotHex, gotAsm, c.wantHex, c.wantAsm)
		}
	}
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}
