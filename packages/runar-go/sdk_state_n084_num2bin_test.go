package runar

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// N-084: the num2bin state encode path fails closed. toInt64 returned 0 for a
// non-decimal string, a bool, []byte, nil or any unknown type, so a hex string
// in a bigint / int / RabinSig / RabinPubKey state field was serialized as
// 0000000000000000 and committed on chain.
//
// Proves: SerializeState panics with a named error for each such value in each
// of the four num2bin types, and valid integers keep their exact bytes.
// Does not prove: anything on chain; the other six SDKs have their own n084
// tests.

func n084Serialize(t *testing.T, typ string, v interface{}) (out string, panicMsg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicMsg = fmt.Sprint(r)
		}
	}()
	out = SerializeState([]StateField{{Name: "k", Type: typ, Index: 0}}, map[string]interface{}{"k": v})
	return
}

func TestN084Num2BinStateRefusesNonInteger(t *testing.T) {
	bad := map[string]interface{}{
		"bool":               true,
		"empty string":       "",
		"hex digits":         "deadbeef",
		"0x hex":             "0x10",
		"non-decimal string": "abc",
		"fractional float":   1.5,
		"nil":                nil,
		"bytes":              []byte{1, 2},
		"struct":             struct{}{},
	}
	for _, typ := range []string{"int", "bigint", "RabinSig", "RabinPubKey"} {
		for name, v := range bad {
			out, msg := n084Serialize(t, typ, v)
			want := fmt.Sprintf(`state field "k" (%s) must be an integer`, typ)
			if !strings.Contains(msg, want) {
				t.Errorf("%s/%s: want panic containing %q, got panic %q (encoded %q)", typ, name, want, msg, out)
			}
		}
	}
}

func TestN084Num2BinStateValidIntegersUnchanged(t *testing.T) {
	cases := []struct {
		v    interface{}
		want string
	}{
		{int64(0), "0000000000000000"},
		{int64(5), "0500000000000000"},
		{int(5), "0500000000000000"},
		{int32(5), "0500000000000000"},
		{uint64(5), "0500000000000000"},
		{int64(-5), "0500000000000080"},
		{big.NewInt(-5), "0500000000000080"},
		{float64(5), "0500000000000000"},
		{"5", "0500000000000000"},
		{"5n", "0500000000000000"},
		{"-5n", "0500000000000080"},
	}
	for _, typ := range []string{"int", "bigint", "RabinSig", "RabinPubKey"} {
		for _, c := range cases {
			out, msg := n084Serialize(t, typ, c.v)
			if msg != "" || out != c.want {
				t.Errorf("%s %T(%v): got %q (panic %q), want %q", typ, c.v, c.v, out, msg, c.want)
			}
		}
	}
}
