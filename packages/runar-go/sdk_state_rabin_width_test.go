package runar

import (
	"math/big"
	"strings"
	"testing"
)

// F-035: RabinPubKey / RabinSig state fields are a bare 8-byte OP_NUM2BIN word,
// exactly like bigint. Both are bigint aliases and every compiler writes and
// reads them that way in the state section (the compiler is canonical, user
// decision D2). The SDK width table omitted both, so they fell to the
// push-data default and deployed a state section the script cannot read.
//
// rabinStateGolden is hand-derived and byte-identical across all seven SDKs
// (the same three values are the `state-rabin` sdk-output fixture):
//
//	RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
//	RabinSig    -1000000007        -> 07ca9a3b00000080
//	bigint      3                  -> 0300000000000000
//
// Proves: the Go codec writes and reads that layout. Does not prove the
// script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).

const rabinStateGolden = "efcdab9078563412" + "07ca9a3b00000080" + "0300000000000000"

func rabinStateFields() []StateField {
	return []StateField{
		{Name: "oracleKey", Type: "RabinPubKey", Index: 0},
		{Name: "lastSig", Type: "RabinSig", Index: 1},
		{Name: "count", Type: "bigint", Index: 2},
	}
}

func TestRabinStateFieldsSerializeAsNum2Bin8(t *testing.T) {
	got := SerializeState(rabinStateFields(), map[string]interface{}{
		"oracleKey": big.NewInt(0x1234567890ABCDEF),
		"lastSig":   int64(-1000000007),
		"count":     int64(3),
	})
	if got != rabinStateGolden {
		t.Fatalf("Rabin state record mismatch:\n got %s\nwant %s", got, rabinStateGolden)
	}
}

func TestRabinStateFieldsDeserialize(t *testing.T) {
	back := mustDeserializeState(t, rabinStateFields(), rabinStateGolden)
	want := map[string]int64{"oracleKey": 0x1234567890ABCDEF, "lastSig": -1000000007, "count": 3}
	for k, w := range want {
		if got, ok := back[k].(int64); !ok || got != w {
			t.Errorf("%s: got %v (%T), want %d", k, back[k], back[k], w)
		}
	}
}

func TestRabinStateFieldOutOfRangeRefused(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "does not fit") {
			t.Fatalf("expected a range refusal, got %v", r)
		}
	}()
	SerializeState([]StateField{{Name: "k", Type: "RabinPubKey", Index: 0}},
		map[string]interface{}{"k": new(big.Int).Lsh(big.NewInt(1), 63)})
}
