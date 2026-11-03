package runar

// N-045 (EXT-2 WideHash), SDK side — defence in depth only.
//
// The on-chain state reader slices each fixed-width byte field at its declared
// width, so a wrong-width value in a state section shifts every later field.
// The consensus defence is the covenant's own OP_SIZE <width>
// OP_NUMEQUALVERIFY before each continuation commit (proved under strict Spend
// in packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
// These tests pin the off-chain refusals: SerializeState and PrepareCall reject
// a wrong-width fixed-width value. (Constructor args are deliberately NOT
// checked: FromUtxo builds its contract with placeholder constructor args. A
// mutable field's deploy-time value still goes through SerializeState.) They
// prove nothing on chain.

import (
	"strings"
	"testing"
)

var n045FixedWidthTypes = []struct {
	typ   string
	width int
}{
	{"PubKey", 33}, {"Sha256", 32}, {"Ripemd160", 20}, {"Addr", 20},
	{"Point", 64}, {"P256Point", 64}, {"P384Point", 96},
}

func n045Panics(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
			if msg == "" {
				msg = "panic"
			}
		}
	}()
	f()
	return ""
}

func TestN045SerializeStateRefusesWrongWidth(t *testing.T) {
	for _, tc := range n045FixedWidthTypes {
		fields := []StateField{{Name: "k", Type: tc.typ, Index: 0}}
		for _, bad := range []int{tc.width - 1, tc.width + 1} {
			msg := n045Panics(func() {
				SerializeState(fields, map[string]interface{}{"k": strings.Repeat("ab", bad)})
			})
			if !strings.Contains(msg, "must be exactly") {
				t.Errorf("%s: %d bytes was not refused (panic=%q)", tc.typ, bad, msg)
			}
		}
		if msg := n045Panics(func() {
			SerializeState(fields, map[string]interface{}{"k": strings.Repeat("zz", tc.width)})
		}); !strings.Contains(msg, "non-hex") {
			t.Errorf("%s: non-hex was not refused (panic=%q)", tc.typ, msg)
		}
		good := strings.Repeat("ab", tc.width)
		if got := SerializeState(fields, map[string]interface{}{"k": good}); got != good {
			t.Errorf("%s: exact width serialized to %q", tc.typ, got)
		}
	}
}

func n045RootArtifact() *RunarArtifact {
	abi := ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "root", Type: "Sha256"}}},
		Methods: []ABIMethod{{
			Name: "updateRoot",
			Params: []ABIParam{
				{Name: "nextRoot", Type: "Sha256"},
				{Name: "_changePKH", Type: "Ripemd160"},
				{Name: "_changeAmount", Type: "bigint"},
				{Name: "_newAmount", Type: "bigint"},
				{Name: "txPreimage", Type: "SigHashPreimage"},
			},
			IsPublic: true,
		}},
	}
	return makeArtifact("51", abi, func(a *RunarArtifact) {
		a.ContractName = "N045Root"
		a.StateFields = []StateField{{Name: "root", Type: "Sha256", Index: 0}}
		csi := 0
		a.CodeSeparatorIndex = &csi
		a.CodeSeparatorIndices = []int{0}
	})
}

func TestN045CallRefusesWrongWidthSha256Arg(t *testing.T) {
	for _, bad := range []int{31, 33, 66} {
		contract := NewRunarContract(n045RootArtifact(), []interface{}{strings.Repeat("11", 32)})
		provider := NewMockProvider("testnet")
		signer := NewMockSigner("", strings.Repeat("00", 20))
		// Pretend deployed: the refusal must fire before any UTXO is touched.
		contract.currentUtxo = &UTXO{
			Txid: strings.Repeat("bb", 32), OutputIndex: 0, Satoshis: 10000,
			Script: contract.GetLockingScript(),
		}
		before := len(provider.GetBroadcastedTxs())
		_, _, err := contract.Call("updateRoot", []interface{}{strings.Repeat("22", bad)}, provider, signer, nil)
		if err == nil || !strings.Contains(err.Error(), "arg 'nextRoot' (index 0)") || !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("%d-byte nextRoot was not refused: %v", bad, err)
		}
		if after := len(provider.GetBroadcastedTxs()); after != before {
			t.Errorf("%d-byte nextRoot: %d tx(s) broadcast", bad, after-before)
		}
	}
}
