package runar

import (
	"testing"
)

// N-076: TokenWallet.GetUtxos must discover a deployed token contract with the
// slot-aware matcher (MatchesArtifact), not a raw prefix of the template. The
// template has a constructor slot, a codeSepIndex slot (baked as OP_1) and a
// codePartLenSlots field (the deployed code-part length), none of which a
// literal prefix of the template can equal.
//
// Proves: a deployed instance of such a template (with a state section) is
// found, while scripts that share the pre-slot prefix but differ after it, or
// carry a wrong code-part length, or are unrelated, are not.
// Does NOT prove: on-chain spendability of the matched UTXO, nor that an
// artifact with only codeSepIndex slots (no constructor slots) is matched —
// MatchesArtifact itself compares such a template literally.

// bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
//
//	ctor slot @2, codeSepIndex slot @4, codePartLen field @7
func n076Artifact() *RunarArtifact {
	return &RunarArtifact{
		ContractName:      "FungibleToken",
		Script:            "76a9" + "00" + "88" + "00" + "75" + "04" + "00000000" + "ac",
		StateFields:       []StateField{{Name: "balance", Type: "bigint", Index: 1}},
		ConstructorSlots:  []ConstructorSlot{{ParamIndex: 0, ByteOffset: 2}},
		CodeSepIndexSlots: []CodeSepIndexSlot{{ByteOffset: 4}},
		CodePartLenSlots:  []CodePartLenSlot{{ByteOffset: 7}},
	}
}

// supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes.
func n076Deployed(tail, length string) string {
	return "76a9" + "02aabb" + "88" + "51" + "75" + "04" + length + tail + "6a" + "0100"
}

func n076Discover(t *testing.T, scripts ...string) []string {
	t.Helper()
	provider := NewMockProvider("testnet")
	signer := NewMockSigner("", "")
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range scripts {
		provider.AddUtxo(addr, UTXO{Txid: string(rune('a'+i)) + "00000000000000000000000000000000000000000000000000000000000000", OutputIndex: 0, Satoshis: 1000, Script: s})
	}
	utxos, err := NewTokenWallet(n076Artifact(), provider, signer).GetUtxos()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, u := range utxos {
		ids = append(ids, u.Txid[:1])
	}
	return ids
}

func TestN076_TokenWalletFindsDeployedSlottedInstance(t *testing.T) {
	got := n076Discover(t, n076Deployed("ac", "0e000000"))
	if len(got) != 1 {
		t.Fatalf("deployed slotted instance not found: %v", got)
	}
}

func TestN076_TokenWalletRejectsScriptsThatOnlyShareThePrefix(t *testing.T) {
	cases := map[string]string{
		"differs after the slots": n076Deployed("ad", "0e000000"),
		"wrong code-part length":  n076Deployed("ac", "0f000000"),
		"unrelated script":        "76a914" + "1111111111111111111111111111111111111111" + "88ac",
	}
	for name, script := range cases {
		if got := n076Discover(t, script); len(got) != 0 {
			t.Errorf("%s: matched %v", name, got)
		}
	}
}
