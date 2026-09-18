package runar

import (
	"strings"
	"testing"
)

// FromUtxo used to return a nil contract with no error when C2 state
// decode failed. Callers that forgot the nil check then signed a
// continuation committing constructor-initial values. The error channel
// is the same one FromTxId already had.
func TestFromUtxo_HostileStateIsAnError(t *testing.T) {
	art := &RunarArtifact{
		Version:      "runar-v0.1.0",
		ContractName: "C2Probe",
		StateFields:  []StateField{{Name: "m", Type: "ByteString", Index: 0}},
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
		},
		Script: "00",
	}
	c, err := FromUtxo(art, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    1,
		Script:      "6a55", // OP_RETURN + 0x55, not a push
	})
	if err == nil {
		t.Fatal("FromUtxo must return an error for a hostile state section, not a live contract")
	}
	if c != nil {
		t.Fatal("FromUtxo must not return a contract when state decode fails")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "fromutxo") {
		t.Fatalf("error must name FromUtxo: %v", err)
	}
}

func TestFromUtxo_StatelessSucceeds(t *testing.T) {
	art := &RunarArtifact{
		Version:      "runar-v0.1.0",
		ContractName: "P2PKH",
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
		},
		Script: "76a914" + strings.Repeat("00", 20) + "88ac",
	}
	c, err := FromUtxo(art, UTXO{
		Txid:        strings.Repeat("ab", 32),
		OutputIndex: 0,
		Satoshis:    1,
		Script:      art.Script,
	})
	if err != nil {
		t.Fatalf("stateless FromUtxo: %v", err)
	}
	if c == nil {
		t.Fatal("stateless FromUtxo returned nil contract")
	}
}
