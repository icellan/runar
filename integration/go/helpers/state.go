package helpers

import (
	"fmt"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ReadOnChainState fetches txid from the node and decodes the state section
// of its outputIndex'th output using the artifact's state field layout.
//
// This reads the ACTUAL bytes the network accepted — not the SDK's in-memory
// state model (RunarContract.GetState()). RunarContract's auto-computed next
// state is derived by running the contract's ANF off-chain, the same IR the
// compiled Script executes; a miscompilation that makes the on-chain script
// commit a wrong-but-accepted state can produce an off-chain prediction that
// silently agrees with it (see PALMER-1 / commit 23ef2d2b, "the off-chain
// interpreter agreed... because it evaluates the same ANF"). Decoding the
// state section straight out of the broadcast transaction's script bytes
// does not go through that computation at all, so it can catch a divergence
// the in-memory model cannot.
func ReadOnChainState(artifact *runar.RunarArtifact, txid string, outputIndex int) (map[string]interface{}, error) {
	raw, err := GetRawTransaction(txid)
	if err != nil {
		return nil, fmt.Errorf("ReadOnChainState: getrawtransaction %s: %w", txid, err)
	}
	vout, ok := raw["vout"].([]interface{})
	if !ok || outputIndex >= len(vout) {
		return nil, fmt.Errorf("ReadOnChainState: tx %s has no output %d", txid, outputIndex)
	}
	om, ok := vout[outputIndex].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ReadOnChainState: tx %s output %d: malformed vout entry", txid, outputIndex)
	}
	sp, ok := om["scriptPubKey"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ReadOnChainState: tx %s output %d: no scriptPubKey", txid, outputIndex)
	}
	scriptHex, ok := sp["hex"].(string)
	if !ok || scriptHex == "" {
		return nil, fmt.Errorf("ReadOnChainState: tx %s output %d: no scriptPubKey hex", txid, outputIndex)
	}

	state, err := runar.ExtractStateFromScript(artifact, scriptHex)
	if err != nil {
		return nil, fmt.Errorf("ReadOnChainState: tx %s output %d: decoding state section: %w", txid, outputIndex, err)
	}
	if state == nil {
		return nil, fmt.Errorf("ReadOnChainState: tx %s output %d: script has no decodable state section", txid, outputIndex)
	}
	return state, nil
}
