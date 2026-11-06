package helpers

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	runar "github.com/icellan/runar/packages/runar-go"
)

// utxoLedger is the harness's own record of unspent outputs, built from the
// transactions it successfully broadcasts.
//
// Teranode has no wallet and no address index: `listunspent` answers "This
// implementation does not implement wallet commands", and neither the RPC
// service nor the asset HTTP API can look outputs up by address or script
// (the asset API only resolves a known txid:vout). Every coin the suite owns
// reaches it through a transaction the suite itself built and broadcast —
// coinbase → FundFromCoinbase → deploy → call — so the harness already knows
// every outpoint it could spend. Recording those transactions replaces the
// wallet query on Teranode. SV Node keeps using `listunspent`.
type utxoLedger struct {
	mu      sync.Mutex
	unspent map[string]runar.UTXO // "txid:vout" → output
}

func newUtxoLedger() *utxoLedger {
	return &utxoLedger{unspent: map[string]runar.UTXO{}}
}

func outpointKey(txid string, vout int) string {
	return fmt.Sprintf("%s:%d", txid, vout)
}

// recordHex applies a transaction the node ACCEPTED: its inputs leave the
// unspent set and its outputs join it. Call only after a successful
// broadcast — recording a rejected tx would hand the SDK phantom coins.
// Satoshis come from the serialized tx, so they are exact.
func (l *utxoLedger) recordHex(txHex string) error {
	tx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		return fmt.Errorf("utxo ledger: parse tx: %w", err)
	}
	txid := tx.TxID().String()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil {
			continue
		}
		delete(l.unspent, outpointKey(in.SourceTXID.String(), int(in.SourceTxOutIndex)))
	}
	for i, out := range tx.Outputs {
		scriptHex := ""
		if out.LockingScript != nil {
			scriptHex = hex.EncodeToString(*out.LockingScript)
		}
		l.unspent[outpointKey(txid, i)] = runar.UTXO{
			Txid:        txid,
			OutputIndex: i,
			Satoshis:    int64(out.Satoshis),
			Script:      scriptHex,
		}
	}
	return nil
}

// utxosForAddress returns the recorded unspent P2PKH outputs paying address.
func (l *utxoLedger) utxosForAddress(address string) ([]runar.UTXO, error) {
	addr, err := script.NewAddressFromString(address)
	if err != nil {
		return nil, fmt.Errorf("utxo ledger: bad address %q: %w", address, err)
	}
	want := "76a914" + hex.EncodeToString(addr.PublicKeyHash) + "88ac"

	l.mu.Lock()
	defer l.mu.Unlock()
	var utxos []runar.UTXO
	for _, u := range l.unspent {
		if u.Script == want {
			utxos = append(utxos, u)
		}
	}
	return utxos, nil
}

// broadcastLedger holds every transaction this process broadcast successfully.
// Populated only on Teranode (see SendRawTransaction).
var broadcastLedger = newUtxoLedger()
