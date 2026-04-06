package helpers

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-sdk/transaction"
	runar "github.com/icellan/runar/packages/runar-go"
)

// RPCProvider implements runar.Provider using JSON-RPC calls to a Bitcoin node.
type RPCProvider struct {
	network string
}

// NewRPCProvider creates a provider that talks to the regtest node via JSON-RPC.
func NewRPCProvider() *RPCProvider {
	return &RPCProvider{network: "regtest"}
}

func (p *RPCProvider) GetTransaction(txid string) (*runar.TransactionData, error) {
	raw, err := GetRawTransaction(txid)
	if err != nil {
		return nil, err
	}
	rawHex, _ := raw["hex"].(string)

	var outputs []runar.TxOutput
	if vout, ok := raw["vout"].([]interface{}); ok {
		for _, o := range vout {
			om, _ := o.(map[string]interface{})
			valBTC, _ := om["value"].(float64)
			sats := int64(valBTC * 1e8)
			scriptHex := ""
			if sp, ok := om["scriptPubKey"].(map[string]interface{}); ok {
				scriptHex, _ = sp["hex"].(string)
			}
			outputs = append(outputs, runar.TxOutput{
				Satoshis: sats,
				Script:   scriptHex,
			})
		}
	}

	return &runar.TransactionData{
		Txid:    txid,
		Version: 1,
		Outputs: outputs,
		Raw:     rawHex,
	}, nil
}

func (p *RPCProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	rawTx := tx.Hex()
	txid, err := SendRawTransaction(rawTx)
	if err != nil {
		return "", err
	}
	_ = Mine(1) // auto-mine for regtest
	return txid, nil
}

func (p *RPCProvider) GetUtxos(address string) ([]runar.UTXO, error) {
	result, err := RPCCall("listunspent", 0, 9999999, []string{address})
	if err != nil {
		return nil, fmt.Errorf("listunspent: %w", err)
	}
	var utxoList []map[string]interface{}
	if err := json.Unmarshal(result, &utxoList); err != nil {
		return nil, err
	}

	var utxos []runar.UTXO
	for _, u := range utxoList {
		txid, _ := u["txid"].(string)
		vout, _ := u["vout"].(float64)
		amount, _ := u["amount"].(float64)
		scriptPubKey, _ := u["scriptPubKey"].(string)
		utxos = append(utxos, runar.UTXO{
			Txid:        txid,
			OutputIndex: int(vout),
			Satoshis:    int64(math.Round(amount * 1e8)),
			Script:      scriptPubKey,
		})
	}
	return utxos, nil
}

func (p *RPCProvider) GetContractUtxo(scriptHash string) (*runar.UTXO, error) {
	return nil, fmt.Errorf("GetContractUtxo not implemented for RPC provider")
}

func (p *RPCProvider) GetNetwork() string {
	return p.network
}

func (p *RPCProvider) GetRawTransaction(txid string) (string, error) {
	raw, err := GetRawTransaction(txid)
	if err != nil {
		return "", err
	}
	rawHex, _ := raw["hex"].(string)
	return rawHex, nil
}

func (p *RPCProvider) GetFeeRate() (int64, error) {
	return 1, nil
}

// SDKSignerFromWallet creates a runar.Signer from an integration test Wallet.
// Uses ExternalSigner so the regtest address (not mainnet) is returned,
// which is required for listunspent to find funded UTXOs.
func SDKSignerFromWallet(w *Wallet) (runar.Signer, error) {
	keyHex := hex.EncodeToString(w.PrivKey.Serialize())
	localSigner, err := runar.NewLocalSigner(keyHex)
	if err != nil {
		return nil, err
	}
	pubKeyHex, _ := localSigner.GetPublicKey()

	return runar.NewExternalSigner(
		pubKeyHex,
		w.Address, // regtest address
		func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
			return localSigner.Sign(txHex, inputIndex, subscript, satoshis, sigHashType)
		},
	), nil
}
