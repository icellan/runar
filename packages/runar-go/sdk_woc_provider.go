package runar

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// WhatsOnChainProvider — HTTP-based BSV API provider
// ---------------------------------------------------------------------------

// WhatsOnChainProvider implements the Provider interface using the
// WhatsOnChain REST API (https://whatsonchain.com).
type WhatsOnChainProvider struct {
	Network string // "mainnet" or "testnet"
	baseURL string
	client  *http.Client
}

// NewWhatsOnChainProvider creates a new WhatsOnChainProvider for the given network.
// Network must be "mainnet" or "testnet" (defaults to "mainnet" if empty).
func NewWhatsOnChainProvider(network string) *WhatsOnChainProvider {
	if network == "" {
		network = "mainnet"
	}
	baseURL := "https://api.whatsonchain.com/v1/bsv/main"
	if network == "testnet" {
		baseURL = "https://api.whatsonchain.com/v1/bsv/test"
	}
	return &WhatsOnChainProvider{
		Network: network,
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

// ---------------------------------------------------------------------------
// WoC API response shapes
// ---------------------------------------------------------------------------

type wocTxVin struct {
	Txid      string `json:"txid"`
	Vout      int    `json:"vout"`
	ScriptSig struct {
		Hex string `json:"hex"`
	} `json:"scriptSig"`
	Sequence uint32 `json:"sequence"`
}

type wocTxVout struct {
	Value        float64 `json:"value"`
	N            int     `json:"n"`
	ScriptPubKey struct {
		Hex string `json:"hex"`
	} `json:"scriptPubKey"`
}

type wocTxResponse struct {
	Txid     string      `json:"txid"`
	Version  int         `json:"version"`
	Vin      []wocTxVin  `json:"vin"`
	Vout     []wocTxVout `json:"vout"`
	Locktime int         `json:"locktime"`
	Hex      string      `json:"hex,omitempty"`
}

type wocUtxoEntry struct {
	TxHash string `json:"tx_hash"`
	TxPos  int    `json:"tx_pos"`
	Value  int64  `json:"value"`
	Height int    `json:"height"`
}

// ---------------------------------------------------------------------------
// Provider interface implementation
// ---------------------------------------------------------------------------

// GetTransaction fetches a transaction by its txid from WhatsOnChain.
func (p *WhatsOnChainProvider) GetTransaction(txid string) (*TransactionData, error) {
	url := fmt.Sprintf("%s/tx/hash/%s", p.baseURL, txid)
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("WoC getTransaction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("WoC getTransaction failed (%d): %s", resp.StatusCode, string(body))
	}

	var data wocTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("WoC getTransaction JSON decode failed: %w", err)
	}

	inputs := make([]TxInput, len(data.Vin))
	for i, vin := range data.Vin {
		inputs[i] = TxInput{
			Txid:        vin.Txid,
			OutputIndex: vin.Vout,
			Script:      vin.ScriptSig.Hex,
			Sequence:    vin.Sequence,
		}
	}

	outputs := make([]TxOutput, len(data.Vout))
	for i, vout := range data.Vout {
		outputs[i] = TxOutput{
			Satoshis: int64(math.Round(vout.Value * 1e8)),
			Script:   vout.ScriptPubKey.Hex,
		}
	}

	return &TransactionData{
		Txid:     data.Txid,
		Version:  data.Version,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: data.Locktime,
		Raw:      data.Hex,
	}, nil
}

// Broadcast sends a transaction to the network via WhatsOnChain.
// Returns the txid on success.
func (p *WhatsOnChainProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	rawTx := tx.Hex()
	payload := fmt.Sprintf(`{"txhex":"%s"}`, rawTx)
	resp, err := p.client.Post(
		fmt.Sprintf("%s/tx/raw", p.baseURL),
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("WoC broadcast request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("WoC broadcast failed (%d): %s", resp.StatusCode, string(body))
	}

	// WoC returns the txid as a JSON-encoded string
	var txid string
	if err := json.NewDecoder(resp.Body).Decode(&txid); err != nil {
		return "", fmt.Errorf("WoC broadcast JSON decode failed: %w", err)
	}
	return txid, nil
}

// GetUtxos returns all UTXOs for a given address from WhatsOnChain.
func (p *WhatsOnChainProvider) GetUtxos(address string) ([]UTXO, error) {
	url := fmt.Sprintf("%s/address/%s/unspent", p.baseURL, address)
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("WoC getUtxos request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("WoC getUtxos failed (%d): %s", resp.StatusCode, string(body))
	}

	var entries []wocUtxoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("WoC getUtxos JSON decode failed: %w", err)
	}

	utxos := make([]UTXO, len(entries))
	for i, e := range entries {
		utxos[i] = UTXO{
			Txid:        e.TxHash,
			OutputIndex: e.TxPos,
			Satoshis:    e.Value,
			Script:      "", // WoC doesn't return locking script in UTXO list
		}
	}
	// DoS-bound: defensive guard — WoC currently returns empty scripts but a
	// future enriched response must not bypass MaxScriptBytes.
	for _, u := range utxos {
		if u.Script == "" {
			continue
		}
		if err := assertScriptHexUnderLimit(
			u.Script, MaxScriptBytes,
			fmt.Sprintf("WhatsOnChainProvider.GetUtxos(%s)", address),
		); err != nil {
			return nil, err
		}
	}
	return utxos, nil
}

// GetContractUtxo finds a UTXO by its script hash from WhatsOnChain.
// Returns nil if no UTXO is found with the given script hash.
func (p *WhatsOnChainProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	url := fmt.Sprintf("%s/script/%s/unspent", p.baseURL, scriptHash)
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("WoC getContractUtxo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("WoC getContractUtxo failed (%d): %s", resp.StatusCode, string(body))
	}

	var entries []wocUtxoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("WoC getContractUtxo JSON decode failed: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	first := entries[0]
	utxo := &UTXO{
		Txid:        first.TxHash,
		OutputIndex: first.TxPos,
		Satoshis:    first.Value,
		Script:      "",
	}
	if utxo.Script != "" {
		if err := assertScriptHexUnderLimit(
			utxo.Script, MaxScriptBytes,
			fmt.Sprintf("WhatsOnChainProvider.GetContractUtxo(%s)", scriptHash),
		); err != nil {
			return nil, err
		}
	}
	return utxo, nil
}

// GetNetwork returns the network this provider is connected to.
func (p *WhatsOnChainProvider) GetNetwork() string {
	return p.Network
}

// GetRawTransaction fetches the raw transaction hex by its txid.
func (p *WhatsOnChainProvider) GetRawTransaction(txid string) (string, error) {
	url := fmt.Sprintf("%s/tx/%s/hex", p.baseURL, txid)
	resp, err := p.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("WoC getRawTransaction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("WoC getRawTransaction failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("WoC getRawTransaction read failed: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// GetFeeRate returns the fee rate in satoshis per KB.
// BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
func (p *WhatsOnChainProvider) GetFeeRate() (int64, error) {
	return 100, nil
}
