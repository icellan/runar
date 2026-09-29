package runar

import (
	"crypto/sha256"
	"encoding/hex"
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
// Network must be exactly "mainnet" or "testnet". Any other value — including the
// empty string — is rejected rather than defaulted, so a typo or an unvalidated
// user-supplied value can never silently point the SDK at live mainnet.
func NewWhatsOnChainProvider(network string) (*WhatsOnChainProvider, error) {
	var baseURL string
	switch network {
	case "mainnet":
		baseURL = "https://api.whatsonchain.com/v1/bsv/main"
	case "testnet":
		baseURL = "https://api.whatsonchain.com/v1/bsv/test"
	default:
		return nil, fmt.Errorf("runar: invalid network %q: must be \"mainnet\" or \"testnet\"", network)
	}
	return &WhatsOnChainProvider{
		Network: network,
		baseURL: baseURL,
		client:  &http.Client{},
	}, nil
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
//
// WoC's GET /address/{address}/unspent listing carries outpoints and values
// but no locking script. The script is the BIP-143 scriptCode a signer commits
// to, so an empty one yields signatures no OP_CHECKSIG accepts (F-040). Each
// distinct txid is therefore fetched via GET /tx/{txid}/hex, its double-SHA256
// must equal the txid, and tx_pos must be an output whose value equals the
// listed value. Any failure is an error; no UTXO is returned with an empty
// script.
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

	txs := make(map[string]*transaction.Transaction)
	utxos := make([]UTXO, len(entries))
	for i, e := range entries {
		tx, ok := txs[e.TxHash]
		if !ok {
			rawHex, err := p.GetRawTransaction(e.TxHash)
			if err != nil {
				return nil, fmt.Errorf("WoC getUtxos: fetching tx %s: %w", e.TxHash, err)
			}
			raw, err := hex.DecodeString(rawHex)
			if err != nil {
				return nil, fmt.Errorf("WoC getUtxos: /tx/%s/hex body is not hex: %w", e.TxHash, err)
			}
			first := sha256.Sum256(raw)
			second := sha256.Sum256(first[:])
			for a, b := 0, len(second)-1; a < b; a, b = a+1, b-1 {
				second[a], second[b] = second[b], second[a]
			}
			if got := hex.EncodeToString(second[:]); got != strings.ToLower(e.TxHash) {
				return nil, fmt.Errorf("WoC getUtxos: txid mismatch: /tx/%s/hex body hashes to %s", e.TxHash, got)
			}
			tx, err = transaction.NewTransactionFromBytes(raw)
			if err != nil {
				return nil, fmt.Errorf("WoC getUtxos: parsing tx %s: %w", e.TxHash, err)
			}
			txs[e.TxHash] = tx
		}
		if e.TxPos < 0 || e.TxPos >= len(tx.Outputs) {
			return nil, fmt.Errorf("WoC getUtxos: no output %d in tx %s (%d outputs)", e.TxPos, e.TxHash, len(tx.Outputs))
		}
		out := tx.Outputs[e.TxPos]
		if e.Value < 0 || uint64(e.Value) != out.Satoshis {
			return nil, fmt.Errorf("WoC getUtxos: value mismatch for %s:%d: listing says %d, tx says %d", e.TxHash, e.TxPos, e.Value, out.Satoshis)
		}
		var scriptHex string
		if out.LockingScript != nil {
			scriptHex = hex.EncodeToString(*out.LockingScript)
		}
		if scriptHex == "" {
			return nil, fmt.Errorf("WoC getUtxos: empty locking script for %s:%d", e.TxHash, e.TxPos)
		}
		if err := assertScriptHexUnderLimit(
			scriptHex, MaxScriptBytes,
			fmt.Sprintf("WhatsOnChainProvider.GetUtxos(%s)", address),
		); err != nil {
			return nil, err
		}
		utxos[i] = UTXO{
			Txid:        e.TxHash,
			OutputIndex: e.TxPos,
			Satoshis:    e.Value,
			Script:      scriptHex,
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
