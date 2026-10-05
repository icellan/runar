package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
//
// N-041: GET /tx/hash/{txid} has no "hex" field and reports values as float
// BTC, so Raw was always empty. The serialized tx is fetched via
// GET /tx/{txid}/hex instead, its double-SHA256 must equal the txid, and
// inputs/outputs (with integer satoshis) are parsed from those bytes.
func (p *WhatsOnChainProvider) GetTransaction(txid string) (*TransactionData, error) {
	tx, rawHex, err := p.fetchVerifiedTx(txid, "getTransaction")
	if err != nil {
		return nil, err
	}

	inputs := make([]TxInput, len(tx.Inputs))
	for i, inp := range tx.Inputs {
		var scriptHex string
		if inp.UnlockingScript != nil {
			scriptHex = hex.EncodeToString(*inp.UnlockingScript)
		}
		inputs[i] = TxInput{
			Txid:        inp.SourceTXID.String(),
			OutputIndex: int(inp.SourceTxOutIndex),
			Script:      scriptHex,
			Sequence:    inp.SequenceNumber,
		}
	}

	outputs := make([]TxOutput, len(tx.Outputs))
	for i, out := range tx.Outputs {
		var scriptHex string
		if out.LockingScript != nil {
			scriptHex = hex.EncodeToString(*out.LockingScript)
		}
		outputs[i] = TxOutput{
			Satoshis: int64(out.Satoshis),
			Script:   scriptHex,
		}
	}

	return &TransactionData{
		Txid:     strings.ToLower(txid),
		Version:  int(tx.Version),
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: int(tx.LockTime),
		Raw:      rawHex,
	}, nil
}

// fetchVerifiedTx fetches GET /tx/{txid}/hex and requires its double-SHA256
// (reversed) to equal txid before parsing it (F-040 / N-041).
func (p *WhatsOnChainProvider) fetchVerifiedTx(txid, context string) (*transaction.Transaction, string, error) {
	rawHex, err := p.GetRawTransaction(txid)
	if err != nil {
		return nil, "", fmt.Errorf("WoC %s: fetching tx %s: %w", context, txid, err)
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, "", fmt.Errorf("WoC %s: /tx/%s/hex body is not hex: %w", context, txid, err)
	}
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	for a, b := 0, len(second)-1; a < b; a, b = a+1, b-1 {
		second[a], second[b] = second[b], second[a]
	}
	if got := hex.EncodeToString(second[:]); got != strings.ToLower(txid) {
		return nil, "", fmt.Errorf("WoC %s: txid mismatch: /tx/%s/hex body hashes to %s", context, txid, got)
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, "", fmt.Errorf("WoC %s: parsing tx %s: %w", context, txid, err)
	}
	return tx, hex.EncodeToString(raw), nil
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
//
// Note: WoC caps this legacy listing at about 1000 entries, so an address
// holding more UTXOs is returned truncated.
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
			var err error
			tx, _, err = p.fetchVerifiedTx(e.TxHash, "getUtxos")
			if err != nil {
				return nil, err
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
//
// N-041: WoC's GET /script/{scriptHash}/unspent listing (a legacy array, or a
// {script, result} object on the /unspent/all family) carries outpoints and
// values but no locking script. The first entry's tx is fetched via
// GET /tx/{txid}/hex and hash-verified; tx_pos must be an output whose value
// equals the listed value, whose script is non-empty and hashes (sha256,
// reversed: WoC's scripthash) to scriptHash. Any failure is an error.
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("WoC getContractUtxo read failed: %w", err)
	}
	var entries []wocUtxoEntry
	if trimmed := strings.TrimSpace(string(body)); strings.HasPrefix(trimmed, "{") {
		var obj struct {
			Result *[]wocUtxoEntry `json:"result"`
		}
		if err := json.Unmarshal(body, &obj); err != nil {
			return nil, fmt.Errorf("WoC getContractUtxo JSON decode failed: %w", err)
		}
		if obj.Result == nil {
			return nil, fmt.Errorf("WoC getContractUtxo: unexpected listing shape for %s", scriptHash)
		}
		entries = *obj.Result
	} else if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("WoC getContractUtxo JSON decode failed: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	first := entries[0]
	tx, _, err := p.fetchVerifiedTx(first.TxHash, "getContractUtxo")
	if err != nil {
		return nil, err
	}
	if first.TxPos < 0 || first.TxPos >= len(tx.Outputs) {
		return nil, fmt.Errorf("WoC getContractUtxo: no output %d in tx %s (%d outputs)", first.TxPos, first.TxHash, len(tx.Outputs))
	}
	out := tx.Outputs[first.TxPos]
	if first.Value < 0 || uint64(first.Value) != out.Satoshis {
		return nil, fmt.Errorf("WoC getContractUtxo: value mismatch for %s:%d: listing says %d, tx says %d", first.TxHash, first.TxPos, first.Value, out.Satoshis)
	}
	var script []byte
	if out.LockingScript != nil {
		script = *out.LockingScript
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("WoC getContractUtxo: empty locking script for %s:%d", first.TxHash, first.TxPos)
	}
	h := sha256.Sum256(script)
	for a, b := 0, len(h)-1; a < b; a, b = a+1, b-1 {
		h[a], h[b] = h[b], h[a]
	}
	if got := hex.EncodeToString(h[:]); got != strings.ToLower(scriptHash) {
		return nil, fmt.Errorf("WoC getContractUtxo: script hash mismatch for %s:%d: output script hashes to %s, requested %s", first.TxHash, first.TxPos, got, scriptHash)
	}
	scriptHex := hex.EncodeToString(script)
	if err := assertScriptHexUnderLimit(
		scriptHex, MaxScriptBytes,
		fmt.Sprintf("WhatsOnChainProvider.GetContractUtxo(%s)", scriptHash),
	); err != nil {
		return nil, err
	}
	return &UTXO{
		Txid:        first.TxHash,
		OutputIndex: first.TxPos,
		Satoshis:    first.Value,
		Script:      scriptHex,
	}, nil
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
