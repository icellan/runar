package runar

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// GorillaPoolProvider -- HTTP-based 1sat Ordinals provider
// ---------------------------------------------------------------------------

// GorillaPoolProvider implements the Provider interface using the GorillaPool
// 1sat Ordinals REST API. It also provides ordinal-specific methods for
// querying inscriptions and BSV-20/BSV-21 token data.
//
// Endpoints:
//
//	Mainnet: https://ordinals.gorillapool.io/api/
//	Testnet: https://testnet.ordinals.gorillapool.io/api/
type GorillaPoolProvider struct {
	Network string // "mainnet" or "testnet"
	baseURL string
	client  *http.Client
}

// NewGorillaPoolProvider creates a new GorillaPoolProvider for the given network.
// Network must be "mainnet" or "testnet" (defaults to "mainnet" if empty).
func NewGorillaPoolProvider(network string) *GorillaPoolProvider {
	if network == "" {
		network = "mainnet"
	}
	baseURL := "https://ordinals.gorillapool.io/api"
	if network == "testnet" {
		baseURL = "https://testnet.ordinals.gorillapool.io/api"
	}
	return &GorillaPoolProvider{
		Network: network,
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

// ---------------------------------------------------------------------------
// GorillaPool API response shapes
// ---------------------------------------------------------------------------

type gpTxVin struct {
	Txid      string `json:"txid"`
	Vout      int    `json:"vout"`
	ScriptSig struct {
		Hex string `json:"hex"`
	} `json:"scriptSig"`
	Sequence uint32 `json:"sequence"`
}

type gpTxVout struct {
	Value        json.Number `json:"value"`
	N            int         `json:"n"`
	ScriptPubKey struct {
		Hex string `json:"hex"`
	} `json:"scriptPubKey"`
}

type gpTxResponse struct {
	Txid     string     `json:"txid"`
	Version  int        `json:"version"`
	Vin      []gpTxVin  `json:"vin"`
	Vout     []gpTxVout `json:"vout"`
	Locktime int        `json:"locktime"`
	Hex      string     `json:"hex,omitempty"`
}

type gpUtxoEntry struct {
	Txid     string `json:"txid"`
	Vout     int    `json:"vout"`
	Satoshis int64  `json:"satoshis"`
	Script   string `json:"script,omitempty"`
}

// InscriptionInfo represents basic inscription metadata from GorillaPool.
type InscriptionInfo struct {
	Txid          string `json:"txid"`
	Vout          int    `json:"vout"`
	Origin        string `json:"origin"`
	ContentType   string `json:"contentType"`
	ContentLength int    `json:"contentLength"`
	Height        int    `json:"height"`
}

// InscriptionDetail extends InscriptionInfo with the inscription content.
type InscriptionDetail struct {
	InscriptionInfo
	Data string `json:"data"` // hex-encoded content
}

// ---------------------------------------------------------------------------
// Standard Provider interface implementation
// ---------------------------------------------------------------------------

// GetTransaction fetches a transaction by its txid from GorillaPool.
func (p *GorillaPoolProvider) GetTransaction(txid string) (*TransactionData, error) {
	apiURL := fmt.Sprintf("%s/tx/%s", p.baseURL, txid)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getTransaction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getTransaction failed (%d): %s", resp.StatusCode, string(body))
	}

	var data gpTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("GorillaPool getTransaction JSON decode failed: %w", err)
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
		val, _ := vout.Value.Float64()
		satoshis := int64(val)
		if val < 1000 {
			satoshis = int64(math.Round(val * 1e8))
		}
		outputs[i] = TxOutput{
			Satoshis: satoshis,
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

// Broadcast sends a transaction to the network via GorillaPool.
// Returns the txid on success.
func (p *GorillaPoolProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	rawTx := tx.Hex()
	payload := fmt.Sprintf(`{"rawTx":"%s"}`, rawTx)
	resp, err := p.client.Post(
		fmt.Sprintf("%s/tx", p.baseURL),
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("GorillaPool broadcast request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GorillaPool broadcast failed (%d): %s", resp.StatusCode, string(body))
	}

	// GorillaPool may return a plain string txid or {"txid":"..."}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("GorillaPool broadcast read response failed: %w", err)
	}
	bodyStr := strings.TrimSpace(string(body))

	// Try JSON decode first
	var txidStr string
	if err := json.Unmarshal([]byte(bodyStr), &txidStr); err == nil {
		return txidStr, nil
	}
	var result struct {
		Txid string `json:"txid"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &result); err == nil && result.Txid != "" {
		return result.Txid, nil
	}

	return bodyStr, nil
}

// GetUtxos returns all UTXOs for a given address from GorillaPool.
func (p *GorillaPoolProvider) GetUtxos(address string) ([]UTXO, error) {
	apiURL := fmt.Sprintf("%s/address/%s/utxos", p.baseURL, address)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getUtxos request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []UTXO{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getUtxos failed (%d): %s", resp.StatusCode, string(body))
	}

	var entries []gpUtxoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("GorillaPool getUtxos JSON decode failed: %w", err)
	}

	utxos := make([]UTXO, len(entries))
	for i, e := range entries {
		utxos[i] = UTXO{
			Txid:        e.Txid,
			OutputIndex: e.Vout,
			Satoshis:    e.Satoshis,
			Script:      e.Script,
		}
	}
	return utxos, nil
}

// GetContractUtxo finds a UTXO by its script hash from GorillaPool.
// Returns nil if no UTXO is found with the given script hash.
func (p *GorillaPoolProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	apiURL := fmt.Sprintf("%s/script/%s/utxos", p.baseURL, scriptHash)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getContractUtxo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getContractUtxo failed (%d): %s", resp.StatusCode, string(body))
	}

	var entries []gpUtxoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("GorillaPool getContractUtxo JSON decode failed: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	first := entries[0]
	return &UTXO{
		Txid:        first.Txid,
		OutputIndex: first.Vout,
		Satoshis:    first.Satoshis,
		Script:      first.Script,
	}, nil
}

// GetNetwork returns the network this provider is connected to.
func (p *GorillaPoolProvider) GetNetwork() string {
	return p.Network
}

// GetRawTransaction fetches the raw transaction hex by its txid.
func (p *GorillaPoolProvider) GetRawTransaction(txid string) (string, error) {
	apiURL := fmt.Sprintf("%s/tx/%s/hex", p.baseURL, txid)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getRawTransaction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GorillaPool getRawTransaction failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getRawTransaction read failed: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// GetFeeRate returns the fee rate in satoshis per KB.
// BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
func (p *GorillaPoolProvider) GetFeeRate() (int64, error) {
	return 100, nil
}

// ---------------------------------------------------------------------------
// Ordinal-specific methods
// ---------------------------------------------------------------------------

// GetInscriptionsByAddress returns all inscriptions associated with an address.
func (p *GorillaPoolProvider) GetInscriptionsByAddress(address string) ([]InscriptionInfo, error) {
	apiURL := fmt.Sprintf("%s/inscriptions/address/%s", p.baseURL, address)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getInscriptionsByAddress request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []InscriptionInfo{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getInscriptionsByAddress failed (%d): %s", resp.StatusCode, string(body))
	}

	var result []InscriptionInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("GorillaPool getInscriptionsByAddress JSON decode failed: %w", err)
	}
	return result, nil
}

// GetInscription returns inscription details (including content) by inscription ID.
// inscriptionId format: "<txid>_<vout>"
func (p *GorillaPoolProvider) GetInscription(inscriptionId string) (*InscriptionDetail, error) {
	apiURL := fmt.Sprintf("%s/inscriptions/%s", p.baseURL, inscriptionId)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getInscription request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getInscription failed (%d): %s", resp.StatusCode, string(body))
	}

	var result InscriptionDetail
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("GorillaPool getInscription JSON decode failed: %w", err)
	}
	return &result, nil
}

// GetBSV20Balance returns the BSV-20 (v1, tick-based) token balance for an address.
func (p *GorillaPoolProvider) GetBSV20Balance(address, tick string) (string, error) {
	apiURL := fmt.Sprintf("%s/bsv20/balance/%s/%s", p.baseURL, address, url.PathEscape(tick))
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getBSV20Balance request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "0", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GorillaPool getBSV20Balance failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getBSV20Balance read failed: %w", err)
	}
	bodyStr := strings.TrimSpace(string(body))

	// Try string
	var strResult string
	if err := json.Unmarshal([]byte(bodyStr), &strResult); err == nil {
		return strResult, nil
	}
	// Try object
	var objResult struct {
		Balance string `json:"balance"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &objResult); err == nil {
		if objResult.Balance != "" {
			return objResult.Balance, nil
		}
	}
	return "0", nil
}

// GetBSV20Utxos returns BSV-20 token UTXOs for an address and ticker.
func (p *GorillaPoolProvider) GetBSV20Utxos(address, tick string) ([]UTXO, error) {
	apiURL := fmt.Sprintf("%s/bsv20/utxos/%s/%s", p.baseURL, address, url.PathEscape(tick))
	return p.fetchUtxoList(apiURL, "getBSV20Utxos")
}

// GetBSV21Balance returns the BSV-21 (v2, ID-based) token balance for an address.
// id format: "<txid>_<vout>"
func (p *GorillaPoolProvider) GetBSV21Balance(address, id string) (string, error) {
	apiURL := fmt.Sprintf("%s/bsv20/balance/%s/%s", p.baseURL, address, url.PathEscape(id))
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getBSV21Balance request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "0", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GorillaPool getBSV21Balance failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("GorillaPool getBSV21Balance read failed: %w", err)
	}
	bodyStr := strings.TrimSpace(string(body))

	var strResult string
	if err := json.Unmarshal([]byte(bodyStr), &strResult); err == nil {
		return strResult, nil
	}
	var objResult struct {
		Balance string `json:"balance"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &objResult); err == nil {
		if objResult.Balance != "" {
			return objResult.Balance, nil
		}
	}
	return "0", nil
}

// GetBSV21Utxos returns BSV-21 token UTXOs for an address and token ID.
// id format: "<txid>_<vout>"
func (p *GorillaPoolProvider) GetBSV21Utxos(address, id string) ([]UTXO, error) {
	apiURL := fmt.Sprintf("%s/bsv20/utxos/%s/%s", p.baseURL, address, url.PathEscape(id))
	return p.fetchUtxoList(apiURL, "getBSV21Utxos")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (p *GorillaPoolProvider) fetchUtxoList(apiURL, methodName string) ([]UTXO, error) {
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool %s request failed: %w", methodName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []UTXO{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool %s failed (%d): %s", methodName, resp.StatusCode, string(body))
	}

	var entries []gpUtxoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("GorillaPool %s JSON decode failed: %w", methodName, err)
	}

	utxos := make([]UTXO, len(entries))
	for i, e := range entries {
		utxos[i] = UTXO{
			Txid:        e.Txid,
			OutputIndex: e.Vout,
			Satoshis:    e.Satoshis,
			Script:      e.Script,
		}
	}
	return utxos, nil
}
