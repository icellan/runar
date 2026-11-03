package runar

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
// Network must be exactly "mainnet" or "testnet". Any other value — including the
// empty string — is rejected rather than defaulted, so a typo or an unvalidated
// user-supplied value can never silently point the SDK at live mainnet.
func NewGorillaPoolProvider(network string) (*GorillaPoolProvider, error) {
	var baseURL string
	switch network {
	case "mainnet":
		baseURL = "https://ordinals.gorillapool.io/api"
	case "testnet":
		baseURL = "https://testnet.ordinals.gorillapool.io/api"
	default:
		return nil, fmt.Errorf("runar: invalid network %q: must be \"mainnet\" or \"testnet\"", network)
	}
	return &GorillaPoolProvider{
		Network: network,
		baseURL: baseURL,
		client:  &http.Client{},
	}, nil
}

// ---------------------------------------------------------------------------
// GorillaPool API response shapes
// ---------------------------------------------------------------------------

// Documented schemas (GorillaPool OpenAPI: Txo, BSV20Txo, TokenBalanceResponse),
// trimmed to the fields read here (N-025).
type gpTxo struct {
	Txid     string    `json:"txid"`
	Vout     int       `json:"vout"`
	Satoshis int64     `json:"satoshis"`
	Height   *int      `json:"height"`
	Origin   *gpOrigin `json:"origin"`
}

type gpOrigin struct {
	Outpoint string `json:"outpoint"`
	Data     *struct {
		Insc *struct {
			File *struct {
				Hash *string `json:"hash"`
				Size *int    `json:"size"`
				Type *string `json:"type"`
			} `json:"file"`
		} `json:"insc"`
	} `json:"data"`
}

type gpBsv20Txo struct {
	Txid     string `json:"txid"`
	Vout     int    `json:"vout"`
	Satoshis int64  `json:"satoshis"`
	Script   string `json:"script"` // base64
}

type gpTokenBalance struct {
	Tick *string `json:"tick"`
	ID   *string `json:"id"`
	All  struct {
		Confirmed string `json:"confirmed"`
		Pending   string `json:"pending"`
	} `json:"all"`
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
//
// It uses GET /tx/{txid}/raw, which returns the bare serialized transaction
// (binary). Each output's satoshis is read from its 8-byte little-endian
// field, so the value is exact (F-027: the former JSON `vout[].value` decode,
// with its `< 1000 → BTC` guess, targeted a field GorillaPool never returns).
// The body must hash to the requested txid.
func (p *GorillaPoolProvider) GetTransaction(txid string) (*TransactionData, error) {
	raw, err := p.fetchVerifiedRaw(txid, "getTransaction")
	if err != nil {
		return nil, err
	}

	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getTransaction: parsing tx: %w", err)
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
		Raw:      hex.EncodeToString(raw),
	}, nil
}

// Broadcast sends a transaction to the network via GorillaPool.
// Returns the txid on success. N-025: the documented Broadcast body is
// {"rawtx": string} (lowercase).
func (p *GorillaPoolProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	payload, err := json.Marshal(map[string]string{"rawtx": tx.Hex()})
	if err != nil {
		return "", fmt.Errorf("GorillaPool broadcast encode failed: %w", err)
	}
	resp, err := p.client.Post(
		fmt.Sprintf("%s/tx", p.baseURL),
		"application/json",
		strings.NewReader(string(payload)),
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

// GetUtxos returns the unspent outputs of an address (N-025).
//
// It reads GET /txos/address/{address}/unspent (Txo[]). The listing carries
// no locking script, so each entry's tx is fetched via /tx/{txid}/raw
// (hash-verified); the output must exist, its value must equal the listing's,
// and its non-empty script is returned. Any non-2xx (404 included) is an
// error. N-159: entries whose origin is set (1-sat ordinal inscriptions,
// BSV-20 / BSV-21 token outputs) are dropped before any fetch — spending one
// as a fee input destroys the inscription or token. They remain available via
// GetInscriptionsByAddress / GetBSV20Utxos / GetBSV21Utxos.
func (p *GorillaPoolProvider) GetUtxos(address string) ([]UTXO, error) {
	var entries []gpTxo
	if err := p.getJSON(fmt.Sprintf("/txos/address/%s/unspent", address), "getUtxos", &entries); err != nil {
		return nil, err
	}
	txs := map[string]*transaction.Transaction{}
	utxos := make([]UTXO, 0, len(entries))
	for _, e := range entries {
		if e.Origin != nil {
			continue
		}
		tx, ok := txs[e.Txid]
		if !ok {
			raw, err := p.fetchVerifiedRaw(e.Txid, "getUtxos")
			if err != nil {
				return nil, err
			}
			tx, err = transaction.NewTransactionFromBytes(raw)
			if err != nil {
				return nil, fmt.Errorf("GorillaPool getUtxos: parsing tx %s: %w", e.Txid, err)
			}
			txs[e.Txid] = tx
		}
		if e.Vout < 0 || e.Vout >= len(tx.Outputs) {
			return nil, fmt.Errorf("GorillaPool getUtxos: no output %d in tx %s (%d outputs)", e.Vout, e.Txid, len(tx.Outputs))
		}
		out := tx.Outputs[e.Vout]
		if int64(out.Satoshis) != e.Satoshis {
			return nil, fmt.Errorf("GorillaPool getUtxos: value mismatch for %s_%d: listing says %d, tx says %d",
				e.Txid, e.Vout, e.Satoshis, out.Satoshis)
		}
		var script string
		if out.LockingScript != nil {
			script = hex.EncodeToString(*out.LockingScript)
		}
		if script == "" {
			return nil, fmt.Errorf("GorillaPool getUtxos: empty locking script for %s_%d", e.Txid, e.Vout)
		}
		if err := assertScriptHexUnderLimit(
			script, MaxScriptBytes,
			fmt.Sprintf("GorillaPoolProvider.GetUtxos(%s)", address),
		); err != nil {
			return nil, err
		}
		utxos = append(utxos, UTXO{Txid: e.Txid, OutputIndex: e.Vout, Satoshis: e.Satoshis, Script: script})
	}
	return utxos, nil
}

// GetContractUtxo always errors (N-025): the GorillaPool API has no documented
// route that looks UTXOs up by script hash (the former /script/{hash}/utxos is
// a 404), so it refuses rather than reporting "no UTXO".
func (p *GorillaPoolProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	return nil, fmt.Errorf("GorillaPool getContractUtxo(%s): lookup by script hash is not supported by the GorillaPool API", scriptHash)
}

// GetNetwork returns the network this provider is connected to.
func (p *GorillaPoolProvider) GetNetwork() string {
	return p.Network
}

// GetRawTransaction fetches the raw transaction hex by its txid via
// GET /tx/{txid}/raw (binary), hash-verified (N-025).
func (p *GorillaPoolProvider) GetRawTransaction(txid string) (string, error) {
	raw, err := p.fetchVerifiedRaw(txid, "getRawTransaction")
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// GetFeeRate returns the fee rate in satoshis per KB.
// BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
func (p *GorillaPoolProvider) GetFeeRate() (int64, error) {
	return 100, nil
}

// ---------------------------------------------------------------------------
// Ordinal-specific methods
// ---------------------------------------------------------------------------

// GetInscriptionsByAddress returns the inscriptions an address currently holds
// (N-025): the unspent Txos from GET /txos/address/{address}/unspent whose
// origin is set.
func (p *GorillaPoolProvider) GetInscriptionsByAddress(address string) ([]InscriptionInfo, error) {
	var entries []gpTxo
	if err := p.getJSON(fmt.Sprintf("/txos/address/%s/unspent", address), "getInscriptionsByAddress", &entries); err != nil {
		return nil, err
	}
	result := []InscriptionInfo{}
	for _, t := range entries {
		if t.Origin != nil {
			result = append(result, gpInscriptionInfo(t))
		}
	}
	return result, nil
}

// GetInscription returns inscription details (including content) by
// inscription ID ("<txid>_<vout>"). N-025: GET /inscriptions/{outpoint}
// returns a Txo; the content is GET /content/{outpoint} (host root), and its
// base64 sha256 must equal origin.data.insc.file.hash.
func (p *GorillaPoolProvider) GetInscription(inscriptionId string) (*InscriptionDetail, error) {
	var t *gpTxo
	if err := p.getJSON(fmt.Sprintf("/inscriptions/%s", inscriptionId), "getInscription", &t); err != nil {
		return nil, err
	}
	if t == nil || t.Origin == nil {
		return nil, fmt.Errorf("GorillaPool getInscription: %s is not an inscription (no origin)", inscriptionId)
	}
	info := gpInscriptionInfo(*t)

	contentURL := fmt.Sprintf("%s/content/%s", strings.TrimSuffix(p.baseURL, "/api"), inscriptionId)
	resp, err := p.client.Get(contentURL)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getInscription content request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool getInscription content failed (%d): %s", resp.StatusCode, string(body))
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool getInscription content read failed: %w", err)
	}
	sum := sha256.Sum256(content)
	got := base64.StdEncoding.EncodeToString(sum[:])
	want := "(none)"
	o := t.Origin
	if o.Data != nil && o.Data.Insc != nil && o.Data.Insc.File != nil && o.Data.Insc.File.Hash != nil {
		want = *o.Data.Insc.File.Hash
	}
	if got != want {
		return nil, fmt.Errorf("GorillaPool getInscription: content hash mismatch for %s: sha256 %s, inscription says %s",
			inscriptionId, got, want)
	}
	return &InscriptionDetail{InscriptionInfo: info, Data: hex.EncodeToString(content)}, nil
}

// GetBSV20Balance returns the confirmed BSV-20 (v1, tick-based) balance of an
// address (N-025): the all.confirmed of the GET /bsv20/{address}/balance entry
// whose tick equals tick exactly; "0" when the address holds no such token.
func (p *GorillaPoolProvider) GetBSV20Balance(address, tick string) (string, error) {
	rows, err := p.tokenBalances(address, "getBSV20Balance")
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Tick != nil && *r.Tick == tick {
			return r.All.Confirmed, nil
		}
	}
	return "0", nil
}

// GetBSV20Utxos returns BSV-20 token UTXOs for an address and ticker, from
// GET /bsv20/{address}/tick/{tick} (N-025).
func (p *GorillaPoolProvider) GetBSV20Utxos(address, tick string) ([]UTXO, error) {
	return p.fetchBsv20Utxos(fmt.Sprintf("/bsv20/%s/tick/%s", address, url.PathEscape(tick)), "getBSV20Utxos")
}

// GetBSV21Balance returns the confirmed BSV-21 (v2, ID-based) balance of an
// address (N-025): the all.confirmed of the GET /bsv20/{address}/balance entry
// whose id equals id; "0" when the address holds no such token.
// id format: "<txid>_<vout>"
func (p *GorillaPoolProvider) GetBSV21Balance(address, id string) (string, error) {
	rows, err := p.tokenBalances(address, "getBSV21Balance")
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.ID != nil && *r.ID == id {
			return r.All.Confirmed, nil
		}
	}
	return "0", nil
}

// GetBSV21Utxos returns BSV-21 token UTXOs for an address and token ID, from
// GET /bsv20/{address}/id/{id} (N-025).
// id format: "<txid>_<vout>"
func (p *GorillaPoolProvider) GetBSV21Utxos(address, id string) ([]UTXO, error) {
	return p.fetchBsv20Utxos(fmt.Sprintf("/bsv20/%s/id/%s", address, url.PathEscape(id)), "getBSV21Utxos")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getJSON GETs baseURL+path and decodes JSON into out. Any non-2xx (a 404
// included) is an error (N-025).
func (p *GorillaPoolProvider) getJSON(path, methodName string, out interface{}) error {
	resp, err := p.client.Get(p.baseURL + path)
	if err != nil {
		return fmt.Errorf("GorillaPool %s request failed: %w", methodName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GorillaPool %s failed (%d): %s", methodName, resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GorillaPool %s JSON decode failed: %w", methodName, err)
	}
	return nil
}

// fetchVerifiedRaw GETs /tx/{txid}/raw; the body must hash (sha256d,
// reversed) to txid.
func (p *GorillaPoolProvider) fetchVerifiedRaw(txid, methodName string) ([]byte, error) {
	resp, err := p.client.Get(fmt.Sprintf("%s/tx/%s/raw", p.baseURL, txid))
	if err != nil {
		return nil, fmt.Errorf("GorillaPool %s request failed: %w", methodName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GorillaPool %s failed (%d): %s", methodName, resp.StatusCode, string(body))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GorillaPool %s read failed: %w", methodName, err)
	}
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	for i, j := 0, len(second)-1; i < j; i, j = i+1, j-1 {
		second[i], second[j] = second[j], second[i]
	}
	if got := hex.EncodeToString(second[:]); got != strings.ToLower(txid) {
		return nil, fmt.Errorf("GorillaPool %s: txid mismatch: response body hashes to %s, requested %s", methodName, got, txid)
	}
	return raw, nil
}

func (p *GorillaPoolProvider) tokenBalances(address, methodName string) ([]gpTokenBalance, error) {
	var rows []gpTokenBalance
	if err := p.getJSON(fmt.Sprintf("/bsv20/%s/balance", address), methodName, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *GorillaPoolProvider) fetchBsv20Utxos(path, methodName string) ([]UTXO, error) {
	var rows []gpBsv20Txo
	if err := p.getJSON(path, methodName, &rows); err != nil {
		return nil, err
	}
	utxos := make([]UTXO, 0, len(rows))
	for _, r := range rows {
		scriptBytes, err := base64.StdEncoding.DecodeString(r.Script)
		if err != nil {
			return nil, fmt.Errorf("GorillaPool %s: bad base64 script for %s_%d: %w", methodName, r.Txid, r.Vout, err)
		}
		if len(scriptBytes) == 0 {
			return nil, fmt.Errorf("GorillaPool %s: no locking script for %s_%d", methodName, r.Txid, r.Vout)
		}
		script := hex.EncodeToString(scriptBytes)
		if err := assertScriptHexUnderLimit(script, MaxScriptBytes, "GorillaPoolProvider."+methodName); err != nil {
			return nil, err
		}
		utxos = append(utxos, UTXO{Txid: r.Txid, OutputIndex: r.Vout, Satoshis: r.Satoshis, Script: script})
	}
	return utxos, nil
}

func gpInscriptionInfo(t gpTxo) InscriptionInfo {
	info := InscriptionInfo{Txid: t.Txid, Vout: t.Vout, Origin: t.Origin.Outpoint}
	if d := t.Origin.Data; d != nil && d.Insc != nil && d.Insc.File != nil {
		if d.Insc.File.Type != nil {
			info.ContentType = *d.Insc.File.Type
		}
		if d.Insc.File.Size != nil {
			info.ContentLength = *d.Insc.File.Size
		}
	}
	if t.Height != nil {
		info.Height = *t.Height
	}
	return info
}
