package runar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// RPCProvider — JSON-RPC provider for Bitcoin nodes
// ---------------------------------------------------------------------------

// RPCProvider implements Provider by making JSON-RPC calls to a Bitcoin node.
type RPCProvider struct {
	url      string
	user     string
	pass     string
	network  string
	autoMine bool // if true, mines 1 block after broadcast (for regtest)
	client   *http.Client
	rpcID    uint64
}

// NewRPCProvider creates an RPCProvider with the given connection details.
// The network defaults to "mainnet". AutoMine is disabled.
func NewRPCProvider(url, user, pass string) *RPCProvider {
	return &RPCProvider{
		url:     url,
		user:    user,
		pass:    pass,
		network: "mainnet",
		client:  &http.Client{Timeout: 10 * time.Minute},
	}
}

// NewRegtestRPCProvider creates an RPCProvider configured for regtest.
// AutoMine is enabled (mines 1 block after each broadcast) and network
// is set to "regtest".
func NewRegtestRPCProvider(url, user, pass string) *RPCProvider {
	return &RPCProvider{
		url:      url,
		user:     user,
		pass:     pass,
		network:  "regtest",
		autoMine: true,
		client:   &http.Client{Timeout: 10 * time.Minute},
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcErrorObj    `json:"error"`
}

type rpcErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (p *RPCProvider) rpcCall(method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}
	id := atomic.AddUint64(&p.rpcID, 1)
	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "1.0",
		ID:      fmt.Sprintf("runar-%d", id),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("rpc marshal: %w", err)
	}

	req, err := http.NewRequest("POST", p.url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("rpc request: %w", err)
	}
	req.SetBasicAuth(p.user, p.pass)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc connection failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rpc read body: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("rpc response parse error: %w (body: %s)", err, truncate(string(body), 512))
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ---------------------------------------------------------------------------
// Provider interface implementation
// ---------------------------------------------------------------------------

// GetTransaction fetches a transaction by txid using getrawtransaction (verbose).
func (p *RPCProvider) GetTransaction(txid string) (*Transaction, error) {
	// Use int 1 for verbose (works with both SV Node and Teranode).
	result, err := p.rpcCall("getrawtransaction", txid, 1)
	if err != nil {
		return nil, fmt.Errorf("getrawtransaction: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(result, &raw); err != nil {
		return nil, fmt.Errorf("getrawtransaction parse: %w", err)
	}

	rawHex, _ := raw["hex"].(string)

	var outputs []TxOutput
	if vout, ok := raw["vout"].([]interface{}); ok {
		for _, o := range vout {
			om, _ := o.(map[string]interface{})
			valBTC, _ := om["value"].(float64)
			sats := int64(math.Round(valBTC * 1e8))
			scriptHex := ""
			if sp, ok := om["scriptPubKey"].(map[string]interface{}); ok {
				scriptHex, _ = sp["hex"].(string)
			}
			outputs = append(outputs, TxOutput{
				Satoshis: sats,
				Script:   scriptHex,
			})
		}
	}

	return &Transaction{
		Txid:    txid,
		Version: 1,
		Outputs: outputs,
		Raw:     rawHex,
	}, nil
}

// Broadcast sends a raw transaction hex via sendrawtransaction.
// If autoMine is enabled (regtest mode), it mines 1 block after broadcast.
func (p *RPCProvider) Broadcast(rawTx string) (string, error) {
	result, err := p.rpcCall("sendrawtransaction", rawTx)
	if err != nil {
		return "", fmt.Errorf("sendrawtransaction: %w", err)
	}

	var txid string
	if err := json.Unmarshal(result, &txid); err != nil {
		return "", fmt.Errorf("sendrawtransaction parse: %w", err)
	}

	if p.autoMine {
		if err := p.mine(1); err != nil {
			// Mining failure is non-fatal — the tx was already broadcast.
			// Log-style: return the txid but wrap the error context.
			return txid, fmt.Errorf("broadcast succeeded (txid %s) but auto-mine failed: %w", txid, err)
		}
	}

	return txid, nil
}

// GetUtxos returns UTXOs for the given address using listunspent.
func (p *RPCProvider) GetUtxos(address string) ([]UTXO, error) {
	result, err := p.rpcCall("listunspent", 0, 9999999, []string{address})
	if err != nil {
		return nil, fmt.Errorf("listunspent: %w", err)
	}

	var utxoList []map[string]interface{}
	if err := json.Unmarshal(result, &utxoList); err != nil {
		return nil, fmt.Errorf("listunspent parse: %w", err)
	}

	var utxos []UTXO
	for _, u := range utxoList {
		txid, _ := u["txid"].(string)
		vout, _ := u["vout"].(float64)
		amount, _ := u["amount"].(float64)
		scriptPubKey, _ := u["scriptPubKey"].(string)
		utxos = append(utxos, UTXO{
			Txid:        txid,
			OutputIndex: int(vout),
			Satoshis:    int64(math.Round(amount * 1e8)),
			Script:      scriptPubKey,
		})
	}
	return utxos, nil
}

// GetContractUtxo is not implemented for RPCProvider.
// Returns nil and an error indicating the limitation.
func (p *RPCProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	return nil, fmt.Errorf("GetContractUtxo not implemented for RPCProvider")
}

// GetNetwork returns the configured network string.
func (p *RPCProvider) GetNetwork() string {
	return p.network
}

// GetRawTransaction fetches the raw transaction hex using getrawtransaction (non-verbose).
func (p *RPCProvider) GetRawTransaction(txid string) (string, error) {
	result, err := p.rpcCall("getrawtransaction", txid, 0)
	if err != nil {
		return "", fmt.Errorf("getrawtransaction: %w", err)
	}
	var rawHex string
	if err := json.Unmarshal(result, &rawHex); err != nil {
		return "", fmt.Errorf("getrawtransaction parse: %w", err)
	}
	return rawHex, nil
}

// GetFeeRate returns 1 sat/byte (standard BSV fee rate).
func (p *RPCProvider) GetFeeRate() (int64, error) {
	return 1, nil
}

// ---------------------------------------------------------------------------
// Mining helper (for regtest auto-mine)
// ---------------------------------------------------------------------------

func (p *RPCProvider) mine(n int) error {
	// Try "generate" first (older nodes), fall back to "generatetoaddress".
	_, err := p.rpcCall("generate", n)
	if err == nil {
		return nil
	}

	addrResult, err := p.rpcCall("getnewaddress")
	if err != nil {
		return fmt.Errorf("getnewaddress: %w", err)
	}
	var addr string
	if err := json.Unmarshal(addrResult, &addr); err != nil {
		return fmt.Errorf("getnewaddress parse: %w", err)
	}

	_, err = p.rpcCall("generatetoaddress", n, addr)
	if err != nil {
		return fmt.Errorf("generatetoaddress: %w", err)
	}
	return nil
}
