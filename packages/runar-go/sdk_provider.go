package runar

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

// Provider abstracts blockchain access for UTXO lookup and broadcast.
type Provider interface {
	// GetTransaction fetches a transaction by its txid.
	GetTransaction(txid string) (*Transaction, error)

	// Broadcast sends a raw transaction hex to the network. Returns the txid.
	Broadcast(rawTx string) (string, error)

	// GetUtxos returns all UTXOs for a given address.
	GetUtxos(address string) ([]UTXO, error)

	// GetContractUtxo finds a UTXO by its script hash (for stateful contract lookup).
	// Returns nil if no UTXO is found with the given script hash.
	GetContractUtxo(scriptHash string) (*UTXO, error)

	// GetNetwork returns the network this provider is connected to.
	GetNetwork() string

	// GetFeeRate returns the current fee rate in satoshis per byte.
	// BSV standard is 1 sat/byte.
	GetFeeRate() (int64, error)
}

// ---------------------------------------------------------------------------
// MockProvider — in-memory provider for testing
// ---------------------------------------------------------------------------

// MockProvider is an in-memory provider for unit tests and local development.
// It stores transactions and UTXOs that can be injected via helper methods,
// and records all broadcasts for assertion in tests.
type MockProvider struct {
	transactions   map[string]*Transaction
	utxos          map[string][]UTXO
	contractUtxos  map[string]*UTXO
	broadcastedTxs []string
	network        string
	broadcastCount int
	feeRate        int64
}

// NewMockProvider creates a new MockProvider for the given network.
func NewMockProvider(network string) *MockProvider {
	if network == "" {
		network = "testnet"
	}
	return &MockProvider{
		transactions:  make(map[string]*Transaction),
		utxos:         make(map[string][]UTXO),
		contractUtxos: make(map[string]*UTXO),
		network:       network,
		feeRate:       1,
	}
}

// AddTransaction injects a transaction into the mock store.
func (m *MockProvider) AddTransaction(tx *Transaction) {
	m.transactions[tx.Txid] = tx
}

// AddUtxo injects a UTXO for the given address.
func (m *MockProvider) AddUtxo(address string, utxo UTXO) {
	m.utxos[address] = append(m.utxos[address], utxo)
}

// AddContractUtxo injects a contract UTXO for lookup by script hash.
func (m *MockProvider) AddContractUtxo(scriptHash string, utxo *UTXO) {
	m.contractUtxos[scriptHash] = utxo
}

// GetBroadcastedTxs returns all raw tx hexes that were broadcast.
func (m *MockProvider) GetBroadcastedTxs() []string {
	return m.broadcastedTxs
}

// GetTransaction fetches a transaction from the mock store.
func (m *MockProvider) GetTransaction(txid string) (*Transaction, error) {
	tx, ok := m.transactions[txid]
	if !ok {
		return nil, fmt.Errorf("MockProvider: transaction %s not found", txid)
	}
	return tx, nil
}

// Broadcast records the raw tx and returns a deterministic fake txid.
func (m *MockProvider) Broadcast(rawTx string) (string, error) {
	m.broadcastedTxs = append(m.broadcastedTxs, rawTx)
	m.broadcastCount++
	fakeTxid := mockHash64(fmt.Sprintf("mock-broadcast-%d-%s", m.broadcastCount, rawTx[:min(16, len(rawTx))]))
	return fakeTxid, nil
}

// GetUtxos returns UTXOs for the given address from the mock store.
func (m *MockProvider) GetUtxos(address string) ([]UTXO, error) {
	return m.utxos[address], nil
}

// GetContractUtxo returns a UTXO by script hash from the mock store.
func (m *MockProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	utxo, ok := m.contractUtxos[scriptHash]
	if !ok {
		return nil, nil
	}
	return utxo, nil
}

// GetNetwork returns the mock network name.
func (m *MockProvider) GetNetwork() string {
	return m.network
}

// GetFeeRate returns the configured fee rate (default 1 sat/byte).
func (m *MockProvider) GetFeeRate() (int64, error) {
	return m.feeRate, nil
}

// SetFeeRate sets the fee rate returned by GetFeeRate (for testing).
func (m *MockProvider) SetFeeRate(rate int64) {
	m.feeRate = rate
}

// ---------------------------------------------------------------------------
// Deterministic mock hash (produces a 64-char hex string like a txid)
// ---------------------------------------------------------------------------

func mockHash64(input string) string {
	h0 := uint32(0x6a09e667)
	h1 := uint32(0xbb67ae85)
	h2 := uint32(0x3c6ef372)
	h3 := uint32(0xa54ff53a)

	for i := 0; i < len(input); i++ {
		c := uint32(input[i])
		h0 = imul32(h0^c, 0x01000193)
		h1 = imul32(h1^c, 0x01000193)
		h2 = imul32(h2^c, 0x01000193)
		h3 = imul32(h3^c, 0x01000193)
	}

	parts := []uint32{h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3}
	var sb strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&sb, "%08x", p)
	}
	return sb.String()
}

// imul32 multiplies two uint32 values, matching JavaScript's Math.imul semantics
// (32-bit wrapping multiplication).
func imul32(a, b uint32) uint32 {
	return a * b
}

