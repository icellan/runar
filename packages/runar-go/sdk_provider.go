package runar

import (
	"fmt"
	"strings"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

// Provider abstracts blockchain access for UTXO lookup and broadcast.
type Provider interface {
	// GetTransaction fetches a transaction by its txid.
	GetTransaction(txid string) (*TransactionData, error)

	// Broadcast sends a transaction to the network. Returns the txid.
	Broadcast(tx *transaction.Transaction) (string, error)

	// GetUtxos returns all UTXOs for a given address.
	GetUtxos(address string) ([]UTXO, error)

	// GetContractUtxo finds a UTXO by its script hash (for stateful contract lookup).
	// Returns nil if no UTXO is found with the given script hash.
	GetContractUtxo(scriptHash string) (*UTXO, error)

	// GetNetwork returns the network this provider is connected to.
	GetNetwork() string

	// GetFeeRate returns the current fee rate in satoshis per KB (1000 bytes).
	// BSV standard is 100 sat/KB (0.1 sat/byte).
	GetFeeRate() (int64, error)

	// GetRawTransaction fetches the raw transaction hex by its txid.
	GetRawTransaction(txid string) (string, error)
}

// ---------------------------------------------------------------------------
// MockProvider — in-memory provider for testing
// ---------------------------------------------------------------------------

// knownOutpoint is the script + value of an outpoint this MockProvider has
// been told about (or has itself produced via a prior Broadcast). Broadcast
// validation can only execute inputs whose outpoint appears here.
type knownOutpoint struct {
	Script   string
	Satoshis int64
}

// MockProvider is an in-memory provider for unit tests and local development.
// It stores transactions and UTXOs that can be injected via helper methods,
// and records all broadcasts for assertion in tests.
//
// Broadcast validation is DEFAULT-ON (testing-gap remediation Phase A5). See
// ValidateBroadcast / README "How fund-path tests fail closed in the Go tier".
type MockProvider struct {
	transactions    map[string]*TransactionData
	rawTransactions map[string]string
	utxos           map[string][]UTXO
	contractUtxos   map[string]*UTXO
	broadcastedTxs  []string
	network         string
	broadcastCount  int
	feeRate         int64

	// validateBroadcasts gates the fail-closed check in Broadcast. Default
	// true; the opt-out is governed by always_ack_allowlist.json (see
	// always_ack_allowlist_test.go).
	validateBroadcasts bool
	// knownOutpoints maps "txid:vout" -> script+value for every outpoint the
	// provider knows about, whether injected (AddTransaction / AddUtxo /
	// AddContractUtxo) or created by an earlier Broadcast.
	knownOutpoints map[string]knownOutpoint
	// lastValidatedInputs / lastTotalInputs record the non-vacuity witness of
	// the most recent validating Broadcast.
	lastValidatedInputs int
	lastTotalInputs     int
	// spentOutpoints maps "txid:vout" -> the real txid of the accepted
	// broadcast that spent it. Checked on EVERY Broadcast, whatever
	// validateBroadcasts says: a node refuses a second transaction spending
	// an outpoint already spent.
	spentOutpoints map[string]string
	// acceptedTxids maps the real txid of every accepted Broadcast to the
	// txid this provider returned for it: re-broadcasting the identical tx is
	// idempotent, as on a node.
	acceptedTxids map[string]string
}

// NewMockProvider creates a new MockProvider for the given network.
// Broadcast validation is ON — see Broadcast.
func NewMockProvider(network string) *MockProvider {
	if network == "" {
		network = "testnet"
	}
	return &MockProvider{
		transactions:       make(map[string]*TransactionData),
		rawTransactions:    make(map[string]string),
		utxos:              make(map[string][]UTXO),
		contractUtxos:      make(map[string]*UTXO),
		knownOutpoints:     make(map[string]knownOutpoint),
		spentOutpoints:     make(map[string]string),
		acceptedTxids:      make(map[string]string),
		network:            network,
		feeRate:            100,
		validateBroadcasts: true,
	}
}

// NewAlwaysAckMockProvider creates a MockProvider whose Broadcast never
// validates the transaction it is handed — the pre-Phase-A5 behaviour.
//
// FOR ALLOWLISTED TESTS ONLY: every _test.go file that calls this (or the
// other opt-outs) must carry a matching entry in always_ack_allowlist.json,
// which always_ack_allowlist_test.go enforces. Fund-path deploy/call tests
// must not use it.
func NewAlwaysAckMockProvider(network string) *MockProvider {
	m := NewMockProvider(network)
	m.validateBroadcasts = false
	return m
}

// EnableBroadcastValidation turns the fail-closed Broadcast check on or off.
// Default is on; passing false is an allowlisted opt-out (see
// NewAlwaysAckMockProvider).
func (m *MockProvider) EnableBroadcastValidation(enabled bool) {
	m.validateBroadcasts = enabled
}

// DisableBroadcastValidation restores the legacy always-ack Broadcast.
// Allowlisted opt-out — see NewAlwaysAckMockProvider.
func (m *MockProvider) DisableBroadcastValidation() {
	m.validateBroadcasts = false
}

// LastValidatedInputCount reports how many inputs the most recent validating
// Broadcast actually executed through the script interpreter. Exposed so a
// test can assert its gate is NOT vacuous.
func (m *MockProvider) LastValidatedInputCount() int { return m.lastValidatedInputs }

// LastBroadcastInputCount reports how many inputs the most recent validating
// Broadcast saw in total (validated + unknown-outpoint).
func (m *MockProvider) LastBroadcastInputCount() int { return m.lastTotalInputs }

// rememberOutpoint records an outpoint's script + value for broadcast validation.
func (m *MockProvider) rememberOutpoint(txid string, vout int, scriptHex string, satoshis int64) {
	if scriptHex == "" {
		return
	}
	m.knownOutpoints[fmt.Sprintf("%s:%d", txid, vout)] = knownOutpoint{Script: scriptHex, Satoshis: satoshis}
}

// AddTransaction injects a transaction into the mock store.
func (m *MockProvider) AddTransaction(tx *TransactionData) {
	m.transactions[tx.Txid] = tx
	if tx.Raw != "" {
		m.rawTransactions[tx.Txid] = tx.Raw
	}
	for i, out := range tx.Outputs {
		m.rememberOutpoint(tx.Txid, i, out.Script, out.Satoshis)
	}
}

// AddUtxo injects a UTXO for the given address.
func (m *MockProvider) AddUtxo(address string, utxo UTXO) {
	m.utxos[address] = append(m.utxos[address], utxo)
	m.rememberOutpoint(utxo.Txid, utxo.OutputIndex, utxo.Script, utxo.Satoshis)
}

// AddContractUtxo injects a contract UTXO for lookup by script hash.
func (m *MockProvider) AddContractUtxo(scriptHash string, utxo *UTXO) {
	m.contractUtxos[scriptHash] = utxo
	if utxo != nil {
		m.rememberOutpoint(utxo.Txid, utxo.OutputIndex, utxo.Script, utxo.Satoshis)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed broadcast validation (testing-gap remediation Phase A5)
// ---------------------------------------------------------------------------

// validateBroadcastTx replays every input whose outpoint the provider knows
// through the go-sdk script interpreter with FULL transaction context (so
// OP_CHECKSIG / OP_PUSH_TX bind to the real spending sighash), then checks
// value conservation when every input is known.
//
// Returns the number of inputs actually executed. A caller MUST treat a zero
// count as a failure: a gate that validates nothing passes vacuously, which
// is exactly the fail-open hole this phase exists to close.
func validateBroadcastTx(tx *transaction.Transaction, known map[string]knownOutpoint) (int, error) {
	validated := 0
	allInputsKnown := true
	var totalKnownIn int64

	for i, in := range tx.Inputs {
		if in.SourceTXID == nil {
			allInputsKnown = false
			continue
		}
		key := fmt.Sprintf("%s:%d", in.SourceTXID.String(), in.SourceTxOutIndex)
		ko, ok := known[key]
		if !ok {
			allInputsKnown = false
			continue
		}
		totalKnownIn += ko.Satoshis

		lockingScript, err := bsvscript.NewFromHex(ko.Script)
		if err != nil {
			return validated, fmt.Errorf("input %d: known outpoint %s has invalid script hex: %w", i, key, err)
		}
		prevOut := &transaction.TransactionOutput{
			Satoshis:      uint64(ko.Satoshis),
			LockingScript: lockingScript,
		}
		if execErr := interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, i, prevOut),
			interpreter.WithAfterGenesis(),
			interpreter.WithAfterChronicle(),
			interpreter.WithForkID(),
		); execErr != nil {
			return validated, fmt.Errorf("input %d: script REJECTED by the go-sdk interpreter: %w", i, execErr)
		}
		validated++
	}

	if allInputsKnown {
		var totalOut int64
		for _, out := range tx.Outputs {
			totalOut += int64(out.Satoshis)
		}
		if totalOut > totalKnownIn {
			return validated, fmt.Errorf(
				"underfunded: outputs (%d sats) exceed known inputs (%d sats)", totalOut, totalKnownIn)
		}
	}

	return validated, nil
}

// GetBroadcastedTxs returns all raw tx hexes that were broadcast.
func (m *MockProvider) GetBroadcastedTxs() []string {
	return m.broadcastedTxs
}

// GetTransaction fetches a transaction from the mock store.
func (m *MockProvider) GetTransaction(txid string) (*TransactionData, error) {
	tx, ok := m.transactions[txid]
	if !ok {
		return nil, fmt.Errorf("MockProvider: transaction %s not found", txid)
	}
	return tx, nil
}

// Broadcast validates the transaction (unless validation has been opted out
// of) and then records it, returning a deterministic fake txid.
//
// Fail-closed by default (testing-gap remediation Phase A5): every input whose
// outpoint the provider knows is executed by the go-sdk script interpreter with
// full transaction context, outputs may not exceed known inputs, and a
// transaction none of whose inputs could be executed is REJECTED rather than
// waved through — a gate that validates nothing is worse than no gate.
func (m *MockProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	if m.validateBroadcasts {
		validated, err := validateBroadcastTx(tx, m.knownOutpoints)
		m.lastValidatedInputs = validated
		m.lastTotalInputs = len(tx.Inputs)
		if err != nil {
			return "", fmt.Errorf("MockProvider: refusing to broadcast invalid transaction: %w", err)
		}
		if validated == 0 {
			return "", fmt.Errorf(
				"MockProvider: refusing to broadcast — validated 0 of %d inputs (no input's "+
					"outpoint is known to this provider, so validation would pass vacuously). "+
					"Seed the spent outpoints via AddUtxo/AddContractUtxo/AddTransaction, or use "+
					"NewAlwaysAckMockProvider (allowlisted) if this test genuinely needs always-ack",
				len(tx.Inputs))
		}
	}

	// Double-spend gate, independent of validateBroadcasts. Re-broadcasting the
	// identical tx is not a conflict (a node treats it as already known).
	spendingTxid := tx.TxID().String()
	prior, rebroadcast := m.acceptedTxids[spendingTxid]
	inputOutpoints := make([]string, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil {
			// Names no outpoint, so there is nothing to check here; validation
			// (when on) counts it as unknown.
			continue
		}
		key := fmt.Sprintf("%s:%d", in.SourceTXID.String(), in.SourceTxOutIndex)
		for _, seen := range inputOutpoints {
			if seen == key {
				return "", fmt.Errorf("MockProvider: refusing to broadcast a transaction that spends %s more than once", key)
			}
		}
		inputOutpoints = append(inputOutpoints, key)
		if spender, ok := m.spentOutpoints[key]; ok && !rebroadcast {
			return "", fmt.Errorf("MockProvider: refusing to broadcast a double spend: %s is already spent by %s", key, spender)
		}
	}

	// Re-broadcasting a tx already accepted is idempotent, as on a node: same
	// txid, nothing registered twice. It is still validated above, so a tx an
	// always-ack provider acked is not waved through once validation is on.
	if rebroadcast {
		return prior, nil
	}

	// Accepted: its inputs are now spent.
	for _, key := range inputOutpoints {
		m.spentOutpoints[key] = spendingTxid
	}

	rawTx := tx.Hex()
	m.broadcastedTxs = append(m.broadcastedTxs, rawTx)
	m.broadcastCount++
	prefix := rawTx
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	fakeTxid := mockHash64(fmt.Sprintf("mock-broadcast-%d-%s", m.broadcastCount, prefix))

	// Auto-store raw hex for subsequent GetRawTransaction lookups, and register
	// the transaction itself so GetTransaction resolves the txid this call just
	// returned (previously only the raw hex was stored, so every post-broadcast
	// GetTransaction reported "not found"). An already-injected TransactionData
	// under the same txid still wins, as before.
	if _, ok := m.transactions[fakeTxid]; !ok {
		m.rawTransactions[fakeTxid] = rawTx
		m.transactions[fakeTxid] = broadcastTxData(fakeTxid, tx, rawTx)
	}

	// Register this tx's own outputs as known outpoints so a chained call
	// (spending the continuation this broadcast just created) can be validated
	// too.
	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		m.rememberOutpoint(fakeTxid, i, out.LockingScript.String(), int64(out.Satoshis))
	}
	m.acceptedTxids[spendingTxid] = fakeTxid

	// A P2PKH output paying an address this provider lists (e.g. the change
	// of a deploy) is a new UTXO of that address, as a node's listing would
	// show it, so a later call can be funded from it.
	for address := range m.utxos {
		p2pkh := p2pkhScriptOrEmpty(address)
		if p2pkh == "" {
			continue
		}
		for i, out := range tx.Outputs {
			if out.LockingScript != nil && strings.EqualFold(out.LockingScript.String(), p2pkh) {
				m.utxos[address] = append(m.utxos[address], UTXO{
					Txid: fakeTxid, OutputIndex: i, Satoshis: int64(out.Satoshis), Script: out.LockingScript.String(),
				})
			}
		}
	}

	return fakeTxid, nil
}

// p2pkhScriptOrEmpty is BuildP2PKHScript for an address label that may not be
// a real address (a test label): "" instead of a panic.
func p2pkhScriptOrEmpty(address string) (script string) {
	defer func() {
		if recover() != nil {
			script = ""
		}
	}()
	return BuildP2PKHScript(address)
}

// broadcastTxData converts a just-broadcast transaction into the
// TransactionData shape GetTransaction serves, keyed by the provider's fake
// txid.
func broadcastTxData(txid string, tx *transaction.Transaction, rawTx string) *TransactionData {
	inputs := make([]TxInput, len(tx.Inputs))
	for i, in := range tx.Inputs {
		var sourceTxid, scriptHex string
		if in.SourceTXID != nil {
			sourceTxid = in.SourceTXID.String()
		}
		if in.UnlockingScript != nil {
			scriptHex = in.UnlockingScript.String()
		}
		inputs[i] = TxInput{
			Txid:        sourceTxid,
			OutputIndex: int(in.SourceTxOutIndex),
			Script:      scriptHex,
			Sequence:    in.SequenceNumber,
		}
	}

	outputs := make([]TxOutput, len(tx.Outputs))
	for i, out := range tx.Outputs {
		var scriptHex string
		if out.LockingScript != nil {
			scriptHex = out.LockingScript.String()
		}
		outputs[i] = TxOutput{
			Satoshis: int64(out.Satoshis),
			Script:   scriptHex,
		}
	}

	return &TransactionData{
		Txid:     txid,
		Version:  int(tx.Version),
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: int(tx.LockTime),
		Raw:      rawTx,
	}
}

// GetUtxos returns UTXOs for the given address from the mock store.
// DoS-bound: rejects pathological UTXO scripts BEFORE they enter the SDK.
func (m *MockProvider) GetUtxos(address string) ([]UTXO, error) {
	// An outpoint an accepted Broadcast spent is no longer a UTXO (a node's
	// listing would not return it either).
	utxos := make([]UTXO, 0, len(m.utxos[address]))
	for _, u := range m.utxos[address] {
		if _, spent := m.spentOutpoints[fmt.Sprintf("%s:%d", u.Txid, u.OutputIndex)]; !spent {
			utxos = append(utxos, u)
		}
	}
	for _, u := range utxos {
		if u.Script == "" {
			continue
		}
		if err := assertScriptHexUnderLimit(
			u.Script, MaxScriptBytes,
			fmt.Sprintf("MockProvider.GetUtxos(%s)", address),
		); err != nil {
			return nil, err
		}
	}
	return utxos, nil
}

// GetContractUtxo returns a UTXO by script hash from the mock store.
// DoS-bound: rejects pathological UTXO scripts BEFORE they enter the SDK.
func (m *MockProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	utxo, ok := m.contractUtxos[scriptHash]
	if !ok {
		return nil, nil
	}
	if utxo != nil && utxo.Script != "" {
		if err := assertScriptHexUnderLimit(
			utxo.Script, MaxScriptBytes,
			fmt.Sprintf("MockProvider.GetContractUtxo(%s)", scriptHash),
		); err != nil {
			return nil, err
		}
	}
	return utxo, nil
}

// GetNetwork returns the mock network name.
func (m *MockProvider) GetNetwork() string {
	return m.network
}

// GetRawTransaction returns the raw hex of a stored transaction.
func (m *MockProvider) GetRawTransaction(txid string) (string, error) {
	// Check raw transactions first (populated by broadcast)
	if raw, ok := m.rawTransactions[txid]; ok {
		return raw, nil
	}
	tx, ok := m.transactions[txid]
	if !ok {
		return "", fmt.Errorf("MockProvider: transaction %s not found", txid)
	}
	if tx.Raw == "" {
		return "", fmt.Errorf("MockProvider: transaction %s has no raw hex", txid)
	}
	return tx.Raw, nil
}

// GetFeeRate returns the configured fee rate (default 100 sat/KB).
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

