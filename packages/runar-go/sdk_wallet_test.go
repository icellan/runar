package runar

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------------
// MockWalletClient — in-memory WalletClient for testing
// ---------------------------------------------------------------------------

type MockWalletClient struct {
	pubKey          string // compressed pubkey hex (66 chars)
	createdActions  []mockCreatedAction
	listedOutputs   []WalletOutput
	signatureResult []byte // DER bytes returned by CreateSignature
	createActionErr error
}

type mockCreatedAction struct {
	description string
	outputs     []WalletActionOutput
}

func newMockWalletClient(pubKeyHex string) *MockWalletClient {
	if pubKeyHex == "" {
		pubKeyHex = "02" + strings.Repeat("ab", 32)
	}
	return &MockWalletClient{
		pubKey:          pubKeyHex,
		signatureResult: makeMockDERSig(),
	}
}

// makeMockDERSig returns a plausible DER-encoded ECDSA signature (70 bytes).
// 0x30 <len> 0x02 <rLen> <R...> 0x02 <sLen> <S...>
func makeMockDERSig() []byte {
	// Minimal valid DER: 30 44 02 20 <32 R bytes> 02 20 <32 S bytes>
	sig := make([]byte, 70)
	sig[0] = 0x30 // SEQUENCE
	sig[1] = 0x44 // length of remaining (68)
	sig[2] = 0x02 // INTEGER
	sig[3] = 0x20 // R length (32)
	// R bytes: 4..35 (zeroes)
	sig[36] = 0x02 // INTEGER
	sig[37] = 0x20 // S length (32)
	// S bytes: 38..69 (zeroes)
	return sig
}

func (m *MockWalletClient) GetPublicKey(protocolID [2]interface{}, keyID string) (string, error) {
	return m.pubKey, nil
}

func (m *MockWalletClient) CreateSignature(hashToDirectlySign []byte, protocolID [2]interface{}, keyID string) ([]byte, error) {
	return m.signatureResult, nil
}

func (m *MockWalletClient) CreateAction(description string, outputs []WalletActionOutput) (*WalletActionResult, error) {
	if m.createActionErr != nil {
		return nil, m.createActionErr
	}
	m.createdActions = append(m.createdActions, mockCreatedAction{description, outputs})
	// Return a deterministic mock txid.
	txid := mockHash64(fmt.Sprintf("wallet-action-%d", len(m.createdActions)))
	return &WalletActionResult{
		Txid:  txid,
		RawTx: "0100000000000000000000", // minimal mock raw tx
	}, nil
}

func (m *MockWalletClient) ListOutputs(basket string, tags []string, limit int) ([]WalletOutput, error) {
	return m.listedOutputs, nil
}

// ---------------------------------------------------------------------------
// WalletProvider interface compliance
// ---------------------------------------------------------------------------

func TestWalletProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*WalletProvider)(nil)
}

func TestWalletSigner_ImplementsSigner(t *testing.T) {
	var _ Signer = (*WalletSigner)(nil)
}

// ---------------------------------------------------------------------------
// WalletProvider tests
// ---------------------------------------------------------------------------

func TestWalletProvider_GetNetwork(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet:  newMockWalletClient(""),
		Network: "testnet",
	})
	if wp.GetNetwork() != "testnet" {
		t.Errorf("expected testnet, got %s", wp.GetNetwork())
	}
}

func TestWalletProvider_GetNetwork_Default(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	if wp.GetNetwork() != "mainnet" {
		t.Errorf("expected mainnet, got %s", wp.GetNetwork())
	}
}

func TestWalletProvider_GetFeeRate(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet:  newMockWalletClient(""),
		FeeRate: 200,
	})
	rate, err := wp.GetFeeRate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rate != 200 {
		t.Errorf("expected 200, got %d", rate)
	}
}

func TestWalletProvider_GetFeeRate_Default(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	rate, err := wp.GetFeeRate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rate != 100 {
		t.Errorf("expected 100, got %d", rate)
	}
}

func TestWalletProvider_GetContractUtxo_ReturnsNil(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	utxo, err := wp.GetContractUtxo("deadbeef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if utxo != nil {
		t.Error("expected nil UTXO")
	}
}

func TestWalletProvider_GetRawTransaction_Cached(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	txid := strings.Repeat("ab", 32)
	rawHex := "0100000001" + strings.Repeat("00", 100)

	wp.mu.Lock()
	wp.txCache[txid] = rawHex
	wp.mu.Unlock()

	result, err := wp.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != rawHex {
		t.Error("expected cached raw hex")
	}
}

func TestWalletProvider_GetRawTransaction_NotFound(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	_, err := wp.GetRawTransaction(strings.Repeat("ab", 32))
	if err == nil {
		t.Error("expected error for missing transaction")
	}
}

func TestWalletProvider_GetUtxos_FiltersSpendable(t *testing.T) {
	mockWallet := newMockWalletClient("")

	pubKeyBytes, _ := hex.DecodeString(mockWallet.pubKey)
	expectedScript := "76a914" + walletHash160Hex(pubKeyBytes) + "88ac"

	mockWallet.listedOutputs = []WalletOutput{
		{
			Satoshis:      10000,
			LockingScript: expectedScript,
			Spendable:     true,
			Outpoint:      strings.Repeat("aa", 32) + ".0",
		},
		{
			Satoshis:      5000,
			LockingScript: expectedScript,
			Spendable:     false, // not spendable — should be filtered
			Outpoint:      strings.Repeat("bb", 32) + ".1",
		},
		{
			Satoshis:      3000,
			LockingScript: "76a914" + strings.Repeat("ff", 20) + "88ac", // different address
			Spendable:     true,
			Outpoint:      strings.Repeat("cc", 32) + ".0",
		},
	}

	signer := NewMockSigner(mockWallet.pubKey, "")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		Signer: signer,
	})

	utxos, err := wp.GetUtxos("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the first output should pass (spendable + matching script).
	if len(utxos) != 1 {
		t.Fatalf("expected 1 UTXO, got %d", len(utxos))
	}
	if utxos[0].Satoshis != 10000 {
		t.Errorf("expected 10000 satoshis, got %d", utxos[0].Satoshis)
	}
}

func TestWalletProvider_GetUtxos_NoSigner(t *testing.T) {
	mockWallet := newMockWalletClient("")
	mockWallet.listedOutputs = []WalletOutput{
		{
			Satoshis:      10000,
			LockingScript: "76a914" + strings.Repeat("00", 20) + "88ac",
			Spendable:     true,
			Outpoint:      strings.Repeat("aa", 32) + ".0",
		},
		{
			Satoshis:      5000,
			LockingScript: "76a914" + strings.Repeat("ff", 20) + "88ac",
			Spendable:     true,
			Outpoint:      strings.Repeat("bb", 32) + ".1",
		},
	}

	// No signer — all spendable outputs should be returned.
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
	})

	utxos, err := wp.GetUtxos("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("expected 2 UTXOs, got %d", len(utxos))
	}
}

func TestWalletProvider_EnsureFunding_AlreadyFunded(t *testing.T) {
	mockWallet := newMockWalletClient("")
	pubKeyBytes, _ := hex.DecodeString(mockWallet.pubKey)
	pubKeyHash := walletHash160Hex(pubKeyBytes)
	expectedScript := "76a914" + pubKeyHash + "88ac"

	mockWallet.listedOutputs = []WalletOutput{
		{
			Satoshis:      50000,
			LockingScript: expectedScript,
			Spendable:     true,
			Outpoint:      strings.Repeat("aa", 32) + ".0",
		},
	}

	// Use the 40-char hex pubkey hash as address (accepted by BuildP2PKHScript).
	signer := NewMockSigner(mockWallet.pubKey, pubKeyHash)
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		Signer: signer,
	})

	err := wp.EnsureFunding(10000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No action should have been created.
	if len(mockWallet.createdActions) != 0 {
		t.Errorf("expected no actions, got %d", len(mockWallet.createdActions))
	}
}

func TestWalletProvider_EnsureFunding_CreatesFunding(t *testing.T) {
	mockWallet := newMockWalletClient("")
	mockWallet.listedOutputs = []WalletOutput{} // empty — no existing funds

	pubKeyBytes, _ := hex.DecodeString(mockWallet.pubKey)
	pubKeyHash := walletHash160Hex(pubKeyBytes)
	// Use the 40-char hex pubkey hash as address (accepted by BuildP2PKHScript).
	signer := NewMockSigner(mockWallet.pubKey, pubKeyHash)
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		Signer: signer,
	})

	err := wp.EnsureFunding(10000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mockWallet.createdActions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(mockWallet.createdActions))
	}
	action := mockWallet.createdActions[0]
	if len(action.outputs) != 1 {
		t.Fatalf("expected 1 output in action, got %d", len(action.outputs))
	}
	if action.outputs[0].Satoshis != 10000 {
		t.Errorf("expected 10000 satoshis, got %d", action.outputs[0].Satoshis)
	}
}

func TestWalletProvider_EnsureFunding_NoSigner(t *testing.T) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		// No signer.
	})

	err := wp.EnsureFunding(10000)
	if err == nil {
		t.Error("expected error when no signer is configured")
	}
}

// ---------------------------------------------------------------------------
// WalletSigner tests
// ---------------------------------------------------------------------------

func TestWalletSigner_GetPublicKey(t *testing.T) {
	mockWallet := newMockWalletClient("02" + strings.Repeat("cd", 32))
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     mockWallet,
	})

	pubKey, err := ws.GetPublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "02" + strings.Repeat("cd", 32)
	if pubKey != expected {
		t.Errorf("expected %s, got %s", expected, pubKey)
	}

	// Second call should return cached result.
	pubKey2, err := ws.GetPublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pubKey2 != expected {
		t.Errorf("cached call: expected %s, got %s", expected, pubKey2)
	}
}

func TestWalletSigner_GetAddress(t *testing.T) {
	mockWallet := newMockWalletClient("02" + strings.Repeat("cd", 32))
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     mockWallet,
	})

	address, err := ws.GetAddress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Address should be non-empty and start with 1 (mainnet P2PKH).
	if address == "" {
		t.Error("expected non-empty address")
	}
	if address[0] != '1' {
		t.Errorf("expected mainnet address starting with '1', got %q", address)
	}
}

func TestWalletSigner_Sign(t *testing.T) {
	mockWallet := newMockWalletClient("02" + strings.Repeat("cd", 32))
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     mockWallet,
	})

	// Build a minimal valid transaction for signing.
	// version(4) + varint(1 input) + prevtx(32) + index(4) + scriptLen(1=0) + sequence(4)
	// + varint(1 output) + value(8) + scriptLen(1) + lockscript(25=P2PKH) + locktime(4)
	txHex := "01000000" + // version
		"01" + // 1 input
		strings.Repeat("aa", 32) + // prev txid
		"00000000" + // prev index
		"00" + // empty scriptSig
		"ffffffff" + // sequence
		"01" + // 1 output
		"e803000000000000" + // 1000 satoshis LE
		"19" + // script length 25
		"76a914" + strings.Repeat("00", 20) + "88ac" + // P2PKH script
		"00000000" // locktime

	subscript := "76a914" + strings.Repeat("00", 20) + "88ac"
	sigHex, err := ws.Sign(txHex, 0, subscript, 2000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The result should be the mock DER sig (70 bytes) + sighash byte (0x41) = 71 bytes = 142 hex chars.
	if len(sigHex) != 142 {
		t.Errorf("expected 142 hex chars, got %d", len(sigHex))
	}

	// Last byte should be 0x41 (ALL|FORKID).
	if !strings.HasSuffix(sigHex, "41") {
		t.Errorf("expected sighash byte 41 at end, got suffix %s", sigHex[len(sigHex)-2:])
	}
}

func TestWalletSigner_Sign_InvalidTx(t *testing.T) {
	mockWallet := newMockWalletClient("")
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     mockWallet,
	})

	_, err := ws.Sign("not-valid-hex", 0, "76a91400", 1000, nil)
	if err == nil {
		t.Error("expected error for invalid tx hex")
	}
}

func TestWalletSigner_Sign_IndexOutOfRange(t *testing.T) {
	mockWallet := newMockWalletClient("")
	ws := NewWalletSigner(WalletSignerOptions{
		ProtocolID: [2]interface{}{2, "test"},
		KeyID:      "1",
		Wallet:     mockWallet,
	})

	txHex := "01000000" +
		"01" +
		strings.Repeat("aa", 32) +
		"00000000" +
		"00" +
		"ffffffff" +
		"01" +
		"e803000000000000" +
		"19" +
		"76a914" + strings.Repeat("00", 20) + "88ac" +
		"00000000"

	_, err := ws.Sign(txHex, 5, "76a91400", 1000, nil)
	if err == nil {
		t.Error("expected error for out-of-range input index")
	}
}

// ---------------------------------------------------------------------------
// DeployWithWallet tests
// ---------------------------------------------------------------------------

func TestDeployWithWallet_Success(t *testing.T) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		Basket: "tokens",
	})

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)

	result, err := contract.DeployWithWallet(&DeployWithWalletOptions{
		Satoshis:    1000,
		Description: "deploy test contract",
		Basket:      "tokens",
		Tags:        []string{"test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Txid == "" {
		t.Error("expected non-empty txid")
	}
	if result.RawTx == "" {
		t.Error("expected non-empty raw tx")
	}

	// Verify the wallet action was created with correct parameters.
	if len(mockWallet.createdActions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(mockWallet.createdActions))
	}
	action := mockWallet.createdActions[0]
	if action.description != "deploy test contract" {
		t.Errorf("expected description 'deploy test contract', got %q", action.description)
	}
	if len(action.outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(action.outputs))
	}
	if action.outputs[0].Satoshis != 1000 {
		t.Errorf("expected 1000 satoshis, got %d", action.outputs[0].Satoshis)
	}
	if action.outputs[0].LockingScript != "51" {
		t.Errorf("expected locking script '51', got %q", action.outputs[0].LockingScript)
	}

	// Verify the UTXO is tracked on the contract.
	utxo := contract.currentUtxo
	if utxo == nil {
		t.Fatal("expected currentUtxo to be set")
	}
	if utxo.Txid != result.Txid {
		t.Errorf("expected utxo txid %s, got %s", result.Txid, utxo.Txid)
	}
	if utxo.Satoshis != 1000 {
		t.Errorf("expected utxo satoshis 1000, got %d", utxo.Satoshis)
	}
}

func TestDeployWithWallet_DefaultSatoshis(t *testing.T) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
	})

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)

	result, err := contract.DeployWithWallet(&DeployWithWalletOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Txid == "" {
		t.Error("expected non-empty txid")
	}
	// Should default to 1 satoshi.
	action := mockWallet.createdActions[0]
	if action.outputs[0].Satoshis != 1 {
		t.Errorf("expected default 1 satoshi, got %d", action.outputs[0].Satoshis)
	}
}

func TestDeployWithWallet_WrongProviderType(t *testing.T) {
	mockProvider := NewMockProvider("testnet")
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(mockProvider, nil)

	_, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	if err == nil {
		t.Error("expected error when provider is not WalletProvider")
	}
	if !strings.Contains(err.Error(), "WalletProvider") {
		t.Errorf("error should mention WalletProvider, got: %v", err)
	}
}

func TestDeployWithWallet_CreateActionError(t *testing.T) {
	mockWallet := newMockWalletClient("")
	mockWallet.createActionErr = fmt.Errorf("wallet unavailable")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
	})

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)

	_, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	if err == nil {
		t.Error("expected error when CreateAction fails")
	}
}

func TestDeployWithWallet_CachesRawTx(t *testing.T) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
	})

	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)

	result, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The raw tx should be cached in the provider.
	wp.mu.Lock()
	cached, ok := wp.txCache[result.Txid]
	wp.mu.Unlock()
	if !ok {
		t.Error("expected raw tx to be cached")
	}
	if cached != result.RawTx {
		t.Error("cached raw tx does not match result")
	}
}

// ---------------------------------------------------------------------------
// parseOutpoint tests
// ---------------------------------------------------------------------------

func TestParseOutpoint(t *testing.T) {
	txid, vout := parseOutpoint(strings.Repeat("ab", 32) + ".3")
	if txid != strings.Repeat("ab", 32) {
		t.Errorf("expected txid %s, got %s", strings.Repeat("ab", 32), txid)
	}
	if vout != 3 {
		t.Errorf("expected vout 3, got %d", vout)
	}
}

func TestParseOutpoint_NoDot(t *testing.T) {
	txid, vout := parseOutpoint("nodothere")
	if txid != "nodothere" {
		t.Errorf("expected 'nodothere', got %s", txid)
	}
	if vout != 0 {
		t.Errorf("expected vout 0, got %d", vout)
	}
}

// ---------------------------------------------------------------------------
// WalletProvider defaults
// ---------------------------------------------------------------------------

func TestWalletProvider_Defaults(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: newMockWalletClient(""),
	})
	if wp.fundingTag != "funding" {
		t.Errorf("expected default fundingTag 'funding', got %q", wp.fundingTag)
	}
	if wp.arcUrl != "https://arc.gorillapool.io" {
		t.Errorf("expected default arcUrl, got %q", wp.arcUrl)
	}
	if wp.feeRate != 100 {
		t.Errorf("expected default feeRate 100, got %f", wp.feeRate)
	}
}

// R-179 (CL-BUG-072): ArcUrl and Network were defaulted independently, so a
// provider configured for testnet reported GetNetwork() == "testnet" and
// broadcast every transaction to the MAINNET ARC, with nothing to say so.
//
// NewWalletProvider cannot return an error without breaking its signature, so
// a non-mainnet provider that named no endpoint is left with an empty arcUrl
// and Broadcast refuses — the tier refuses as early as its constructor allows.
func TestR179_TestnetWithoutArcURLRefusesToBroadcast(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet:  newMockWalletClient(""),
		Network: "testnet",
	})
	if wp.arcUrl != "" {
		t.Fatalf("a testnet provider must not inherit the mainnet ARC endpoint, got %q", wp.arcUrl)
	}

	_, err := wp.Broadcast(transaction.NewTransaction())
	if err == nil {
		t.Fatal("Broadcast must refuse when no ARC endpoint matches the network")
	}
	if !strings.Contains(err.Error(), "testnet") ||
		!strings.Contains(err.Error(), "arc.gorillapool.io") {
		t.Errorf("the refusal must name the network and the mainnet endpoint it declined to use; got: %v", err)
	}
}

func TestR179_TestnetWithAnExplicitArcURLIsAccepted(t *testing.T) {
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet:  newMockWalletClient(""),
		Network: "testnet",
		ArcUrl:  "https://arc.testnet.example",
	})
	if wp.arcUrl != "https://arc.testnet.example" {
		t.Errorf("explicit ArcUrl was not honoured, got %q", wp.arcUrl)
	}
	if wp.GetNetwork() != "testnet" {
		t.Errorf("expected testnet, got %q", wp.GetNetwork())
	}
}

func TestR179_MainnetDefaultIsUnchanged(t *testing.T) {
	for _, network := range []string{"", "mainnet"} {
		wp := NewWalletProvider(WalletProviderOptions{
			Wallet:  newMockWalletClient(""),
			Network: network,
		})
		if wp.GetNetwork() != "mainnet" {
			t.Errorf("network %q: expected mainnet, got %q", network, wp.GetNetwork())
		}
		if wp.arcUrl != "https://arc.gorillapool.io" {
			t.Errorf("network %q: expected the mainnet ARC default, got %q", network, wp.arcUrl)
		}
	}
}
