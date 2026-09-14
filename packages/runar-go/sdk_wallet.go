package runar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// WalletClient — BRC-100 wallet abstraction
// ---------------------------------------------------------------------------

// WalletClient is an abstract interface for BRC-100 compatible wallets.
// Server-side applications provide their own implementation.
type WalletClient interface {
	// GetPublicKey returns the compressed public key hex for the given protocol/key pair.
	GetPublicKey(protocolID [2]interface{}, keyID string) (string, error)

	// CreateSignature signs a pre-hashed digest (32 bytes) using the wallet's key.
	// Returns DER-encoded ECDSA signature bytes.
	CreateSignature(hashToDirectlySign []byte, protocolID [2]interface{}, keyID string) ([]byte, error)

	// CreateAction creates a wallet action with the specified outputs.
	// Returns txid and raw transaction hex.
	CreateAction(description string, outputs []WalletActionOutput) (*WalletActionResult, error)

	// ListOutputs returns spendable outputs matching the given basket and tags.
	ListOutputs(basket string, tags []string, limit int) ([]WalletOutput, error)
}

// WalletActionOutput describes a single output for a wallet action.
type WalletActionOutput struct {
	LockingScript string
	Satoshis      int64
	Description   string
	Basket        string
	Tags          []string
}

// WalletActionResult is the result of creating a wallet action.
type WalletActionResult struct {
	Txid  string
	RawTx string // raw hex
}

// WalletOutput describes a spendable output from a wallet.
type WalletOutput struct {
	Satoshis      int64
	LockingScript string
	Spendable     bool
	Outpoint      string // "txid.voutIndex"
}

// ---------------------------------------------------------------------------
// WalletProvider — Provider backed by a BRC-100 WalletClient
// ---------------------------------------------------------------------------

// WalletProviderOptions configures a WalletProvider.
type WalletProviderOptions struct {
	Wallet        WalletClient
	Signer        Signer
	Basket        string
	FundingTag    string // default "funding"
	ArcUrl        string // default "https://arc.gorillapool.io"
	OverlayUrl    string // optional
	OverlayTopics []string
	Network       string  // "mainnet" or "testnet"
	FeeRate       float64 // default 100
}

// WalletProvider implements the Provider interface using a BRC-100 WalletClient
// for UTXO management and funding, ARC for broadcast, and an optional overlay
// service for transaction lookups.
type WalletProvider struct {
	wallet        WalletClient
	signer        Signer
	basket        string
	fundingTag    string
	arcUrl        string
	overlayUrl    string
	overlayTopics []string
	network       string
	feeRate       float64
	txCache       map[string]string // txid → raw hex
	mu            sync.Mutex
	client        *http.Client
}

// mainnetArcURL is the default ARC broadcaster. It is a MAINNET endpoint —
// see R-179 for why that matters when Network is not "mainnet".
const mainnetArcURL = "https://arc.gorillapool.io"

// NewWalletProvider creates a new WalletProvider with the given options.
func NewWalletProvider(opts WalletProviderOptions) *WalletProvider {
	fundingTag := opts.FundingTag
	if fundingTag == "" {
		fundingTag = "funding"
	}
	network := opts.Network
	if network == "" {
		network = "mainnet"
	}
	// R-179: only mainnet has a default ARC endpoint, because the default IS a
	// mainnet endpoint. A non-mainnet provider that names none is left with an
	// empty arcUrl and refuses in Broadcast.
	arcUrl := opts.ArcUrl
	if arcUrl == "" && network == "mainnet" {
		arcUrl = mainnetArcURL
	}
	feeRate := opts.FeeRate
	if feeRate == 0 {
		feeRate = 100
	}
	return &WalletProvider{
		wallet:        opts.Wallet,
		signer:        opts.Signer,
		basket:        opts.Basket,
		fundingTag:    fundingTag,
		arcUrl:        arcUrl,
		overlayUrl:    opts.OverlayUrl,
		overlayTopics: opts.OverlayTopics,
		network:       network,
		feeRate:       feeRate,
		txCache:       make(map[string]string),
		client:        &http.Client{},
	}
}

// GetNetwork returns the network this provider is connected to.
func (p *WalletProvider) GetNetwork() string {
	return p.network
}

// GetFeeRate returns the configured fee rate in satoshis per KB.
func (p *WalletProvider) GetFeeRate() (int64, error) {
	return int64(p.feeRate), nil
}

// GetUtxos returns spendable P2PKH UTXOs from the wallet that match the
// signer's public key. The address parameter is used to filter outputs
// whose locking script corresponds to the signer's pubkey hash.
func (p *WalletProvider) GetUtxos(address string) ([]UTXO, error) {
	tags := []string{p.fundingTag}
	outputs, err := p.wallet.ListOutputs(p.basket, tags, 100)
	if err != nil {
		return nil, fmt.Errorf("WalletProvider.GetUtxos: listing outputs: %w", err)
	}

	// Derive the expected P2PKH script for the signer's public key.
	var expectedScript string
	if p.signer != nil {
		pubKeyHex, err := p.signer.GetPublicKey()
		if err == nil {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err == nil {
				expectedScript = "76a914" + walletHash160Hex(pubKeyBytes) + "88ac"
			}
		}
	}

	var utxos []UTXO
	for _, out := range outputs {
		if !out.Spendable {
			continue
		}
		// Filter by P2PKH match if we have a signer pubkey.
		if expectedScript != "" && out.LockingScript != "" && out.LockingScript != expectedScript {
			continue
		}
		txid, vout := parseOutpoint(out.Outpoint)
		utxos = append(utxos, UTXO{
			Txid:        txid,
			OutputIndex: vout,
			Satoshis:    out.Satoshis,
			Script:      out.LockingScript,
		})
	}
	return utxos, nil
}

// Broadcast sends a raw transaction to the ARC service.
// Posts the raw bytes to arcUrl/v1/tx with Content-Type application/octet-stream.
func (p *WalletProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	// R-179: ArcUrl and Network used to be defaulted independently, so a
	// provider configured for testnet reported GetNetwork() == "testnet" and
	// broadcast to the MAINNET ARC. There is no canonical testnet ARC endpoint
	// to default to, so a non-mainnet provider that named no endpoint is left
	// with an empty one and refuses here, rather than reaching real money.
	if p.arcUrl == "" {
		return "", fmt.Errorf(
			"WalletProvider.Broadcast: no ARC endpoint for network %q — %q is a MAINNET "+
				"broadcaster; set WalletProviderOptions.ArcUrl explicitly", p.network, mainnetArcURL)
	}
	rawHex := tx.Hex()
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("WalletProvider.Broadcast: decoding tx hex: %w", err)
	}

	url := strings.TrimRight(p.arcUrl, "/") + "/v1/tx"
	req, err := http.NewRequest("POST", url, bytes.NewReader(rawBytes))
	if err != nil {
		return "", fmt.Errorf("WalletProvider.Broadcast: creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("WalletProvider.Broadcast: sending request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("WalletProvider.Broadcast: ARC returned %d: %s", resp.StatusCode, string(body))
	}

	// Cache the raw tx for later lookups.
	txid := tx.TxID().String()
	p.mu.Lock()
	p.txCache[txid] = rawHex
	p.mu.Unlock()

	return txid, nil
}

// GetTransaction fetches transaction data. Checks local cache first, then
// attempts the overlay service if configured.
func (p *WalletProvider) GetTransaction(txid string) (*TransactionData, error) {
	rawHex, err := p.GetRawTransaction(txid)
	if err != nil {
		return nil, fmt.Errorf("WalletProvider.GetTransaction: %w", err)
	}

	// Parse raw hex into TransactionData using go-sdk.
	tx, err := transaction.NewTransactionFromHex(rawHex)
	if err != nil {
		return nil, fmt.Errorf("WalletProvider.GetTransaction: parsing tx: %w", err)
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
		Txid:     txid,
		Version:  int(tx.Version),
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: int(tx.LockTime),
		Raw:      rawHex,
	}, nil
}

// GetContractUtxo returns nil — wallet-based providers do not support
// contract UTXO lookup by script hash.
func (p *WalletProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	return nil, nil
}

// GetRawTransaction returns the raw hex of a transaction. Checks the local
// cache first, then the overlay service.
func (p *WalletProvider) GetRawTransaction(txid string) (string, error) {
	p.mu.Lock()
	cached, ok := p.txCache[txid]
	p.mu.Unlock()
	if ok {
		return cached, nil
	}

	// Try overlay service if configured.
	if p.overlayUrl != "" {
		url := strings.TrimRight(p.overlayUrl, "/") + "/api/tx/" + txid + "/hex"
		resp, err := p.client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err == nil {
					rawHex := strings.TrimSpace(string(body))
					p.mu.Lock()
					p.txCache[txid] = rawHex
					p.mu.Unlock()
					return rawHex, nil
				}
			}
		}
	}

	return "", fmt.Errorf("WalletProvider.GetRawTransaction: transaction %s not found", txid)
}

// EnsureFunding checks that the signer's address has at least minSatoshis
// available. If the balance is insufficient, it creates a funding UTXO
// via the wallet's CreateAction.
func (p *WalletProvider) EnsureFunding(minSatoshis int64) error {
	if p.signer == nil {
		return fmt.Errorf("WalletProvider.EnsureFunding: no signer configured")
	}

	address, err := p.signer.GetAddress()
	if err != nil {
		return fmt.Errorf("WalletProvider.EnsureFunding: getting address: %w", err)
	}

	utxos, err := p.GetUtxos(address)
	if err != nil {
		return fmt.Errorf("WalletProvider.EnsureFunding: listing UTXOs: %w", err)
	}

	var total int64
	for _, u := range utxos {
		total += u.Satoshis
	}

	if total >= minSatoshis {
		return nil // already funded
	}

	// Build a P2PKH locking script for the signer's address.
	lockingScript := BuildP2PKHScript(address)

	_, err = p.wallet.CreateAction("fund contract deployment", []WalletActionOutput{
		{
			LockingScript: lockingScript,
			Satoshis:      minSatoshis,
			Description:   "funding for contract deployment",
			Basket:        p.basket,
			Tags:          []string{p.fundingTag},
		},
	})
	if err != nil {
		return fmt.Errorf("WalletProvider.EnsureFunding: creating funding action: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// WalletSigner — Signer backed by a BRC-100 WalletClient
// ---------------------------------------------------------------------------

// WalletSignerOptions configures a WalletSigner.
type WalletSignerOptions struct {
	ProtocolID [2]interface{} // e.g., {2, "my app"}
	KeyID      string         // e.g., "1"
	Wallet     WalletClient
}

// WalletSigner implements the Signer interface by delegating key operations
// to a BRC-100 WalletClient.
type WalletSigner struct {
	protocolID   [2]interface{}
	keyID        string
	wallet       WalletClient
	cachedPubKey string
	mu           sync.Mutex
}

// NewWalletSigner creates a new WalletSigner with the given options.
func NewWalletSigner(opts WalletSignerOptions) *WalletSigner {
	return &WalletSigner{
		protocolID: opts.ProtocolID,
		keyID:      opts.KeyID,
		wallet:     opts.Wallet,
	}
}

// GetPublicKey returns the hex-encoded compressed public key from the wallet.
// The result is cached after the first call.
func (s *WalletSigner) GetPublicKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cachedPubKey != "" {
		return s.cachedPubKey, nil
	}

	pubKey, err := s.wallet.GetPublicKey(s.protocolID, s.keyID)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.GetPublicKey: %w", err)
	}
	s.cachedPubKey = pubKey
	return pubKey, nil
}

// GetAddress returns the BSV P2PKH address derived from the wallet's public key.
// Computes hash160 of the compressed public key and encodes as a Base58Check address.
func (s *WalletSigner) GetAddress() (string, error) {
	pubKeyHex, err := s.GetPublicKey()
	if err != nil {
		return "", fmt.Errorf("WalletSigner.GetAddress: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.GetAddress: invalid pubkey hex: %w", err)
	}

	// Use go-sdk's address derivation from raw public key bytes.
	pubKey, err := script.NewAddressFromPublicKeyHash(walletHash160(pubKeyBytes), true)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.GetAddress: address derivation failed: %w", err)
	}
	return pubKey.AddressString, nil
}

// Sign signs a transaction input by computing the BIP-143 sighash locally
// and delegating the actual ECDSA signing to the wallet.
func (s *WalletSigner) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	flag := sighash.AllForkID
	if sigHashType != nil {
		flag = sighash.Flag(*sigHashType)
	}

	tx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.Sign: failed to parse transaction: %w", err)
	}

	if inputIndex < 0 || inputIndex >= len(tx.Inputs) {
		return "", fmt.Errorf("WalletSigner.Sign: input index %d out of range (tx has %d inputs)", inputIndex, len(tx.Inputs))
	}

	lockScript, err := script.NewFromHex(subscript)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.Sign: failed to parse subscript: %w", err)
	}

	tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(satoshis),
		LockingScript: lockScript,
	})

	sigHashBytes, err := tx.CalcInputSignatureHash(uint32(inputIndex), flag)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.Sign: sighash computation failed: %w", err)
	}

	// Delegate signing to the wallet.
	derBytes, err := s.wallet.CreateSignature(sigHashBytes, s.protocolID, s.keyID)
	if err != nil {
		return "", fmt.Errorf("WalletSigner.Sign: wallet signing failed: %w", err)
	}

	// Append sighash flag byte.
	result := append(derBytes, byte(flag))
	return hex.EncodeToString(result), nil
}

// ---------------------------------------------------------------------------
// DeployWithWallet — deploy a contract using a WalletProvider
// ---------------------------------------------------------------------------

// DeployWithWalletOptions configures a wallet-based deployment.
type DeployWithWalletOptions struct {
	Satoshis    int64
	Description string
	Basket      string
	Tags        []string
	// AcknowledgeUnsound names the builtins the caller accepts despite the
	// compiler not claiming they are sound (R-062). Required — naming each one
	// — when the artifact declares UnsoundPrimitives; ignored otherwise. Same
	// mechanism and same error as DeployOptions.AcknowledgeUnsound on Deploy.
	AcknowledgeUnsound []string
}

// DeployWithWalletResult is the result of a wallet-based deployment.
type DeployWithWalletResult struct {
	Txid  string
	RawTx string
}

// DeployWithWallet deploys the contract by creating a wallet action with
// the contract's locking script as an output. The wallet handles funding
// and transaction construction.
//
// The provider must be a *WalletProvider.
func (c *RunarContract) DeployWithWallet(options *DeployWithWalletOptions) (*DeployWithWalletResult, error) {
	wp, ok := c.provider.(*WalletProvider)
	if !ok {
		return nil, fmt.Errorf("RunarContract.DeployWithWallet: provider must be a *WalletProvider")
	}

	lockingScript := c.GetLockingScript()
	if lockingScript == "" {
		return nil, fmt.Errorf("RunarContract.DeployWithWallet: empty locking script")
	}

	// DoS-bound: reject pathological scripts BEFORE involving the wallet. Deploy
	// has run this since it was added; the wallet path never did.
	if guardErr := assertScriptHexUnderLimit(
		lockingScript, MaxScriptBytes,
		c.Artifact.ContractName+".DeployWithWallet",
	); guardErr != nil {
		return nil, guardErr
	}

	// R-062: the wallet is a SECOND funding path, and it must make the same
	// decision Deploy makes — refuse to fund a script reaching a builtin the
	// compiler does not claim is sound unless the caller says so here. Before
	// CreateAction, so no wallet is ever asked for the coins.
	if guardErr := assertUnsoundPrimitivesAcknowledged(
		c.Artifact, options.AcknowledgeUnsound,
		c.Artifact.ContractName+".DeployWithWallet",
	); guardErr != nil {
		return nil, guardErr
	}

	satoshis := options.Satoshis
	if satoshis <= 0 {
		satoshis = 1
	}

	description := options.Description
	if description == "" {
		description = "deploy " + c.Artifact.ContractName
	}

	basket := options.Basket
	if basket == "" {
		basket = wp.basket
	}

	result, err := wp.wallet.CreateAction(description, []WalletActionOutput{
		{
			LockingScript: lockingScript,
			Satoshis:      satoshis,
			Description:   "contract output",
			Basket:        basket,
			Tags:          options.Tags,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("RunarContract.DeployWithWallet: creating action: %w", err)
	}

	// Track the deployed UTXO.
	c.currentUtxo = &UTXO{
		Txid:        result.Txid,
		OutputIndex: 0,
		Satoshis:    satoshis,
		Script:      lockingScript,
	}

	// Cache the raw transaction for later lookups.
	if result.RawTx != "" {
		wp.mu.Lock()
		wp.txCache[result.Txid] = result.RawTx
		wp.mu.Unlock()
	}

	return &DeployWithWalletResult{
		Txid:  result.Txid,
		RawTx: result.RawTx,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// walletHash160 computes RIPEMD160(SHA256(data)).
func walletHash160(data []byte) []byte {
	h256 := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(h256[:])
	return r.Sum(nil)
}

// walletHash160Hex computes RIPEMD160(SHA256(data)) and returns hex.
func walletHash160Hex(data []byte) string {
	return hex.EncodeToString(walletHash160(data))
}

// parseOutpoint parses an outpoint string "txid.voutIndex" into its parts.
func parseOutpoint(outpoint string) (txid string, vout int) {
	parts := strings.SplitN(outpoint, ".", 2)
	if len(parts) != 2 {
		return outpoint, 0
	}
	var idx int
	fmt.Sscanf(parts[1], "%d", &idx)
	return parts[0], idx
}
