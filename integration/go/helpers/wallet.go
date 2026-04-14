package helpers

import (
	"encoding/hex"
	"fmt"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Wallet holds a secp256k1 keypair with derived address and scripts.
type Wallet struct {
	PrivKey     *ec.PrivateKey
	PubKey      *ec.PublicKey
	PubKeyBytes []byte
	PubKeyHash  []byte
	Address     string
}

// NewWallet generates a random ECDSA keypair.
func NewWallet() *Wallet {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		panic(fmt.Sprintf("keygen failed: %v", err))
	}
	pub := priv.PubKey()
	pubBytes := pub.Compressed()
	pubHash := crypto.Hash160(pubBytes)

	addr, _ := script.NewAddressFromPublicKey(pub, false) // false = regtest/testnet

	return &Wallet{
		PrivKey:     priv,
		PubKey:      pub,
		PubKeyBytes: pubBytes,
		PubKeyHash:  pubHash,
		Address:     addr.AddressString,
	}
}

// PubKeyHex returns the compressed public key as hex.
func (w *Wallet) PubKeyHex() string {
	return hex.EncodeToString(w.PubKeyBytes)
}

// PubKeyHashHex returns the Hash160 of the public key as hex.
func (w *Wallet) PubKeyHashHex() string {
	return hex.EncodeToString(w.PubKeyHash)
}

// P2PKHScript returns the P2PKH locking script hex for this wallet.
func (w *Wallet) P2PKHScript() string {
	return "76a914" + w.PubKeyHashHex() + "88ac"
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	Txid     string
	Vout     int
	Satoshis int64
	Script   string
}

// FundWallet sends BTC to the wallet, mines a block, and finds the UTXO.
// On SV Node: uses the built-in wallet (sendtoaddress).
// On Teranode: builds a raw TX from a coinbase UTXO.
func FundWallet(w *Wallet, btcAmount float64) (*UTXO, error) {
	if IsTeranode() {
		return FundFromCoinbase(w, btcAmount)
	}
	return fundWalletSVNode(w, btcAmount)
}

func fundWalletSVNode(w *Wallet, btcAmount float64) (*UTXO, error) {
	txid, err := SendToAddress(w.Address, btcAmount)
	if err != nil {
		return nil, fmt.Errorf("sendtoaddress: %w", err)
	}
	if err := Mine(1); err != nil {
		return nil, fmt.Errorf("mine: %w", err)
	}
	return FindUTXO(txid, w.P2PKHScript())
}

// SplitFund funds a wallet with a single RPC call, then creates a splitting
// transaction with `n` equal P2PKH outputs. Returns all UTXOs. Only 1 block
// is mined for the split, regardless of n. This is much faster than calling
// FundWallet n times (which mines a block per call).
func SplitFund(w *Wallet, n int, satoshisPerOutput int64) ([]*UTXO, error) {
	// Calculate total needed: n outputs + fee
	feeBudget := int64(n*34 + 200) // ~34 bytes per output + overhead
	totalBTC := float64(int64(n)*satoshisPerOutput+feeBudget) / 1e8

	funding, err := FundWallet(w, totalBTC)
	if err != nil {
		return nil, fmt.Errorf("initial fund: %w", err)
	}

	// Build splitting transaction
	tx := buildSplitTx(funding, w, n, satoshisPerOutput)

	// Sign the single P2PKH input
	if err := signP2PKHInputHelper(tx, 0, w); err != nil {
		return nil, fmt.Errorf("sign split tx: %w", err)
	}

	txid, err := SendRawTransaction(tx.Hex())
	if err != nil {
		return nil, fmt.Errorf("broadcast split: %w", err)
	}
	if err := Mine(1); err != nil {
		return nil, fmt.Errorf("mine split: %w", err)
	}

	// Collect all UTXOs
	utxos := make([]*UTXO, n)
	for i := 0; i < n; i++ {
		utxos[i] = &UTXO{
			Txid:     txid,
			Vout:     i,
			Satoshis: satoshisPerOutput,
			Script:   w.P2PKHScript(),
		}
	}
	return utxos, nil
}

// FundedWallet pairs a wallet with its pre-funded UTXO for parallel test execution.
type FundedWallet struct {
	Wallet *Wallet
	UTXO   *UTXO
}

// SplitFundParallel creates n separate wallets, each with its own funded UTXO.
// Uses a single funding+split transaction. Each wallet can be used independently
// in parallel goroutines without UTXO contention.
func SplitFundParallel(n int, satoshisPerOutput int64) ([]*FundedWallet, error) {
	// Create n wallets
	wallets := make([]*Wallet, n)
	for i := 0; i < n; i++ {
		wallets[i] = NewWallet()
	}

	// Fund a master wallet
	master := NewWallet()
	RPCCall("importaddress", master.Address, "", false)
	feeBudget := int64(n*34 + 200)
	totalBTC := float64(int64(n)*satoshisPerOutput+feeBudget) / 1e8

	funding, err := FundWallet(master, totalBTC)
	if err != nil {
		return nil, fmt.Errorf("fund master: %w", err)
	}

	// Build split tx with one output per wallet
	tx := transaction.NewTransaction()
	fundScript, _ := script.NewFromHex(funding.Script)
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       TxidToChainHash(funding.Txid),
		SourceTxOutIndex: uint32(funding.Vout),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(funding.Satoshis),
		LockingScript: fundScript,
	})

	for i := 0; i < n; i++ {
		outScript, _ := script.NewFromHex(wallets[i].P2PKHScript())
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(satoshisPerOutput),
			LockingScript: outScript,
		})
	}

	if err := signP2PKHInputHelper(tx, 0, master); err != nil {
		return nil, fmt.Errorf("sign split: %w", err)
	}

	txid, err := SendRawTransaction(tx.Hex())
	if err != nil {
		return nil, fmt.Errorf("broadcast split: %w", err)
	}
	if err := Mine(1); err != nil {
		return nil, fmt.Errorf("mine split: %w", err)
	}

	// Import all wallet addresses and build results
	result := make([]*FundedWallet, n)
	for i := 0; i < n; i++ {
		RPCCall("importaddress", wallets[i].Address, "", false)
		result[i] = &FundedWallet{
			Wallet: wallets[i],
			UTXO: &UTXO{
				Txid:     txid,
				Vout:     i,
				Satoshis: satoshisPerOutput,
				Script:   wallets[i].P2PKHScript(),
			},
		}
	}
	return result, nil
}

// FindUTXO scans a transaction's outputs for one matching the given script hex.
func FindUTXO(txid, scriptHex string) (*UTXO, error) {
	tx, err := GetRawTransaction(txid)
	if err != nil {
		return nil, err
	}
	vouts, ok := tx["vout"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("no vout in tx %s", txid)
	}
	for _, v := range vouts {
		vout := v.(map[string]interface{})
		n := int(vout["n"].(float64))
		sats := parseSatoshis(vout["value"].(float64))

		sp := vout["scriptPubKey"].(map[string]interface{})
		outHex := sp["hex"].(string)
		if strings.EqualFold(outHex, scriptHex) {
			return &UTXO{Txid: txid, Vout: n, Satoshis: sats, Script: outHex}, nil
		}
	}
	return nil, fmt.Errorf("no output matching script %s in tx %s", scriptHex[:20]+"...", txid)
}

// FindUTXOByIndex returns a specific output from a transaction.
func FindUTXOByIndex(txid string, vout int) (*UTXO, error) {
	tx, err := GetRawTransaction(txid)
	if err != nil {
		return nil, err
	}
	vouts, ok := tx["vout"].([]interface{})
	if !ok || vout >= len(vouts) {
		return nil, fmt.Errorf("vout %d not found in tx %s", vout, txid)
	}
	v := vouts[vout].(map[string]interface{})
	sats := parseSatoshis(v["value"].(float64))
	sp := v["scriptPubKey"].(map[string]interface{})
	outHex := sp["hex"].(string)
	return &UTXO{Txid: txid, Vout: vout, Satoshis: sats, Script: outHex}, nil
}

// buildSplitTx creates a transaction with n equal P2PKH outputs to the same wallet.
func buildSplitTx(funding *UTXO, w *Wallet, n int, satoshisPerOutput int64) *transaction.Transaction {
	tx := transaction.NewTransaction()

	fundScript, _ := script.NewFromHex(funding.Script)
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       TxidToChainHash(funding.Txid),
		SourceTxOutIndex: uint32(funding.Vout),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(funding.Satoshis),
		LockingScript: fundScript,
	})

	outScript, _ := script.NewFromHex(w.P2PKHScript())
	for i := 0; i < n; i++ {
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(satoshisPerOutput),
			LockingScript: outScript,
		})
	}
	return tx
}

// signP2PKHInputHelper wraps signP2PKHInput from tx.go.
func signP2PKHInputHelper(tx *transaction.Transaction, inputIdx int, w *Wallet) error {
	return signP2PKHInput(tx, inputIdx, w)
}
