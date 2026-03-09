package helpers

import (
	"encoding/hex"
	"fmt"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
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
