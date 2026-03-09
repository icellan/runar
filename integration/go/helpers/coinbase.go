package helpers

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var (
	coinbaseWallet     *Wallet
	coinbaseWalletOnce sync.Once
	// nextCoinbaseHeight tracks the next block height whose coinbase UTXO
	// hasn't been consumed yet. Starts at 1 (block 0 is genesis).
	nextCoinbaseHeight uint64 = 1
)

// CoinbaseWallet returns a deterministic wallet used for mining coinbase
// rewards on Teranode (which has no built-in wallet).
// Uses a fixed private key so the address is stable across runs.
func CoinbaseWallet() *Wallet {
	coinbaseWalletOnce.Do(func() {
		// Deterministic private key for regtest coinbase.
		// This is NOT a secret — regtest only.
		privKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
		privKeyBytes, _ := hex.DecodeString(privKeyHex)
		priv, pub := ec.PrivateKeyFromBytes(privKeyBytes)
		pubBytes := pub.Compressed()
		pubHash := crypto.Hash160(pubBytes)
		addr, _ := script.NewAddressFromPublicKey(pub, false) // false = regtest

		coinbaseWallet = &Wallet{
			PrivKey:     priv,
			PubKey:      pub,
			PubKeyBytes: pubBytes,
			PubKeyHash:  pubHash,
			Address:     addr.AddressString,
		}
	})
	return coinbaseWallet
}

// GetCoinbaseUTXO returns the next available coinbase UTXO from a mined block.
// Each call consumes one block's coinbase (50 BTC regtest reward).
// The coinbase must be mature (100+ blocks on top of it).
func GetCoinbaseUTXO() (*UTXO, error) {
	height := int(atomic.AddUint64(&nextCoinbaseHeight, 1) - 1)

	// Get the block hash for this height
	blockHash, err := GetBlockHash(height)
	if err != nil {
		return nil, fmt.Errorf("getblockhash(%d): %w", height, err)
	}

	// Parse the coinbase transaction directly from the raw block.
	// This avoids depending on getrawtransaction (which requires the asset service
	// to have indexed the block — unreliable on Teranode for coinbase txs).
	coinbaseTx, err := coinbaseTxFromRawBlock(blockHash, height)
	if err != nil {
		return nil, err
	}

	coinbaseTxid := coinbaseTx.TxID().String()
	cbWallet := CoinbaseWallet()
	expectedScript := cbWallet.P2PKHScript()

	for i, out := range coinbaseTx.Outputs {
		outHex := hex.EncodeToString(*out.LockingScript)
		if outHex == expectedScript {
			return &UTXO{
				Txid:     coinbaseTxid,
				Vout:     i,
				Satoshis: int64(out.Satoshis),
				Script:   outHex,
			}, nil
		}
	}

	return nil, fmt.Errorf("coinbase output not found for block %d (txid %s)", height, coinbaseTxid)
}

// FundFromCoinbase creates a P2PKH funding transaction from a coinbase UTXO
// to the target wallet. Used on Teranode which has no sendtoaddress RPC.
func FundFromCoinbase(target *Wallet, btcAmount float64) (*UTXO, error) {
	coinbaseUTXO, err := GetCoinbaseUTXO()
	if err != nil {
		return nil, fmt.Errorf("get coinbase UTXO: %w", err)
	}

	targetSats := int64(btcAmount * 1e8)
	cbWallet := CoinbaseWallet()

	// Build a P2PKH transaction: coinbase → target + change
	txHex, err := DeployContract(
		target.P2PKHScript(),
		coinbaseUTXO,
		targetSats,
		cbWallet,
	)
	if err != nil {
		return nil, fmt.Errorf("build funding tx: %w", err)
	}

	// Broadcast and mine
	txid, err := BroadcastAndMine(txHex)
	if err != nil {
		return nil, fmt.Errorf("broadcast funding tx: %w", err)
	}

	return FindUTXO(txid, target.P2PKHScript())
}

// coinbaseTxFromRawBlock fetches the raw block hex (verbosity 0) and extracts
// the coinbase transaction by deserializing the first transaction.
// This works on both SV Node and Teranode, and avoids needing getrawtransaction.
func coinbaseTxFromRawBlock(blockHash string, height int) (*transaction.Transaction, error) {
	result, err := RPCCall("getblock", blockHash, 0)
	if err != nil {
		return nil, fmt.Errorf("getblock raw(%s): %w", blockHash, err)
	}

	var rawHex string
	if err := json.Unmarshal(result, &rawHex); err != nil {
		return nil, fmt.Errorf("parse raw block hex: %w", err)
	}

	blockBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("decode raw block hex: %w", err)
	}

	// Block format: 80-byte header, then serialized transactions
	if len(blockBytes) < 81 {
		return nil, fmt.Errorf("raw block too short for block %d", height)
	}

	// Skip the 80-byte header
	txData := blockBytes[80:]

	// Read CompactSize varint for tx count (we only care that there's at least 1)
	_, bytesRead := readCompactSize(txData)
	if bytesRead == 0 {
		return nil, fmt.Errorf("invalid compact size in block %d", height)
	}
	txData = txData[bytesRead:]

	// Teranode uses an extended block format with extra fields after tx count:
	//   varint SizeInBytes, varint SubtreeLength, [32-byte subtree hashes],
	//   coinbase tx, varint BlockHeight
	// SV Node uses standard format: transactions follow immediately after tx count.
	// Detect by trying standard parse first; if it returns 0 outputs, try Teranode format.
	coinbaseTx, _, err := transaction.NewTransactionFromStream(txData)
	if err == nil && len(coinbaseTx.Outputs) > 0 {
		return coinbaseTx, nil
	}

	// Teranode extended format: skip SizeInBytes + SubtreeLength + subtree hashes
	_, n := readCompactSize(txData) // SizeInBytes
	if n == 0 {
		return nil, fmt.Errorf("invalid SizeInBytes varint in block %d", height)
	}
	txData = txData[n:]

	subtreeLen, n := readCompactSize(txData) // SubtreeLength
	if n == 0 {
		return nil, fmt.Errorf("invalid SubtreeLength varint in block %d", height)
	}
	txData = txData[n:]

	// Skip subtree hashes (32 bytes each)
	txData = txData[subtreeLen*32:]

	// Now parse the coinbase transaction
	coinbaseTx, _, err = transaction.NewTransactionFromStream(txData)
	if err != nil {
		return nil, fmt.Errorf("parse coinbase tx from block %d: %w", height, err)
	}

	return coinbaseTx, nil
}

// readCompactSize reads a Bitcoin CompactSize unsigned integer.
// Returns the value and number of bytes consumed.
func readCompactSize(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0] < 0xfd:
		return uint64(b[0]), 1
	case b[0] == 0xfd && len(b) >= 3:
		return uint64(b[1]) | uint64(b[2])<<8, 3
	case b[0] == 0xfe && len(b) >= 5:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24, 5
	case b[0] == 0xff && len(b) >= 9:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24 |
			uint64(b[5])<<32 | uint64(b[6])<<40 | uint64(b[7])<<48 | uint64(b[8])<<56, 9
	default:
		return 0, 0
	}
}

// parseSatoshis converts a value from getrawtransaction verbose output to satoshis.
// SV Node returns BTC (e.g. 50.0), Teranode returns satoshis (e.g. 5000000000).
func parseSatoshis(value float64) int64 {
	if IsTeranode() {
		// Teranode returns satoshis directly
		return int64(value)
	}
	// SV Node returns BTC — convert to satoshis
	btc := new(big.Float).SetFloat64(value)
	sats := new(big.Float).Mul(btc, new(big.Float).SetFloat64(1e8))
	result, _ := sats.Int64()
	return result
}
