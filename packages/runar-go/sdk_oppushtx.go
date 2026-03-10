package runar

import (
	"encoding/hex"
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// OP_PUSH_TX uses private key k=1 (public key = generator point G).
var opPushTxPrivKey *ec.PrivateKey

// secp256k1 curve order n (for low-S enforcement).
var curveOrder, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func init() {
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	opPushTxPrivKey, _ = ec.PrivateKeyFromBytes(keyBytes)
}

// ComputeOpPushTx computes the OP_PUSH_TX DER signature and BIP-143 preimage
// for a contract input in a raw transaction.
//
// The OP_PUSH_TX technique uses private key k=1 (public key = generator G).
// The signature is a standard ECDSA signature with low-S enforcement.
//
// Parameters:
//   - txHex: the raw transaction hex
//   - inputIndex: the contract input to sign (usually 0)
//   - subscript: the locking script of the UTXO being spent (hex)
//   - satoshis: the satoshi value of the UTXO being spent
//
// Returns the DER signature (with sighash flag) and the preimage, both as raw bytes.
func ComputeOpPushTx(txHex string, inputIndex int, subscript string, satoshis int64) ([]byte, []byte, error) {
	return ComputeOpPushTxWithCodeSep(txHex, inputIndex, subscript, satoshis, -1)
}

// ComputeOpPushTxWithCodeSep is like ComputeOpPushTx but supports OP_CODESEPARATOR.
// When codeSeparatorIndex >= 0, the scriptCode in the BIP-143 preimage uses only the
// portion of the subscript AFTER the OP_CODESEPARATOR byte at that offset.
func ComputeOpPushTxWithCodeSep(txHex string, inputIndex int, subscript string, satoshis int64, codeSeparatorIndex int) ([]byte, []byte, error) {
	tx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		return nil, nil, fmt.Errorf("parse transaction: %w", err)
	}

	if inputIndex >= len(tx.Inputs) {
		return nil, nil, fmt.Errorf("input index %d out of range (%d inputs)", inputIndex, len(tx.Inputs))
	}

	// If OP_CODESEPARATOR is present, use only the script after it as scriptCode.
	scriptCode := subscript
	if codeSeparatorIndex >= 0 {
		// Each byte is 2 hex chars. Skip past the separator byte (+1 byte = +2 hex chars).
		scriptCode = subscript[(codeSeparatorIndex+1)*2:]
	}

	lockScript, err := script.NewFromHex(scriptCode)
	if err != nil {
		return nil, nil, fmt.Errorf("parse subscript: %w", err)
	}

	tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(satoshis),
		LockingScript: lockScript,
	})

	// Get the raw preimage
	preimage, err := tx.CalcInputPreimage(uint32(inputIndex), sighash.AllForkID)
	if err != nil {
		return nil, nil, fmt.Errorf("calc preimage: %w", err)
	}

	// Compute sighash
	sigHashBytes, err := tx.CalcInputSignatureHash(uint32(inputIndex), sighash.AllForkID)
	if err != nil {
		return nil, nil, fmt.Errorf("calc sighash: %w", err)
	}

	// Sign with k=1 private key using the go-sdk
	sig, err := opPushTxPrivKey.Sign(sigHashBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}

	// Enforce low-S
	halfN := new(big.Int).Rsh(curveOrder, 1)
	if sig.S.Cmp(halfN) > 0 {
		sig.S = new(big.Int).Sub(curveOrder, sig.S)
	}

	derBytes := sig.Serialize()
	derBytes = append(derBytes, byte(sighash.AllForkID))

	return derBytes, preimage, nil
}

// OpPushTxPubKeyHex returns the hex-encoded compressed public key for OP_PUSH_TX
// (the generator point G, corresponding to private key k=1).
func OpPushTxPubKeyHex() string {
	return hex.EncodeToString(opPushTxPrivKey.PubKey().Compressed())
}
