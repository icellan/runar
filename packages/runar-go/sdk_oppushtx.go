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
//
// Builds the preimage under the default ALL|FORKID sighash. For a method
// declaring a non-default @sighash mode (issue #123), use
// ComputeOpPushTxWithSigHash so the derived signature and preimage match the
// on-chain OP_PUSH_TX binding flag.
func ComputeOpPushTxWithCodeSep(txHex string, inputIndex int, subscript string, satoshis int64, codeSeparatorIndex int) ([]byte, []byte, error) {
	return ComputeOpPushTxWithSigHash(txHex, inputIndex, subscript, satoshis, codeSeparatorIndex, int(sighash.AllForkID))
}

// ComputeOpPushTxWithSigHash is the mode-aware form (issue #123). sigHashType is
// the BIP-143 sighash type the preimage is built under (e.g. 0x43 for
// SINGLE|FORKID); it drives which preimage fields the node zeroes AND the
// sighash flag byte appended to the DER signature. Must match the method's
// declared @sighash mode or the on-chain binding fails to verify. Pass 0 or
// 0x41 for the default ALL|FORKID.
func ComputeOpPushTxWithSigHash(txHex string, inputIndex int, subscript string, satoshis int64, codeSeparatorIndex int, sigHashType int) ([]byte, []byte, error) {
	if sigHashType == 0 {
		sigHashType = int(sighash.AllForkID)
	}
	flag := sighash.Flag(sigHashType & 0xff)

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
		// R-178: this slice used to panic with "slice bounds out of range" when
		// the index was past the end — a fund-moving primitive taking down the
		// caller's process instead of reporting a bad input.
		trimPos := (codeSeparatorIndex + 1) * 2
		if trimPos > len(subscript) {
			return nil, nil, fmt.Errorf(
				"compute_op_push_tx: codeSeparatorIndex %d is past the end of the subscript (%d bytes)",
				codeSeparatorIndex, len(subscript)/2)
		}
		scriptCode = subscript[trimPos:]
	}

	lockScript, err := script.NewFromHex(scriptCode)
	if err != nil {
		return nil, nil, fmt.Errorf("parse subscript: %w", err)
	}

	tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(satoshis),
		LockingScript: lockScript,
	})

	// Get the raw preimage under the declared sighash flag (the flag controls
	// which BIP-143 digest fields are zeroed: hashPrevouts under ANYONECANPAY,
	// hashSequence unless pure ALL, hashOutputs under NONE / same-index SINGLE).
	preimage, err := tx.CalcInputPreimage(uint32(inputIndex), flag)
	if err != nil {
		return nil, nil, fmt.Errorf("calc preimage: %w", err)
	}

	// Compute sighash
	sigHashBytes, err := tx.CalcInputSignatureHash(uint32(inputIndex), flag)
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
	derBytes = append(derBytes, byte(flag))

	return derBytes, preimage, nil
}

// OpPushTxPubKeyHex returns the hex-encoded compressed public key for OP_PUSH_TX
// (the generator point G, corresponding to private key k=1).
func OpPushTxPubKeyHex() string {
	return hex.EncodeToString(opPushTxPrivKey.PubKey().Compressed())
}
