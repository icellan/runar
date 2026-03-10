package helpers

import (
	"encoding/hex"
	"fmt"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// SignOpPushTx computes the OP_PUSH_TX DER signature and BIP-143 preimage
// for a contract input. Delegates to the SDK's ComputeOpPushTx.
//
// Returns (sigWithFlagHex, preimageHex, error).
func SignOpPushTx(tx *transaction.Transaction, inputIdx uint32) (string, string, error) {
	if int(inputIdx) >= len(tx.Inputs) {
		return "", "", fmt.Errorf("input index %d out of range", inputIdx)
	}

	prevOutput := tx.Inputs[inputIdx].SourceTxOutput()
	if prevOutput == nil {
		return "", "", fmt.Errorf("input %d has no source output set", inputIdx)
	}

	subscript := hex.EncodeToString(*prevOutput.LockingScript)
	satoshis := int64(prevOutput.Satoshis)

	sigBytes, preimage, err := runar.ComputeOpPushTx(tx.Hex(), int(inputIdx), subscript, satoshis)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(sigBytes), hex.EncodeToString(preimage), nil
}

// SignOpPushTxWithCodeSep is like SignOpPushTx but trims the subscript at the
// given OP_CODESEPARATOR byte offset for BIP-143 sighash computation.
func SignOpPushTxWithCodeSep(tx *transaction.Transaction, inputIdx uint32, codeSepIdx int) (string, string, error) {
	if int(inputIdx) >= len(tx.Inputs) {
		return "", "", fmt.Errorf("input index %d out of range", inputIdx)
	}

	prevOutput := tx.Inputs[inputIdx].SourceTxOutput()
	if prevOutput == nil {
		return "", "", fmt.Errorf("input %d has no source output set", inputIdx)
	}

	subscript := hex.EncodeToString(*prevOutput.LockingScript)
	satoshis := int64(prevOutput.Satoshis)

	sigBytes, preimage, err := runar.ComputeOpPushTxWithCodeSep(tx.Hex(), int(inputIdx), subscript, satoshis, codeSepIdx)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(sigBytes), hex.EncodeToString(preimage), nil
}

// OpPushTxPubKeyHex returns the compressed public key hex for OP_PUSH_TX.
func OpPushTxPubKeyHex() string {
	return runar.OpPushTxPubKeyHex()
}
