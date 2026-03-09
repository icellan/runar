package helpers

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// DeployContract creates a transaction with the contract as output 0.
// Returns the signed transaction hex.
func DeployContract(lockingScriptHex string, fundingUTXO *UTXO, contractSats int64, changeWallet *Wallet) (string, error) {
	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		return "", fmt.Errorf("invalid locking script: %w", err)
	}

	tx := transaction.NewTransaction()
	err = tx.AddInputFrom(fundingUTXO.Txid, uint32(fundingUTXO.Vout), fundingUTXO.Script, uint64(fundingUTXO.Satoshis), nil)
	if err != nil {
		return "", fmt.Errorf("add input: %w", err)
	}

	// Output 0: contract
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(contractSats),
		LockingScript: lockScript,
	})

	// Change output if there's excess
	changeSats := fundingUTXO.Satoshis - contractSats - 500 // rough fee
	if changeSats > 546 {
		changeScript, _ := script.NewFromHex(changeWallet.P2PKHScript())
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(changeSats),
			LockingScript: changeScript,
		})
	}

	// Sign input 0 (P2PKH)
	if err := signP2PKHInput(tx, 0, changeWallet); err != nil {
		return "", err
	}

	return tx.Hex(), nil
}

// SpendContract creates a transaction spending a contract UTXO with the given unlocking script.
// outputScriptHex and outputSats define the spending output (e.g., P2PKH for the receiver).
func SpendContract(contractUTXO *UTXO, unlockingScriptHex string, outputScriptHex string, outputSats int64) (string, error) {
	lockScript, err := script.NewFromHex(contractUTXO.Script)
	if err != nil {
		return "", fmt.Errorf("invalid contract script: %w", err)
	}

	tx := transaction.NewTransaction()
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       TxidToChainHash(contractUTXO.Txid),
		SourceTxOutIndex: uint32(contractUTXO.Vout),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(contractUTXO.Satoshis),
		LockingScript: lockScript,
	})

	outputScript, _ := script.NewFromHex(outputScriptHex)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(outputSats),
		LockingScript: outputScript,
	})

	// Set unlocking script
	unlockScript, _ := script.NewFromHex(unlockingScriptHex)
	tx.Inputs[0].UnlockingScript = unlockScript

	return tx.Hex(), nil
}

// BuildSpendTx creates a spending transaction for signing. Returns the transaction
// so callers can compute sighash and build the unlocking script.
func BuildSpendTx(contractUTXO *UTXO, outputScriptHex string, outputSats int64) (*transaction.Transaction, error) {
	lockScript, err := script.NewFromHex(contractUTXO.Script)
	if err != nil {
		return nil, fmt.Errorf("invalid contract script: %w", err)
	}

	tx := transaction.NewTransaction()
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       TxidToChainHash(contractUTXO.Txid),
		SourceTxOutIndex: uint32(contractUTXO.Vout),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(contractUTXO.Satoshis),
		LockingScript: lockScript,
	})

	outputScript, _ := script.NewFromHex(outputScriptHex)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(outputSats),
		LockingScript: outputScript,
	})

	return tx, nil
}

// SignInput computes the sighash and signs an input with the given key.
// Returns the DER signature + sighash byte as hex.
func SignInput(tx *transaction.Transaction, inputIdx int, key *ec.PrivateKey) (string, error) {
	sigHash, err := tx.CalcInputSignatureHash(uint32(inputIdx), sighash.AllForkID)
	if err != nil {
		return "", fmt.Errorf("calc sighash: %w", err)
	}
	sig, err := key.Sign(sigHash)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sigDER := sig.Serialize()
	sigWithFlag := append(sigDER, byte(sighash.AllForkID))
	return hex.EncodeToString(sigWithFlag), nil
}

// BroadcastAndMine broadcasts a raw transaction and mines a block.
func BroadcastAndMine(txHex string) (string, error) {
	txid, err := SendRawTransaction(txHex)
	if err != nil {
		return "", err
	}
	if err := Mine(1); err != nil {
		return txid, fmt.Errorf("mine after broadcast: %w", err)
	}
	return txid, nil
}

func signP2PKHInput(tx *transaction.Transaction, inputIdx int, wallet *Wallet) error {
	sigHex, err := SignInput(tx, inputIdx, wallet.PrivKey)
	if err != nil {
		return err
	}
	sigBytes, _ := hex.DecodeString(sigHex)
	unlockHex := EncodePushBytes(sigBytes) + EncodePushBytes(wallet.PubKeyBytes)
	unlockScript, _ := script.NewFromHex(unlockHex)
	tx.Inputs[inputIdx].UnlockingScript = unlockScript
	return nil
}

// TxidToChainHash converts a txid string to a chainhash.Hash.
func TxidToChainHash(txid string) *chainhash.Hash {
	h, _ := chainhash.NewHashFromHex(txid)
	return h
}
