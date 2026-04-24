package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// Transaction construction for contract deployment
// ---------------------------------------------------------------------------

// P2PKH sizes for fee estimation
const (
	p2pkhInputSize  = 148 // prevTxid(32) + index(4) + scriptSig(~107) + sequence(4) + varint(1)
	p2pkhOutputSize = 34  // satoshis(8) + varint(1) + P2PKH script(25)
	txOverhead      = 10  // version(4) + input varint(1) + output varint(1) + locktime(4)
)

// BuildDeployTransaction builds an unsigned Transaction that creates an output
// with the given locking script. The transaction consumes the provided UTXOs,
// places the contract output first, and sends any remaining value (minus fees)
// to a change address.
//
// Returns the unsigned Transaction object and the number of inputs.
func BuildDeployTransaction(
	lockingScript string,
	utxos []UTXO,
	satoshis int64,
	changeAddress string,
	changeScript string,
	feeRate ...int64,
) (tx *transaction.Transaction, inputCount int, err error) {
	if len(utxos) == 0 {
		return nil, 0, fmt.Errorf("buildDeployTransaction: no UTXOs provided")
	}

	var totalInput int64
	for _, u := range utxos {
		totalInput += u.Satoshis
	}

	fee := EstimateDeployFee(len(utxos), len(lockingScript)/2, feeRate...)
	change := totalInput - satoshis - fee

	if change < 0 {
		return nil, 0, fmt.Errorf(
			"buildDeployTransaction: insufficient funds. Need %d sats, have %d",
			satoshis+fee, totalInput,
		)
	}

	tx = transaction.NewTransaction()

	// Inputs (unsigned — empty unlocking script)
	for _, utxo := range utxos {
		if err := tx.AddInputFrom(utxo.Txid, uint32(utxo.OutputIndex), utxo.Script, uint64(utxo.Satoshis), nil); err != nil {
			return nil, 0, fmt.Errorf("buildDeployTransaction: add input: %w", err)
		}
	}

	// Output 0: contract locking script
	lockScript, err := sdkscript.NewFromHex(lockingScript)
	if err != nil {
		return nil, 0, fmt.Errorf("buildDeployTransaction: invalid locking script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(satoshis),
		LockingScript: lockScript,
	})

	// Output 1: change (if any)
	if change > 0 {
		actualChangeScript := changeScript
		if actualChangeScript == "" {
			actualChangeScript = BuildP2PKHScript(changeAddress)
		}
		changeLS, err := sdkscript.NewFromHex(actualChangeScript)
		if err != nil {
			return nil, 0, fmt.Errorf("buildDeployTransaction: invalid change script: %w", err)
		}
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(change),
			LockingScript: changeLS,
		})
	}

	return tx, len(utxos), nil
}

// SelectUtxos selects the minimum set of UTXOs needed to fund a deployment,
// using a largest-first strategy.
func SelectUtxos(utxos []UTXO, targetSatoshis int64, lockingScriptByteLen int, feeRate ...int64) []UTXO {
	sorted := make([]UTXO, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Satoshis > sorted[j].Satoshis
	})

	var selected []UTXO
	var total int64

	for _, utxo := range sorted {
		selected = append(selected, utxo)
		total += utxo.Satoshis

		fee := EstimateDeployFee(len(selected), lockingScriptByteLen, feeRate...)
		if total >= targetSatoshis+fee {
			return selected
		}
	}

	// Return all UTXOs; BuildDeployTransaction will return an error if still insufficient
	return selected
}

// EstimateDeployFee estimates the fee for a deploy transaction given the
// number of P2PKH inputs and the contract locking script byte length.
// Includes a P2PKH change output. feeRate is in satoshis per KB (0 defaults to 100).
func EstimateDeployFee(numInputs int, lockingScriptByteLen int, feeRate ...int64) int64 {
	rate := int64(100)
	if len(feeRate) > 0 && feeRate[0] > 0 {
		rate = feeRate[0]
	}
	inputsSize := numInputs * p2pkhInputSize
	contractOutputSize := 8 + varIntByteSize(lockingScriptByteLen) + lockingScriptByteLen
	changeOutputSize := p2pkhOutputSize
	txSize := int64(txOverhead + inputsSize + contractOutputSize + changeOutputSize)
	return (txSize*rate + 999) / 1000
}

// EstimateCallFee estimates the fee for a method-call transaction. The
// transaction consumes the previous contract UTXO (with an unlocking script
// of unlockingScriptByteLen bytes), numFundingInputs P2PKH funding inputs,
// emits a stateful continuation output with the given lockingScriptByteLen,
// and a P2PKH change output. feeRate is in satoshis per KB (0 defaults to 100).
//
// Mirrors the TS estimateCallFee in packages/runar-sdk/src/calling.ts.
func EstimateCallFee(lockingScriptByteLen int, unlockingScriptByteLen int, numFundingInputs int, feeRate ...int64) int64 {
	rate := int64(100)
	if len(feeRate) > 0 && feeRate[0] > 0 {
		rate = feeRate[0]
	}
	// Contract input: prevTxid(32) + index(4) + varint + script + sequence(4).
	contractInputSize := 32 + 4 + varIntByteSize(unlockingScriptByteLen) + unlockingScriptByteLen + 4
	fundingInputsSize := numFundingInputs * p2pkhInputSize
	contractOutputSize := 8 + varIntByteSize(lockingScriptByteLen) + lockingScriptByteLen
	changeOutputSize := p2pkhOutputSize
	txSize := int64(txOverhead + contractInputSize + fundingInputsSize + contractOutputSize + changeOutputSize)
	return (txSize*rate + 999) / 1000
}

// ---------------------------------------------------------------------------
// Bitcoin wire format helpers (kept for fee estimation and other callers)
// ---------------------------------------------------------------------------

func toLittleEndian32(n int) string {
	b0 := n & 0xff
	b1 := (n >> 8) & 0xff
	b2 := (n >> 16) & 0xff
	b3 := (n >> 24) & 0xff
	return fmt.Sprintf("%02x%02x%02x%02x", b0, b1, b2, b3)
}

func toLittleEndian64(n int64) string {
	lo := int(n & 0xffffffff)
	hi := int((n >> 32) & 0xffffffff)
	return toLittleEndian32(lo) + toLittleEndian32(hi)
}

func encodeVarInt(n int) string {
	if n < 0xfd {
		return fmt.Sprintf("%02x", n)
	} else if n <= 0xffff {
		lo := n & 0xff
		hi := (n >> 8) & 0xff
		return fmt.Sprintf("fd%02x%02x", lo, hi)
	} else if n <= 0xffffffff {
		return "fe" + toLittleEndian32(n)
	}
	return "ff" + toLittleEndian64(int64(n))
}

func reverseHex(h string) string {
	pairs := make([]string, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		pairs[i/2] = h[i : i+2]
	}
	// Reverse
	for i, j := 0, len(pairs)-1; i < j; i, j = i+1, j-1 {
		pairs[i], pairs[j] = pairs[j], pairs[i]
	}
	result := ""
	for _, p := range pairs {
		result += p
	}
	return result
}

func varIntByteSize(n int) int {
	if n < 0xfd {
		return 1
	}
	if n <= 0xffff {
		return 3
	}
	if n <= 0xffffffff {
		return 5
	}
	return 9
}

// BuildP2PKHScript builds a standard P2PKH locking script from an address,
// pubkey hash, or public key.
//
//	OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
//	76      a9         14        <20 bytes>    88              ac
//
// Accepted input formats:
//   - 40-char hex: treated as raw 20-byte pubkey hash (hash160)
//   - 66-char hex: compressed public key (auto-hashed via hash160)
//   - 130-char hex: uncompressed public key (auto-hashed via hash160)
//   - Other: decoded as Base58Check BSV address
func BuildP2PKHScript(address string) string {
	pubKeyHash := address

	if len(address) == 40 && isHex(address) {
		// Already a raw 20-byte pubkey hash in hex
		pubKeyHash = address
	} else if (len(address) == 66 || len(address) == 130) && isHex(address) {
		// Compressed (33 bytes) or uncompressed (65 bytes) public key — hash it
		pubKeyBytes, err := hex.DecodeString(address)
		if err != nil {
			panic(fmt.Sprintf("BuildP2PKHScript: invalid public key hex %q: %v", address, err))
		}
		pubKeyHash = computeHash160Hex(pubKeyBytes)
	} else {
		// Decode Base58Check address to extract the 20-byte pubkey hash
		addr, err := sdkscript.NewAddressFromString(address)
		if err != nil {
			panic(fmt.Sprintf("BuildP2PKHScript: invalid address %q: %v", address, err))
		}
		pubKeyHash = hex.EncodeToString(addr.PublicKeyHash)
	}
	return "76a914" + pubKeyHash + "88ac"
}

// computeHash160Hex computes RIPEMD160(SHA256(data)) and returns the hex-encoded result.
func computeHash160Hex(data []byte) string {
	h256 := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(h256[:])
	return hex.EncodeToString(r.Sum(nil))
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
