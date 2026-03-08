package runar

import (
	"fmt"
)

// BuildCallOptions provides optional parameters for BuildCallTransaction.
type BuildCallOptions struct {
	// Multiple contract outputs (replaces single newLockingScript).
	ContractOutputs []ContractOutput
	// Additional contract inputs with their own unlocking scripts (for merge).
	AdditionalContractInputs []AdditionalContractInput
}

// ContractOutput describes one contract continuation output.
type ContractOutput struct {
	Script   string
	Satoshis int64
}

// AdditionalContractInput describes an extra contract input with its unlocking script.
type AdditionalContractInput struct {
	Utxo            UTXO
	UnlockingScript string
}

// ---------------------------------------------------------------------------
// Transaction construction for method invocation
// ---------------------------------------------------------------------------

// BuildCallTransaction builds a raw transaction that spends a contract UTXO.
//
// The transaction:
//   - Input 0: the current contract UTXO with the given unlocking script.
//   - Additional inputs: funding UTXOs if provided.
//   - Output 0 (optional): new contract UTXO with updated locking script
//     (for stateful contracts).
//   - Last output (optional): change.
//
// Returns the transaction hex (with unlocking script for input 0 already
// placed) and the total input count.
func BuildCallTransaction(
	currentUtxo UTXO,
	unlockingScript string,
	newLockingScript string,
	newSatoshis int64,
	changeAddress string,
	changeScript string,
	additionalUtxos []UTXO,
	feeRate int64,
	opts ...*BuildCallOptions,
) (txHex string, inputCount int, changeAmount int64) {
	var extraContractInputs []AdditionalContractInput
	var contractOutputs []ContractOutput
	if len(opts) > 0 && opts[0] != nil {
		extraContractInputs = opts[0].AdditionalContractInputs
		contractOutputs = opts[0].ContractOutputs
	}

	// Build full input list: primary contract, extra contract inputs, P2PKH funding
	allUtxos := []UTXO{currentUtxo}
	for _, ci := range extraContractInputs {
		allUtxos = append(allUtxos, ci.Utxo)
	}
	allUtxos = append(allUtxos, additionalUtxos...)

	var totalInput int64
	for _, u := range allUtxos {
		totalInput += u.Satoshis
	}

	// Determine contract outputs: explicit multi-output takes priority over single
	if len(contractOutputs) == 0 && newLockingScript != "" {
		sats := newSatoshis
		if sats <= 0 {
			sats = currentUtxo.Satoshis
		}
		contractOutputs = []ContractOutput{{Script: newLockingScript, Satoshis: sats}}
	}

	contractOutputSats := int64(0)
	for _, co := range contractOutputs {
		contractOutputSats += co.Satoshis
	}

	// Estimate fee using actual script sizes
	input0Size := 32 + 4 + varIntByteSize(len(unlockingScript)/2) +
		len(unlockingScript)/2 + 4
	extraContractInputsSize := 0
	for _, ci := range extraContractInputs {
		extraContractInputsSize += 32 + 4 +
			varIntByteSize(len(ci.UnlockingScript)/2) +
			len(ci.UnlockingScript)/2 + 4
	}
	p2pkhInputsSize := len(additionalUtxos) * 148
	inputsSize := input0Size + extraContractInputsSize + p2pkhInputsSize

	outputsSize := 0
	for _, co := range contractOutputs {
		outputsSize += 8 + varIntByteSize(len(co.Script)/2) + len(co.Script)/2
	}
	if changeAddress != "" || changeScript != "" {
		outputsSize += 34 // P2PKH change
	}
	estimatedSize := 10 + inputsSize + outputsSize
	rate := feeRate
	if rate <= 0 {
		rate = 1
	}
	fee := int64(estimatedSize) * rate

	change := totalInput - contractOutputSats - fee

	// Build raw transaction
	var tx string

	// Version (4 bytes LE)
	tx += toLittleEndian32(1)

	// Input count
	tx += encodeVarInt(len(allUtxos))

	// Input 0: primary contract UTXO with unlocking script
	tx += reverseHex(currentUtxo.Txid)
	tx += toLittleEndian32(currentUtxo.OutputIndex)
	tx += encodeVarInt(len(unlockingScript) / 2)
	tx += unlockingScript
	tx += "ffffffff"

	// Additional contract inputs (with their own unlocking scripts)
	for _, ci := range extraContractInputs {
		tx += reverseHex(ci.Utxo.Txid)
		tx += toLittleEndian32(ci.Utxo.OutputIndex)
		tx += encodeVarInt(len(ci.UnlockingScript) / 2)
		tx += ci.UnlockingScript
		tx += "ffffffff"
	}

	// P2PKH funding inputs (unsigned)
	for _, utxo := range additionalUtxos {
		tx += reverseHex(utxo.Txid)
		tx += toLittleEndian32(utxo.OutputIndex)
		tx += "00" // empty scriptSig
		tx += "ffffffff"
	}

	// Output count
	numOutputs := len(contractOutputs)
	if change > 0 && (changeAddress != "" || changeScript != "") {
		numOutputs++
	}
	tx += encodeVarInt(numOutputs)

	// Contract outputs
	for _, co := range contractOutputs {
		tx += toLittleEndian64(co.Satoshis)
		tx += encodeVarInt(len(co.Script) / 2)
		tx += co.Script
	}

	// Change output
	if change > 0 && (changeAddress != "" || changeScript != "") {
		actualChangeScript := changeScript
		if actualChangeScript == "" {
			actualChangeScript = BuildP2PKHScript(changeAddress)
		}
		tx += toLittleEndian64(change)
		tx += encodeVarInt(len(actualChangeScript) / 2)
		tx += actualChangeScript
	}

	// Locktime
	tx += toLittleEndian32(0)

	retChange := int64(0)
	if change > 0 {
		retChange = change
	}
	return tx, len(allUtxos), retChange
}

// ---------------------------------------------------------------------------
// Insert unlocking script into a raw transaction
// ---------------------------------------------------------------------------

// InsertUnlockingScript parses a raw transaction hex, locates the target
// input's scriptSig field, replaces it with the provided unlocking script,
// and returns the modified transaction hex.
func InsertUnlockingScript(txHex string, inputIndex int, unlockScript string) string {
	pos := 0

	// Skip version (4 bytes = 8 hex chars)
	pos += 8

	// Read input count
	inputCount, icLen := readVarIntHex(txHex, pos)
	pos += icLen

	if inputIndex >= inputCount {
		panic(fmt.Sprintf(
			"insertUnlockingScript: input index %d out of range (%d inputs)",
			inputIndex, inputCount,
		))
	}

	for i := 0; i < inputCount; i++ {
		// Skip prevTxid (32 bytes = 64 hex chars)
		pos += 64
		// Skip prevOutputIndex (4 bytes = 8 hex chars)
		pos += 8

		// Read scriptSig length
		scriptLen, slLen := readVarIntHex(txHex, pos)

		if i == inputIndex {
			// Build the replacement: new varint length + new script data
			newScriptByteLen := len(unlockScript) / 2
			newVarInt := writeVarIntHex(newScriptByteLen)

			before := txHex[:pos]
			after := txHex[pos+slLen+scriptLen*2:]
			return before + newVarInt + unlockScript + after
		}

		// Skip this input's scriptSig + sequence (4 bytes = 8 hex chars)
		pos += slLen + scriptLen*2 + 8
	}

	panic(fmt.Sprintf(
		"insertUnlockingScript: input index %d out of range",
		inputIndex,
	))
}

// readVarIntHex reads a Bitcoin varint from a hex string at the given position.
// Returns the decoded value and the number of hex characters consumed.
func readVarIntHex(hex string, pos int) (int, int) {
	first := hexByteAt(hex, pos)
	if first < 0xfd {
		return int(first), 2
	}
	if first == 0xfd {
		lo := hexByteAt(hex, pos+2)
		hi := hexByteAt(hex, pos+4)
		return int(lo) | (int(hi) << 8), 6
	}
	if first == 0xfe {
		b0 := hexByteAt(hex, pos+2)
		b1 := hexByteAt(hex, pos+4)
		b2 := hexByteAt(hex, pos+6)
		b3 := hexByteAt(hex, pos+8)
		return int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24), 10
	}
	// 0xff — 8-byte varint; handle the low 4 bytes
	b0 := hexByteAt(hex, pos+2)
	b1 := hexByteAt(hex, pos+4)
	b2 := hexByteAt(hex, pos+6)
	b3 := hexByteAt(hex, pos+8)
	return int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24), 18
}

// writeVarIntHex encodes a number as a Bitcoin varint in hex.
func writeVarIntHex(n int) string {
	if n < 0xfd {
		return fmt.Sprintf("%02x", n)
	}
	if n <= 0xffff {
		lo := n & 0xff
		hi := (n >> 8) & 0xff
		return fmt.Sprintf("fd%02x%02x", lo, hi)
	}
	if n <= 0xffffffff {
		return "fe" + toLittleEndian32(n)
	}
	panic("writeVarIntHex: value too large")
}

func hexByteAt(hex string, pos int) uint64 {
	val, _ := parseHexByte(hex[pos : pos+2])
	return val
}

func parseHexByte(s string) (uint64, error) {
	var val uint64
	for _, c := range s {
		val <<= 4
		if c >= '0' && c <= '9' {
			val |= uint64(c - '0')
		} else if c >= 'a' && c <= 'f' {
			val |= uint64(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			val |= uint64(c - 'A' + 10)
		}
	}
	return val, nil
}
