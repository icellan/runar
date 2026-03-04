package runar

import (
	"fmt"
)

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
	feeRate ...int64,
) (txHex string, inputCount int) {
	allUtxos := []UTXO{currentUtxo}
	allUtxos = append(allUtxos, additionalUtxos...)

	var totalInput int64
	for _, u := range allUtxos {
		totalInput += u.Satoshis
	}

	// Calculate outputs total
	contractOutputSats := int64(0)
	if newLockingScript != "" {
		if newSatoshis > 0 {
			contractOutputSats = newSatoshis
		} else {
			contractOutputSats = currentUtxo.Satoshis
		}
	}

	// Estimate fee using actual script sizes
	// Input 0 is the contract UTXO with a known unlocking script
	input0Size := 32 + 4 + varIntByteSize(len(unlockingScript)/2) +
		len(unlockingScript)/2 + 4
	additionalInputsSize := (len(allUtxos) - 1) * 148 // P2PKH
	inputsSize := input0Size + additionalInputsSize

	outputsSize := 0
	if newLockingScript != "" {
		outputsSize += 8 + varIntByteSize(len(newLockingScript)/2) +
			len(newLockingScript)/2
	}
	if changeAddress != "" || changeScript != "" {
		outputsSize += 34 // P2PKH change
	}
	estimatedSize := 10 + inputsSize + outputsSize
	rate := int64(1)
	if len(feeRate) > 0 && feeRate[0] > 0 {
		rate = feeRate[0]
	}
	fee := int64(estimatedSize) * rate

	change := totalInput - contractOutputSats - fee

	// Build raw transaction
	var tx string

	// Version (4 bytes LE)
	tx += toLittleEndian32(1)

	// Input count
	tx += encodeVarInt(len(allUtxos))

	// Input 0: contract UTXO with unlocking script
	tx += reverseHex(currentUtxo.Txid)
	tx += toLittleEndian32(currentUtxo.OutputIndex)
	tx += encodeVarInt(len(unlockingScript) / 2)
	tx += unlockingScript
	tx += "ffffffff"

	// Additional inputs (unsigned)
	for i := 1; i < len(allUtxos); i++ {
		utxo := allUtxos[i]
		tx += reverseHex(utxo.Txid)
		tx += toLittleEndian32(utxo.OutputIndex)
		tx += "00" // empty scriptSig
		tx += "ffffffff"
	}

	// Output count
	numOutputs := 0
	if newLockingScript != "" {
		numOutputs++
	}
	if change > 0 && (changeAddress != "" || changeScript != "") {
		numOutputs++
	}
	tx += encodeVarInt(numOutputs)

	// Output 0: new contract state (if stateful)
	if newLockingScript != "" {
		tx += toLittleEndian64(contractOutputSats)
		tx += encodeVarInt(len(newLockingScript) / 2)
		tx += newLockingScript
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

	return tx, len(allUtxos)
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
