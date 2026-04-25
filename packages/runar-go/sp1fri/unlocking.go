// Off-chain unlocking-script encoder for the SP1 v6.0.2 STARK / FRI
// verifier deployed via the Rúnar `runar.VerifySP1FRI(...)` intrinsic.
//
// The on-chain verifier emitted by
// `compilers/go/codegen/sp1_fri.go::EmitFullSP1FriVerifierBody` assumes the
// unlocking script has pushed every parsed proof field as canonical
// 4-byte LE u32s in canonical declaration order (deepest-first), followed
// by `numChunks` raw proof-body chunks, then the three typed ByteString
// args (proofBlob, publicValues, sp1VKeyHash) on top in declaration
// order. The authoritative spec for the push order is
// `compilers/go/codegen/sp1_fri.go::sp1FriPrePushedFieldNames`. This file
// generalises the inline prelude in `compilers/go/codegen/sp1_fri_test.go`
// (TestSp1FriVerifier_AcceptsMinimalGuestFixture, lines 569-642) into a
// reusable host-side API.
//
// Usage:
//
//	proof, _ := sp1fri.DecodeProof(proofBlobRaw)
//	if err := sp1fri.Verify(proof, publicValuesU32); err != nil { ... }
//	bytes, err := sp1fri.EncodeUnlockingScript(
//	    proof, proofBlobRaw, publicValuesBytes, sp1VKeyHashBytes,
//	    sp1fri.MinimalGuestParams())
//	if err != nil { ... }
//	// `bytes` is raw Bitcoin Script ready to be wrapped in the spending
//	// transaction's input UnlockingScript.
//
// Refer to docs/sp1-fri-verifier.md §2.1 for the canonical declaration
// order and §10 for the production-deployment per-query layout.
//
// IMPORTANT: this file deliberately re-implements its own push encoders
// (rather than importing `compilers/go/codegen`) to avoid an import
// cycle: `codegen` test code imports `sp1fri`, so `sp1fri` cannot
// transitively import `codegen` (Go forbids test-induced cycles too).
// The encoders below mirror `compilers/go/codegen/emit.go`
// `encodePushBigInt` / `encodePushData` byte-for-byte; the assertion that
// they stay aligned is the script-VM acceptance test.

package sp1fri

import (
	"bytes"
	"fmt"
	"math/big"
)

// ParamSet captures the SP1 STARK / FRI parameter tuple that the
// host-side encoder needs to know in order to materialise the canonical
// pre-pushed-field name list. It mirrors
// `compilers/go/codegen/sp1_fri.go::SP1FriVerifierParams` field-for-field
// so callers do not need to import the compiler package.
//
// Each compiled `runar.VerifySP1FRI(...)` locking script is parameterised
// by exactly one ParamSet at compile time; the unlocking script MUST be
// encoded with the matching ParamSet or the verifier will reject (Step 1
// SHA-256 binding will fail and/or the field-push layer will not
// align with the locking script's tracker layout).
type ParamSet struct {
	// LogBlowup is the FRI rate parameter. PoC fixture: 2.
	LogBlowup int
	// NumQueries is the number of FRI queries. PoC: 2; production: ~100.
	NumQueries int
	// MerkleDepth is the input MMCS Merkle tree depth. PoC: 4.
	MerkleDepth int
	// SumcheckRounds — currently unused by the orchestrator but kept here
	// for parity with the codegen-side struct so callers can build a
	// ParamSet from a single source of truth.
	SumcheckRounds int
	// LogFinalPolyLen — `len(finalPoly) = 1 << LogFinalPolyLen`. PoC: 2.
	LogFinalPolyLen int
	// CommitPoWBits — leading-zero-bits requirement for each round's
	// commit-phase witness. PoC: 1.
	CommitPoWBits int
	// QueryPoWBits — leading-zero-bits requirement for the query-phase
	// witness. PoC: 1.
	QueryPoWBits int
	// MaxLogArity — FRI folding arity per round. PoC + production: 1.
	MaxLogArity int
	// NumPolynomials — for the PoC AIR width=2 + quotient chunks=1 fully
	// determines the OpenedValues shape; the encoder consults
	// `proof.OpenedValues` directly so this is informational here.
	NumPolynomials int
	// PublicValuesByteSize — length of the publicValues ByteString in
	// bytes. PoC fixture: 12.
	PublicValuesByteSize int
	// SP1VKeyHashByteSize — length of the sp1VKeyHash ByteString in
	// bytes. PoC fixture: 0 (no SP1 outer wrapper); production: 32.
	SP1VKeyHashByteSize int
	// DegreeBits is the trace-domain log2-size. PoC: 3.
	DegreeBits int
	// BaseDegreeBits — `degreeBits - is_zk`. PoC: 3 (non-ZK).
	BaseDegreeBits int
	// PreprocessedWidth — 0 when there is no preprocessed trace (Fib AIR).
	PreprocessedWidth int

	// NumChunks is the number of dummy proof-body chunks the unlocking
	// script pushes for the Step 1 SHA-256 binding. The validated
	// `EmitFullSP1FriVerifierBody` orchestrator hardcodes this to 8 (see
	// `sp1_fri.go:316`); we expose it here so the encoder stays in lock
	// step with future codegen evolutions but default to 8 via
	// `MinimalGuestParams()`.
	NumChunks int
}

// MinimalGuestParams returns the canonical PoC parameter set. It mirrors
// `compilers/go/codegen/sp1_fri.go::DefaultSP1FriParams()` byte-for-byte
// (validated against the
// `tests/vectors/sp1/fri/minimal-guest/proof.postcard` fixture by
// `TestSp1FriVerifier_AcceptsMinimalGuestFixture`).
func MinimalGuestParams() ParamSet {
	return ParamSet{
		LogBlowup:            2,
		NumQueries:           2,
		MerkleDepth:          4,
		SumcheckRounds:       4,
		LogFinalPolyLen:      2,
		CommitPoWBits:        1,
		QueryPoWBits:         1,
		MaxLogArity:          1,
		NumPolynomials:       2,
		PublicValuesByteSize: 12, // [0,1,21] u32-LE-packed = 12 bytes
		SP1VKeyHashByteSize:  0,  // PoC fixture has no SP1 wrapper
		DegreeBits:           3,
		BaseDegreeBits:       3,
		PreprocessedWidth:    0,
		NumChunks:            8, // matches sp1_fri.go::EmitFullSP1FriVerifierBody numChunks
	}
}

// EncodeUnlockingScript builds the raw Bitcoin Script byte sequence that
// pairs with a compiled `runar.VerifySP1FRI(...)` locking script.
//
// The push layout (deepest → top) mirrors
// `compilers/go/codegen/sp1_fri.go::sp1FriPrePushedFieldNames`:
//
//  1. Step 8 inputs (deepest):
//     - queryPowWitness            (KoalaBear element, canonical u32 LE)
//     - logArities[r] for r in [numRounds-1, ..., 0]
//     - finalPoly[i].c0..c3 for i in [0, finalPolyLen)
//     - per-round (r in [0, numRounds)):
//     - friCommitDigests[r][0..7] (8 KoalaBear elements)
//     - commitPowWitnesses[r]
//
//  2. Steps 2-5 inputs:
//     - traceLocal[i].c0..c3       for i in [0, 2)
//     - traceNext[i].c0..c3        for i in [0, 2)
//     - quotientChunks[0][i].c0..c3 for i in [0, 4)
//     - quotientDigest[0..7]
//     - traceDigest[0..7]
//     - publicValues               (single ByteString)
//
//  3. Raw proof-body chunks (params.NumChunks) — arbitrary contiguous
//     slices whose concatenation == proofBlob (see `chunkProof` in
//     `compilers/go/codegen/sp1_fri_test.go:61` and Step 1 binding
//     rationale at `sp1_fri.go::EmitProofBlobBindingHash`).
//
//  4. Typed args (top, in declaration order):
//     - proofBlob
//     - publicValues  (re-pushed; the orchestrator's Step 1e discards this
//     copy and uses the deeper `_obs_public_values` slot)
//     - sp1VKeyHash   (only when params.SP1VKeyHashByteSize > 0)
//
// Returns the raw Bitcoin Script bytes (uses OP_PUSHDATA*/OP_*/etc).
// Caller wraps in transaction input UnlockingScript.
//
// The caller MUST ensure `len(publicValues) == params.PublicValuesByteSize`
// and `len(sp1VKeyHash) == params.SP1VKeyHashByteSize`, otherwise the
// returned script will not match the locking script's compile-time
// expectations and the verifier will reject.
func EncodeUnlockingScript(
	proof *Proof,
	proofBlobRaw []byte,
	publicValues []byte,
	sp1VKeyHash []byte,
	params ParamSet,
) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("EncodeUnlockingScript: proof is nil")
	}
	if len(proofBlobRaw) == 0 {
		return nil, fmt.Errorf("EncodeUnlockingScript: proofBlobRaw is empty")
	}
	if params.NumChunks < 1 {
		return nil, fmt.Errorf("EncodeUnlockingScript: NumChunks must be >= 1, got %d", params.NumChunks)
	}
	if params.NumQueries < 1 {
		return nil, fmt.Errorf("EncodeUnlockingScript: NumQueries must be >= 1, got %d", params.NumQueries)
	}
	if params.LogFinalPolyLen < 0 {
		return nil, fmt.Errorf("EncodeUnlockingScript: LogFinalPolyLen must be >= 0, got %d", params.LogFinalPolyLen)
	}
	if params.NumChunks > len(proofBlobRaw) {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: NumChunks=%d > |proofBlobRaw|=%d (cannot split into non-empty chunks)",
			params.NumChunks, len(proofBlobRaw))
	}
	if params.PublicValuesByteSize > 0 && len(publicValues) != params.PublicValuesByteSize {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: publicValues length mismatch: want %d got %d",
			params.PublicValuesByteSize, len(publicValues))
	}
	if params.SP1VKeyHashByteSize > 0 && len(sp1VKeyHash) != params.SP1VKeyHashByteSize {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: sp1VKeyHash length mismatch: want %d got %d",
			params.SP1VKeyHashByteSize, len(sp1VKeyHash))
	}

	// ---------- Project proof fields into canonical KoalaBear form ----------
	traceLocal := make([]Ext4, len(proof.OpenedValues.TraceLocal))
	for i, e := range proof.OpenedValues.TraceLocal {
		traceLocal[i] = FromKbExt4(e)
	}
	if proof.OpenedValues.TraceNext == nil {
		return nil, fmt.Errorf("EncodeUnlockingScript: proof.OpenedValues.TraceNext is nil — fixture missing transition row")
	}
	traceNext := make([]Ext4, len(*proof.OpenedValues.TraceNext))
	for i, e := range *proof.OpenedValues.TraceNext {
		traceNext[i] = FromKbExt4(e)
	}
	if len(traceLocal) < 2 || len(traceNext) < 2 {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: AIR width mismatch: want >=2 trace cols, got local=%d next=%d",
			len(traceLocal), len(traceNext))
	}
	if len(proof.OpenedValues.QuotientChunks) < 1 {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: proof.OpenedValues.QuotientChunks is empty (need >=1 quotient batch)")
	}
	quotChunks0 := proof.OpenedValues.QuotientChunks[0]
	if len(quotChunks0) < 4 {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: quotientChunks[0] has %d Ext4 elements, want >=4",
			len(quotChunks0))
	}
	quotChunks0Canon := make([]Ext4, len(quotChunks0))
	for i, e := range quotChunks0 {
		quotChunks0Canon[i] = FromKbExt4(e)
	}

	if len(proof.Commitments.Trace) < 1 || len(proof.Commitments.QuotientChunks) < 1 {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: missing trace/quotient commitments (cap_height=0 expects 1 digest each)")
	}
	traceDigest := CanonicalDigest(proof.Commitments.Trace[0])
	quotientDigest := CanonicalDigest(proof.Commitments.QuotientChunks[0])

	numRounds := len(proof.OpeningProof.CommitPhaseCommits)
	if numRounds < 1 {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: proof.OpeningProof.CommitPhaseCommits is empty (need >=1 round)")
	}
	if len(proof.OpeningProof.CommitPowWitnesses) != numRounds {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: CommitPowWitnesses len=%d != numRounds=%d",
			len(proof.OpeningProof.CommitPowWitnesses), numRounds)
	}
	friCommitDigests := make([][8]uint32, numRounds)
	for r, cap := range proof.OpeningProof.CommitPhaseCommits {
		if len(cap) < 1 {
			return nil, fmt.Errorf(
				"EncodeUnlockingScript: CommitPhaseCommits[%d] is empty (cap_height=0 expects 1 digest)", r)
		}
		friCommitDigests[r] = CanonicalDigest(cap[0])
	}
	commitPowWitnesses := make([]uint32, numRounds)
	for r, w := range proof.OpeningProof.CommitPowWitnesses {
		commitPowWitnesses[r] = w.Canonical()
	}

	finalPolyLen := 1 << params.LogFinalPolyLen
	if len(proof.OpeningProof.FinalPoly) != finalPolyLen {
		return nil, fmt.Errorf(
			"EncodeUnlockingScript: FinalPoly len=%d != 1<<LogFinalPolyLen=%d",
			len(proof.OpeningProof.FinalPoly), finalPolyLen)
	}
	finalPoly := make([]Ext4, finalPolyLen)
	for i, e := range proof.OpeningProof.FinalPoly {
		finalPoly[i] = FromKbExt4(e)
	}

	logArities := make([]int, numRounds)
	if len(proof.OpeningProof.QueryProofs) > 0 {
		ops := proof.OpeningProof.QueryProofs[0].CommitPhaseOpenings
		if len(ops) != numRounds {
			return nil, fmt.Errorf(
				"EncodeUnlockingScript: QueryProofs[0].CommitPhaseOpenings len=%d != numRounds=%d",
				len(ops), numRounds)
		}
		for r, op := range ops {
			logArities[r] = int(op.LogArity)
		}
	}
	queryPowWitness := proof.OpeningProof.QueryPowWitness.Canonical()

	// ---------- Emit raw Bitcoin Script bytes ----------
	//
	// The order below MUST match `sp1FriPrePushedFieldNames` byte-for-byte;
	// each block is annotated with the corresponding line range in
	// `sp1_fri.go` and `sp1_fri_test.go::TestSp1FriVerifier_AcceptsMinimalGuestFixture`
	// (the authoritative reference).
	var buf bytes.Buffer

	// 1a. Step 8 inputs (deepest of the transcript-input layer). Mirrors
	// sp1_fri.go::sp1FriPrePushedFieldNames §1 (lines 207-224) and
	// sp1_fri_test.go:583-598.
	emitPushUint32(&buf, queryPowWitness)
	for r := numRounds - 1; r >= 0; r-- {
		emitPushInt(&buf, int64(logArities[r]))
	}
	for i := 0; i < finalPolyLen; i++ {
		ext := finalPoly[i]
		for j := 0; j < 4; j++ {
			emitPushUint32(&buf, ext[j])
		}
	}
	for r := 0; r < numRounds; r++ {
		for i := 0; i < 8; i++ {
			emitPushUint32(&buf, friCommitDigests[r][i])
		}
		emitPushUint32(&buf, commitPowWitnesses[r])
	}

	// 1b. Steps 2-5 inputs (above Step 8 inputs). Mirrors
	// sp1_fri.go::sp1FriPrePushedFieldNames §3 (lines 226-255) and
	// sp1_fri_test.go:602-626.
	for i := 0; i < 2; i++ {
		ext := traceLocal[i]
		for j := 0; j < 4; j++ {
			emitPushUint32(&buf, ext[j])
		}
	}
	for i := 0; i < 2; i++ {
		ext := traceNext[i]
		for j := 0; j < 4; j++ {
			emitPushUint32(&buf, ext[j])
		}
	}
	for i := 0; i < 4; i++ {
		ext := quotChunks0Canon[i]
		for j := 0; j < 4; j++ {
			emitPushUint32(&buf, ext[j])
		}
	}
	for i := 0; i < 8; i++ {
		emitPushUint32(&buf, quotientDigest[i])
	}
	for i := 0; i < 8; i++ {
		emitPushUint32(&buf, traceDigest[i])
	}
	emitPushBytes(&buf, publicValues) // _obs_public_values

	// 2. Raw proof-body chunks (above transcript inputs). Mirrors
	// sp1_fri_test.go:629-631 + chunkProof helper at line 61.
	chunks := chunkProofBytes(proofBlobRaw, params.NumChunks)
	for _, c := range chunks {
		emitPushBytes(&buf, c)
	}

	// 3. proofBlob typed arg.
	emitPushBytes(&buf, proofBlobRaw)

	// 4. publicValues typed arg (re-pushed; the orchestrator discards this
	// copy and uses the deeper _obs_public_values slot — see
	// sp1_fri.go::EmitFullSP1FriVerifierBody §1e for the rationale).
	emitPushBytes(&buf, publicValues)

	// 5. sp1VKeyHash typed arg — only when SP1VKeyHashByteSize > 0.
	if params.SP1VKeyHashByteSize > 0 {
		emitPushBytes(&buf, sp1VKeyHash)
	}

	return buf.Bytes(), nil
}

// chunkProofBytes splits `bs` into `n` contiguous, non-empty pieces in
// canonical (left-to-right) order. The resulting concatenation equals
// `bs` byte-for-byte. Mirrors `chunkProof(t, bs, n)` in
// `compilers/go/codegen/sp1_fri_test.go:61` and is the only chunking the
// Step 1 SHA-256 binding requires (the binding only checks
// `sha256(concat(chunks)) == sha256(proofBlob)`; structural per-field
// decoding lives in the field-push layer above the chunks).
//
// The caller has already validated `n >= 1` and `n <= len(bs)`.
func chunkProofBytes(bs []byte, n int) [][]byte {
	chunkSize := len(bs) / n
	out := make([][]byte, n)
	for i := 0; i < n-1; i++ {
		out[i] = bs[i*chunkSize : (i+1)*chunkSize]
	}
	out[n-1] = bs[(n-1)*chunkSize:]
	return out
}

// =============================================================================
// Bitcoin Script push encoders — byte-for-byte copies of the helpers in
// `compilers/go/codegen/emit.go`. Re-implemented here to break the
// import cycle (codegen tests already import sp1fri).
// =============================================================================

// emitPushUint32 pushes a canonical KoalaBear element (or any uint32) as
// a Bitcoin Script number. Plonky3 fits all KoalaBear elements in 31
// bits so int64 conversion is lossless and the resulting push is at most
// 4 bytes (LE sign-magnitude with a leading 0x00 byte to avoid the
// high-bit sign flag).
func emitPushUint32(buf *bytes.Buffer, v uint32) {
	emitPushBigInt(buf, new(big.Int).SetInt64(int64(v)))
}

// emitPushInt pushes a small signed integer (e.g. logArities widened
// from uint8).
func emitPushInt(buf *bytes.Buffer, v int64) {
	emitPushBigInt(buf, big.NewInt(v))
}

// emitPushBytes pushes a raw ByteString using the smallest available
// PUSHDATA opcode. Mirrors `compilers/go/codegen/emit.go::encodePushData`
// (lines 304-357) byte-for-byte.
func emitPushBytes(buf *bytes.Buffer, data []byte) {
	length := len(data)

	if length == 0 {
		// OP_0 — pushes empty array onto the stack
		buf.WriteByte(0x00)
		return
	}

	// MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16, 0x81 must
	// use OP_1NEGATE. Note: 0x00 is NOT converted to OP_0 because OP_0
	// pushes an empty []byte, not [0x00].
	if length == 1 {
		b := data[0]
		if b >= 1 && b <= 16 {
			buf.WriteByte(0x50 + b) // OP_1 through OP_16
			return
		}
		if b == 0x81 {
			buf.WriteByte(0x4f) // OP_1NEGATE
			return
		}
	}

	switch {
	case length <= 75:
		buf.WriteByte(byte(length))
		buf.Write(data)
	case length <= 0xff:
		buf.WriteByte(0x4c) // OP_PUSHDATA1
		buf.WriteByte(byte(length))
		buf.Write(data)
	case length <= 0xffff:
		buf.WriteByte(0x4d) // OP_PUSHDATA2
		buf.WriteByte(byte(length & 0xff))
		buf.WriteByte(byte((length >> 8) & 0xff))
		buf.Write(data)
	default:
		buf.WriteByte(0x4e) // OP_PUSHDATA4
		buf.WriteByte(byte(length & 0xff))
		buf.WriteByte(byte((length >> 8) & 0xff))
		buf.WriteByte(byte((length >> 16) & 0xff))
		buf.WriteByte(byte((length >> 24) & 0xff))
		buf.Write(data)
	}
}

// emitPushBigInt pushes a big.Int as a script number, using the
// small-integer opcodes (OP_0..OP_16, OP_1NEGATE) where possible.
// Mirrors `compilers/go/codegen/emit.go::encodePushBigInt` byte-for-byte.
func emitPushBigInt(buf *bytes.Buffer, n *big.Int) {
	if n.Sign() == 0 {
		buf.WriteByte(0x00) // OP_0
		return
	}
	if n.Cmp(bigIntNegOne) == 0 {
		buf.WriteByte(0x4f) // OP_1NEGATE
		return
	}
	if n.Sign() > 0 && n.Cmp(bigInt16) <= 0 {
		buf.WriteByte(byte(0x50 + n.Int64())) // OP_1 .. OP_16
		return
	}
	numBytes := encodeScriptNumberLE(n)
	emitPushBytes(buf, numBytes)
}

// encodeScriptNumberLE encodes `n` as Bitcoin Script LE sign-magnitude.
// Mirrors `compilers/go/codegen/emit.go::encodeScriptNumber`.
func encodeScriptNumberLE(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}
	negative := n.Sign() < 0
	abs := new(big.Int).Abs(n)

	var out []byte
	mask := big.NewInt(0xff)
	for abs.Sign() > 0 {
		b := new(big.Int).And(abs, mask)
		out = append(out, byte(b.Int64()))
		abs.Rsh(abs, 8)
	}
	last := out[len(out)-1]
	if last&0x80 != 0 {
		if negative {
			out = append(out, 0x80)
		} else {
			out = append(out, 0x00)
		}
	} else if negative {
		out[len(out)-1] = last | 0x80
	}
	return out
}

var (
	bigIntNegOne = big.NewInt(-1)
	bigInt16     = big.NewInt(16)
)
