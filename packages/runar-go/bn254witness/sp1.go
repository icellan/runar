package bn254witness

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// SP1VKFile is the JSON schema for the SP1 v6.0.0 verifying key stored in
// Rúnar's test fixtures. Values are decimal strings (for big.Int parsing).
// The G2 points are pre-negated, matching SP1's Solidity verifier convention
// — they go into the VerifyingKey verbatim with no further transformation.
type SP1VKFile struct {
	Version      string      `json:"version"`
	Curve        string      `json:"curve"`
	NumPubInputs int         `json:"numPubInputs"`
	Convention   string      `json:"convention"`
	Source       string      `json:"source,omitempty"`
	AlphaG1      sp1G1File   `json:"alphaG1"`
	BetaNegG2    sp1G2File   `json:"betaNegG2"`
	GammaNegG2   sp1G2File   `json:"gammaNegG2"`
	DeltaNegG2   sp1G2File   `json:"deltaNegG2"`
	IC           []sp1G1File `json:"ic"`
}

// sp1G1File is a G1 point in vk.json: two decimal strings x, y (Fp).
type sp1G1File struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// sp1G2File is a G2 point in vk.json: four decimal strings (x0, x1, y0, y1)
// in Rúnar (real, imag) order. Real part is `_0`, imag part is `_1`, matching
// both SP1's Solidity constants and Rúnar's on-chain convention.
type sp1G2File struct {
	X0 string `json:"x0"`
	X1 string `json:"x1"`
	Y0 string `json:"y0"`
	Y1 string `json:"y1"`
}

// LoadSP1VKFromFile reads a vk.json file in the Rúnar SP1 fixture format
// and returns a VerifyingKey ready to feed into GenerateWitness.
//
// The G2 points are already pre-negated in the file, so this function is a
// pure deserialization step — no arithmetic or Fp2 swap is applied. This is
// the architectural goal of the Rúnar Groth16 refactor: SP1 VK constants
// drop in verbatim.
func LoadSP1VKFromFile(path string) (VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: read %s: %w", path, err)
	}

	var file SP1VKFile
	if err := json.Unmarshal(data, &file); err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: parse %s: %w", path, err)
	}

	if file.Curve != "bn254" {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: unsupported curve %q (want bn254)", file.Curve)
	}
	if file.NumPubInputs <= 0 {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: numPubInputs must be > 0, got %d", file.NumPubInputs)
	}
	if len(file.IC) != file.NumPubInputs+1 {
		return VerifyingKey{}, fmt.Errorf(
			"LoadSP1VKFromFile: IC length %d != numPubInputs+1 (%d)",
			len(file.IC), file.NumPubInputs+1,
		)
	}

	alpha, err := parseG1(file.AlphaG1)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: alphaG1: %w", err)
	}
	betaNeg, err := parseG2(file.BetaNegG2)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: betaNegG2: %w", err)
	}
	gammaNeg, err := parseG2(file.GammaNegG2)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: gammaNegG2: %w", err)
	}
	deltaNeg, err := parseG2(file.DeltaNegG2)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: deltaNegG2: %w", err)
	}

	ic := make([]*[2]*big.Int, len(file.IC))
	for i, p := range file.IC {
		pair, err := parseG1(p)
		if err != nil {
			return VerifyingKey{}, fmt.Errorf("LoadSP1VKFromFile: ic[%d]: %w", i, err)
		}
		ic[i] = &pair
	}

	return VerifyingKey{
		AlphaG1:    alpha,
		BetaNegG2:  betaNeg,
		GammaNegG2: gammaNeg,
		DeltaNegG2: deltaNeg,
		IC:         ic,
	}, nil
}

// parseDecimal parses a decimal-string representation of a big.Int. Empty
// strings are rejected (no "default to zero" convenience) because a missing
// field in a VK almost always indicates a schema typo.
func parseDecimal(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty string")
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("not a decimal big integer: %q", s)
	}
	return v, nil
}

func parseG1(p sp1G1File) ([2]*big.Int, error) {
	x, err := parseDecimal(p.X)
	if err != nil {
		return [2]*big.Int{}, fmt.Errorf("x: %w", err)
	}
	y, err := parseDecimal(p.Y)
	if err != nil {
		return [2]*big.Int{}, fmt.Errorf("y: %w", err)
	}
	return [2]*big.Int{x, y}, nil
}

func parseG2(p sp1G2File) ([4]*big.Int, error) {
	x0, err := parseDecimal(p.X0)
	if err != nil {
		return [4]*big.Int{}, fmt.Errorf("x0: %w", err)
	}
	x1, err := parseDecimal(p.X1)
	if err != nil {
		return [4]*big.Int{}, fmt.Errorf("x1: %w", err)
	}
	y0, err := parseDecimal(p.Y0)
	if err != nil {
		return [4]*big.Int{}, fmt.Errorf("y0: %w", err)
	}
	y1, err := parseDecimal(p.Y1)
	if err != nil {
		return [4]*big.Int{}, fmt.Errorf("y1: %w", err)
	}
	return [4]*big.Int{x0, x1, y0, y1}, nil
}

// ParseSP1RawProof parses the 324-byte raw Groth16 proof produced by
// SP1's `Groth16Bn254Proof::raw_proof` field into a Rúnar Proof.
//
// The raw_proof is gnark-crypto's native `groth16_bn254.Proof.WriteRawTo`
// output, called by SP1's Go gnark-ffi wrapper in
// `sp1-recursion-gnark-ffi/go/sp1/utils.go::NewSP1Groth16Proof`. The layout
// (for a commitment-free proof, which is the case for all SP1 v6 proofs):
//
//	bytes   0.. 64  Ar  (G1 uncompressed): x[32] || y[32]
//	bytes  64..192  Bs  (G2 uncompressed): x.A1 || x.A0 || y.A1 || y.A0
//	                                        (gnark stores G2 IMAG-FIRST)
//	bytes 192..256  Krs (G1 uncompressed): x[32] || y[32]
//	bytes 256..260  Commitments slice length (uint32 big-endian)
//	bytes 260..324  CommitmentPok (G1, 64 bytes — often zero for SP1)
//
// Rúnar uses `(x0=real, x1=imag)` for Fp2, so the Bs bytes are swapped
// into Rúnar order during parsing.
//
// For SP1 v6 the Commitments length is always 0 (no Pedersen commitments)
// and CommitmentPok is zero, so the last 68 bytes are ignored. This parser
// enforces that.
//
// NOTE: unlike the full SP1 verifier protocol, raw_proof has NO 4-byte VK
// hash prefix and NO [exit_code, vk_root, proof_nonce] header. Those fields
// are exposed separately via public_inputs and checked by the Solidity
// verifier; they're not part of `raw_proof`. The encoded_proof file is the
// one that carries the Solidity-calldata header.
func ParseSP1RawProof(rawProofHex string) (Proof, error) {
	s := strings.TrimSpace(rawProofHex)
	s = strings.TrimPrefix(s, "0x")

	buf, err := hex.DecodeString(s)
	if err != nil {
		return Proof{}, fmt.Errorf("ParseSP1RawProof: hex decode: %w", err)
	}
	const (
		g1Size = 64
		g2Size = 128
		// Full gnark raw proof = Ar + Bs + Krs + len(Commitments) + CommitmentPok.
		fullSize = g1Size + g2Size + g1Size + 4 + g1Size
	)
	if len(buf) != fullSize {
		return Proof{}, fmt.Errorf("ParseSP1RawProof: want %d bytes, got %d", fullSize, len(buf))
	}

	// 1. Ar (Proof.A)
	ar, err := parseG1Raw(buf[0:g1Size])
	if err != nil {
		return Proof{}, fmt.Errorf("ParseSP1RawProof: Ar: %w", err)
	}

	// 2. Bs (Proof.B) — gnark imag-first, swap to Rúnar (real, imag)
	bs, err := parseG2RawGnarkImagFirst(buf[g1Size : g1Size+g2Size])
	if err != nil {
		return Proof{}, fmt.Errorf("ParseSP1RawProof: Bs: %w", err)
	}

	// 3. Krs (Proof.C)
	krsOff := g1Size + g2Size
	krs, err := parseG1Raw(buf[krsOff : krsOff+g1Size])
	if err != nil {
		return Proof{}, fmt.Errorf("ParseSP1RawProof: Krs: %w", err)
	}

	// 4. Commitments slice length — must be zero for SP1 v6
	commitOff := krsOff + g1Size
	nbCommitments := binary.BigEndian.Uint32(buf[commitOff : commitOff+4])
	if nbCommitments != 0 {
		return Proof{}, fmt.Errorf(
			"ParseSP1RawProof: expected 0 Pedersen commitments for SP1 v6, got %d",
			nbCommitments,
		)
	}

	// 5. CommitmentPok — read but not used. We don't enforce it to be zero
	//    because gnark may encode the infinity point here as (0,0) or as a
	//    flagged sentinel; either way it's ignored by SP1's Solidity verifier
	//    when nbCommitments==0.

	return Proof{A: ar, B: bs, C: krs}, nil
}

// parseG1Raw reads a 64-byte uncompressed G1 point in big-endian Fp order
// (x[32] || y[32]) — the same layout gnark-crypto uses in WriteRawTo for G1.
func parseG1Raw(buf []byte) ([2]*big.Int, error) {
	if len(buf) != 64 {
		return [2]*big.Int{}, fmt.Errorf("parseG1Raw: want 64 bytes, got %d", len(buf))
	}
	x := new(big.Int).SetBytes(buf[0:32])
	y := new(big.Int).SetBytes(buf[32:64])
	return [2]*big.Int{x, y}, nil
}

// parseG2RawGnarkImagFirst reads a 128-byte uncompressed G2 point in gnark's
// native WriteRawTo order (x.A1 || x.A0 || y.A1 || y.A0, imag-first) and
// returns it in Rúnar (real, imag) order [x0, x1, y0, y1].
//
// Note: gnark encodes the compression mode in the top 2 bits of byte 0
// (mMask = 0b11 << 6). For uncompressed points (mUncompressed = 0b00)
// those bits are zero so the mask strip is a no-op, but we do it anyway
// to stay robust against future gnark revisions that might repurpose the
// sentinel. This matches gnark's own SetBytes behavior.
func parseG2RawGnarkImagFirst(buf []byte) ([4]*big.Int, error) {
	if len(buf) != 128 {
		return [4]*big.Int{}, fmt.Errorf("parseG2RawGnarkImagFirst: want 128 bytes, got %d", len(buf))
	}
	// gnark/ecc/bn254/marshal.go: mMask = 0b11 << 6 (top 2 bits, = 0xC0).
	// Stripping is safe for uncompressed points (where those bits are zero)
	// and correct for the compressed variants too (though we only handle
	// uncompressed here).
	var xA1Bytes [32]byte
	copy(xA1Bytes[:], buf[0:32])
	const gnarkMMask = byte(0b11000000)
	xA1Bytes[0] &^= gnarkMMask

	xA1 := new(big.Int).SetBytes(xA1Bytes[:])
	xA0 := new(big.Int).SetBytes(buf[32:64])
	yA1 := new(big.Int).SetBytes(buf[64:96])
	yA0 := new(big.Int).SetBytes(buf[96:128])

	// Swap to Rúnar order: (x0=real, x1=imag, y0=real, y1=imag)
	return [4]*big.Int{xA0, xA1, yA0, yA1}, nil
}

// LoadSP1PublicInputs reads the newline-separated decimal scalars from
// `groth16_public_inputs.txt`. Empty lines are tolerated and skipped.
// The returned slice preserves file order so callers can feed it directly
// into GenerateWitness (alongside the matching VK IC length).
func LoadSP1PublicInputs(path string) ([]*big.Int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("LoadSP1PublicInputs: read %s: %w", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]*big.Int, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, err := parseDecimal(line)
		if err != nil {
			return nil, fmt.Errorf("LoadSP1PublicInputs: line %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}
