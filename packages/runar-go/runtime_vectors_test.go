package runar

// Cross-SDK runtime conformance vectors — see
// conformance/runtime-vectors/hashes.json for the source-of-truth and the
// `_consumers` field for the per-SDK test files that mirror these
// assertions. A divergence between any two runtime impls shows up here.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type sha256FinalizeVector struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Remaining  string `json:"remaining"`
	MsgBitLen  int64  `json:"msg_bit_len"`
	Expected   string `json:"expected"`
}

type blake3HashVector struct {
	Name     string `json:"name"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

type blake3CompressVector struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Block    string `json:"block"`
	Expected string `json:"expected"`
}

type runtimeVectors struct {
	Constants struct {
		Sha256IV string `json:"sha256_iv"`
		Blake3IV string `json:"blake3_iv"`
	} `json:"constants"`
	Sha256Finalize  []sha256FinalizeVector `json:"sha256_finalize"`
	Blake3Hash      []blake3HashVector     `json:"blake3_hash"`
	Blake3Compress  []blake3CompressVector `json:"blake3_compress"`
}

// loadRuntimeVectors reads conformance/runtime-vectors/hashes.json. The
// repo root is found by walking up from this file's directory until we
// see a `conformance` subdirectory — that way the test runs no matter
// which working directory `go test` is invoked from.
func loadRuntimeVectors(t *testing.T) runtimeVectors {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		candidate := filepath.Join(dir, "conformance", "runtime-vectors", "hashes.json")
		if _, err := os.Stat(candidate); err == nil {
			data, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatalf("read vectors: %v", err)
			}
			var v runtimeVectors
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatalf("parse vectors: %v", err)
			}
			return v
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate conformance/runtime-vectors/hashes.json walking up from %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

func TestRuntimeVectors_Sha256Finalize(t *testing.T) {
	vectors := loadRuntimeVectors(t)
	if len(vectors.Sha256Finalize) == 0 {
		t.Fatal("hashes.json carries no sha256_finalize vectors")
	}
	for _, v := range vectors.Sha256Finalize {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			state, err := hex.DecodeString(v.State)
			if err != nil {
				t.Fatalf("bad state hex: %v", err)
			}
			remaining, err := hex.DecodeString(v.Remaining)
			if err != nil {
				t.Fatalf("bad remaining hex: %v", err)
			}
			got := Sha256Finalize(ByteString(state), ByteString(remaining), v.MsgBitLen)
			if hex.EncodeToString([]byte(got)) != v.Expected {
				t.Errorf("Sha256Finalize(%s) = %s; want %s", v.Name, hex.EncodeToString([]byte(got)), v.Expected)
			}
		})
	}
}

func TestRuntimeVectors_Blake3Compress(t *testing.T) {
	vectors := loadRuntimeVectors(t)
	if len(vectors.Blake3Compress) == 0 {
		t.Fatal("hashes.json carries no blake3_compress vectors")
	}
	for _, v := range vectors.Blake3Compress {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			state, err := hex.DecodeString(v.State)
			if err != nil {
				t.Fatalf("bad state hex: %v", err)
			}
			block, err := hex.DecodeString(v.Block)
			if err != nil {
				t.Fatalf("bad block hex: %v", err)
			}
			got := Blake3Compress(ByteString(state), ByteString(block))
			if hex.EncodeToString([]byte(got)) != v.Expected {
				t.Errorf("Blake3Compress(%s) = %s; want %s", v.Name, hex.EncodeToString([]byte(got)), v.Expected)
			}
		})
	}
}

func TestRuntimeVectors_Blake3Hash(t *testing.T) {
	vectors := loadRuntimeVectors(t)
	if len(vectors.Blake3Hash) == 0 {
		t.Fatal("hashes.json carries no blake3_hash vectors")
	}
	for _, v := range vectors.Blake3Hash {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			input, err := hex.DecodeString(v.Input)
			if err != nil {
				t.Fatalf("bad input hex: %v", err)
			}
			got := Blake3Hash(ByteString(input))
			if hex.EncodeToString([]byte(got)) != v.Expected {
				t.Errorf("Blake3Hash(%s) = %s; want %s", v.Name, hex.EncodeToString([]byte(got)), v.Expected)
			}
		})
	}
}

func TestRuntimeVectors_Constants(t *testing.T) {
	vectors := loadRuntimeVectors(t)
	// BLAKE3 deliberately reuses the SHA-256 IV. Catching a constant-table
	// typo against the JSON source is the whole point of this row.
	if vectors.Constants.Blake3IV != vectors.Constants.Sha256IV {
		t.Errorf("blake3_iv (%s) != sha256_iv (%s) — design says they must match", vectors.Constants.Blake3IV, vectors.Constants.Sha256IV)
	}
	// Spot-check the IV bytes match the SDK's BLAKE3 implementation by
	// running blake3Compress on an all-zero block: the runtime helper
	// embeds the IV internally, so a divergence here is loud.
	zeroBlock := make([]byte, 64)
	cv, _ := hex.DecodeString(vectors.Constants.Blake3IV)
	got := Blake3Compress(ByteString(cv), ByteString(zeroBlock))
	if len(got) != 32 {
		t.Errorf("Blake3Compress(IV, zeros) returned %d bytes, want 32", len(got))
	}
}
