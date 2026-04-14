package runar

import (
	"encoding/json"
	"os"
	"testing"
)

type poseidon2VectorFile struct {
	Vectors []poseidon2Vector `json:"vectors"`
}

type poseidon2Vector struct {
	Op       string   `json:"op"`
	Input    []int64  `json:"input,omitempty"`
	Left     []int64  `json:"left,omitempty"`
	Right    []int64  `json:"right,omitempty"`
	Expected []int64  `json:"expected"`
	Desc     string   `json:"description"`
}

func loadPoseidon2Vectors(t *testing.T) poseidon2VectorFile {
	data, err := os.ReadFile("../../tests/vectors/poseidon2_koalabear.json")
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var f poseidon2VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return f
}

func TestPoseidon2KB_MockMatchesPlonky3(t *testing.T) {
	vf := loadPoseidon2Vectors(t)

	for _, v := range vf.Vectors {
		t.Run(v.Desc, func(t *testing.T) {
			switch v.Op {
			case "permute":
				var state [poseidon2KBWidth]int64
				copy(state[:], v.Input)
				poseidon2KBPermute(&state)
				for i := 0; i < poseidon2KBWidth; i++ {
					if state[i] != v.Expected[i] {
						t.Errorf("state[%d] = %d, want %d", i, state[i], v.Expected[i])
					}
				}
			case "compress":
				var left, right [8]int64
				copy(left[:], v.Left)
				copy(right[:], v.Right)
				result := poseidon2KBCompress(left, right)
				for i := 0; i < 8; i++ {
					if result[i] != v.Expected[i] {
						t.Errorf("result[%d] = %d, want %d", i, result[i], v.Expected[i])
					}
				}
			}
		})
	}
}
