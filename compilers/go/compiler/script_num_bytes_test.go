package compiler

import "math/big"

// scriptNumBytes encodes n in Bitcoin Script number form (little-endian,
// sign-magnitude).
func scriptNumBytes(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}
	neg := n.Sign() < 0
	be := new(big.Int).Abs(n).Bytes()
	le := make([]byte, len(be))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	if le[len(le)-1]&0x80 != 0 {
		le = append(le, 0)
	}
	if neg {
		le[len(le)-1] |= 0x80
	}
	return le
}

// ScriptNumBytesForTest exposes scriptNumBytes to the external test package
// (poseidon2_merkle_root_binding_test.go, which imports packages/runar-go and
// so cannot live in package compiler).
var ScriptNumBytesForTest = scriptNumBytes
