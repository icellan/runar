package runar

import "fmt"

// checkedMul returns a * b, panicking if the result overflows int64.
// Bitcoin Script supports arbitrary-precision integers, but Go's int64
// has a ±9.2×10¹⁸ range. This helper ensures silent wraparound never
// produces wrong results in native Go tests.
func checkedMul(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	result := a * b
	if result/a != b {
		panic(fmt.Sprintf("runar: int64 overflow in %d * %d — Bitcoin Script supports arbitrary precision but Go uses int64; see compilers/go/README.md", a, b))
	}
	return result
}

// checkedAdd returns a + b, panicking if the result overflows int64.
func checkedAdd(a, b int64) int64 {
	result := a + b
	// Overflow: positive + positive = negative, or negative + negative = positive.
	if (b > 0 && result < a) || (b < 0 && result > a) {
		panic(fmt.Sprintf("runar: int64 overflow in %d + %d — Bitcoin Script supports arbitrary precision but Go uses int64; see compilers/go/README.md", a, b))
	}
	return result
}
