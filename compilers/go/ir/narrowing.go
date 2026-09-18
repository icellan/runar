package ir

import (
	"fmt"
	"math"
	"math/big"
)

// IntValueExact narrows an arbitrary-precision compile-time constant to an
// `int`, refusing rather than truncating when the value does not fit.
//
// This exists because `big.Int.Int64()` is a *silent modular* narrowing: it
// returns the low 64 bits reinterpreted as a signed value whenever
// `IsInt64()` is false. Three distinct wrong outcomes follow from using it
// as if it were a conversion:
//
//	2^63      -> math.MinInt64 (a positive value becomes negative)
//	2^64 + 10 -> 10            (an astronomically large value becomes small)
//	10^20     -> ~7.77e18      (a value the caller never wrote)
//
// Every downstream range check (`n > 0`, `depth < 1 || depth > 64`,
// `idx < 0 || idx > 4`) inspects the already-corrupted result, so the check
// reports "in range" for values that are nothing of the sort. Checking the
// *big.Int first is the only order that works.
//
// `what` names the thing being narrowed and is used verbatim in the error
// message, e.g. "merkleRootSha256: depth".
//
// The semantics mirror Java's BigInteger.intValueExact(), which the project
// already uses as the reference behaviour in the Java tier.
func IntValueExact(v *big.Int, what string) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("%s: missing compile-time constant value", what)
	}
	if !v.IsInt64() {
		return 0, fmt.Errorf(
			"%s: value %s does not fit in a 64-bit signed integer and cannot be resolved at compile time",
			what, v.String(),
		)
	}
	n := v.Int64()
	if n < math.MinInt32 || n > math.MaxInt32 {
		// int is 64-bit on every platform this compiler targets, but a
		// compile-time constant that large is never a legitimate loop
		// count, arity, depth or index — and clamping the accepted range
		// here keeps the guard identical on a 32-bit build.
		return 0, fmt.Errorf(
			"%s: value %s is out of range for a compile-time integer",
			what, v.String(),
		)
	}
	return int(n), nil
}

// MustIntValueExact is IntValueExact for the panic-based diagnostic paths
// (ANF lowering and stack lowering both convert a panic into an ordinary
// compiler error via recover, so a panic here surfaces as a diagnostic, not
// a crash).
func MustIntValueExact(v *big.Int, what string) int {
	n, err := IntValueExact(v, what)
	if err != nil {
		panic(err.Error())
	}
	return n
}
