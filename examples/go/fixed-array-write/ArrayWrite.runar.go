//go:build ignore

package contract

import "runar"

// ArrayWrite is the Go port of
// examples/ts/fixed-array-write/ArrayWrite.runar.ts.
//
// Exercises a RUNTIME-index WRITE, `c.Table[i]++`. The array literal lives in
// the private init() method, which is how the Go and Rust DSL surfaces spell a
// property initializer.
type ArrayWrite struct {
	runar.StatefulSmartContract
	Table [4]runar.Int
}

func (c *ArrayWrite) init() {
	c.Table = [4]runar.Int{0, 0, 0, 0}
}

func (c *ArrayWrite) Bump(i runar.Int) {
	c.Table[i]++
	runar.Assert(true)
}
