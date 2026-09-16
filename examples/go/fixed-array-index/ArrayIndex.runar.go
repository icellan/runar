package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ArrayIndex is the Go port of
// examples/ts/fixed-array-index/ArrayIndex.runar.ts.
//
// Exercises `[4]runar.Int` together with a RUNTIME index read c.Table[i].
// The array literal lives in the private init() method, which is how the Go
// and Rust DSL surfaces spell a property initializer.
type ArrayIndex struct {
	runar.SmartContract
	Table [4]runar.Int `runar:"readonly"`
}

func (c *ArrayIndex) init() {
	c.Table = [4]runar.Int{10, 20, 30, 40}
}

func (c *ArrayIndex) Lookup(i runar.Int, expected runar.Int) {
	runar.Assert(c.Table[i] == expected)
}
