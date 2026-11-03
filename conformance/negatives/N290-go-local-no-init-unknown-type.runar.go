// N-325: a Go `var q runar.TTT` with no initializer. Python, Zig and Java
// accept the same shape with a real type, so the unknown name must be what
// they refuse; Zig used to accept it (N-323 only checked the initializer
// branch). TS, Go, Rust and Ruby refuse the shape itself.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type LocalNoInitUnknownType struct {
	runar.SmartContract
	T runar.Int `runar:"readonly"`
}

func (c *LocalNoInitUnknownType) Verify(a runar.Int) {
	var q runar.TTT
	q = a
	runar.Assert(q == c.T)
}
