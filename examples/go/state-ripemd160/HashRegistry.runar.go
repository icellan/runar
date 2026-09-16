//go:build ignore

// EXCLUDED FROM THE GO BUILD — `runar.Ripemd160` is a function in the SDK and a
// type here.
//
//	runar.Ripemd160 (value of type func(...) ...) is not a type
//
// `CurrentHash runar.Ripemd160` is the only spelling the .runar.go surface has
// for the RIPEMD-160 digest type: parser_gocontract.go's mapGoType maps
// `Ripemd160`, and `runar.Ripemd160Hash` — the name packages/runar-go actually
// declares — is rejected by the frontend with "unsupported type
// 'Ripemd160Hash' in property declaration".
//
// packages/runar-go binds `Ripemd160` to the FUNCTION because the alternative
// fails open: as a type, `runar.Ripemd160(x)` compiles as a conversion that
// returns x and drops the hash. Adding `Ripemd160Hash` to the .runar.go type
// table of all seven compilers is what unblocks this file and byte-builtins,
// and that is a cross-tier parser change rather than an examples change.

package contract

import "runar"

type HashRegistry struct {
	runar.StatefulSmartContract
	CurrentHash runar.Ripemd160
}

func (c *HashRegistry) Update(newHash runar.Ripemd160) {
	c.CurrentHash = newHash
	runar.Assert(true)
}
