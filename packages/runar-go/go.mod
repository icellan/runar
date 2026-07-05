module github.com/icellan/runar/packages/runar-go

go 1.26

require (
	github.com/bsv-blockchain/go-sdk v1.2.21
	github.com/consensys/gnark-crypto v0.14.0
	github.com/icellan/runar/compilers/go v1.0.0-rc.1
	golang.org/x/crypto v0.48.0
)

require (
	github.com/bits-and-blooms/bitset v1.14.2 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	golang.org/x/sys v0.41.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

// NOTE: local development resolves github.com/icellan/runar/compilers/go via the
// root go.work `use ./compilers/go` directive, so no `replace` is needed here.
// A `replace => ../../compilers/go` was removed because it is honored only from
// the main module and thus breaks downstream `go get` of this SDK (the require
// must point at a real published tag — compilers/go/v1.0.0-rc.1 — instead).
