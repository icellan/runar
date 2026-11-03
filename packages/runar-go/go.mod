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

// NOTE: go.work is the supported build path for this monorepo (root go.work's
// `use ./compilers/go` and `use ./packages/runar-go` directives resolve both
// modules to this local checkout, so no `replace` is needed here). Standalone,
// non-workspace builds (GOWORK=off) and `go get` of this module are NOT
// currently supported: compilers/go v1.0.0-rc.1 above is not a published tag
// (published compilers/go tags top out at v0.4.5), and the latest published
// tag of this module does not contain packages compilers/go's current source
// already imports from it. Closing that cycle with real tags is tracked as
// N-204; until then, build and test via `go.work`, not `go get`.
