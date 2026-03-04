module runar-webapp-blackjack

go 1.26

require (
	github.com/bsv-blockchain/go-sdk v1.2.18
	github.com/icellan/runar/compilers/go v0.0.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	golang.org/x/crypto v0.47.0 // indirect
)

replace github.com/icellan/runar/compilers/go => ../../compilers/go
