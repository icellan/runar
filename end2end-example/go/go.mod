module runar-end2end-example

go 1.26

require (
	github.com/icellan/runar/compilers/go v0.0.0
	github.com/icellan/runar/packages/runar-go v0.0.0
)

require (
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	golang.org/x/crypto v0.31.0 // indirect
)

replace github.com/icellan/runar/packages/runar-go => ../../packages/runar-go

replace github.com/icellan/runar/compilers/go => ../../compilers/go
