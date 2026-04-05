//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	runar "github.com/icellan/runar/packages/runar-go"
)

type TypedArg struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Input struct {
	Artifact        json.RawMessage `json:"artifact"`
	ConstructorArgs []TypedArg      `json:"constructorArgs"`
}

func convertArg(arg TypedArg) interface{} {
	switch arg.Type {
	case "bigint", "int":
		n := new(big.Int)
		n.SetString(arg.Value, 10)
		return n
	case "bool":
		return arg.Value == "true"
	default:
		return arg.Value
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go-sdk-tool <input.json>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	var artifact runar.RunarArtifact
	if err := json.Unmarshal(input.Artifact, &artifact); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading artifact: %v\n", err)
		os.Exit(1)
	}

	args := make([]interface{}, len(input.ConstructorArgs))
	for i, a := range input.ConstructorArgs {
		args[i] = convertArg(a)
	}

	contract := runar.NewRunarContract(&artifact, args)
	fmt.Print(contract.GetLockingScript())
}
