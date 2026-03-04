package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
)

func compileBlackjackBet(playerPubKeyHex, housePubKeyHex string, oraclePubKey *big.Int, roundId int64) (scriptHex string, scriptAsm string, err error) {
	source, err := readContractSource()
	if err != nil {
		return "", "", fmt.Errorf("read contract: %w", err)
	}

	parseResult := frontend.ParseSource(source, "BlackjackBet.runar.ts")
	if len(parseResult.Errors) > 0 {
		return "", "", fmt.Errorf("parse: %v", parseResult.Errors)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return "", "", fmt.Errorf("validate: %v", validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return "", "", fmt.Errorf("typecheck: %v", tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	for i := range program.Properties {
		switch program.Properties[i].Name {
		case "playerPubKey":
			program.Properties[i].InitialValue = playerPubKeyHex
		case "housePubKey":
			program.Properties[i].InitialValue = housePubKeyHex
		case "oraclePubKey":
			program.Properties[i].InitialValue = new(big.Int).Set(oraclePubKey)
		case "roundId":
			program.Properties[i].InitialValue = float64(roundId)
		}
	}

	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		return "", "", fmt.Errorf("stack lower: %w", err)
	}

	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return "", "", fmt.Errorf("emit: %w", err)
	}

	return emitResult.ScriptHex, emitResult.ScriptAsm, nil
}

func readContractSource() ([]byte, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)

	candidates := []string{
		filepath.Join(dir, "BlackjackBet.runar.ts"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("BlackjackBet.runar.ts not found (tried %v)", candidates)
}
