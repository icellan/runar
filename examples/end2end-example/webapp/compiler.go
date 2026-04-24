package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
)

// sourceLang describes how to locate a PriceBet source variant and what
// filename hint to pass to the Go compiler's parser dispatch.
//
// The webapp was originally hardcoded to TypeScript. It now mirrors the
// input-format dispatch already performed by frontend.ParseSource() in
// compilers/go/frontend/parser.go — adding every language the Go compiler
// can parse, including Java (milestone M7-Go / M17 playground wiring).
type sourceLang struct {
	// key is the short id used on the wire ("ts", "sol", "java", ...).
	key string
	// filename is the parser-dispatch hint passed to frontend.ParseSource.
	// Extension must match one of the cases in that function.
	filename string
	// dirs is the ordered list of directories searched (relative to this
	// source file) for a PriceBet variant in the given language.
	dirs []string
}

var sourceLangs = map[string]sourceLang{
	"ts":   {key: "ts", filename: "PriceBet.runar.ts", dirs: []string{"../ts", "."}},
	"sol":  {key: "sol", filename: "PriceBet.runar.sol", dirs: []string{"../sol", "."}},
	"move": {key: "move", filename: "PriceBet.runar.move", dirs: []string{"../move", "."}},
	"go":   {key: "go", filename: "PriceBet.runar.go", dirs: []string{"../go", "."}},
	"rs":   {key: "rs", filename: "PriceBet.runar.rs", dirs: []string{"../rust", "."}},
	"py":   {key: "py", filename: "PriceBet.runar.py", dirs: []string{"../python", "."}},
	"rb":   {key: "rb", filename: "PriceBet.runar.rb", dirs: []string{"../ruby", "."}},
	"zig":  {key: "zig", filename: "PriceBet.runar.zig", dirs: []string{"../zig", "."}},
	// Java: no external PriceBet.runar.java yet (milestone 12 / examples/java
	// ports are separate from examples/end2end-example). The webapp carries
	// its own copy alongside main.go so the Java compile path works without
	// reaching outside this directory.
	"java": {key: "java", filename: "PriceBet.runar.java", dirs: []string{".", "../java"}},
}

// normalizeLang returns the canonical short id for a lang string. Empty
// string and unknown values fall back to "ts" (the default).
func normalizeLang(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "ts", "typescript":
		return "ts"
	case "sol", "solidity":
		return "sol"
	case "move":
		return "move"
	case "go", "golang":
		return "go"
	case "rs", "rust":
		return "rs"
	case "py", "python":
		return "py"
	case "rb", "ruby":
		return "rb"
	case "zig":
		return "zig"
	case "java":
		return "java"
	default:
		return "ts"
	}
}

func compilePriceBet(lang, alicePubKeyHex, bobPubKeyHex string, threshold int) (scriptHex string, scriptAsm string, err error) {
	key := normalizeLang(lang)
	spec, ok := sourceLangs[key]
	if !ok {
		return "", "", fmt.Errorf("unknown source language %q", lang)
	}

	source, err := readContractSource(spec)
	if err != nil {
		return "", "", fmt.Errorf("read contract (%s): %w", key, err)
	}

	parseResult := frontend.ParseSource(source, spec.filename)
	if len(parseResult.Errors) > 0 {
		return "", "", fmt.Errorf("parse %s: %v", key, parseResult.Errors)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return "", "", fmt.Errorf("validate %s: %v", key, validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return "", "", fmt.Errorf("typecheck %s: %v", key, tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	for i := range program.Properties {
		switch program.Properties[i].Name {
		case "alicePubKey":
			program.Properties[i].InitialValue = alicePubKeyHex
		case "bobPubKey":
			program.Properties[i].InitialValue = bobPubKeyHex
		case "oraclePubKey":
			program.Properties[i].InitialValue = float64(12345)
		case "strikePrice":
			program.Properties[i].InitialValue = float64(threshold)
		}
	}

	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		return "", "", fmt.Errorf("stack lower %s: %w", key, err)
	}

	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return "", "", fmt.Errorf("emit %s: %w", key, err)
	}

	return emitResult.ScriptHex, emitResult.ScriptAsm, nil
}

func readContractSource(spec sourceLang) ([]byte, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)

	candidates := make([]string, 0, len(spec.dirs))
	for _, d := range spec.dirs {
		candidates = append(candidates, filepath.Join(dir, d, spec.filename))
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("%s not found (tried %v)", spec.filename, candidates)
}

// compileSource compiles an arbitrary Rúnar source string for the playground
// endpoint. The filename argument drives parser dispatch (for example
// "P2PKH.runar.java" selects the Java parser). Unlike compilePriceBet this
// path does not patch property initializers — the caller gets whatever the
// compiler produces from the literal source.
func compileSource(source []byte, filename string) (scriptHex string, scriptAsm string, err error) {
	parseResult := frontend.ParseSource(source, filename)
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
