// Command runar-compiler-go is the Go implementation of the Rúnar compiler.
//
// Phase 1: IR consumer mode — accepts ANF IR JSON, emits Bitcoin Script.
// Phase 2: Full compilation from .runar.ts source files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/icellan/runar/compilers/go/compiler"
)

func main() {
	irFile := flag.String("ir", "", "path to ANF IR JSON file")
	sourceFile := flag.String("source", "", "path to .runar.ts source file (Phase 2)")
	outputFile := flag.String("output", "", "output artifact path (default: stdout)")
	hexOnly := flag.Bool("hex", false, "output only the script hex (no artifact JSON)")
	asmOnly := flag.Bool("asm", false, "output only the script ASM (no artifact JSON)")
	emitIR := flag.Bool("emit-ir", false, "output only the ANF IR JSON (requires --source)")
	disableConstFold := flag.Bool("disable-constant-folding", false, "disable ANF constant folding pass")
	flag.Parse()

	opts := compiler.CompileOptions{
		DisableConstantFolding: *disableConstFold,
	}

	if *irFile == "" && *sourceFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: runar-compiler-go [--ir <path> | --source <path>] [--output <path>] [--hex] [--asm] [--emit-ir]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Phase 1: Compile from ANF IR JSON to Bitcoin Script (--ir).")
		fmt.Fprintln(os.Stderr, "Phase 2: Compile from .runar.ts source to Bitcoin Script (--source).")
		os.Exit(1)
	}

	// Handle --emit-ir: dump ANF IR JSON and exit
	if *emitIR {
		if *sourceFile == "" {
			fmt.Fprintln(os.Stderr, "--emit-ir requires --source")
			os.Exit(1)
		}
		program, err := compiler.CompileSourceToIR(*sourceFile, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Compilation error: %v\n", err)
			os.Exit(1)
		}
		// Serialize to generic map and ensure "if" values always have an
		// "else" field (even if empty) to match TS compiler IR format.
		// Go's omitempty drops empty slices, but TS always emits else: [].
		fullJSON, err := json.Marshal(program)
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(fullJSON, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		ensureIRFields(raw)
		irJSON, err := json.MarshalIndent(raw, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(irJSON))
		return
	}

	var artifact *compiler.Artifact
	var err error

	if *sourceFile != "" {
		artifact, err = compiler.CompileFromSource(*sourceFile, opts)
	} else {
		artifact, err = compiler.CompileFromIR(*irFile, opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Compilation error: %v\n", err)
		os.Exit(1)
	}

	// Determine output
	var output string
	if *hexOnly {
		output = artifact.Script
	} else if *asmOnly {
		output = artifact.ASM
	} else {
		jsonBytes, err := compiler.ArtifactToJSON(artifact)
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON serialization error: %v\n", err)
			os.Exit(1)
		}
		output = string(jsonBytes)
	}

	// Write output
	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Output written to %s\n", *outputFile)
	} else {
		fmt.Println(output)
	}
}

// ensureIRFields walks a generic JSON map and patches up fields that Go's
// omitempty drops but the TS compiler always emits:
//   - "else": [] on "if" ANF nodes
//   - "preimage": "" on "add_output" ANF nodes
func ensureIRFields(v interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		if kind, ok := val["kind"]; ok {
			if kind == "if" {
				if _, hasElse := val["else"]; !hasElse {
					val["else"] = []interface{}{}
				}
			}
			if kind == "add_output" {
				if _, hasPreimage := val["preimage"]; !hasPreimage {
					val["preimage"] = ""
				}
			}
		}
		for _, child := range val {
			ensureIRFields(child)
		}
	case []interface{}:
		for _, item := range val {
			ensureIRFields(item)
		}
	}
}
