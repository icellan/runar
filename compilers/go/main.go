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
	// Subcommand dispatch: if the first arg looks like a subcommand
	// (not a flag), route it to the dedicated handler. This lets us add
	// backends like `groth16-wa` without touching the legacy flag-based
	// path used for `.runar.ts` source / ANF IR compilation.
	if len(os.Args) > 1 && len(os.Args[1]) > 0 && os.Args[1][0] != '-' {
		switch os.Args[1] {
		case "groth16-wa":
			// Strip the subcommand from os.Args so the subcommand's
			// own flag set parses the remainder.
			os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
			if err := runGroth16WA(); err != nil {
				fmt.Fprintf(os.Stderr, "groth16-wa: %v\n", err)
				os.Exit(1)
			}
			return
		}
		// Unknown non-flag first arg: fall through to the flag parser,
		// which will either accept it (e.g. user passed a stray positional)
		// or error out with a standard flag usage message.
	}

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

// runGroth16WA implements the `runarc groth16-wa` subcommand. It reads a
// `.groth16.vk.json` verifying key file and emits a Rúnar artifact JSON
// containing the witness-assisted BN254 Groth16 verifier locking script
// pre-baked for that specific VK.
//
// The caller has already stripped the "groth16-wa" word from os.Args, so
// this function uses its own flag set rather than the package-level one
// used by the legacy flag-based modes.
//
// Usage:
//
//	runar-compiler-go groth16-wa --vk path/to/vk.json --out path/to/out.runar.json
//	                              [--name MyVerifier] [--modulo-threshold 0]
func runGroth16WA() error {
	fs := flag.NewFlagSet("groth16-wa", flag.ExitOnError)
	vkPath := fs.String("vk", "", "path to .groth16.vk.json verifying key file (required)")
	outPath := fs.String("out", "", "output artifact JSON path (required)")
	contractName := fs.String("name", "", "contract name in the output artifact (default \"Groth16Verifier\")")
	moduloThreshold := fs.Int("modulo-threshold", 0, "bytes threshold for deferred mod reduction; 0 = strict (recommended, ~718 KB for SP1 v6); 2048 follows the nChain paper but is MUCH slower on today's interpreters")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: runar-compiler-go groth16-wa --vk <vk.json> --out <artifact.json> [--name <ContractName>] [--modulo-threshold <int>]")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Compiles a BN254 Groth16 witness-assisted verifier with a fixed verifying key")
		fmt.Fprintln(fs.Output(), "baked in. The resulting Rúnar artifact can be deployed as a stateless contract")
		fmt.Fprintln(fs.Output(), "via the Rúnar SDK. See spec/groth16_wa_vk.schema.json for the input format.")
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *vkPath == "" {
		fs.Usage()
		return fmt.Errorf("--vk is required")
	}
	if *outPath == "" {
		fs.Usage()
		return fmt.Errorf("--out is required")
	}

	artifact, err := compiler.CompileGroth16WA(*vkPath, compiler.Groth16WAOpts{
		ContractName:    *contractName,
		ModuloThreshold: *moduloThreshold,
	})
	if err != nil {
		return err
	}

	jsonBytes, err := compiler.ArtifactToJSON(artifact)
	if err != nil {
		return fmt.Errorf("serialize artifact: %w", err)
	}

	if err := os.WriteFile(*outPath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}

	// Size readout is the most important piece of feedback for this
	// command — the script bytes are what the user is going to deploy.
	scriptBytes := len(artifact.Script) / 2
	fmt.Fprintf(os.Stderr, "groth16-wa: wrote %s\n", *outPath)
	fmt.Fprintf(os.Stderr, "  contract: %s\n", artifact.ContractName)
	fmt.Fprintf(os.Stderr, "  script:   %d bytes (%.1f KB)\n", scriptBytes, float64(scriptBytes)/1024)
	if artifact.Groth16WA != nil {
		fmt.Fprintf(os.Stderr, "  pub ins:  %d\n", artifact.Groth16WA.NumPubInputs)
		fmt.Fprintf(os.Stderr, "  vk sha256: %s\n", artifact.Groth16WA.VKDigest)
	}
	return nil
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
			if kind == "call" || kind == "method_call" {
				if _, hasArgs := val["args"]; !hasArgs {
					val["args"] = []interface{}{}
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
