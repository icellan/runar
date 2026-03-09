package compiler

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Artifact types — mirrors the TypeScript RunarArtifact schema
// ---------------------------------------------------------------------------

// ABIParam describes a parameter in the ABI.
type ABIParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ABIConstructor describes the constructor ABI.
type ABIConstructor struct {
	Params []ABIParam `json:"params"`
}

// ABIMethod describes a method in the ABI.
type ABIMethod struct {
	Name       string     `json:"name"`
	Params     []ABIParam `json:"params"`
	IsPublic   bool       `json:"isPublic"`
	IsTerminal *bool      `json:"isTerminal,omitempty"`
}

// ABI describes the contract's public interface.
type ABI struct {
	Constructor ABIConstructor `json:"constructor"`
	Methods     []ABIMethod    `json:"methods"`
}

// StateField describes a stateful contract field.
type StateField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// ConstructorSlot records a constructor parameter placeholder in the compiled script.
type ConstructorSlot = codegen.ConstructorSlot

// Artifact is the final compiled output of a Rúnar compiler.
type Artifact struct {
	Version          string            `json:"version"`
	CompilerVersion  string            `json:"compilerVersion"`
	ContractName     string            `json:"contractName"`
	ABI              ABI               `json:"abi"`
	Script           string            `json:"script"`
	ASM              string            `json:"asm"`
	StateFields      []StateField      `json:"stateFields,omitempty"`
	ConstructorSlots []ConstructorSlot `json:"constructorSlots,omitempty"`
	BuildTimestamp   string            `json:"buildTimestamp"`
}

const (
	schemaVersion   = "runar-v0.1.0"
	compilerVersion = "0.1.0-go"
)

// ---------------------------------------------------------------------------
// Compilation pipeline
// ---------------------------------------------------------------------------

// CompileFromIR reads an ANF IR JSON file and compiles it to a Rúnar artifact.
func CompileFromIR(irPath string) (*Artifact, error) {
	program, err := ir.LoadIR(irPath)
	if err != nil {
		return nil, fmt.Errorf("loading IR: %w", err)
	}

	return CompileFromProgram(program)
}

// CompileFromIRBytes compiles from raw ANF IR JSON bytes.
func CompileFromIRBytes(data []byte) (*Artifact, error) {
	program, err := ir.LoadIRFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("loading IR: %w", err)
	}

	return CompileFromProgram(program)
}

// CompileFromProgram compiles a parsed ANF program to a Rúnar artifact.
func CompileFromProgram(program *ir.ANFProgram) (*Artifact, error) {
	// EC optimization — algebraic simplification of EC calls
	program = frontend.OptimizeEC(program)

	// Pass 5: Stack lowering
	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		return nil, fmt.Errorf("stack lowering: %w", err)
	}

	// Peephole optimization — runs on Stack IR before emission.
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}

	// Pass 6: Emit
	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	artifact := assembleArtifact(program, emitResult.ScriptHex, emitResult.ScriptAsm, emitResult.ConstructorSlots)
	return artifact, nil
}

// assembleArtifact builds the final output artifact from the compilation products.
func assembleArtifact(program *ir.ANFProgram, scriptHex, scriptAsm string, constructorSlots []ConstructorSlot) *Artifact {
	// Build ABI
	constructorParams := make([]ABIParam, len(program.Properties))
	for i, prop := range program.Properties {
		constructorParams[i] = ABIParam{Name: prop.Name, Type: prop.Type}
	}

	// Build state fields for stateful contracts.
	// Index = property position (matching constructor arg order), not sequential mutable index.
	var stateFields []StateField
	for i, prop := range program.Properties {
		if !prop.Readonly {
			stateFields = append(stateFields, StateField{
				Name:  prop.Name,
				Type:  prop.Type,
				Index: i,
			})
		}
	}

	isStateful := len(stateFields) > 0
	methods := make([]ABIMethod, len(program.Methods))
	for i, method := range program.Methods {
		params := make([]ABIParam, len(method.Params))
		for j, p := range method.Params {
			params[j] = ABIParam{Name: p.Name, Type: p.Type}
		}
		m := ABIMethod{
			Name:     method.Name,
			Params:   params,
			IsPublic: method.IsPublic,
		}
		// For stateful contracts, mark public methods without _changePKH as terminal
		if isStateful && method.IsPublic {
			hasChange := false
			for _, p := range method.Params {
				if p.Name == "_changePKH" {
					hasChange = true
					break
				}
			}
			if !hasChange {
				t := true
				m.IsTerminal = &t
			}
		}
		methods[i] = m
	}

	return &Artifact{
		Version:         schemaVersion,
		CompilerVersion: compilerVersion,
		ContractName:    program.ContractName,
		ABI: ABI{
			Constructor: ABIConstructor{Params: constructorParams},
			Methods:     methods,
		},
		Script:           scriptHex,
		ASM:              scriptAsm,
		StateFields:      stateFields,
		ConstructorSlots: constructorSlots,
		BuildTimestamp:    time.Now().UTC().Format(time.RFC3339),
	}
}

// CompileFromSource compiles a .runar.ts source file through all passes to a Rúnar artifact.
func CompileFromSource(sourcePath string) (*Artifact, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}

	// Pass 1: Parse
	parseResult := frontend.ParseSource(source, sourcePath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors:\n  %s", strings.Join(parseResult.Errors, "\n  "))
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
	}

	// Pass 2: Validate
	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors:\n  %s", strings.Join(validResult.Errors, "\n  "))
	}

	// Pass 3: Type check
	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors:\n  %s", strings.Join(tcResult.Errors, "\n  "))
	}

	// Pass 4: ANF lowering
	program := frontend.LowerToANF(parseResult.Contract)

	// EC optimization — algebraic simplification of EC calls
	program = frontend.OptimizeEC(program)

	// Feed into existing compilation pipeline (passes 5-6)
	return CompileFromProgram(program)
}

// CompileSourceToIR runs passes 1-4 on a .runar.ts source file and returns the ANF program.
func CompileSourceToIR(sourcePath string) (*ir.ANFProgram, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}

	parseResult := frontend.ParseSource(source, sourcePath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors:\n  %s", strings.Join(parseResult.Errors, "\n  "))
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors:\n  %s", strings.Join(validResult.Errors, "\n  "))
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors:\n  %s", strings.Join(tcResult.Errors, "\n  "))
	}

	program := frontend.LowerToANF(parseResult.Contract)
	program = frontend.OptimizeEC(program)
	return program, nil
}

// ArtifactToJSON serialises an artifact to pretty-printed JSON.
func ArtifactToJSON(artifact *Artifact) ([]byte, error) {
	return json.MarshalIndent(artifact, "", "  ")
}
