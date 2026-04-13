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
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Index        int         `json:"index"`
	InitialValue interface{} `json:"initialValue,omitempty"`
}

// ConstructorSlot records a constructor parameter placeholder in the compiled script.
type ConstructorSlot = codegen.ConstructorSlot

// CodeSepIndexSlot records a codeSepIndex placeholder in the compiled script.
type CodeSepIndexSlot = codegen.CodeSepIndexSlot

// SourceMapping is re-exported from codegen.
type SourceMapping = codegen.SourceMapping

// SourceMap holds the source-level debug mappings (opcode index -> source location).
type SourceMap struct {
	Mappings []SourceMapping `json:"mappings"`
}

// IRDebug holds optional IR snapshots for debugging / conformance checking.
type IRDebug struct {
	ANF   *ir.ANFProgram       `json:"anf,omitempty"`
	Stack []codegen.StackMethod `json:"stack,omitempty"`
}

// Groth16WAMeta records metadata about a witness-assisted Groth16 verifier
// artifact produced by `runarc groth16-wa`. It lets downstream consumers
// sanity-check that the baked-in VK matches what they expect without having
// to re-derive anything from the script bytes.
type Groth16WAMeta struct {
	// NumPubInputs is the number of public inputs the Groth16 circuit was
	// parameterised with. Matches `vk.numPubInputs` from the input JSON.
	NumPubInputs int `json:"numPubInputs"`

	// VKDigest is the SHA-256 hex of the RAW bytes of the source VK JSON
	// file (not a canonical form). It is a pure reproducibility marker:
	// if two artifacts have the same VKDigest, they were compiled from
	// byte-identical VK files. It is NOT a cryptographic commitment to
	// the VK semantics and should not be used for anything load-bearing.
	VKDigest string `json:"vkDigest"`
}

// Artifact is the final compiled output of a Rúnar compiler.
type Artifact struct {
	Version                string            `json:"version"`
	CompilerVersion        string            `json:"compilerVersion"`
	ContractName           string            `json:"contractName"`
	ABI                    ABI               `json:"abi"`
	Script                 string            `json:"script"`
	ASM                    string            `json:"asm"`
	StateFields            []StateField      `json:"stateFields,omitempty"`
	ConstructorSlots       []ConstructorSlot  `json:"constructorSlots,omitempty"`
	CodeSepIndexSlots      []CodeSepIndexSlot `json:"codeSepIndexSlots,omitempty"`
	CodeSeparatorIndex     *int               `json:"codeSeparatorIndex,omitempty"`
	CodeSeparatorIndices   []int             `json:"codeSeparatorIndices,omitempty"`
	BuildTimestamp         string            `json:"buildTimestamp"`
	ANF                    *ir.ANFProgram    `json:"anf,omitempty"`
	SourceMapData          *SourceMap        `json:"sourceMap,omitempty"`
	IR                     *IRDebug          `json:"ir,omitempty"`

	// Groth16WA is populated only for artifacts produced by the
	// `runarc groth16-wa` backend. Nil for normal Rúnar contract
	// compilations. See Groth16WAMeta for field semantics.
	Groth16WA *Groth16WAMeta `json:"groth16WA,omitempty"`
}

const (
	schemaVersion   = "runar-v0.4.4"
	compilerVersion = "0.4.4-go"
)

// ---------------------------------------------------------------------------
// Compilation pipeline
// ---------------------------------------------------------------------------

// CompileFromIR reads an ANF IR JSON file and compiles it to a Rúnar artifact.
func CompileFromIR(irPath string, opts ...CompileOptions) (*Artifact, error) {
	program, err := ir.LoadIR(irPath)
	if err != nil {
		return nil, fmt.Errorf("loading IR: %w", err)
	}

	return CompileFromProgram(program, opts...)
}

// CompileFromIRBytes compiles from raw ANF IR JSON bytes.
func CompileFromIRBytes(data []byte, opts ...CompileOptions) (*Artifact, error) {
	program, err := ir.LoadIRFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("loading IR: %w", err)
	}

	return CompileFromProgram(program, opts...)
}

// CompileFromProgram compiles a parsed ANF program to a Rúnar artifact.
func CompileFromProgram(program *ir.ANFProgram, opts ...CompileOptions) (*Artifact, error) {
	o := mergeOptions(opts)

	// Bake constructor args into ANF properties.
	applyConstructorArgs(program, o.ConstructorArgs)

	// Pass 4.25: Constant folding (on by default)
	if !o.DisableConstantFolding {
		program = frontend.FoldConstants(program)
	}

	// EC optimization — algebraic simplification of EC calls
	program = frontend.OptimizeEC(program)

	// Mode 3: when CompileOptions.Groth16WAVKey is set, load the SP1
	// vk.json and build the codegen.Groth16Config that the stack-lowering
	// preamble emitter will consume. The compiler package can import
	// bn254witness (which already imports codegen for the NAF table); the
	// codegen package cannot, so the loading happens here.
	var lowerOpts codegen.LowerToStackOptions
	if o.Groth16WAVKey != "" {
		cfg, err := loadGroth16WAConfig(o.Groth16WAVKey)
		if err != nil {
			return nil, fmt.Errorf("loading Groth16WAVKey %q: %w", o.Groth16WAVKey, err)
		}
		lowerOpts.Groth16WAConfig = &cfg
	}

	// Pass 5: Stack lowering
	stackMethods, err := codegen.LowerToStack(program, lowerOpts)
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

	artifact := assembleArtifact(program, emitResult.ScriptHex, emitResult.ScriptAsm, emitResult.ConstructorSlots, emitResult.CodeSepIndexSlots, emitResult.CodeSeparatorIndex, emitResult.CodeSeparatorIndices, emitResult.SourceMap, stackMethods, o)
	return artifact, nil
}

// assembleArtifact builds the final output artifact from the compilation products.
func assembleArtifact(program *ir.ANFProgram, scriptHex, scriptAsm string, constructorSlots []ConstructorSlot, codeSepIndexSlots []CodeSepIndexSlot, codeSeparatorIndex int, codeSeparatorIndices []int, sourceMap []codegen.SourceMapping, stackMethods []codegen.StackMethod, opts CompileOptions) *Artifact {
	// Build ABI
	// Build constructor params, excluding properties with initializers
	// (properties with default values are not constructor parameters).
	var constructorParams []ABIParam
	for _, prop := range program.Properties {
		if prop.InitialValue == nil {
			constructorParams = append(constructorParams, ABIParam{Name: prop.Name, Type: prop.Type})
		}
	}

	// Build state fields for stateful contracts.
	// Index = property position (matching constructor arg order), not sequential mutable index.
	var stateFields []StateField
	for i, prop := range program.Properties {
		if !prop.Readonly {
			sf := StateField{
				Name:  prop.Name,
				Type:  prop.Type,
				Index: i,
			}
			if prop.InitialValue != nil {
				sf.InitialValue = prop.InitialValue
			}
			stateFields = append(stateFields, sf)
		}
	}

	isStateful := len(stateFields) > 0
	// Build method ABIs (exclude constructor — it's in abi.constructor, not methods)
	var methods []ABIMethod
	for _, method := range program.Methods {
		if method.Name == "constructor" {
			continue
		}
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
		methods = append(methods, m)
	}

	// Only include codeSeparatorIndex when an OP_CODESEPARATOR was emitted (index >= 0)
	var csIndex *int
	if codeSeparatorIndex >= 0 {
		v := codeSeparatorIndex
		csIndex = &v
	}
	// Only include codeSeparatorIndices when non-empty
	var csIndices []int
	if len(codeSeparatorIndices) > 0 {
		csIndices = codeSeparatorIndices
	}

	artifact := &Artifact{
		Version:         schemaVersion,
		CompilerVersion: compilerVersion,
		ContractName:    program.ContractName,
		ABI: ABI{
			Constructor: ABIConstructor{Params: constructorParams},
			Methods:     methods,
		},
		Script:               scriptHex,
		ASM:                  scriptAsm,
		StateFields:          stateFields,
		ConstructorSlots:     constructorSlots,
		CodeSepIndexSlots:   codeSepIndexSlots,
		CodeSeparatorIndex:   csIndex,
		CodeSeparatorIndices: csIndices,
		BuildTimestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	// Always include ANF IR for stateful contracts — the SDK uses it
	// to auto-compute state transitions without requiring manual newState.
	if isStateful {
		artifact.ANF = program
	}

	// Optional source map
	if opts.IncludeSourceMap && len(sourceMap) > 0 {
		artifact.SourceMapData = &SourceMap{Mappings: sourceMap}
	}

	// Optional IR snapshots
	if opts.IncludeIR {
		artifact.IR = &IRDebug{
			ANF:   program,
			Stack: stackMethods,
		}
	}

	return artifact
}

// CompileFromSource compiles a .runar.ts source file through all passes to a Rúnar artifact.
func CompileFromSource(sourcePath string, opts ...CompileOptions) (*Artifact, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}

	// Pass 1: Parse
	parseResult := frontend.ParseSource(source, sourcePath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors:\n  %s", strings.Join(parseResult.ErrorStrings(), "\n  "))
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
	}

	// Pass 2: Validate
	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors:\n  %s", strings.Join(validResult.ErrorStrings(), "\n  "))
	}

	// Pass 3: Type check
	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors:\n  %s", strings.Join(tcResult.ErrorStrings(), "\n  "))
	}

	// Pass 4: ANF lowering
	program := frontend.LowerToANF(parseResult.Contract)

	// Feed into existing compilation pipeline (passes 4.25+)
	return CompileFromProgram(program, opts...)
}

// CompileSourceToIR runs passes 1-4 on a .runar.ts source file and returns the ANF program.
func CompileSourceToIR(sourcePath string, opts ...CompileOptions) (*ir.ANFProgram, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}

	parseResult := frontend.ParseSource(source, sourcePath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors:\n  %s", strings.Join(parseResult.ErrorStrings(), "\n  "))
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors:\n  %s", strings.Join(validResult.ErrorStrings(), "\n  "))
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors:\n  %s", strings.Join(tcResult.ErrorStrings(), "\n  "))
	}

	program := frontend.LowerToANF(parseResult.Contract)

	o := mergeOptions(opts)
	// Pass 4.25: Constant folding (on by default)
	if !o.DisableConstantFolding {
		program = frontend.FoldConstants(program)
	}

	program = frontend.OptimizeEC(program)
	return program, nil
}

// ---------------------------------------------------------------------------
// CompileResult — rich compilation output (mirrors TypeScript CompileResult)
// ---------------------------------------------------------------------------

// CompileResult holds the full result of a compilation pipeline run.
// Unlike CompileFromSource (which returns (*Artifact, error) and stops at first
// error), CompileResult collects ALL diagnostics from ALL passes and returns
// partial results (contract AST, ANF IR) as they become available.
type CompileResult struct {
	// Contract is the parsed AST (available after pass 1 — parse).
	Contract *frontend.ContractNode

	// ANF is the A-Normal Form IR (available after pass 4 — ANF lowering).
	ANF *ir.ANFProgram

	// Diagnostics contains ALL diagnostics from ALL passes (errors + warnings).
	Diagnostics []frontend.Diagnostic

	// Success is true only if there are no error-severity diagnostics.
	Success bool

	// Artifact is the final compiled output (available if compilation succeeds).
	Artifact *Artifact

	// ScriptHex is the hex-encoded Bitcoin Script (available if compilation succeeds).
	ScriptHex string

	// ScriptAsm is the human-readable ASM (available if compilation succeeds).
	ScriptAsm string
}

// hasErrors returns true if any diagnostic has error severity.
func hasErrors(diagnostics []frontend.Diagnostic) bool {
	for _, d := range diagnostics {
		if d.Severity == frontend.SeverityError {
			return true
		}
	}
	return false
}

// CompileFromSourceWithResult compiles a source file through all passes,
// collecting ALL diagnostics from ALL passes and returning partial results.
// Unlike CompileFromSource, this function never returns an error — all errors
// are captured in the returned CompileResult.Diagnostics slice.
func CompileFromSourceWithResult(sourcePath string, opts ...CompileOptions) *CompileResult {
	result := &CompileResult{}
	o := mergeOptions(opts)

	// Read source file
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
			fmt.Sprintf("reading source file: %s", err),
			frontend.SeverityError,
			nil,
		))
		return result
	}

	// Pass 1: Parse
	parseResult := frontend.ParseSource(source, sourcePath)
	result.Diagnostics = append(result.Diagnostics, parseResult.Errors...)
	result.Contract = parseResult.Contract

	if hasErrors(result.Diagnostics) || result.Contract == nil {
		if result.Contract == nil && !hasErrors(result.Diagnostics) {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("no contract found in %s", sourcePath),
				frontend.SeverityError,
				nil,
			))
		}
		return result
	}

	if o.ParseOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 2: Validate
	validResult := frontend.Validate(result.Contract)
	result.Diagnostics = append(result.Diagnostics, validResult.Errors...)
	result.Diagnostics = append(result.Diagnostics, validResult.Warnings...)

	if hasErrors(result.Diagnostics) {
		return result
	}

	if o.ValidateOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 3: Type check
	tcResult := frontend.TypeCheck(result.Contract)
	result.Diagnostics = append(result.Diagnostics, tcResult.Errors...)

	if hasErrors(result.Diagnostics) {
		return result
	}

	if o.TypecheckOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 4: ANF lowering
	result.ANF = frontend.LowerToANF(result.Contract)

	// Bake constructor args into ANF properties.
	applyConstructorArgs(result.ANF, o.ConstructorArgs)

	// Pass 4.25: Constant folding (on by default)
	if !o.DisableConstantFolding {
		result.ANF = frontend.FoldConstants(result.ANF)
	}

	// Pass 4.5: EC optimization
	result.ANF = frontend.OptimizeEC(result.ANF)

	// Pass 5: Stack lowering (recover from panics)
	var stackMethods []codegen.StackMethod
	func() {
		defer func() {
			if r := recover(); r != nil {
				result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
					fmt.Sprintf("stack lowering panic: %v", r),
					frontend.SeverityError,
					nil,
				))
			}
		}()
		var stackErr error
		stackMethods, stackErr = codegen.LowerToStack(result.ANF)
		if stackErr != nil {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("stack lowering: %s", stackErr),
				frontend.SeverityError,
				nil,
			))
		}
	}()

	if hasErrors(result.Diagnostics) {
		return result
	}

	// Peephole optimization
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}

	// Pass 6: Emit (recover from panics)
	func() {
		defer func() {
			if r := recover(); r != nil {
				result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
					fmt.Sprintf("emit panic: %v", r),
					frontend.SeverityError,
					nil,
				))
			}
		}()
		emitResult, emitErr := codegen.Emit(stackMethods)
		if emitErr != nil {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("emit: %s", emitErr),
				frontend.SeverityError,
				nil,
			))
			return
		}

		artifact := assembleArtifact(result.ANF, emitResult.ScriptHex, emitResult.ScriptAsm, emitResult.ConstructorSlots, emitResult.CodeSepIndexSlots, emitResult.CodeSeparatorIndex, emitResult.CodeSeparatorIndices, emitResult.SourceMap, stackMethods, o)
		result.Artifact = artifact
		result.ScriptHex = emitResult.ScriptHex
		result.ScriptAsm = emitResult.ScriptAsm
	}()

	result.Success = !hasErrors(result.Diagnostics)
	return result
}

// CompileFromSourceStrWithResult compiles a source string through all passes,
// collecting ALL diagnostics. The fileName parameter determines which parser to use.
func CompileFromSourceStrWithResult(source string, fileName string, opts ...CompileOptions) *CompileResult {
	result := &CompileResult{}
	o := mergeOptions(opts)

	// Pass 1: Parse
	parseResult := frontend.ParseSource([]byte(source), fileName)
	result.Diagnostics = append(result.Diagnostics, parseResult.Errors...)
	result.Contract = parseResult.Contract

	if hasErrors(result.Diagnostics) || result.Contract == nil {
		if result.Contract == nil && !hasErrors(result.Diagnostics) {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("no contract found in %s", fileName),
				frontend.SeverityError,
				nil,
			))
		}
		return result
	}

	if o.ParseOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 2: Validate
	validResult := frontend.Validate(result.Contract)
	result.Diagnostics = append(result.Diagnostics, validResult.Errors...)
	result.Diagnostics = append(result.Diagnostics, validResult.Warnings...)

	if hasErrors(result.Diagnostics) {
		return result
	}

	if o.ValidateOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 3: Type check
	tcResult := frontend.TypeCheck(result.Contract)
	result.Diagnostics = append(result.Diagnostics, tcResult.Errors...)

	if hasErrors(result.Diagnostics) {
		return result
	}

	if o.TypecheckOnly {
		result.Success = !hasErrors(result.Diagnostics)
		return result
	}

	// Pass 4: ANF lowering
	result.ANF = frontend.LowerToANF(result.Contract)

	// Bake constructor args into ANF properties.
	applyConstructorArgs(result.ANF, o.ConstructorArgs)

	// Pass 4.25: Constant folding (on by default)
	if !o.DisableConstantFolding {
		result.ANF = frontend.FoldConstants(result.ANF)
	}

	// Pass 4.5: EC optimization
	result.ANF = frontend.OptimizeEC(result.ANF)

	// Pass 5: Stack lowering (recover from panics)
	var stackMethods []codegen.StackMethod
	func() {
		defer func() {
			if r := recover(); r != nil {
				result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
					fmt.Sprintf("stack lowering panic: %v", r),
					frontend.SeverityError,
					nil,
				))
			}
		}()
		var stackErr error
		stackMethods, stackErr = codegen.LowerToStack(result.ANF)
		if stackErr != nil {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("stack lowering: %s", stackErr),
				frontend.SeverityError,
				nil,
			))
		}
	}()

	if hasErrors(result.Diagnostics) {
		return result
	}

	// Peephole optimization
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}

	// Pass 6: Emit (recover from panics)
	func() {
		defer func() {
			if r := recover(); r != nil {
				result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
					fmt.Sprintf("emit panic: %v", r),
					frontend.SeverityError,
					nil,
				))
			}
		}()
		emitResult, emitErr := codegen.Emit(stackMethods)
		if emitErr != nil {
			result.Diagnostics = append(result.Diagnostics, frontend.MakeDiagnostic(
				fmt.Sprintf("emit: %s", emitErr),
				frontend.SeverityError,
				nil,
			))
			return
		}

		artifact := assembleArtifact(result.ANF, emitResult.ScriptHex, emitResult.ScriptAsm, emitResult.ConstructorSlots, emitResult.CodeSepIndexSlots, emitResult.CodeSeparatorIndex, emitResult.CodeSeparatorIndices, emitResult.SourceMap, stackMethods, o)
		result.Artifact = artifact
		result.ScriptHex = emitResult.ScriptHex
		result.ScriptAsm = emitResult.ScriptAsm
	}()

	result.Success = !hasErrors(result.Diagnostics)
	return result
}

// ArtifactToJSON serialises an artifact to pretty-printed JSON.
func ArtifactToJSON(artifact *Artifact) ([]byte, error) {
	return json.MarshalIndent(artifact, "", "  ")
}
