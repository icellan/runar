package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/compiler"
	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Artifact mirrors the compiler's Artifact type.
type Artifact struct {
	ContractName     string
	Script           string
	ASM              string
	ConstructorSlots []codegen.ConstructorSlot
	ABI              ABI
}

// ABI describes the contract's public interface.
type ABI struct {
	Methods []ABIMethod
}

// ABIMethod describes a method in the ABI.
type ABIMethod struct {
	Name     string
	IsPublic bool
}

// projectRoot returns the absolute path to the project root.
func projectRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// CompileContract compiles a .runar.ts source file with constructor args injected.
func CompileContract(sourcePath string, constructorArgs map[string]interface{}) (*Artifact, error) {
	absPath := filepath.Join(projectRoot(), sourcePath)
	source, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading source: %w", err)
	}

	parseResult := frontend.ParseSource(source, absPath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", parseResult.Errors)
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", absPath)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors: %v", validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors: %v", tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	// Inject constructor args (must use index to modify in place)
	for i := range program.Properties {
		if val, ok := constructorArgs[program.Properties[i].Name]; ok {
			switch v := val.(type) {
			case string:
				program.Properties[i].InitialValue = v
			case float64:
				program.Properties[i].InitialValue = v
			case int64:
				program.Properties[i].InitialValue = float64(v)
			case int:
				program.Properties[i].InitialValue = float64(v)
			case *big.Int:
				program.Properties[i].InitialValue = v
			case []byte:
				program.Properties[i].InitialValue = v
			default:
				return nil, fmt.Errorf("unsupported constructor arg type for %s: %T", program.Properties[i].Name, val)
			}
		}
	}

	return compileFromProgram(program)
}

func compileFromProgram(program *ir.ANFProgram) (*Artifact, error) {
	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		return nil, fmt.Errorf("stack lowering: %w", err)
	}

	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}

	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	methods := make([]ABIMethod, len(program.Methods))
	for i, m := range program.Methods {
		methods[i] = ABIMethod{Name: m.Name, IsPublic: m.IsPublic}
	}

	_ = time.Now() // suppress unused import

	return &Artifact{
		ContractName:     program.ContractName,
		Script:           emitResult.ScriptHex,
		ASM:              emitResult.ScriptAsm,
		ConstructorSlots: emitResult.ConstructorSlots,
		ABI:              ABI{Methods: methods},
	}, nil
}

// CompileToSDKArtifactAbs compiles a source file at an absolute path and
// returns a runar.RunarArtifact suitable for use with RunarContract.
// Use this when the contract source is outside the Rúnar project tree.
func CompileToSDKArtifactAbs(absPath string) (*runar.RunarArtifact, error) {
	return compileToSDKArtifact(absPath)
}

// CompileToSDKArtifactWithGroth16WAVKey compiles a Mode 3 stateful contract
// (one whose method body calls runar.AssertGroth16WitnessAssisted) by
// supplying the SP1-format Groth16 verifying key path that the codegen will
// load and bake into the witness-assisted verifier preamble. The resulting
// artifact is otherwise a standard SDK artifact and can be deployed and
// called via RunarContract just like any other.
//
// vkAbsPath must be an absolute path to a vk.json file matching the schema
// in tests/vectors/sp1/v6.0.0/README.md.
func CompileToSDKArtifactWithGroth16WAVKey(sourcePath string, vkAbsPath string) (*runar.RunarArtifact, error) {
	absPath := filepath.Join(projectRoot(), sourcePath)
	return compileToSDKArtifactWithOptions(absPath, vkAbsPath)
}

// CompileToSDKArtifactAbsWithGroth16WAVKey is the absolute-path variant of
// CompileToSDKArtifactWithGroth16WAVKey. Use this when the contract source
// lives outside the Rúnar project tree (e.g. bsv-evm's
// pkg/covenant/contracts/rollup_groth16_wa.runar.go).
func CompileToSDKArtifactAbsWithGroth16WAVKey(absSourcePath string, vkAbsPath string) (*runar.RunarArtifact, error) {
	return compileToSDKArtifactWithOptions(absSourcePath, vkAbsPath)
}

// CompileToSDKArtifact compiles a source file relative to the Rúnar project
// root and returns a runar.RunarArtifact suitable for use with RunarContract.
func CompileToSDKArtifact(sourcePath string, constructorArgs map[string]interface{}) (*runar.RunarArtifact, error) {
	absPath := filepath.Join(projectRoot(), sourcePath)
	return compileToSDKArtifact(absPath)
}

func compileToSDKArtifact(absPath string) (*runar.RunarArtifact, error) {
	return compileToSDKArtifactWithOptions(absPath, "")
}

// compileToSDKArtifactWithOptions is the worker behind both compileToSDKArtifact
// and CompileToSDKArtifactWithGroth16WAVKey. When groth16WAVKey is non-empty,
// the codegen pass is given a LowerToStackOptions with the loaded VK so the
// witness-assisted Groth16 verifier preamble emitter has access to it.
func compileToSDKArtifactWithOptions(absPath, groth16WAVKey string) (*runar.RunarArtifact, error) {
	source, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading source: %w", err)
	}

	parseResult := frontend.ParseSource(source, absPath)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", parseResult.Errors)
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", absPath)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors: %v", validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors: %v", tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	// NOTE: Do NOT inject constructor args into InitialValue here.
	// The compiler must emit placeholder opcodes so ConstructorSlots are
	// generated. The SDK's RunarContract.buildCodeScript then splices the
	// actual values at deployment time. Setting InitialValue would bake values
	// into the script AND the SDK would append them again (CLEANSTACK bug).

	var lowerOpts codegen.LowerToStackOptions
	if groth16WAVKey != "" {
		// Mode 3 path: load the SP1 vk.json into a Groth16Config so the
		// codegen preamble emitter can bake the verifying key into the
		// inlined witness-assisted verifier ops. The compiler package
		// owns this loader (it can import bn254witness; the codegen
		// package cannot, due to an import cycle).
		cfg, cfgErr := compiler.LoadGroth16WAConfigForTests(groth16WAVKey)
		if cfgErr != nil {
			return nil, fmt.Errorf("loading groth16 vk %q: %w", groth16WAVKey, cfgErr)
		}
		lowerOpts.Groth16WAConfig = &cfg
	}

	stackMethods, err := codegen.LowerToStack(program, lowerOpts)
	if err != nil {
		return nil, fmt.Errorf("stack lowering: %w", err)
	}
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}
	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	// Build ABI from ANF program (post-lowering) — includes compiler-injected params
	// like SigHashPreimage, _changePKH, _changeAmount for stateful contracts.
	contract := parseResult.Contract
	var abiMethods []runar.ABIMethod
	for _, m := range program.Methods {
		var params []runar.ABIParam
		for _, p := range m.Params {
			params = append(params, runar.ABIParam{Name: p.Name, Type: p.Type})
		}
		abiMethods = append(abiMethods, runar.ABIMethod{
			Name:     m.Name,
			Params:   params,
			IsPublic: m.IsPublic,
		})
	}

	var ctorParams []runar.ABIParam
	for _, p := range contract.Constructor.Params {
		typeName := "bigint"
		if p.Type != nil {
			typeName = AstTypeName(p.Type)
		}
		ctorParams = append(ctorParams, runar.ABIParam{Name: p.Name, Type: typeName})
	}

	// Build state fields for stateful contracts
	var stateFields []runar.StateField
	if contract.ParentClass == "StatefulSmartContract" {
		for i, p := range contract.Properties {
			if p.Readonly {
				continue
			}
			typeName := "bigint"
			if p.Type != nil {
				typeName = AstTypeName(p.Type)
			}
			field := runar.StateField{
				Name:  p.Name,
				Type:  typeName,
				Index: i, // property position
			}
			// Include initialValue from ANF property if present
			for _, anfProp := range program.Properties {
				if anfProp.Name == p.Name && anfProp.InitialValue != nil {
					field.InitialValue = anfProp.InitialValue
					break
				}
			}
			stateFields = append(stateFields, field)
		}
	}

	// Build constructor slots
	var cSlots []runar.ConstructorSlot
	for _, s := range emitResult.ConstructorSlots {
		cSlots = append(cSlots, runar.ConstructorSlot{
			ParamIndex: s.ParamIndex,
			ByteOffset: s.ByteOffset,
		})
	}

	// Convert compiler IR ANF to SDK ANF for auto-state computation
	sdkANF := ConvertIRANFToSDK(program)

	artifact := &runar.RunarArtifact{
		Version:          "runar-v0.1.0",
		CompilerVersion:  "integration-test",
		ContractName:     program.ContractName,
		Script:           emitResult.ScriptHex,
		ASM:              emitResult.ScriptAsm,
		ConstructorSlots: cSlots,
		StateFields:      stateFields,
		ANF:              sdkANF,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: ctorParams},
			Methods:     abiMethods,
		},
	}
	if emitResult.CodeSeparatorIndex >= 0 {
		idx := emitResult.CodeSeparatorIndex
		artifact.CodeSeparatorIndex = &idx
	}
	if len(emitResult.CodeSeparatorIndices) > 0 {
		artifact.CodeSeparatorIndices = emitResult.CodeSeparatorIndices
	}
	if len(emitResult.CodeSepIndexSlots) > 0 {
		for _, s := range emitResult.CodeSepIndexSlots {
			artifact.CodeSepIndexSlots = append(artifact.CodeSepIndexSlots, runar.CodeSepIndexSlot{
				ByteOffset:   s.ByteOffset,
				CodeSepIndex: s.CodeSepIndex,
			})
		}
	}
	return artifact, nil
}

// CompileContract2 is like CompileContract but takes source as a string.
func CompileContract2(source, fileName string, constructorArgs map[string]interface{}) (*Artifact, error) {
	parseResult := frontend.ParseSource([]byte(source), fileName)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", parseResult.Errors)
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", fileName)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors: %v", validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors: %v", tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	for i := range program.Properties {
		if val, ok := constructorArgs[program.Properties[i].Name]; ok {
			switch v := val.(type) {
			case string:
				program.Properties[i].InitialValue = v
			case float64:
				program.Properties[i].InitialValue = v
			case int64:
				program.Properties[i].InitialValue = float64(v)
			case int:
				program.Properties[i].InitialValue = float64(v)
			case *big.Int:
				program.Properties[i].InitialValue = v
			case []byte:
				program.Properties[i].InitialValue = v
			default:
				return nil, fmt.Errorf("unsupported constructor arg type for %s: %T", program.Properties[i].Name, val)
			}
		}
	}

	return compileFromProgram(program)
}

// CompileSourceStringToSDKArtifact compiles a source string to an SDK artifact.
// Unlike CompileContract2, it does NOT inject InitialValue — the SDK's
// RunarContract.buildCodeScript splices values via ConstructorSlots at deploy time.
func CompileSourceStringToSDKArtifact(source, fileName string, constructorArgs map[string]interface{}) (*runar.RunarArtifact, error) {
	parseResult := frontend.ParseSource([]byte(source), fileName)
	if len(parseResult.Errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", parseResult.Errors)
	}
	if parseResult.Contract == nil {
		return nil, fmt.Errorf("no contract found in %s", fileName)
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		return nil, fmt.Errorf("validation errors: %v", validResult.Errors)
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		return nil, fmt.Errorf("type check errors: %v", tcResult.Errors)
	}

	program := frontend.LowerToANF(parseResult.Contract)

	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		return nil, fmt.Errorf("stack lowering: %w", err)
	}
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}
	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	// Build ABI from ANF program (post-lowering) — includes compiler-injected params
	var abiMethods []runar.ABIMethod
	for _, m := range program.Methods {
		var params []runar.ABIParam
		for _, p := range m.Params {
			params = append(params, runar.ABIParam{Name: p.Name, Type: p.Type})
		}
		abiMethods = append(abiMethods, runar.ABIMethod{
			Name:     m.Name,
			Params:   params,
			IsPublic: m.IsPublic,
		})
	}

	contract := parseResult.Contract
	var ctorParams []runar.ABIParam
	for _, p := range contract.Constructor.Params {
		typeName := "bigint"
		if p.Type != nil {
			typeName = AstTypeName(p.Type)
		}
		ctorParams = append(ctorParams, runar.ABIParam{Name: p.Name, Type: typeName})
	}

	// Build state fields for stateful contracts
	var stateFields []runar.StateField
	if contract.ParentClass == "StatefulSmartContract" {
		for i, p := range contract.Properties {
			if p.Readonly {
				continue
			}
			typeName := "bigint"
			if p.Type != nil {
				typeName = AstTypeName(p.Type)
			}
			field := runar.StateField{
				Name:  p.Name,
				Type:  typeName,
				Index: i,
			}
			for _, anfProp := range program.Properties {
				if anfProp.Name == p.Name && anfProp.InitialValue != nil {
					field.InitialValue = anfProp.InitialValue
					break
				}
			}
			stateFields = append(stateFields, field)
		}
	}

	var cSlots []runar.ConstructorSlot
	for _, s := range emitResult.ConstructorSlots {
		cSlots = append(cSlots, runar.ConstructorSlot{
			ParamIndex: s.ParamIndex,
			ByteOffset: s.ByteOffset,
		})
	}

	sdkANF := ConvertIRANFToSDK(program)

	artifact := &runar.RunarArtifact{
		Version:          "runar-v0.1.0",
		CompilerVersion:  "integration-test",
		ContractName:     program.ContractName,
		Script:           emitResult.ScriptHex,
		ASM:              emitResult.ScriptAsm,
		ConstructorSlots: cSlots,
		StateFields:      stateFields,
		ANF:              sdkANF,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: ctorParams},
			Methods:     abiMethods,
		},
	}
	if emitResult.CodeSeparatorIndex >= 0 {
		idx := emitResult.CodeSeparatorIndex
		artifact.CodeSeparatorIndex = &idx
	}
	if len(emitResult.CodeSeparatorIndices) > 0 {
		artifact.CodeSeparatorIndices = emitResult.CodeSeparatorIndices
	}
	if len(emitResult.CodeSepIndexSlots) > 0 {
		for _, s := range emitResult.CodeSepIndexSlots {
			artifact.CodeSepIndexSlots = append(artifact.CodeSepIndexSlots, runar.CodeSepIndexSlot{
				ByteOffset:   s.ByteOffset,
				CodeSepIndex: s.CodeSepIndex,
			})
		}
	}
	return artifact, nil
}

// AstTypeName extracts the type name string from a frontend.TypeNode.
func AstTypeName(t frontend.TypeNode) string {
	switch v := t.(type) {
	case frontend.PrimitiveType:
		return v.Name
	case frontend.FixedArrayType:
		return fmt.Sprintf("FixedArray<%s,%d>", AstTypeName(v.Element), v.Length)
	case frontend.CustomType:
		return v.Name
	default:
		return "bigint"
	}
}

// ---------------------------------------------------------------------------
// IR → SDK ANF conversion
// ---------------------------------------------------------------------------

// ConvertIRANFToSDK converts the compiler's ir.ANFProgram (typed structs) to
// the SDK's runar.ANFProgram (map[string]interface{} values) so the SDK's
// auto-state computation (ComputeNewState) can interpret the ANF.
func ConvertIRANFToSDK(program *ir.ANFProgram) *runar.ANFProgram {
	sdkProps := make([]runar.ANFProperty, len(program.Properties))
	for i, p := range program.Properties {
		sdkProps[i] = runar.ANFProperty{
			Name:         p.Name,
			Type:         p.Type,
			Readonly:     p.Readonly,
			InitialValue: p.InitialValue,
		}
	}

	sdkMethods := make([]runar.ANFMethod, len(program.Methods))
	for i, m := range program.Methods {
		sdkParams := make([]runar.ANFParam, len(m.Params))
		for j, p := range m.Params {
			sdkParams[j] = runar.ANFParam{Name: p.Name, Type: p.Type}
		}
		sdkMethods[i] = runar.ANFMethod{
			Name:     m.Name,
			Params:   sdkParams,
			Body:     ConvertIRBindings(m.Body),
			IsPublic: m.IsPublic,
		}
	}

	return &runar.ANFProgram{
		ContractName: program.ContractName,
		Properties:   sdkProps,
		Methods:      sdkMethods,
	}
}

func ConvertIRBindings(bindings []ir.ANFBinding) []runar.ANFBinding {
	result := make([]runar.ANFBinding, len(bindings))
	for i, b := range bindings {
		result[i] = runar.ANFBinding{
			Name:  b.Name,
			Value: ConvertIRValue(b.Value),
		}
	}
	return result
}

func ConvertIRValue(v ir.ANFValue) map[string]interface{} {
	m := map[string]interface{}{
		"kind": v.Kind,
	}

	switch v.Kind {
	case "load_param", "load_prop":
		m["name"] = v.Name

	case "load_const":
		// Reconstruct the value from the typed Const* fields (which are json:"-")
		if v.ConstString != nil {
			m["value"] = *v.ConstString
		} else if v.ConstBool != nil {
			m["value"] = *v.ConstBool
		} else if v.ConstBigInt != nil {
			// Use int64 if it fits, otherwise string representation
			if v.ConstInt != nil {
				m["value"] = float64(*v.ConstInt)
			} else {
				m["value"] = v.ConstBigInt.String()
			}
		} else if v.ConstInt != nil {
			m["value"] = float64(*v.ConstInt)
		}

	case "bin_op":
		m["op"] = v.Op
		m["left"] = v.Left
		m["right"] = v.Right
		if v.ResultType != "" {
			m["result_type"] = v.ResultType
		}

	case "unary_op":
		m["op"] = v.Op
		m["operand"] = v.Operand
		if v.ResultType != "" {
			m["result_type"] = v.ResultType
		}

	case "call":
		m["func"] = v.Func
		args := make([]interface{}, len(v.Args))
		for i, a := range v.Args {
			args[i] = a
		}
		m["args"] = args

	case "method_call":
		m["object"] = v.Object
		m["method"] = v.Method
		args := make([]interface{}, len(v.Args))
		for i, a := range v.Args {
			args[i] = a
		}
		m["args"] = args

	case "if":
		m["cond"] = v.Cond
		m["then"] = ConvertBindingsToInterface(v.Then)
		m["else"] = ConvertBindingsToInterface(v.Else)

	case "loop":
		m["count"] = v.Count
		m["iterVar"] = v.IterVar
		m["body"] = ConvertBindingsToInterface(v.Body)

	case "assert":
		m["value"] = v.ValueRef

	case "update_prop":
		m["name"] = v.Name
		m["value"] = v.ValueRef

	case "check_preimage":
		m["preimage"] = v.Preimage

	case "deserialize_state":
		m["preimage"] = v.Preimage

	case "add_output":
		m["satoshis"] = v.Satoshis
		if len(v.StateValues) > 0 {
			sv := make([]interface{}, len(v.StateValues))
			for i, s := range v.StateValues {
				sv[i] = s
			}
			m["stateValues"] = sv
		}
		if v.Preimage != "" {
			m["preimage"] = v.Preimage
		}

	case "add_raw_output":
		m["satoshis"] = v.Satoshis
		m["scriptBytes"] = v.ScriptBytes

	case "add_data_output":
		m["satoshis"] = v.Satoshis
		m["scriptBytes"] = v.ScriptBytes

	case "get_state_script":
		// no extra fields needed
	}

	return m
}

// ConvertBindingsToInterface converts IR bindings to []interface{} of maps,
// matching the format that anfGetBindings expects in the SDK interpreter.
func ConvertBindingsToInterface(bindings []ir.ANFBinding) []interface{} {
	result := make([]interface{}, len(bindings))
	for i, b := range bindings {
		result[i] = map[string]interface{}{
			"name":  b.Name,
			"value": ConvertIRValue(b.Value),
		}
	}
	return result
}

// ComputeHashOutputsFromTxHex manually parses a raw TX hex and computes
// the BIP-143 hashOutputs (double-SHA256 of serialized outputs).
func ComputeHashOutputsFromTxHex(txHex string) string {
	pos := 8 // skip version
	// Input count
	ic, icl := readVI(txHex, pos)
	pos += icl
	// Skip all inputs
	for i := 0; i < ic; i++ {
		pos += 64 + 8 // prevtxid + vout
		sl, sll := readVI(txHex, pos)
		pos += sll + sl*2 + 8 // scriptSig + sequence
	}
	// Output count
	oc, ocl := readVI(txHex, pos)
	pos += ocl
	// Serialize all outputs
	var outputsHex string
	for i := 0; i < oc; i++ {
		valHex := txHex[pos : pos+16]
		pos += 16
		sl, sll := readVI(txHex, pos)
		viHex := txHex[pos : pos+sll]
		pos += sll
		scriptHex := txHex[pos : pos+sl*2]
		pos += sl * 2
		outputsHex += valHex + viHex + scriptHex
		_ = i
	}
	outputsBytes, _ := hex.DecodeString(outputsHex)
	h1 := sha256Sum(outputsBytes)
	h2 := sha256Sum(h1)
	return hex.EncodeToString(h2)
}

func readVI(h string, pos int) (int, int) {
	fb, _ := strconv.ParseUint(h[pos:pos+2], 16, 8)
	if fb < 0xfd {
		return int(fb), 2
	}
	if fb == 0xfd {
		lo, _ := strconv.ParseUint(h[pos+2:pos+4], 16, 8)
		hi, _ := strconv.ParseUint(h[pos+4:pos+6], 16, 8)
		return int(lo) | int(hi)<<8, 6
	}
	if fb == 0xfe {
		b0, _ := strconv.ParseUint(h[pos+2:pos+4], 16, 8)
		b1, _ := strconv.ParseUint(h[pos+4:pos+6], 16, 8)
		b2, _ := strconv.ParseUint(h[pos+6:pos+8], 16, 8)
		b3, _ := strconv.ParseUint(h[pos+8:pos+10], 16, 8)
		return int(b0) | int(b1)<<8 | int(b2)<<16 | int(b3)<<24, 10
	}
	// fb == 0xff: 8-byte little-endian value
	b0, _ := strconv.ParseUint(h[pos+2:pos+4], 16, 8)
	b1, _ := strconv.ParseUint(h[pos+4:pos+6], 16, 8)
	b2, _ := strconv.ParseUint(h[pos+6:pos+8], 16, 8)
	b3, _ := strconv.ParseUint(h[pos+8:pos+10], 16, 8)
	b4, _ := strconv.ParseUint(h[pos+10:pos+12], 16, 8)
	b5, _ := strconv.ParseUint(h[pos+12:pos+14], 16, 8)
	b6, _ := strconv.ParseUint(h[pos+14:pos+16], 16, 8)
	b7, _ := strconv.ParseUint(h[pos+16:pos+18], 16, 8)
	return int(b0) | int(b1)<<8 | int(b2)<<16 | int(b3)<<24 |
		int(b4)<<32 | int(b5)<<40 | int(b6)<<48 | int(b7)<<56, 18
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// CompileWithTSCompiler compiles a source string using the TypeScript compiler
// via the Node CLI. Returns the raw artifact JSON bytes.
func CompileWithTSCompiler(source, fileName string) ([]byte, error) {
	// Write source to temp file
	tmpDir, err := os.MkdirTemp("", "runar-ts-compile-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, fileName)
	if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
		return nil, err
	}

	outDir := filepath.Join(tmpDir, "out")
	os.MkdirAll(outDir, 0755)

	// Run TS compiler
	root := projectRoot()
	cmd := fmt.Sprintf("npx tsx %s/packages/runar-cli/src/bin.ts compile %s -o %s",
		root, srcPath, outDir)
	out, err := runCmd(cmd, root, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TS compile: %s: %w", out, err)
	}

	// Read the artifact JSON (filename without the extension + .json)
	baseName := fileName[:len(fileName)-3] // strip .ts
	artifactPath := filepath.Join(outDir, baseName+".json")
	return os.ReadFile(artifactPath)
}

func runCmd(cmdStr, dir string, timeout time.Duration) (string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
