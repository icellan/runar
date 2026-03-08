package helpers

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/icellan/runar/compilers/go/codegen"
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
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
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

// CompileToSDKArtifact compiles a source file and returns a runar.RunarArtifact
// suitable for use with RunarContract from the SDK.
func CompileToSDKArtifact(sourcePath string, constructorArgs map[string]interface{}) (*runar.RunarArtifact, error) {
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
		return nil, fmt.Errorf("no contract found in %s", sourcePath)
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
	for _, p := range program.Properties {
		ctorParams = append(ctorParams, runar.ABIParam{Name: p.Name, Type: p.Type})
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
				typeName = astTypeName(p.Type)
			}
			stateFields = append(stateFields, runar.StateField{
				Name:  p.Name,
				Type:  typeName,
				Index: i, // matches constructor arg order
			})
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

	return &runar.RunarArtifact{
		Version:          "runar-v0.1.0",
		CompilerVersion:  "integration-test",
		ContractName:     program.ContractName,
		Script:           emitResult.ScriptHex,
		ASM:              emitResult.ScriptAsm,
		ConstructorSlots: cSlots,
		StateFields:      stateFields,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: ctorParams},
			Methods:     abiMethods,
		},
	}, nil
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

	var ctorParams []runar.ABIParam
	for _, p := range program.Properties {
		ctorParams = append(ctorParams, runar.ABIParam{Name: p.Name, Type: p.Type})
	}

	var cSlots []runar.ConstructorSlot
	for _, s := range emitResult.ConstructorSlots {
		cSlots = append(cSlots, runar.ConstructorSlot{
			ParamIndex: s.ParamIndex,
			ByteOffset: s.ByteOffset,
		})
	}

	return &runar.RunarArtifact{
		Version:          "runar-v0.1.0",
		CompilerVersion:  "integration-test",
		ContractName:     program.ContractName,
		Script:           emitResult.ScriptHex,
		ASM:              emitResult.ScriptAsm,
		ConstructorSlots: cSlots,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: ctorParams},
			Methods:     abiMethods,
		},
	}, nil
}

// astTypeName extracts the type name string from a frontend.TypeNode.
func astTypeName(t frontend.TypeNode) string {
	switch v := t.(type) {
	case frontend.PrimitiveType:
		return v.Name
	case frontend.FixedArrayType:
		return fmt.Sprintf("FixedArray<%s,%d>", astTypeName(v.Element), v.Length)
	case frontend.CustomType:
		return v.Name
	default:
		return "bigint"
	}
}
