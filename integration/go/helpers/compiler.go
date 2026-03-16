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
	for _, p := range contract.Constructor.Params {
		typeName := "bigint"
		if p.Type != nil {
			typeName = astTypeName(p.Type)
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
				typeName = astTypeName(p.Type)
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
	sdkANF := convertIRANFToSDK(program)

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

// ---------------------------------------------------------------------------
// IR → SDK ANF conversion
// ---------------------------------------------------------------------------

// convertIRANFToSDK converts the compiler's ir.ANFProgram (typed structs) to
// the SDK's runar.ANFProgram (map[string]interface{} values) so the SDK's
// auto-state computation (ComputeNewState) can interpret the ANF.
func convertIRANFToSDK(program *ir.ANFProgram) *runar.ANFProgram {
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
			Body:     convertIRBindings(m.Body),
			IsPublic: m.IsPublic,
		}
	}

	return &runar.ANFProgram{
		ContractName: program.ContractName,
		Properties:   sdkProps,
		Methods:      sdkMethods,
	}
}

func convertIRBindings(bindings []ir.ANFBinding) []runar.ANFBinding {
	result := make([]runar.ANFBinding, len(bindings))
	for i, b := range bindings {
		result[i] = runar.ANFBinding{
			Name:  b.Name,
			Value: convertIRValue(b.Value),
		}
	}
	return result
}

func convertIRValue(v ir.ANFValue) map[string]interface{} {
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
		m["then"] = convertBindingsToInterface(v.Then)
		m["else"] = convertBindingsToInterface(v.Else)

	case "loop":
		m["count"] = v.Count
		m["iterVar"] = v.IterVar
		m["body"] = convertBindingsToInterface(v.Body)

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

	case "get_state_script":
		// no extra fields needed
	}

	return m
}

// convertBindingsToInterface converts IR bindings to []interface{} of maps,
// matching the format that anfGetBindings expects in the SDK interpreter.
func convertBindingsToInterface(bindings []ir.ANFBinding) []interface{} {
	result := make([]interface{}, len(bindings))
	for i, b := range bindings {
		result[i] = map[string]interface{}{
			"name":  b.Name,
			"value": convertIRValue(b.Value),
		}
	}
	return result
}
