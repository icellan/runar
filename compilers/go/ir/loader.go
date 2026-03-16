package ir

import (
	"fmt"
	"os"

	"encoding/json"
)

// LoadIR reads an ANF IR JSON file from disk, deserialises it, validates it,
// and decodes constant values into their typed Go representations.
func LoadIR(path string) (*ANFProgram, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading IR file: %w", err)
	}

	var program ANFProgram
	if err := json.Unmarshal(data, &program); err != nil {
		return nil, fmt.Errorf("invalid IR JSON: %w", err)
	}

	// Decode typed constant values from raw JSON
	if err := DecodeConstants(&program); err != nil {
		return nil, fmt.Errorf("decoding constants: %w", err)
	}

	if err := ValidateIR(&program); err != nil {
		return nil, err
	}

	return &program, nil
}

// LoadIRFromBytes is like LoadIR but accepts raw JSON bytes directly.
func LoadIRFromBytes(data []byte) (*ANFProgram, error) {
	var program ANFProgram
	if err := json.Unmarshal(data, &program); err != nil {
		return nil, fmt.Errorf("invalid IR JSON: %w", err)
	}

	if err := DecodeConstants(&program); err != nil {
		return nil, fmt.Errorf("decoding constants: %w", err)
	}

	if err := ValidateIR(&program); err != nil {
		return nil, err
	}

	return &program, nil
}

// MaxLoopCount is the maximum number of loop iterations allowed in a single
// loop binding. This prevents resource exhaustion from malicious or accidental
// extremely large loop counts during loop unrolling.
const MaxLoopCount = 10000

// ValidateIR performs basic structural validation of a parsed ANF program.
func ValidateIR(program *ANFProgram) error {
	if program.ContractName == "" {
		return fmt.Errorf("IR validation: contractName is required")
	}

	for i, method := range program.Methods {
		if method.Name == "" {
			return fmt.Errorf("IR validation: method[%d] has empty name", i)
		}
		for j, param := range method.Params {
			if param.Name == "" {
				return fmt.Errorf("IR validation: method %s param[%d] has empty name", method.Name, j)
			}
			if param.Type == "" {
				return fmt.Errorf("IR validation: method %s param %s has empty type", method.Name, param.Name)
			}
		}
		if err := validateBindings(method.Body, method.Name); err != nil {
			return err
		}
	}

	for i, prop := range program.Properties {
		if prop.Name == "" {
			return fmt.Errorf("IR validation: property[%d] has empty name", i)
		}
		if prop.Type == "" {
			return fmt.Errorf("IR validation: property %s has empty type", prop.Name)
		}
	}

	return nil
}

// knownKinds enumerates all valid ANF value kinds.
var knownKinds = map[string]bool{
	"load_param":       true,
	"load_prop":        true,
	"load_const":       true,
	"bin_op":           true,
	"unary_op":         true,
	"call":             true,
	"method_call":      true,
	"if":               true,
	"loop":             true,
	"assert":           true,
	"update_prop":      true,
	"get_state_script": true,
	"check_preimage":     true,
	"deserialize_state": true,
	"add_output":        true,
	"add_raw_output":    true,
	"array_literal":     true,
}

func validateBindings(bindings []ANFBinding, methodName string) error {
	for i, binding := range bindings {
		if binding.Name == "" {
			return fmt.Errorf("IR validation: method %s binding[%d] has empty name", methodName, i)
		}
		kind := binding.Value.Kind
		if kind == "" {
			return fmt.Errorf("IR validation: method %s binding %s has empty kind", methodName, binding.Name)
		}
		if !knownKinds[kind] {
			return fmt.Errorf("IR validation: method %s binding %s has unknown kind %q", methodName, binding.Name, kind)
		}

		// Validate nested bindings
		if kind == "if" {
			if err := validateBindings(binding.Value.Then, methodName); err != nil {
				return err
			}
			if err := validateBindings(binding.Value.Else, methodName); err != nil {
				return err
			}
		}
		if kind == "loop" {
			if binding.Value.Count < 0 {
				return fmt.Errorf("IR validation: method %s binding %s has negative loop count %d", methodName, binding.Name, binding.Value.Count)
			}
			if binding.Value.Count > MaxLoopCount {
				return fmt.Errorf("IR validation: method %s binding %s has loop count %d exceeding maximum %d", methodName, binding.Name, binding.Value.Count, MaxLoopCount)
			}
			if err := validateBindings(binding.Value.Body, methodName); err != nil {
				return err
			}
		}
	}
	return nil
}
