// Package ir defines the Go representation of Rúnar's A-Normal Form intermediate
// representation. These types mirror the canonical ANF IR JSON schema and are
// used to deserialise IR files produced by any conformant Rúnar compiler.
package ir

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

// ANFProgram is the top-level IR container.
type ANFProgram struct {
	ContractName string        `json:"contractName"`
	Properties   []ANFProperty `json:"properties"`
	Methods      []ANFMethod   `json:"methods"`
}

// ANFProperty describes a contract-level property (constructor parameter).
type ANFProperty struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Readonly     bool        `json:"readonly"`
	InitialValue interface{} `json:"initialValue,omitempty"` // string | number | bool
}

// ANFMethod is a single contract method.
type ANFMethod struct {
	Name     string       `json:"name"`
	Params   []ANFParam   `json:"params"`
	Body     []ANFBinding `json:"body"`
	IsPublic bool         `json:"isPublic"`
}

// ANFParam describes a method parameter.
type ANFParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ---------------------------------------------------------------------------
// Bindings — the core of the ANF representation
// ---------------------------------------------------------------------------

// ANFBinding is a single let-binding: `let <Name> = <Value>`.
// Names follow the pattern t0, t1, ... and are scoped per method.
type ANFBinding struct {
	Name  string   `json:"name"`
	Value ANFValue `json:"value"`
}

// ---------------------------------------------------------------------------
// ANF value types (discriminated on Kind)
// ---------------------------------------------------------------------------

// ANFValue uses a flat struct with a Kind discriminator. Only the fields
// relevant to the specific Kind are populated. This approach avoids the need
// for interface-based dispatch while remaining straightforward to deserialise
// from JSON.
type ANFValue struct {
	Kind string `json:"kind"`

	// load_param, load_prop, update_prop
	Name string `json:"name,omitempty"`

	// load_const — the raw JSON value is decoded separately
	RawValue json.RawMessage `json:"value,omitempty"`

	// Decoded constant value (populated by decodeConstValue)
	ConstString *string   `json:"-"`
	ConstBigInt *big.Int  `json:"-"`
	ConstBool   *bool     `json:"-"`
	ConstInt    *int64    `json:"-"` // small integers from JSON numbers

	// bin_op
	Op         string `json:"op,omitempty"`
	Left       string `json:"left,omitempty"`
	Right      string `json:"right,omitempty"`
	ResultType string `json:"result_type,omitempty"` // operand type hint: "bytes" for byte-typed equality

	// unary_op
	Operand string `json:"operand,omitempty"`

	// call
	Func string   `json:"func,omitempty"`
	Args []string `json:"args,omitempty"`

	// method_call
	Object string `json:"object,omitempty"`
	Method string `json:"method,omitempty"`

	// if
	Cond string       `json:"cond,omitempty"`
	Then []ANFBinding `json:"then,omitempty"`
	Else []ANFBinding `json:"else,omitempty"`

	// loop
	Count   int    `json:"count,omitempty"`
	IterVar string `json:"iterVar,omitempty"`
	// loop body reuses Then field? No — we use a separate Body field.
	Body []ANFBinding `json:"body,omitempty"`

	// assert, update_prop (value ref), check_preimage
	ValueRef string `json:"-"` // populated from RawValue for assert / update_prop / check_preimage

	// check_preimage, deserialize_state
	Preimage string `json:"preimage,omitempty"`

	// add_output
	Satoshis    string   `json:"satoshis,omitempty"`
	StateValues []string `json:"stateValues,omitempty"`

	// add_raw_output
	ScriptBytes string `json:"scriptBytes,omitempty"`

	// array_literal
	Elements []string `json:"elements,omitempty"`
}

// DecodeConstants walks the program and decodes the RawValue fields in
// load_const bindings into their typed Go representations, and extracts
// the value reference string for assert/update_prop kinds.
func DecodeConstants(program *ANFProgram) error {
	for mi := range program.Methods {
		if err := decodeBindings(program.Methods[mi].Body); err != nil {
			return fmt.Errorf("method %s: %w", program.Methods[mi].Name, err)
		}
	}
	return nil
}

func decodeBindings(bindings []ANFBinding) error {
	for i := range bindings {
		v := &bindings[i].Value
		if err := decodeValue(v); err != nil {
			return fmt.Errorf("binding %s: %w", bindings[i].Name, err)
		}
	}
	return nil
}

func decodeValue(v *ANFValue) error {
	switch v.Kind {
	case "load_const":
		return decodeConstValue(v)
	case "assert":
		// The "value" field is a string reference
		if len(v.RawValue) > 0 {
			var s string
			if err := json.Unmarshal(v.RawValue, &s); err != nil {
				return fmt.Errorf("assert value: %w", err)
			}
			v.ValueRef = s
		}
	case "update_prop":
		// The "value" field is a string reference
		if len(v.RawValue) > 0 {
			var s string
			if err := json.Unmarshal(v.RawValue, &s); err != nil {
				return fmt.Errorf("update_prop value: %w", err)
			}
			v.ValueRef = s
		}
	case "if":
		if err := decodeBindings(v.Then); err != nil {
			return fmt.Errorf("if/then: %w", err)
		}
		if err := decodeBindings(v.Else); err != nil {
			return fmt.Errorf("if/else: %w", err)
		}
	case "loop":
		if err := decodeBindings(v.Body); err != nil {
			return fmt.Errorf("loop/body: %w", err)
		}
	case "add_output":
		// satoshis and stateValues are decoded directly from JSON tags; nothing extra needed.
	}
	return nil
}

func decodeConstValue(v *ANFValue) error {
	if len(v.RawValue) == 0 {
		return fmt.Errorf("load_const missing value")
	}

	raw := v.RawValue

	// Try boolean
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		// Check it's actually true/false, not a number
		s := string(raw)
		if s == "true" || s == "false" {
			v.ConstBool = &b
			return nil
		}
	}

	// Try string (hex-encoded bytes)
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		v.ConstString = &str
		return nil
	}

	// Try number (JSON numbers can be integers or floats)
	var num json.Number
	if err := json.Unmarshal(raw, &num); err == nil {
		// Try as int64 first
		if i, err := num.Int64(); err == nil {
			v.ConstInt = &i
			bi := big.NewInt(i)
			v.ConstBigInt = bi
			return nil
		}
		// Try as big.Int
		bi := new(big.Int)
		if _, ok := bi.SetString(num.String(), 10); ok {
			v.ConstBigInt = bi
			return nil
		}
	}

	return fmt.Errorf("unable to decode constant value: %s", string(raw))
}
