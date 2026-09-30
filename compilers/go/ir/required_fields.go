package ir

import (
	"encoding/json"
	"fmt"
)

// N-069 — presence and JSON type of the ANF IR's required fields, checked on
// the generic decoded document BEFORE it is unmarshalled into ANFProgram.
//
// encoding/json turns a missing field into its zero value, so a public method
// with no `body` loaded as a method with zero bindings and was refused only by
// accident, far downstream; a wrongly typed one surfaced as a raw decoder
// message ("cannot unmarshal string into Go struct field ..."). The required
// set is anf-ir.schema.json's `required` keys, minus the ones every loader
// defaults for older payloads (loop start/step, add_output preimage).
//
// The diagnostics are shared verbatim with the other six tiers (Java's F-084
// loader is the origin), pinned by conformance/negatives/ir-required-fields.test.ts:
//
//	IR validation: required field <path> is missing
//	IR validation: <path> must be <a type>, got <json type>

type irObj = map[string]any

func irJSONType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "number"
	}
}

func irFieldPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func irMalformed(path, expected string, got any) error {
	return fmt.Errorf("IR validation: %s must be %s, got %s", path, expected, irJSONType(got))
}

// irReq treats absence and a JSON null alike as "missing".
func irReq(obj irObj, key, path string) (any, error) {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil, fmt.Errorf("IR validation: required field %s is missing", irFieldPath(path, key))
	}
	return v, nil
}

func irReqString(obj irObj, key, path string) error {
	v, err := irReq(obj, key, path)
	if err != nil {
		return err
	}
	if _, ok := v.(string); !ok {
		return irMalformed(irFieldPath(path, key), "a string", v)
	}
	return nil
}

func irReqBool(obj irObj, key, path string) error {
	v, err := irReq(obj, key, path)
	if err != nil {
		return err
	}
	if _, ok := v.(bool); !ok {
		return irMalformed(irFieldPath(path, key), "a boolean", v)
	}
	return nil
}

func irReqArray(obj irObj, key, path string) ([]any, error) {
	v, err := irReq(obj, key, path)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, irMalformed(irFieldPath(path, key), "an array", v)
	}
	return arr, nil
}

func irAsObject(v any, path string) (irObj, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, irMalformed(path, "an object", v)
	}
	return obj, nil
}

func irReqStrings(obj irObj, key, path string) error {
	arr, err := irReqArray(obj, key, path)
	if err != nil {
		return err
	}
	lp := irFieldPath(path, key)
	for i, e := range arr {
		if _, ok := e.(string); !ok {
			return irMalformed(fmt.Sprintf("%s[%d]", lp, i), "a string", e)
		}
	}
	return nil
}

func irCheckStrings(obj irObj, path string, keys ...string) error {
	for _, k := range keys {
		if err := irReqString(obj, k, path); err != nil {
			return err
		}
	}
	return nil
}

func irCheckBindings(obj irObj, key, path string) error {
	arr, err := irReqArray(obj, key, path)
	if err != nil {
		return err
	}
	lp := irFieldPath(path, key)
	for i, b := range arr {
		bp := fmt.Sprintf("%s[%d]", lp, i)
		binding, err := irAsObject(b, bp)
		if err != nil {
			return err
		}
		if err := irReqString(binding, "name", bp); err != nil {
			return err
		}
		value, err := irAsObject(binding["value"], bp+".value")
		if err != nil {
			return err
		}
		if err := irCheckValue(value, bp+".value"); err != nil {
			return err
		}
	}
	return nil
}

func irCheckValue(v irObj, path string) error {
	if err := irReqString(v, "kind", path); err != nil {
		return err
	}
	switch v["kind"].(string) {
	case "load_param", "load_prop":
		return irCheckStrings(v, path, "name")
	case "bin_op":
		return irCheckStrings(v, path, "op", "left", "right")
	case "unary_op":
		return irCheckStrings(v, path, "op", "operand")
	case "call":
		if err := irReqString(v, "func", path); err != nil {
			return err
		}
		return irReqStrings(v, "args", path)
	case "method_call":
		if err := irCheckStrings(v, path, "object", "method"); err != nil {
			return err
		}
		return irReqStrings(v, "args", path)
	case "if":
		if err := irReqString(v, "cond", path); err != nil {
			return err
		}
		if err := irCheckBindings(v, "then", path); err != nil {
			return err
		}
		if err := irCheckBindings(v, "else", path); err != nil {
			return err
		}
		if _, ok := v["results"]; ok {
			return irReqStrings(v, "results", path)
		}
	case "loop":
		if err := irCheckBindings(v, "body", path); err != nil {
			return err
		}
		return irReqString(v, "iterVar", path)
	case "assert":
		return irCheckStrings(v, path, "value")
	case "update_prop":
		return irCheckStrings(v, path, "name", "value")
	case "check_preimage", "deserialize_state":
		return irCheckStrings(v, path, "preimage")
	case "add_output":
		if err := irReqString(v, "satoshis", path); err != nil {
			return err
		}
		return irReqStrings(v, "stateValues", path)
	case "add_raw_output", "add_data_output":
		return irCheckStrings(v, path, "satoshis", "scriptBytes")
	case "array_literal":
		return irReqStrings(v, "elements", path)
	}
	// load_const, get_state_script, raw_script: value-level rules check their
	// fields. Unknown kinds are refused by ValidateIR.
	return nil
}

// assertRequiredIRFields returns the first required field that is missing or
// of the wrong JSON type. See the file comment.
func assertRequiredIRFields(data []byte) error {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("invalid IR JSON: %w", err)
	}
	program, err := irAsObject(root, "the IR document")
	if err != nil {
		return err
	}
	if err := irReqString(program, "contractName", ""); err != nil {
		return err
	}
	props, err := irReqArray(program, "properties", "")
	if err != nil {
		return err
	}
	for i, p := range props {
		pp := fmt.Sprintf("properties[%d]", i)
		prop, err := irAsObject(p, pp)
		if err != nil {
			return err
		}
		if err := irCheckStrings(prop, pp, "name", "type"); err != nil {
			return err
		}
		if err := irReqBool(prop, "readonly", pp); err != nil {
			return err
		}
	}
	methods, err := irReqArray(program, "methods", "")
	if err != nil {
		return err
	}
	for i, m := range methods {
		mp := fmt.Sprintf("methods[%d]", i)
		method, err := irAsObject(m, mp)
		if err != nil {
			return err
		}
		if err := irReqString(method, "name", mp); err != nil {
			return err
		}
		if err := irReqBool(method, "isPublic", mp); err != nil {
			return err
		}
		params, err := irReqArray(method, "params", mp)
		if err != nil {
			return err
		}
		for j, p := range params {
			pp := fmt.Sprintf("%s.params[%d]", mp, j)
			param, err := irAsObject(p, pp)
			if err != nil {
				return err
			}
			if err := irCheckStrings(param, pp, "name", "type"); err != nil {
				return err
			}
		}
		if err := irCheckBindings(method, "body", mp); err != nil {
			return err
		}
	}
	return nil
}
