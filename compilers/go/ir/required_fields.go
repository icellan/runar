package ir

import (
	"encoding/json"
	"fmt"
	"strconv"
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

// F-038 / F-065: the two OPTIONAL keys the artifact copies into the fields the
// SDK signs by. Absent or null is legal (IR written before they existed); a
// present value must be one the source path can produce. Shared verbatim with
// the other six tiers.
func irOptParentClass(program irObj) error {
	v, ok := program["parentClass"]
	if !ok || v == nil {
		return nil
	}
	s, isStr := v.(string)
	if !isStr {
		return irMalformed("parentClass", "a string", v)
	}
	switch s {
	case "SmartContract", "StatefulSmartContract", "UnsafeSmartContract":
		return nil
	}
	return fmt.Errorf("IR validation: parentClass must be one of SmartContract, StatefulSmartContract, UnsafeSmartContract, got %s", s)
}

func irOptSigHashType(method irObj, path string) error {
	v, ok := method["sigHashType"]
	if !ok || v == nil {
		return nil
	}
	lp := irFieldPath(path, "sigHashType")
	n, isNum := v.(float64)
	if !isNum {
		return irMalformed(lp, "an integer", v)
	}
	switch n {
	case 0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3:
		return nil
	}
	return fmt.Errorf("IR validation: %s must be one of 65, 66, 67, 193, 194, 195, got %v", lp, n)
}

// N-059 / F-102: a check_preimage binding's optional sighashFlag, at every
// nesting depth, on the raw document — where an explicit 0 is still
// distinguishable from an absent field (the typed ANFValue decodes both to 0).
// Codegen appends `sighashFlag & 0xff` to the OP_PUSH_TX binding, so an
// out-of-set value is a byte no BSV spend can satisfy and an explicit 0 emits
// 0x00 in five tiers. Absent (or null) means the default ALL|FORKID. In a
// public method the flag must also equal the method's sigHashType (default
// 0x41): the artifact tells the SDK to sign under sigHashType, the script
// derives its sighash under the flag, and a divergence is unspendable. Both
// diagnostics are shared verbatim with the other six tiers (the first is
// F-068's, which validateBindings also still raises on the typed program).
func irCheckSighashFlags(obj irObj, key, path, method string, isPublic bool, declared float64) error {
	lp := irFieldPath(path, key)
	for i, b := range obj[key].([]any) {
		binding := b.(map[string]any)
		vp := fmt.Sprintf("%s[%d].value", lp, i)
		v := binding["value"].(map[string]any)
		switch v["kind"] {
		case "if":
			if err := irCheckSighashFlags(v, "then", vp, method, isPublic, declared); err != nil {
				return err
			}
			if err := irCheckSighashFlags(v, "else", vp, method, isPublic, declared); err != nil {
				return err
			}
		case "loop":
			if err := irCheckSighashFlags(v, "body", vp, method, isPublic, declared); err != nil {
				return err
			}
		case "check_preimage":
			// Ports #170: only the two constructions exist; anything else must
			// not reach codegen, where it would silently emit the default blob.
			if raw, ok := v["bindingVariant"]; ok && raw != nil && raw != "lowS" && raw != "all" {
				return fmt.Errorf(
					"IR validation: method %s binding %v check_preimage has an invalid bindingVariant; bindingVariant must be \"lowS\" or \"all\"",
					method, binding["name"])
			}
			flag := float64(0x41)
			if raw, ok := v["sighashFlag"]; ok && raw != nil {
				n, isNum := raw.(float64)
				if !isNum {
					return irMalformed(irFieldPath(vp, "sighashFlag"), "an integer", raw)
				}
				flag = n
				switch n {
				case 0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3:
				default:
					return fmt.Errorf(
						"IR validation: method %s binding %v check_preimage has sighashFlag %s; sighashFlag must be one of {0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3} (ALL/NONE/SINGLE with FORKID, optionally ANYONECANPAY). Any other value is truncated to a sighash byte no BSV spend can satisfy.",
						method, binding["name"], strconv.FormatFloat(n, 'f', -1, 64))
				}
			}
			if isPublic && flag != declared {
				return fmt.Errorf(
					"IR validation: method %s binding %v check_preimage has sighashFlag %s but the method declares sigHashType %s; a public method's check_preimage must bind the sighash type its ABI declares, or the SDK signs a preimage the script rejects.",
					method, binding["name"], strconv.FormatFloat(flag, 'f', -1, 64), strconv.FormatFloat(declared, 'f', -1, 64))
			}
		}
	}
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
	if err := irOptParentClass(program); err != nil {
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
		if err := irOptSigHashType(method, mp); err != nil {
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
		declared, isNum := method["sigHashType"].(float64)
		if !isNum {
			declared = 0x41
		}
		if err := irCheckSighashFlags(method, "body", mp, method["name"].(string), method["isPublic"].(bool), declared); err != nil {
			return err
		}
	}
	return assertIRIdentifiers(program)
}

// N-207: the declared identifiers are non-empty, and a method's parameter
// names are distinct. Runs after the type walk above, so every field read
// here is a string. "" is a string, so N-069 alone let an empty name through;
// and duplicate param names alias ONE stack slot (every load_param resolves to
// the last declared one, so assert(p0 === p1) over two params of the same name
// compiled to an always-true script). Shared verbatim with the other six
// tiers, pinned by conformance/negatives/ir-identifiers.test.ts:
//
//	IR validation: <path> must be a non-empty string
//	IR validation: <path>.name '<name>' duplicates <earlier path>.name
func irNonEmpty(obj irObj, key, path string) error {
	if obj[key] == "" {
		return fmt.Errorf("IR validation: %s must be a non-empty string", irFieldPath(path, key))
	}
	return nil
}

// irNonEmptyBindingNames is N-408: a binding's name is non-empty at every
// nesting level (a method body, an `if` arm, a `loop` body), named by the path
// the type walk uses: methods[0].body[1].value.then[0].name.
func irNonEmptyBindingNames(obj irObj, key, path string) error {
	lp := irFieldPath(path, key)
	for i, b := range obj[key].([]any) {
		bp := fmt.Sprintf("%s[%d]", lp, i)
		binding := b.(irObj)
		if err := irNonEmpty(binding, "name", bp); err != nil {
			return err
		}
		value := binding["value"].(irObj)
		vp := bp + ".value"
		if err := irNonEmpty(value, "kind", vp); err != nil {
			return err
		}
		switch value["kind"] {
		case "if":
			for _, arm := range []string{"then", "else"} {
				if err := irNonEmptyBindingNames(value, arm, vp); err != nil {
					return err
				}
			}
		case "loop":
			if err := irNonEmptyBindingNames(value, "body", vp); err != nil {
				return err
			}
		}
	}
	return nil
}

func assertIRIdentifiers(program irObj) error {
	if err := irNonEmpty(program, "contractName", ""); err != nil {
		return err
	}
	for i, p := range program["properties"].([]any) {
		pp := fmt.Sprintf("properties[%d]", i)
		for _, k := range []string{"name", "type"} {
			if err := irNonEmpty(p.(irObj), k, pp); err != nil {
				return err
			}
		}
	}
	for i, m := range program["methods"].([]any) {
		mp := fmt.Sprintf("methods[%d]", i)
		method := m.(irObj)
		if err := irNonEmpty(method, "name", mp); err != nil {
			return err
		}
		seen := map[string]int{}
		for j, p := range method["params"].([]any) {
			pp := fmt.Sprintf("%s.params[%d]", mp, j)
			param := p.(irObj)
			for _, k := range []string{"name", "type"} {
				if err := irNonEmpty(param, k, pp); err != nil {
					return err
				}
			}
			name := param["name"].(string)
			if first, dup := seen[name]; dup {
				return fmt.Errorf("IR validation: %s.name '%s' duplicates %s.params[%d].name", pp, name, mp, first)
			}
			seen[name] = j
		}
		if err := irNonEmptyBindingNames(method, "body", mp); err != nil {
			return err
		}
	}
	return nil
}
