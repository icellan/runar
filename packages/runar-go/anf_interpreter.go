package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// ANF IR types (mirrors runar-ir-schema for Go)
// ---------------------------------------------------------------------------

// ANFProgram is the top-level ANF IR for a compiled contract.
type ANFProgram struct {
	ContractName string        `json:"contractName"`
	Properties   []ANFProperty `json:"properties"`
	Methods      []ANFMethod   `json:"methods"`
}

// ANFProperty describes a contract property in ANF IR.
type ANFProperty struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Readonly     bool        `json:"readonly"`
	InitialValue interface{} `json:"initialValue,omitempty"`
}

// ANFMethod describes a contract method in ANF IR.
type ANFMethod struct {
	Name     string       `json:"name"`
	Params   []ANFParam   `json:"params"`
	Body     []ANFBinding `json:"body"`
	IsPublic bool         `json:"isPublic"`
}

// ANFParam describes a method parameter in ANF IR.
type ANFParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ANFBinding represents a single let-binding in the ANF IR.
// The Value field is a raw JSON object whose "kind" field discriminates
// the variant (load_param, load_const, bin_op, call, update_prop, etc.).
type ANFBinding struct {
	Name  string                 `json:"name"`
	Value map[string]interface{} `json:"value"`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ComputeNewState interprets the ANF IR to compute the state transition for
// a contract method call. It returns the updated state (merged with current).
func ComputeNewState(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
) (map[string]interface{}, error) {
	// Find the method
	var method *ANFMethod
	for i := range anf.Methods {
		if anf.Methods[i].Name == methodName && anf.Methods[i].IsPublic {
			method = &anf.Methods[i]
			break
		}
	}
	if method == nil {
		return nil, fmt.Errorf("computeNewState: method '%s' not found in ANF IR", methodName)
	}

	// Initialize environment with property values
	env := make(map[string]interface{})
	for _, prop := range anf.Properties {
		if v, ok := currentState[prop.Name]; ok {
			env[prop.Name] = v
		} else if prop.InitialValue != nil {
			env[prop.Name] = prop.InitialValue
		}
	}

	// Load method params, skip implicit ones
	implicit := map[string]bool{
		"_changePKH":    true,
		"_changeAmount": true,
		"_newAmount":    true,
		"txPreimage":    true,
	}
	for _, param := range method.Params {
		if implicit[param.Name] {
			continue
		}
		if v, ok := args[param.Name]; ok {
			env[param.Name] = v
		}
	}

	// Track state mutations
	stateDelta := make(map[string]interface{})

	// Walk bindings
	anfEvalBindings(anf, method.Body, env, stateDelta)

	// Merge delta into current state
	result := make(map[string]interface{})
	for k, v := range currentState {
		result[k] = v
	}
	for k, v := range stateDelta {
		result[k] = v
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

func anfEvalBindings(
	anf *ANFProgram,
	bindings []ANFBinding,
	env map[string]interface{},
	stateDelta map[string]interface{},
) {
	for _, binding := range bindings {
		val := anfEvalValue(anf, binding.Value, env, stateDelta)
		env[binding.Name] = val
	}
}

func anfEvalValue(
	anf *ANFProgram,
	value map[string]interface{},
	env map[string]interface{},
	stateDelta map[string]interface{},
) interface{} {
	kind, _ := value["kind"].(string)

	switch kind {
	case "load_param":
		name, _ := value["name"].(string)
		return env[name]

	case "load_prop":
		name, _ := value["name"].(string)
		return env[name]

	case "load_const":
		v := value["value"]
		// Handle @ref: aliases
		if s, ok := v.(string); ok && strings.HasPrefix(s, "@ref:") {
			return env[s[5:]]
		}
		return v

	case "bin_op":
		op, _ := value["op"].(string)
		leftName, _ := value["left"].(string)
		rightName, _ := value["right"].(string)
		resultType, _ := value["result_type"].(string)
		return anfEvalBinOp(op, env[leftName], env[rightName], resultType)

	case "unary_op":
		op, _ := value["op"].(string)
		operandName, _ := value["operand"].(string)
		resultType, _ := value["result_type"].(string)
		return anfEvalUnaryOp(op, env[operandName], resultType)

	case "call":
		funcName, _ := value["func"].(string)
		argNames := anfGetStringSlice(value["args"])
		argVals := make([]interface{}, len(argNames))
		for i, name := range argNames {
			argVals[i] = env[name]
		}
		return anfEvalCall(funcName, argVals)

	case "method_call":
		methodName, _ := value["method"].(string)
		argNames := anfGetStringSlice(value["args"])
		argVals := make([]interface{}, len(argNames))
		for i, name := range argNames {
			argVals[i] = env[name]
		}
		// Look up private method in ANF program
		if anf != nil {
			for i := range anf.Methods {
				if anf.Methods[i].Name == methodName && !anf.Methods[i].IsPublic {
					m := &anf.Methods[i]
					// Create new env with params mapped to args
					callEnv := make(map[string]interface{})
					// Copy property values from caller env
					for _, prop := range anf.Properties {
						if v, ok := env[prop.Name]; ok {
							callEnv[prop.Name] = v
						}
					}
					// Map params to arg values
					for j, param := range m.Params {
						if j < len(argVals) {
							callEnv[param.Name] = argVals[j]
						}
					}
					// Evaluate method body
					anfEvalBindings(anf, m.Body, callEnv, stateDelta)
					// Copy updated property values back to caller env
					for _, prop := range anf.Properties {
						if v, ok := callEnv[prop.Name]; ok {
							env[prop.Name] = v
						}
					}
					// Return last binding's value
					if len(m.Body) > 0 {
						return callEnv[m.Body[len(m.Body)-1].Name]
					}
					return nil
				}
			}
		}
		return nil

	case "if":
		condName, _ := value["cond"].(string)
		cond := env[condName]
		var branch []ANFBinding
		if anfIsTruthy(cond) {
			branch = anfGetBindings(value["then"])
		} else {
			branch = anfGetBindings(value["else"])
		}
		// Create a child env for the branch
		childEnv := make(map[string]interface{})
		for k, v := range env {
			childEnv[k] = v
		}
		anfEvalBindings(anf, branch, childEnv, stateDelta)
		// Copy new bindings back
		for k, v := range childEnv {
			env[k] = v
		}
		// Return last binding's value
		if len(branch) > 0 {
			return childEnv[branch[len(branch)-1].Name]
		}
		return nil

	case "loop":
		count := anfToInt(value["count"])
		iterVar, _ := value["iterVar"].(string)
		body := anfGetBindings(value["body"])
		var lastVal interface{}
		for i := int64(0); i < count; i++ {
			env[iterVar] = big.NewInt(i)
			loopEnv := make(map[string]interface{})
			for k, v := range env {
				loopEnv[k] = v
			}
			anfEvalBindings(anf, body, loopEnv, stateDelta)
			for k, v := range loopEnv {
				env[k] = v
			}
			if len(body) > 0 {
				lastVal = loopEnv[body[len(body)-1].Name]
			}
		}
		return lastVal

	case "assert":
		// Skip in simulation
		return nil

	case "update_prop":
		propName, _ := value["name"].(string)
		valName, _ := value["value"].(string)
		newVal := env[valName]
		env[propName] = newVal
		stateDelta[propName] = newVal
		return nil

	case "add_output":
		// If stateValues are present, map them to mutable properties in declaration order
		if stateVals, ok := value["stateValues"]; ok {
			stateNames := anfGetStringSlice(stateVals)
			if anf != nil && len(stateNames) > 0 {
				// Collect mutable properties in declaration order
				var mutableProps []ANFProperty
				for _, prop := range anf.Properties {
					if !prop.Readonly {
						mutableProps = append(mutableProps, prop)
					}
				}
				// Map each state value to the corresponding mutable property
				for j, name := range stateNames {
					if j < len(mutableProps) {
						newVal := env[name]
						env[mutableProps[j].Name] = newVal
						stateDelta[mutableProps[j].Name] = newVal
					}
				}
			}
		}
		return nil

	// On-chain-only operations — skip
	case "check_preimage", "deserialize_state", "get_state_script", "add_raw_output":
		return nil
	}

	return nil
}

// ---------------------------------------------------------------------------
// Binary operations
// ---------------------------------------------------------------------------

func anfEvalBinOp(op string, left, right interface{}, resultType string) interface{} {
	if resultType == "bytes" || (isHexString(left) && isHexString(right)) {
		return anfEvalBytesBinOp(op, anfToString(left), anfToString(right))
	}

	l := anfToBigInt(left)
	r := anfToBigInt(right)

	switch op {
	case "+":
		return new(big.Int).Add(l, r)
	case "-":
		return new(big.Int).Sub(l, r)
	case "*":
		return new(big.Int).Mul(l, r)
	case "/":
		if r.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(l, r)
	case "%":
		if r.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Rem(l, r)
	case "==", "===":
		return l.Cmp(r) == 0
	case "!=", "!==":
		return l.Cmp(r) != 0
	case "<":
		return l.Cmp(r) < 0
	case "<=":
		return l.Cmp(r) <= 0
	case ">":
		return l.Cmp(r) > 0
	case ">=":
		return l.Cmp(r) >= 0
	case "&&":
		return anfIsTruthy(left) && anfIsTruthy(right)
	case "||":
		return anfIsTruthy(left) || anfIsTruthy(right)
	case "&":
		return new(big.Int).And(l, r)
	case "|":
		return new(big.Int).Or(l, r)
	case "^":
		return new(big.Int).Xor(l, r)
	case "<<":
		shift := uint(r.Int64())
		return new(big.Int).Lsh(l, shift)
	case ">>":
		shift := uint(r.Int64())
		return new(big.Int).Rsh(l, shift)
	}
	return big.NewInt(0)
}

func anfEvalBytesBinOp(op, left, right string) interface{} {
	switch op {
	case "+": // cat
		return left + right
	case "==", "===":
		return left == right
	case "!=", "!==":
		return left != right
	}
	return ""
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

func anfEvalUnaryOp(op string, operand interface{}, resultType string) interface{} {
	if resultType == "bytes" {
		if op == "~" {
			h := anfToString(operand)
			b, _ := hex.DecodeString(h)
			for i := range b {
				b[i] = ^b[i]
			}
			return hex.EncodeToString(b)
		}
		return operand
	}

	val := anfToBigInt(operand)
	switch op {
	case "-":
		return new(big.Int).Neg(val)
	case "!":
		return !anfIsTruthy(operand)
	case "~":
		return new(big.Int).Not(val)
	}
	return val
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

func anfEvalCall(funcName string, args []interface{}) interface{} {
	switch funcName {
	// Crypto — mock
	case "checkSig", "checkMultiSig", "checkPreimage":
		return true

	// Crypto — real hashes
	case "sha256":
		return anfHashFn("sha256", args[0])
	case "hash256":
		return anfHashFn("hash256", args[0])
	case "hash160":
		return anfHashFn("hash160", args[0])
	case "ripemd160":
		return anfHashFn("ripemd160", args[0])

	// Assert — skip
	case "assert":
		return nil

	// Byte operations
	case "num2bin":
		n := anfToBigInt(args[0])
		length := int(anfToBigInt(args[1]).Int64())
		return anfNum2binHex(n, length)

	case "bin2num":
		return anfBin2numBigInt(anfToString(args[0]))

	case "cat":
		return anfToString(args[0]) + anfToString(args[1])

	case "substr":
		h := anfToString(args[0])
		start := int(anfToBigInt(args[1]).Int64())
		length := int(anfToBigInt(args[2]).Int64())
		lo := start * 2
		hi := (start + length) * 2
		if lo > len(h) {
			lo = len(h)
		}
		if hi > len(h) {
			hi = len(h)
		}
		return h[lo:hi]

	case "reverseBytes":
		h := anfToString(args[0])
		pairs := make([]string, 0, len(h)/2)
		for i := 0; i+1 < len(h); i += 2 {
			pairs = append(pairs, h[i:i+2])
		}
		for i, j := 0, len(pairs)-1; i < j; i, j = i+1, j-1 {
			pairs[i], pairs[j] = pairs[j], pairs[i]
		}
		return strings.Join(pairs, "")

	case "len":
		h := anfToString(args[0])
		return big.NewInt(int64(len(h) / 2))

	// Math builtins
	case "abs":
		v := anfToBigInt(args[0])
		return new(big.Int).Abs(v)

	case "min":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if a.Cmp(b) < 0 {
			return new(big.Int).Set(a)
		}
		return new(big.Int).Set(b)

	case "max":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if a.Cmp(b) > 0 {
			return new(big.Int).Set(a)
		}
		return new(big.Int).Set(b)

	case "within":
		x := anfToBigInt(args[0])
		lo := anfToBigInt(args[1])
		hi := anfToBigInt(args[2])
		return x.Cmp(lo) >= 0 && x.Cmp(hi) < 0

	case "safediv":
		a := anfToBigInt(args[0])
		d := anfToBigInt(args[1])
		if d.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(a, d)

	case "safemod":
		a := anfToBigInt(args[0])
		d := anfToBigInt(args[1])
		if d.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Rem(a, d)

	case "clamp":
		v := anfToBigInt(args[0])
		lo := anfToBigInt(args[1])
		hi := anfToBigInt(args[2])
		if v.Cmp(lo) < 0 {
			return new(big.Int).Set(lo)
		}
		if v.Cmp(hi) > 0 {
			return new(big.Int).Set(hi)
		}
		return new(big.Int).Set(v)

	case "sign":
		v := anfToBigInt(args[0])
		return big.NewInt(int64(v.Sign()))

	case "pow":
		base := anfToBigInt(args[0])
		exp := anfToBigInt(args[1])
		if exp.Sign() < 0 {
			return big.NewInt(0)
		}
		result := big.NewInt(1)
		for i := big.NewInt(0); i.Cmp(exp) < 0; i.Add(i, big.NewInt(1)) {
			result.Mul(result, base)
		}
		return result

	case "sqrt":
		v := anfToBigInt(args[0])
		if v.Sign() <= 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Sqrt(v)

	case "gcd":
		a := new(big.Int).Abs(anfToBigInt(args[0]))
		b := new(big.Int).Abs(anfToBigInt(args[1]))
		return new(big.Int).GCD(nil, nil, a, b)

	case "divmod":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if b.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(a, b)

	case "log2":
		v := anfToBigInt(args[0])
		if v.Sign() <= 0 {
			return big.NewInt(0)
		}
		return big.NewInt(int64(v.BitLen() - 1))

	case "bool":
		if anfIsTruthy(args[0]) {
			return big.NewInt(1)
		}
		return big.NewInt(0)

	case "mulDiv":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		c := anfToBigInt(args[2])
		prod := new(big.Int).Mul(a, b)
		return new(big.Int).Quo(prod, c)

	case "percentOf":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		prod := new(big.Int).Mul(a, b)
		return new(big.Int).Quo(prod, big.NewInt(10000))

	// Preimage intrinsics — return dummy values
	case "extractOutputHash", "extractAmount":
		return strings.Repeat("00", 32)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

func anfHashFn(name string, input interface{}) string {
	h := anfToString(input)
	data, _ := hex.DecodeString(h)

	switch name {
	case "sha256":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	case "hash256":
		first := sha256.Sum256(data)
		second := sha256.Sum256(first[:])
		return hex.EncodeToString(second[:])
	case "hash160":
		s := sha256.Sum256(data)
		r := ripemd160.New()
		r.Write(s[:])
		return hex.EncodeToString(r.Sum(nil))
	case "ripemd160":
		r := ripemd160.New()
		r.Write(data)
		return hex.EncodeToString(r.Sum(nil))
	}
	return ""
}

// ---------------------------------------------------------------------------
// Numeric helpers
// ---------------------------------------------------------------------------

// anfToBigInt converts an interface{} value to *big.Int.
// Handles *big.Int, float64, string (plain or "42n" format), json.Number, int64, int, bool.
func anfToBigInt(v interface{}) *big.Int {
	switch val := v.(type) {
	case *big.Int:
		return new(big.Int).Set(val)
	case int64:
		return big.NewInt(val)
	case int:
		return big.NewInt(int64(val))
	case float64:
		// JSON numbers arrive as float64
		return big.NewInt(int64(val))
	case bool:
		if val {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	case string:
		s := val
		// Handle "42n" bigint format
		if len(s) > 0 && s[len(s)-1] == 'n' {
			s = s[:len(s)-1]
		}
		n := new(big.Int)
		if _, ok := n.SetString(s, 10); ok {
			return n
		}
		return big.NewInt(0)
	}
	return big.NewInt(0)
}

func anfIsTruthy(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case *big.Int:
		return val.Sign() != 0
	case int64:
		return val != 0
	case int:
		return val != 0
	case float64:
		return val != 0
	case string:
		return val != "" && val != "0" && val != "false"
	}
	return false
}

func anfToString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// isHexString checks whether v is a string that looks like a hex-encoded byte string
// (even length, all hex chars). Returns false for numeric strings and booleans.
func isHexString(v interface{}) bool {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// anfToInt extracts an int64 from a JSON value (float64, string, etc.).
func anfToInt(v interface{}) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case string:
		n := new(big.Int)
		s := val
		if len(s) > 0 && s[len(s)-1] == 'n' {
			s = s[:len(s)-1]
		}
		if _, ok := n.SetString(s, 10); ok {
			return n.Int64()
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Byte encoding helpers
// ---------------------------------------------------------------------------

func anfNum2binHex(n *big.Int, byteLen int) string {
	if n.Sign() == 0 {
		return strings.Repeat("00", byteLen)
	}

	negative := n.Sign() < 0
	abs := new(big.Int).Abs(n)

	var bytes []byte
	for abs.Sign() > 0 {
		b := byte(new(big.Int).And(abs, big.NewInt(0xff)).Int64())
		bytes = append(bytes, b)
		abs.Rsh(abs, 8)
	}

	// Sign bit handling
	if len(bytes) > 0 {
		if negative {
			if bytes[len(bytes)-1]&0x80 == 0 {
				bytes[len(bytes)-1] |= 0x80
			} else {
				bytes = append(bytes, 0x80)
			}
		} else {
			if bytes[len(bytes)-1]&0x80 != 0 {
				bytes = append(bytes, 0x00)
			}
		}
	}

	// Pad or truncate
	for len(bytes) < byteLen {
		bytes = append(bytes, 0x00)
	}
	if len(bytes) > byteLen {
		bytes = bytes[:byteLen]
	}

	return hex.EncodeToString(bytes)
}

func anfBin2numBigInt(h string) *big.Int {
	if len(h) == 0 {
		return big.NewInt(0)
	}
	bytes := make([]byte, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		b, err := hex.DecodeString(h[i : i+2])
		if err != nil {
			return big.NewInt(0)
		}
		bytes = append(bytes, b[0])
	}
	if len(bytes) == 0 {
		return big.NewInt(0)
	}

	negative := bytes[len(bytes)-1]&0x80 != 0
	if negative {
		bytes[len(bytes)-1] &= 0x7f
	}

	// Little-endian to big.Int
	result := big.NewInt(0)
	for i := len(bytes) - 1; i >= 0; i-- {
		result.Lsh(result, 8)
		result.Or(result, big.NewInt(int64(bytes[i])))
	}

	if negative {
		result.Neg(result)
	}
	return result
}

// ---------------------------------------------------------------------------
// ANF JSON helpers
// ---------------------------------------------------------------------------

// anfGetStringSlice extracts a []string from a JSON array ([]interface{}).
func anfGetStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		result[i], _ = item.(string)
	}
	return result
}

// anfGetBindings extracts []ANFBinding from a JSON array of binding objects.
func anfGetBindings(v interface{}) []ANFBinding {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	bindings := make([]ANFBinding, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		val, _ := obj["value"].(map[string]interface{})
		bindings = append(bindings, ANFBinding{
			Name:  name,
			Value: val,
		})
	}
	return bindings
}

// buildNamedArgs maps user-visible ABI params to their resolved argument values
// by name. This produces the named-args map that ComputeNewState expects.
func buildNamedArgs(userParams []ABIParam, resolvedArgs []interface{}) map[string]interface{} {
	named := make(map[string]interface{})
	for i, param := range userParams {
		if i < len(resolvedArgs) {
			named[param.Name] = resolvedArgs[i]
		}
	}
	return named
}
