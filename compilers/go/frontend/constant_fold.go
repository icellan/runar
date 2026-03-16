// Package frontend provides the constant folding pass for ANF IR.
//
// Constant folding evaluates compile-time-known expressions and replaces
// them with load_const bindings. Constants are propagated through the
// binding chain so downstream operations can be folded too.
package frontend

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Constant value representation
// ---------------------------------------------------------------------------

type constKind int

const (
	constBigInt constKind = iota
	constBool
	constString
)

type constValue struct {
	kind   constKind
	bigint *big.Int
	b      bool
	s      string
}

// ---------------------------------------------------------------------------
// Constant environment
// ---------------------------------------------------------------------------

type constEnv struct {
	m map[string]*constValue
}

func newConstEnv() *constEnv {
	return &constEnv{m: make(map[string]*constValue)}
}

func (e *constEnv) set(name string, v *constValue) {
	e.m[name] = v
}

func (e *constEnv) get(name string) *constValue {
	return e.m[name]
}

func (e *constEnv) clone() *constEnv {
	c := newConstEnv()
	for k, v := range e.m {
		c.m[k] = v
	}
	return c
}

// ---------------------------------------------------------------------------
// Binary operation evaluation
// ---------------------------------------------------------------------------

var zero = big.NewInt(0)

func evalBinOp(op string, left, right *constValue) *constValue {
	// Arithmetic/bitwise/comparison on bigints
	if left.kind == constBigInt && right.kind == constBigInt {
		a, b := left.bigint, right.bigint
		switch op {
		case "+":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Add(a, b)}
		case "-":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Sub(a, b)}
		case "*":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Mul(a, b)}
		case "/":
			if b.Sign() == 0 {
				return nil
			}
			// Truncated division (toward zero), matching JS BigInt semantics.
			return &constValue{kind: constBigInt, bigint: new(big.Int).Quo(a, b)}
		case "%":
			if b.Sign() == 0 {
				return nil
			}
			// Remainder matching JS BigInt (sign follows dividend).
			return &constValue{kind: constBigInt, bigint: new(big.Int).Rem(a, b)}
		case "===":
			return &constValue{kind: constBool, b: a.Cmp(b) == 0}
		case "!==":
			return &constValue{kind: constBool, b: a.Cmp(b) != 0}
		case "<":
			return &constValue{kind: constBool, b: a.Cmp(b) < 0}
		case ">":
			return &constValue{kind: constBool, b: a.Cmp(b) > 0}
		case "<=":
			return &constValue{kind: constBool, b: a.Cmp(b) <= 0}
		case ">=":
			return &constValue{kind: constBool, b: a.Cmp(b) >= 0}
		case "&":
			return &constValue{kind: constBigInt, bigint: new(big.Int).And(a, b)}
		case "|":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Or(a, b)}
		case "^":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Xor(a, b)}
		case "<<":
			if a.Sign() < 0 {
				return nil // skip for negative left operand (BSV shifts are logical)
			}
			if b.Sign() < 0 || !b.IsInt64() {
				return nil
			}
			return &constValue{kind: constBigInt, bigint: new(big.Int).Lsh(a, uint(b.Int64()))}
		case ">>":
			if a.Sign() < 0 {
				return nil // skip for negative left operand (BSV shifts are logical)
			}
			if b.Sign() < 0 || !b.IsInt64() {
				return nil
			}
			return &constValue{kind: constBigInt, bigint: new(big.Int).Rsh(a, uint(b.Int64()))}
		}
		return nil
	}

	// Boolean operations
	if left.kind == constBool && right.kind == constBool {
		switch op {
		case "&&":
			return &constValue{kind: constBool, b: left.b && right.b}
		case "||":
			return &constValue{kind: constBool, b: left.b || right.b}
		case "===":
			return &constValue{kind: constBool, b: left.b == right.b}
		case "!==":
			return &constValue{kind: constBool, b: left.b != right.b}
		}
		return nil
	}

	// String (ByteString) operations
	if left.kind == constString && right.kind == constString {
		switch op {
		case "+":
			if !isValidHex(left.s) || !isValidHex(right.s) {
				return nil
			}
			return &constValue{kind: constString, s: left.s + right.s}
		case "===":
			return &constValue{kind: constBool, b: left.s == right.s}
		case "!==":
			return &constValue{kind: constBool, b: left.s != right.s}
		}
		return nil
	}

	// Cross-type equality
	if op == "===" {
		return &constValue{kind: constBool, b: false}
	}
	if op == "!==" {
		return &constValue{kind: constBool, b: true}
	}

	return nil
}

var hexRegexp = regexp.MustCompile(`^[0-9a-fA-F]*$`)

func isValidHex(s string) bool {
	return hexRegexp.MatchString(s)
}

// ---------------------------------------------------------------------------
// Unary operation evaluation
// ---------------------------------------------------------------------------

func evalUnaryOp(op string, operand *constValue) *constValue {
	if operand.kind == constBool {
		switch op {
		case "!":
			return &constValue{kind: constBool, b: !operand.b}
		}
		return nil
	}

	if operand.kind == constBigInt {
		switch op {
		case "-":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Neg(operand.bigint)}
		case "~":
			return &constValue{kind: constBigInt, bigint: new(big.Int).Not(operand.bigint)}
		case "!":
			return &constValue{kind: constBool, b: operand.bigint.Sign() == 0}
		}
		return nil
	}

	return nil
}

// ---------------------------------------------------------------------------
// Builtin call evaluation (pure math functions only)
// ---------------------------------------------------------------------------

func evalBuiltinCall(funcName string, args []*constValue) *constValue {
	// Only fold pure math builtins with bigint arguments
	bigArgs := make([]*big.Int, 0, len(args))
	for _, a := range args {
		if a.kind != constBigInt {
			return nil
		}
		bigArgs = append(bigArgs, a.bigint)
	}

	switch funcName {
	case "abs":
		if len(bigArgs) != 1 {
			return nil
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Abs(bigArgs[0])}

	case "min":
		if len(bigArgs) != 2 {
			return nil
		}
		if bigArgs[0].Cmp(bigArgs[1]) < 0 {
			return &constValue{kind: constBigInt, bigint: new(big.Int).Set(bigArgs[0])}
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Set(bigArgs[1])}

	case "max":
		if len(bigArgs) != 2 {
			return nil
		}
		if bigArgs[0].Cmp(bigArgs[1]) > 0 {
			return &constValue{kind: constBigInt, bigint: new(big.Int).Set(bigArgs[0])}
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Set(bigArgs[1])}

	case "safediv":
		if len(bigArgs) != 2 || bigArgs[1].Sign() == 0 {
			return nil
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Quo(bigArgs[0], bigArgs[1])}

	case "safemod":
		if len(bigArgs) != 2 || bigArgs[1].Sign() == 0 {
			return nil
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Rem(bigArgs[0], bigArgs[1])}

	case "clamp":
		if len(bigArgs) != 3 {
			return nil
		}
		val, lo, hi := bigArgs[0], bigArgs[1], bigArgs[2]
		if val.Cmp(lo) < 0 {
			return &constValue{kind: constBigInt, bigint: new(big.Int).Set(lo)}
		}
		if val.Cmp(hi) > 0 {
			return &constValue{kind: constBigInt, bigint: new(big.Int).Set(hi)}
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Set(val)}

	case "sign":
		if len(bigArgs) != 1 {
			return nil
		}
		switch bigArgs[0].Sign() {
		case 1:
			return &constValue{kind: constBigInt, bigint: big.NewInt(1)}
		case -1:
			return &constValue{kind: constBigInt, bigint: big.NewInt(-1)}
		default:
			return &constValue{kind: constBigInt, bigint: big.NewInt(0)}
		}

	case "pow":
		if len(bigArgs) != 2 {
			return nil
		}
		base, exp := bigArgs[0], bigArgs[1]
		if exp.Sign() < 0 || exp.Cmp(big.NewInt(256)) > 0 {
			return nil
		}
		result := big.NewInt(1)
		e := exp.Int64()
		for i := int64(0); i < e; i++ {
			result.Mul(result, base)
		}
		return &constValue{kind: constBigInt, bigint: result}

	case "mulDiv":
		if len(bigArgs) != 3 || bigArgs[2].Sign() == 0 {
			return nil
		}
		tmp := new(big.Int).Mul(bigArgs[0], bigArgs[1])
		return &constValue{kind: constBigInt, bigint: new(big.Int).Quo(tmp, bigArgs[2])}

	case "percentOf":
		if len(bigArgs) != 2 {
			return nil
		}
		tmp := new(big.Int).Mul(bigArgs[0], bigArgs[1])
		return &constValue{kind: constBigInt, bigint: new(big.Int).Quo(tmp, big.NewInt(10000))}

	case "sqrt":
		if len(bigArgs) != 1 {
			return nil
		}
		n := bigArgs[0]
		if n.Sign() < 0 {
			return nil
		}
		if n.Sign() == 0 {
			return &constValue{kind: constBigInt, bigint: big.NewInt(0)}
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Sqrt(n)}

	case "gcd":
		if len(bigArgs) != 2 {
			return nil
		}
		a := new(big.Int).Abs(bigArgs[0])
		b := new(big.Int).Abs(bigArgs[1])
		return &constValue{kind: constBigInt, bigint: new(big.Int).GCD(nil, nil, a, b)}

	case "divmod":
		if len(bigArgs) != 2 || bigArgs[1].Sign() == 0 {
			return nil
		}
		return &constValue{kind: constBigInt, bigint: new(big.Int).Quo(bigArgs[0], bigArgs[1])}

	case "log2":
		if len(bigArgs) != 1 {
			return nil
		}
		n := bigArgs[0]
		if n.Sign() <= 0 {
			return &constValue{kind: constBigInt, bigint: big.NewInt(0)}
		}
		bits := int64(n.BitLen() - 1)
		return &constValue{kind: constBigInt, bigint: big.NewInt(bits)}

	case "bool":
		if len(bigArgs) != 1 {
			return nil
		}
		return &constValue{kind: constBool, b: bigArgs[0].Sign() != 0}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Fold bindings
// ---------------------------------------------------------------------------

func foldBindings(bindings []ir.ANFBinding, env *constEnv) []ir.ANFBinding {
	result := make([]ir.ANFBinding, 0, len(bindings))
	for _, b := range bindings {
		folded := foldBinding(b, env)
		result = append(result, folded)
	}
	return result
}

func foldBinding(binding ir.ANFBinding, env *constEnv) ir.ANFBinding {
	foldedValue := foldValue(&binding.Value, env)

	// If the folded value is a load_const, register in the environment
	if foldedValue.Kind == "load_const" {
		if cv := anfValueToConst(foldedValue); cv != nil {
			env.set(binding.Name, cv)
		}
	}

	return ir.ANFBinding{Name: binding.Name, Value: *foldedValue}
}

func anfValueToConst(v *ir.ANFValue) *constValue {
	if v.ConstBigInt != nil {
		return &constValue{kind: constBigInt, bigint: v.ConstBigInt}
	}
	if v.ConstBool != nil {
		return &constValue{kind: constBool, b: *v.ConstBool}
	}
	if v.ConstString != nil {
		// Skip @ref: aliases — they are binding references, not real constants
		if strings.HasPrefix(*v.ConstString, "@ref:") {
			return nil
		}
		return &constValue{kind: constString, s: *v.ConstString}
	}
	return nil
}

func constToANFValue(cv *constValue) ir.ANFValue {
	switch cv.kind {
	case constBigInt:
		if cv.bigint.IsInt64() {
			return makeLoadConstInt(cv.bigint.Int64())
		}
		return makeLoadConstBigInt(cv.bigint)
	case constBool:
		return makeLoadConstBool(cv.b)
	case constString:
		return makeLoadConstString(cv.s)
	}
	panic("unknown constValue kind")
}

func makeLoadConstBigInt(val *big.Int) ir.ANFValue {
	raw, _ := json.Marshal(val.String())
	return ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstBigInt: new(big.Int).Set(val),
	}
}

// ---------------------------------------------------------------------------
// Fold a single value
// ---------------------------------------------------------------------------

func foldValue(value *ir.ANFValue, env *constEnv) *ir.ANFValue {
	switch value.Kind {
	case "load_const", "load_param", "load_prop":
		return value

	case "bin_op":
		leftConst := env.get(value.Left)
		rightConst := env.get(value.Right)
		if leftConst != nil && rightConst != nil {
			result := evalBinOp(value.Op, leftConst, rightConst)
			if result != nil {
				v := constToANFValue(result)
				return &v
			}
		}
		return value

	case "unary_op":
		operandConst := env.get(value.Operand)
		if operandConst != nil {
			result := evalUnaryOp(value.Op, operandConst)
			if result != nil {
				v := constToANFValue(result)
				return &v
			}
		}
		return value

	case "call":
		allConst := true
		for _, arg := range value.Args {
			if env.get(arg) == nil {
				allConst = false
				break
			}
		}
		if allConst {
			constArgs := make([]*constValue, len(value.Args))
			for i, arg := range value.Args {
				constArgs[i] = env.get(arg)
			}
			folded := evalBuiltinCall(value.Func, constArgs)
			if folded != nil {
				v := constToANFValue(folded)
				return &v
			}
		}
		return value

	case "method_call":
		return value

	case "if":
		condConst := env.get(value.Cond)
		if condConst != nil && condConst.kind == constBool {
			if condConst.b {
				thenEnv := env.clone()
				foldedThen := foldBindings(value.Then, thenEnv)
				// Merge constants from taken branch back into env
				for _, b := range foldedThen {
					if cv := anfValueToConst(&b.Value); cv != nil {
						env.set(b.Name, cv)
					}
				}
				return &ir.ANFValue{
					Kind: "if",
					Cond: value.Cond,
					Then: foldedThen,
					Else: nil,
				}
			}
			elseEnv := env.clone()
			foldedElse := foldBindings(value.Else, elseEnv)
			for _, b := range foldedElse {
				if cv := anfValueToConst(&b.Value); cv != nil {
					env.set(b.Name, cv)
				}
			}
			return &ir.ANFValue{
				Kind: "if",
				Cond: value.Cond,
				Then: nil,
				Else: foldedElse,
			}
		}

		// Condition not known — fold both branches independently
		thenEnv := env.clone()
		elseEnv := env.clone()
		foldedThen := foldBindings(value.Then, thenEnv)
		foldedElse := foldBindings(value.Else, elseEnv)
		return &ir.ANFValue{
			Kind: "if",
			Cond: value.Cond,
			Then: foldedThen,
			Else: foldedElse,
		}

	case "loop":
		bodyEnv := env.clone()
		foldedBody := foldBindings(value.Body, bodyEnv)
		return &ir.ANFValue{
			Kind:    "loop",
			Count:   value.Count,
			IterVar: value.IterVar,
			Body:    foldedBody,
		}

	case "assert", "update_prop", "get_state_script",
		"check_preimage", "deserialize_state",
		"add_output", "add_raw_output":
		return value
	}

	return value
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// FoldConstants applies constant folding to an ANF program.
// It evaluates compile-time-known expressions and replaces them with
// load_const bindings. Also runs dead binding elimination afterward.
func FoldConstants(program *ir.ANFProgram) *ir.ANFProgram {
	return foldConstantsOnly(program)
}

// foldConstantsOnly applies constant folding without dead binding elimination.
// Used by tests that want to inspect folded bindings before DCE.
func foldConstantsOnly(program *ir.ANFProgram) *ir.ANFProgram {
	result := *program
	result.Methods = make([]ir.ANFMethod, len(program.Methods))
	for i, method := range program.Methods {
		result.Methods[i] = foldMethod(&method)
	}
	return &result
}

func foldMethod(method *ir.ANFMethod) ir.ANFMethod {
	env := newConstEnv()
	foldedBody := foldBindings(method.Body, env)
	return ir.ANFMethod{
		Name:     method.Name,
		Params:   method.Params,
		Body:     foldedBody,
		IsPublic: method.IsPublic,
	}
}
