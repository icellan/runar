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
		// OP_AND/OP_OR/OP_XOR/OP_LSHIFT/OP_RSHIFT operate on the operands'
		// raw script-number BYTES, not their numeric value — native big.Int
		// folding produces results that differ from the deployed script (e.g.
		// 255 << 1 is 254 on-chain, not 510; 255 & 1 aborts). Never fold them;
		// emit the opcode so runtime byte-array semantics govern. (See
		// packages/runar-go/anf_interpreter.go's anfEvalBinOp, which models the
		// same semantics for the interpreter.)
		case "&", "|", "^", "<<", ">>":
			return nil
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
		// OP_INVERT flips the operand's script-number bytes, not native
		// big.Int.Not (two's-complement ~n). Never fold; emit the opcode so
		// runtime byte-array semantics govern.
		case "~":
			return nil
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

	result := ir.ANFBinding{Name: binding.Name, Value: *foldedValue}
	if binding.SourceLoc != nil {
		result.SourceLoc = binding.SourceLoc
	}
	return result
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
		return makeLoadConstInt(cv.bigint)
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
		// Fold both arms independently, ALWAYS — including when the condition
		// is a compile-time constant.
		//
		// This pass used to "optimise" a statically-known condition by blanking
		// the untaken arm (Else: nil) while LEAVING the `if` node itself in
		// place, and by propagating the taken arm's constants into the
		// enclosing env. Both halves were unsound:
		//
		//   * An arm is not a free-floating binding list — it carries a
		//     STACK-SHAPE CONTRACT that ANF lowering establishes and stack
		//     lowering depends on. For two or more branch-merged locals both
		//     arms end with the identical __merge$<i> result block, which is
		//     how lowerIf learns K and adopts the K results by name. Blanking
		//     one arm makes the merged-result count 0, the N>=2 name-matched
		//     reconcile cannot fire, and ONE stack slot is registered for K
		//     physical results — every post-branch operand then resolves one or
		//     more slots off. At K=2 that miscompiled SILENTLY: the deployed
		//     script accepted spends the source rejects and rejected spends the
		//     source accepts. At K=1 it surfaced as "value not found on stack",
		//     a compile-time rejection of source that compiles with folding
		//     disabled.
		//   * Propagating the taken arm's constants outward is only sound if
		//     the other arm is really gone. The `if` node survives this pass,
		//     so both arms are still emitted and either can run.
		//
		// Correct dead-arm elimination would have to delete the `if` and splice
		// the live arm into the parent, re-establishing the parent's shape.
		// That is a lowering-level rewrite, not a fold, so it does not live
		// here. The bytes given up are the statically-dead arm's ops, which
		// never execute.
		thenEnv := env.clone()
		elseEnv := env.clone()
		foldedThen := foldBindings(value.Then, thenEnv)
		foldedElse := foldBindings(value.Else, elseEnv)
		return &ir.ANFValue{
			Kind: "if",
			Cond: value.Cond,
			Then: foldedThen,
			Else: foldedElse,
			// The declared result list survives folding untouched: folding an
			// arm's bindings cannot change WHICH slots the arm leaves, and
			// dropping the list would silently return the `if` to the
			// single-result reconcile it was migrated off.
			Results: value.Results,
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
		"add_output", "add_raw_output", "add_data_output":
		return value

	case "array_literal":
		// Not folded — elements are SSA refs, not compile-time constants.
		return value

	case "raw_script":
		// Opaque byte span — never folded. Bytes are byte-canonical and the
		// peephole optimizer treats it as a hard barrier.
		return value

	default:
		// Exhaustiveness guard. A silent fall-through here would return
		// the value unchanged when a new foldable kind is added, silently
		// missing the fold opportunity.
		panic(&ir.UnknownANFKindError{Kind: value.Kind, Location: "constant-fold.foldValue"})
	}
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

// foldMethod folds a method's body. It copies the method wholesale and
// overwrites only Body — never re-enumerating ir.ANFMethod's fields.
//
// Enumerating them is how N-093 shipped: the rebuild listed 4 of 5 fields and
// silently dropped SigHashType, so a `@sighash` directive survived fold-OFF and
// vanished under the shipped fold-ON default. SigHashType is `json:"-"`, so the
// cross-tier ANF comparison structurally cannot catch that class of loss.
// Copy-then-overwrite makes a future sixth field unlosable by construction
// (the same shape frontend/expand_fixed_arrays.go already uses).
func foldMethod(method *ir.ANFMethod) ir.ANFMethod {
	env := newConstEnv()
	m := *method
	m.Body = foldBindings(method.Body, env)
	return m
}
