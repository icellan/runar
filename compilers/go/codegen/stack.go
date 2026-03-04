// Package codegen implements the Stack IR lowering and Bitcoin Script emission
// passes of the Rúnar Go compiler. It mirrors the TypeScript compiler's Pass 5
// (stack lowering) and Pass 6 (emit).
package codegen

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const maxStackDepth = 800

// ---------------------------------------------------------------------------
// Stack IR types
// ---------------------------------------------------------------------------

// StackOp represents a single stack-machine operation.
type StackOp struct {
	Op         string    // "push", "dup", "swap", "roll", "pick", "drop", "opcode", "if", "nip", "over", "rot", "tuck", "placeholder"
	Value      PushValue // for push ops
	Depth      int       // for roll/pick (informational)
	Code       string    // for opcode ops (e.g. "OP_ADD")
	Then       []StackOp // for if ops
	Else       []StackOp // for if ops
	ParamIndex int       // for placeholder ops — index into constructor params
	ParamName  string    // for placeholder ops — name of constructor param
}

// PushValue holds the typed value for a push operation.
type PushValue struct {
	Kind    string // "bigint", "bool", "bytes"
	BigInt  *big.Int
	Bool    bool
	Bytes   []byte
}

// StackMethod is the stack-lowered form of a single contract method.
type StackMethod struct {
	Name          string
	Ops           []StackOp
	MaxStackDepth int
}

// ---------------------------------------------------------------------------
// Builtin function -> opcode mapping
// ---------------------------------------------------------------------------

var builtinOpcodes = map[string][]string{
	"sha256":       {"OP_SHA256"},
	"ripemd160":    {"OP_RIPEMD160"},
	"hash160":      {"OP_HASH160"},
	"hash256":      {"OP_HASH256"},
	"checkSig":     {"OP_CHECKSIG"},
	"checkMultiSig": {"OP_CHECKMULTISIG"},
	"len":          {"OP_SIZE"},
	"cat":          {"OP_CAT"},
	"num2bin":      {"OP_NUM2BIN"},
	"bin2num":      {"OP_BIN2NUM"},
	"abs":          {"OP_ABS"},
	"min":          {"OP_MIN"},
	"max":          {"OP_MAX"},
	"within":       {"OP_WITHIN"},
	"split":        {"OP_SPLIT"},
	"left":         {"OP_SPLIT", "OP_DROP"},
	"int2str":      {"OP_NUM2BIN"},
	"bool":         {"OP_0NOTEQUAL"},
	"unpack":       {"OP_BIN2NUM"},
}

// ---------------------------------------------------------------------------
// Binary operator -> opcode mapping
// ---------------------------------------------------------------------------

var binopOpcodes = map[string][]string{
	"+":   {"OP_ADD"},
	"-":   {"OP_SUB"},
	"*":   {"OP_MUL"},
	"/":   {"OP_DIV"},
	"%":   {"OP_MOD"},
	"===": {"OP_NUMEQUAL"},
	"!==": {"OP_NUMEQUAL", "OP_NOT"},
	"<":   {"OP_LESSTHAN"},
	">":   {"OP_GREATERTHAN"},
	"<=":  {"OP_LESSTHANOREQUAL"},
	">=":  {"OP_GREATERTHANOREQUAL"},
	"&&":  {"OP_BOOLAND"},
	"||":  {"OP_BOOLOR"},
	"&":   {"OP_AND"},
	"|":   {"OP_OR"},
	"^":   {"OP_XOR"},
	"<<":  {"OP_LSHIFT"},
	">>":  {"OP_RSHIFT"},
}

// ---------------------------------------------------------------------------
// Unary operator -> opcode mapping
// ---------------------------------------------------------------------------

var unaryopOpcodes = map[string][]string{
	"!": {"OP_NOT"},
	"-": {"OP_NEGATE"},
	"~": {"OP_INVERT"},
}

// ---------------------------------------------------------------------------
// Stack map — tracks named values on the stack
// ---------------------------------------------------------------------------

type stackMap struct {
	slots []string // element is variable name or "" for anonymous
}

func newStackMap(initial []string) *stackMap {
	slots := make([]string, len(initial))
	copy(slots, initial)
	return &stackMap{slots: slots}
}

func (s *stackMap) depth() int {
	return len(s.slots)
}

func (s *stackMap) push(name string) {
	s.slots = append(s.slots, name)
}

func (s *stackMap) pop() string {
	if len(s.slots) == 0 {
		panic("stack underflow")
	}
	last := s.slots[len(s.slots)-1]
	s.slots = s.slots[:len(s.slots)-1]
	return last
}

// findDepth returns the distance from the top of the stack to the named value.
// 0 = top of stack. Returns -1 if not found.
func (s *stackMap) findDepth(name string) int {
	for i := len(s.slots) - 1; i >= 0; i-- {
		if s.slots[i] == name {
			return len(s.slots) - 1 - i
		}
	}
	return -1
}

func (s *stackMap) has(name string) bool {
	for _, slot := range s.slots {
		if slot == name {
			return true
		}
	}
	return false
}

func (s *stackMap) removeAtDepth(depthFromTop int) string {
	index := len(s.slots) - 1 - depthFromTop
	if index < 0 || index >= len(s.slots) {
		panic(fmt.Sprintf("invalid stack depth: %d", depthFromTop))
	}
	removed := s.slots[index]
	s.slots = append(s.slots[:index], s.slots[index+1:]...)
	return removed
}

func (s *stackMap) peekAtDepth(depthFromTop int) string {
	index := len(s.slots) - 1 - depthFromTop
	if index < 0 || index >= len(s.slots) {
		panic(fmt.Sprintf("invalid stack depth: %d", depthFromTop))
	}
	return s.slots[index]
}

func (s *stackMap) clone() *stackMap {
	slots := make([]string, len(s.slots))
	copy(slots, s.slots)
	return &stackMap{slots: slots}
}

func (s *stackMap) swap() {
	n := len(s.slots)
	if n < 2 {
		panic("stack underflow on swap")
	}
	s.slots[n-1], s.slots[n-2] = s.slots[n-2], s.slots[n-1]
}

func (s *stackMap) dup() {
	if len(s.slots) < 1 {
		panic("stack underflow on dup")
	}
	s.slots = append(s.slots, s.slots[len(s.slots)-1])
}

// ---------------------------------------------------------------------------
// Use analysis — determine last-use sites for each variable
// ---------------------------------------------------------------------------

func computeLastUses(bindings []ir.ANFBinding) map[string]int {
	lastUse := make(map[string]int)
	for i, binding := range bindings {
		refs := collectRefs(&binding.Value)
		for _, ref := range refs {
			lastUse[ref] = i
		}
	}
	return lastUse
}

func collectRefs(value *ir.ANFValue) []string {
	var refs []string

	switch value.Kind {
	case "load_param":
		// Track param name so last-use analysis keeps the param on the stack
		// (via PICK) until its final load_param, then consumes it (via ROLL).
		refs = append(refs, value.Name)
	case "load_prop", "get_state_script":
		// no refs
	case "load_const":
		// load_const with @ref: values reference another binding
		if value.ConstString != nil && len(*value.ConstString) > 5 && (*value.ConstString)[:5] == "@ref:" {
			refs = append(refs, (*value.ConstString)[5:])
		}
	case "bin_op":
		refs = append(refs, value.Left, value.Right)
	case "unary_op":
		refs = append(refs, value.Operand)
	case "call":
		refs = append(refs, value.Args...)
	case "method_call":
		refs = append(refs, value.Object)
		refs = append(refs, value.Args...)
	case "if":
		refs = append(refs, value.Cond)
		for _, b := range value.Then {
			refs = append(refs, collectRefs(&b.Value)...)
		}
		for _, b := range value.Else {
			refs = append(refs, collectRefs(&b.Value)...)
		}
	case "loop":
		for _, b := range value.Body {
			refs = append(refs, collectRefs(&b.Value)...)
		}
	case "assert":
		refs = append(refs, value.ValueRef)
	case "update_prop":
		refs = append(refs, value.ValueRef)
	case "check_preimage":
		refs = append(refs, value.Preimage)
	case "add_output":
		refs = append(refs, value.Satoshis)
		refs = append(refs, value.StateValues...)
	}

	return refs
}

// ---------------------------------------------------------------------------
// Lowering context
// ---------------------------------------------------------------------------

type loweringContext struct {
	sm             *stackMap
	ops            []StackOp
	maxDepth       int
	properties     []ir.ANFProperty
	privateMethods map[string]*ir.ANFMethod // private methods available for inlining
}

func newLoweringContext(params []string, properties []ir.ANFProperty) *loweringContext {
	ctx := &loweringContext{
		sm:             newStackMap(params),
		properties:     properties,
		privateMethods: make(map[string]*ir.ANFMethod),
	}
	ctx.trackDepth()
	return ctx
}

func (ctx *loweringContext) trackDepth() {
	if ctx.sm.depth() > ctx.maxDepth {
		ctx.maxDepth = ctx.sm.depth()
	}
}

func (ctx *loweringContext) emitOp(op StackOp) {
	ctx.ops = append(ctx.ops, op)
	ctx.trackDepth()
}

// bringToTop moves the named value to the top of the stack.
// If consume is true, the original position is freed (ROLL semantics).
// If consume is false, a copy is made (PICK semantics).
func (ctx *loweringContext) bringToTop(name string, consume bool) {
	depth := ctx.sm.findDepth(name)
	if depth < 0 {
		panic(fmt.Sprintf("value %q not found on stack", name))
	}

	if depth == 0 {
		if !consume {
			ctx.emitOp(StackOp{Op: "dup"})
			ctx.sm.dup()
		}
		return
	}

	if depth == 1 && consume {
		ctx.emitOp(StackOp{Op: "swap"})
		ctx.sm.swap()
		return
	}

	if consume {
		if depth == 2 {
			// ROT is ROLL 2
			ctx.emitOp(StackOp{Op: "rot"})
			removed := ctx.sm.removeAtDepth(2)
			ctx.sm.push(removed)
		} else {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(depth))})
			ctx.sm.push("") // temporary depth literal on stack map
			ctx.emitOp(StackOp{Op: "roll", Depth: depth})
			ctx.sm.pop() // remove depth literal
			rolled := ctx.sm.removeAtDepth(depth)
			ctx.sm.push(rolled)
		}
	} else {
		if depth == 1 {
			ctx.emitOp(StackOp{Op: "over"})
			picked := ctx.sm.peekAtDepth(1)
			ctx.sm.push(picked)
		} else {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(depth))})
			ctx.sm.push("") // temporary depth literal
			ctx.emitOp(StackOp{Op: "pick", Depth: depth})
			ctx.sm.pop() // remove depth literal
			picked := ctx.sm.peekAtDepth(depth)
			ctx.sm.push(picked)
		}
	}

	ctx.trackDepth()
}

func (ctx *loweringContext) isLastUse(ref string, currentIndex int, lastUses map[string]int) bool {
	last, ok := lastUses[ref]
	return !ok || last <= currentIndex
}

// ---------------------------------------------------------------------------
// Lower bindings
// ---------------------------------------------------------------------------

func (ctx *loweringContext) lowerBindings(bindings []ir.ANFBinding, terminalAssert bool) {
	lastUses := computeLastUses(bindings)

	// Find the terminal binding index (if terminalAssert is set).
	// If the last binding is an 'if' whose branches end in asserts,
	// that 'if' is the terminal point (not an earlier standalone assert).
	lastAssertIdx := -1
	terminalIfIdx := -1
	if terminalAssert {
		lastBinding := bindings[len(bindings)-1]
		if lastBinding.Value.Kind == "if" {
			terminalIfIdx = len(bindings) - 1
		} else {
			for i := len(bindings) - 1; i >= 0; i-- {
				if bindings[i].Value.Kind == "assert" {
					lastAssertIdx = i
					break
				}
			}
		}
	}

	for i, binding := range bindings {
		if binding.Value.Kind == "assert" && i == lastAssertIdx {
			// Terminal assert: leave value on stack instead of OP_VERIFY
			ctx.lowerAssert(binding.Value.ValueRef, i, lastUses, true)
		} else if binding.Value.Kind == "if" && i == terminalIfIdx {
			// Terminal if: propagate terminalAssert into both branches
			ctx.lowerIf(binding.Name, binding.Value.Cond, binding.Value.Then, binding.Value.Else, i, lastUses, true)
		} else {
			ctx.lowerBinding(&binding, i, lastUses)
		}
	}
}

// lowerBindingsProtected works like lowerBindings but ensures that variables
// in the protectedNames set are never consumed (always PICK'd, never ROLL'd).
// This is used during loop unrolling so that outer-scope variables survive
// across iterations.
func (ctx *loweringContext) lowerBindingsProtected(bindings []ir.ANFBinding, protectedNames map[string]bool) {
	lastUses := computeLastUses(bindings)

	// Remove protected names from lastUses so they're never treated as last-use.
	// This forces bringToTop to use PICK instead of ROLL for these variables.
	for name := range protectedNames {
		delete(lastUses, name)
	}
	// Set protected names to a very high last-use index so isLastUse always returns false
	for name := range protectedNames {
		lastUses[name] = 1<<31 - 1 // MAX_INT
	}

	for i, binding := range bindings {
		ctx.lowerBinding(&binding, i, lastUses)
	}
}

func (ctx *loweringContext) lowerBinding(binding *ir.ANFBinding, bindingIndex int, lastUses map[string]int) {
	name := binding.Name
	value := &binding.Value

	switch value.Kind {
	case "load_param":
		ctx.lowerLoadParam(name, value.Name, bindingIndex, lastUses)
	case "load_prop":
		ctx.lowerLoadProp(name, value.Name)
	case "load_const":
		ctx.lowerLoadConst(name, value)
	case "bin_op":
		ctx.lowerBinOp(name, value.Op, value.Left, value.Right, bindingIndex, lastUses, value.ResultType)
	case "unary_op":
		ctx.lowerUnaryOp(name, value.Op, value.Operand, bindingIndex, lastUses)
	case "call":
		ctx.lowerCall(name, value.Func, value.Args, bindingIndex, lastUses)
	case "method_call":
		ctx.lowerMethodCall(name, value.Object, value.Method, value.Args, bindingIndex, lastUses)
	case "if":
		ctx.lowerIf(name, value.Cond, value.Then, value.Else, bindingIndex, lastUses)
	case "loop":
		ctx.lowerLoop(name, value.Count, value.Body, value.IterVar)
	case "assert":
		ctx.lowerAssert(value.ValueRef, bindingIndex, lastUses, false)
	case "update_prop":
		ctx.lowerUpdateProp(value.Name, value.ValueRef, bindingIndex, lastUses)
	case "get_state_script":
		ctx.lowerGetStateScript(name)
	case "check_preimage":
		ctx.lowerCheckPreimage(name, value.Preimage, bindingIndex, lastUses)
	case "add_output":
		ctx.lowerAddOutput(name, value.Satoshis, value.StateValues, bindingIndex, lastUses)
	}
}

// ---------------------------------------------------------------------------
// Individual lowering methods
// ---------------------------------------------------------------------------

func (ctx *loweringContext) lowerLoadParam(bindingName, paramName string, bindingIndex int, lastUses map[string]int) {
	if ctx.sm.has(paramName) {
		isLast := ctx.isLastUse(paramName, bindingIndex, lastUses)
		ctx.bringToTop(paramName, isLast)
		ctx.sm.pop()
		ctx.sm.push(bindingName)
	} else {
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
		ctx.sm.push(bindingName)
	}
}

func (ctx *loweringContext) lowerLoadProp(bindingName, propName string) {
	var prop *ir.ANFProperty
	for i := range ctx.properties {
		if ctx.properties[i].Name == propName {
			prop = &ctx.properties[i]
			break
		}
	}

	if prop != nil && prop.InitialValue != nil {
		ctx.pushPropertyValue(prop.InitialValue)
	} else if ctx.sm.has(propName) {
		ctx.bringToTop(propName, false)
		ctx.sm.pop()
	} else {
		// Property value will be provided at deployment time; emit a placeholder.
		// The emitter records byte offsets so the SDK can splice in real values.
		paramIndex := 0
		for i, p := range ctx.properties {
			if p.Name == propName {
				paramIndex = i
				break
			}
		}
		ctx.emitOp(StackOp{Op: "placeholder", ParamIndex: paramIndex, ParamName: propName})
	}
	ctx.sm.push(bindingName)
}

func (ctx *loweringContext) pushPropertyValue(val interface{}) {
	switch v := val.(type) {
	case bool:
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bool", Bool: v}})
	case float64:
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(v))})
	case *big.Int:
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	case string:
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: hexToBytes(v)}})
	default:
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
	}
}

func (ctx *loweringContext) lowerLoadConst(bindingName string, value *ir.ANFValue) {
	// Handle @ref: aliases (ANF variable aliasing)
	// When a load_const has a string value starting with "@ref:", it's an alias
	// to another binding. We bring that value to the top via PICK (non-consuming).
	if value.ConstString != nil && len(*value.ConstString) > 5 && (*value.ConstString)[:5] == "@ref:" {
		refName := (*value.ConstString)[5:]
		if ctx.sm.has(refName) {
			ctx.bringToTop(refName, false)
			ctx.sm.pop()
			ctx.sm.push(bindingName)
		} else {
			// Referenced value not on stack -- push a placeholder
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
			ctx.sm.push(bindingName)
		}
		return
	}
	// Handle @this marker -- compile-time concept, not a runtime value
	if value.ConstString != nil && *value.ConstString == "@this" {
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
		ctx.sm.push(bindingName)
		return
	}
	if value.ConstBool != nil {
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bool", Bool: *value.ConstBool}})
	} else if value.ConstBigInt != nil {
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(value.ConstBigInt)}})
	} else if value.ConstString != nil {
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: hexToBytes(*value.ConstString)}})
	} else {
		// Fallback: push 0
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
	}
	ctx.sm.push(bindingName)
}

func (ctx *loweringContext) lowerBinOp(bindingName, op, left, right string, bindingIndex int, lastUses map[string]int, resultType string) {
	leftIsLast := ctx.isLastUse(left, bindingIndex, lastUses)
	ctx.bringToTop(left, leftIsLast)

	rightIsLast := ctx.isLastUse(right, bindingIndex, lastUses)
	ctx.bringToTop(right, rightIsLast)

	ctx.sm.pop()
	ctx.sm.pop()

	// For equality operators, choose OP_EQUAL vs OP_NUMEQUAL based on operand type.
	if resultType == "bytes" && (op == "===" || op == "!==") {
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_EQUAL"})
		if op == "!==" {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NOT"})
		}
	} else {
		opcodes, ok := binopOpcodes[op]
		if !ok {
			panic(fmt.Sprintf("unknown binary operator: %s", op))
		}
		for _, code := range opcodes {
			ctx.emitOp(StackOp{Op: "opcode", Code: code})
		}
	}

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerUnaryOp(bindingName, op, operand string, bindingIndex int, lastUses map[string]int) {
	isLast := ctx.isLastUse(operand, bindingIndex, lastUses)
	ctx.bringToTop(operand, isLast)

	ctx.sm.pop()

	opcodes, ok := unaryopOpcodes[op]
	if !ok {
		panic(fmt.Sprintf("unknown unary operator: %s", op))
	}
	for _, code := range opcodes {
		ctx.emitOp(StackOp{Op: "opcode", Code: code})
	}

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerCall(bindingName, funcName string, args []string, bindingIndex int, lastUses map[string]int) {
	// Special handling for assert
	if funcName == "assert" {
		if len(args) >= 1 {
			isLast := ctx.isLastUse(args[0], bindingIndex, lastUses)
			ctx.bringToTop(args[0], isLast)
			ctx.sm.pop()
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_VERIFY"})
			ctx.sm.push(bindingName)
		}
		return
	}

	// super() in constructor — no opcode emission needed.
	// Constructor args are already on the stack.
	if funcName == "super" {
		ctx.sm.push(bindingName)
		return
	}

	if funcName == "reverseBytes" {
		ctx.lowerReverseBytes(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "substr" {
		ctx.lowerSubstr(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "verifyRabinSig" {
		ctx.lowerVerifyRabinSig(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "verifyWOTS" {
		ctx.lowerVerifyWOTS(bindingName, args, bindingIndex, lastUses)
		return
	}

	if strings.HasPrefix(funcName, "verifySLHDSA_SHA2_") {
		paramKey := strings.TrimPrefix(funcName, "verifySLHDSA_")
		ctx.lowerVerifySLHDSA(bindingName, paramKey, args, bindingIndex, lastUses)
		return
	}

	if funcName == "safediv" || funcName == "safemod" {
		ctx.lowerSafeDivMod(bindingName, funcName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "clamp" {
		ctx.lowerClamp(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "pow" {
		ctx.lowerPow(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "mulDiv" {
		ctx.lowerMulDiv(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "percentOf" {
		ctx.lowerPercentOf(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "sqrt" {
		ctx.lowerSqrt(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "gcd" {
		ctx.lowerGcd(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "divmod" {
		ctx.lowerDivmod(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "log2" {
		ctx.lowerLog2(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "sign" {
		ctx.lowerSign(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "right" {
		ctx.lowerRight(bindingName, args, bindingIndex, lastUses)
		return
	}

	// pack() and toByteString() are type-level casts — no-ops at the script level
	if funcName == "pack" || funcName == "toByteString" {
		if len(args) >= 1 {
			arg := args[0]
			isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
			ctx.bringToTop(arg, isLast)
			// Replace the arg's stack entry with the binding name
			ctx.sm.pop()
			ctx.sm.push(bindingName)
		}
		return
	}

	// Preimage field extractors — each needs a custom OP_SPLIT sequence
	// because OP_SPLIT produces two stack values and the intermediate stack
	// management cannot be expressed in the simple builtinOpcodes table.
	if len(funcName) > 7 && funcName[:7] == "extract" {
		ctx.lowerExtractor(bindingName, funcName, args, bindingIndex, lastUses)
		return
	}

	// General builtin: push args in order, then emit opcodes
	for _, arg := range args {
		isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
		ctx.bringToTop(arg, isLast)
	}

	// Pop all args
	for range args {
		ctx.sm.pop()
	}

	opcodes, ok := builtinOpcodes[funcName]
	if !ok {
		// Unknown function — push a placeholder. This can happen for
		// private method calls in non-public methods that are never emitted.
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
		ctx.sm.push(bindingName)
		return
	}
	for _, code := range opcodes {
		ctx.emitOp(StackOp{Op: "opcode", Code: code})
	}

	// Some builtins produce two outputs
	if funcName == "split" {
		ctx.sm.push("")          // left part
		ctx.sm.push(bindingName) // right part (top)
	} else if funcName == "len" {
		ctx.sm.push("")          // original value still present
		ctx.sm.push(bindingName) // size on top
	} else {
		ctx.sm.push(bindingName)
	}

	ctx.trackDepth()
}

func (ctx *loweringContext) lowerMethodCall(bindingName, _ string, method string, args []string, bindingIndex int, lastUses map[string]int) {
	if method == "getStateScript" {
		ctx.lowerGetStateScript(bindingName)
		return
	}

	// Check if this is a private method call that should be inlined
	if privateMethod, ok := ctx.privateMethods[method]; ok {
		ctx.inlineMethodCall(bindingName, privateMethod, args, bindingIndex, lastUses)
		return
	}

	// For other method calls, treat like a function call
	ctx.lowerCall(bindingName, method, args, bindingIndex, lastUses)
}

// inlineMethodCall inlines a private method by lowering its body in the current context.
// The method's parameters are bound to the call arguments.
func (ctx *loweringContext) inlineMethodCall(bindingName string, method *ir.ANFMethod, args []string, bindingIndex int, lastUses map[string]int) {
	// First, bring all args to the top of the stack and rename them to the method param names
	for i, arg := range args {
		if i < len(method.Params) {
			isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
			ctx.bringToTop(arg, isLast)
			// Rename to param name
			ctx.sm.pop()
			ctx.sm.push(method.Params[i].Name)
		}
	}

	// Lower the method body
	ctx.lowerBindings(method.Body, false)

	// The last binding's result should be on top of the stack.
	// Rename it to the calling binding name.
	if len(method.Body) > 0 {
		lastBindingName := method.Body[len(method.Body)-1].Name
		// Find and rename the top entry
		if ctx.sm.depth() > 0 {
			topName := ctx.sm.peekAtDepth(0)
			if topName == lastBindingName {
				ctx.sm.pop()
				ctx.sm.push(bindingName)
			}
		}
	}
}

func (ctx *loweringContext) lowerIf(bindingName, cond string, thenBindings, elseBindings []ir.ANFBinding, bindingIndex int, lastUses map[string]int, terminalAssert ...bool) {
	ta := len(terminalAssert) > 0 && terminalAssert[0]

	isLast := ctx.isLastUse(cond, bindingIndex, lastUses)
	ctx.bringToTop(cond, isLast)
	ctx.sm.pop() // OP_IF consumes the condition

	// Lower then-branch
	thenCtx := newLoweringContext(nil, ctx.properties)
	thenCtx.sm = ctx.sm.clone()
	thenCtx.lowerBindings(thenBindings, ta)

	if ta && thenCtx.sm.depth() > 1 {
		excess := thenCtx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			thenCtx.emitOp(StackOp{Op: "nip"})
			thenCtx.sm.removeAtDepth(1)
		}
	}

	thenOps := thenCtx.ops

	// Lower else-branch
	elseCtx := newLoweringContext(nil, ctx.properties)
	elseCtx.sm = ctx.sm.clone()
	elseCtx.lowerBindings(elseBindings, ta)

	if ta && elseCtx.sm.depth() > 1 {
		excess := elseCtx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			elseCtx.emitOp(StackOp{Op: "nip"})
			elseCtx.sm.removeAtDepth(1)
		}
	}

	elseOps := elseCtx.ops

	ifOp := StackOp{
		Op:   "if",
		Then: thenOps,
	}
	if len(elseOps) > 0 {
		ifOp.Else = elseOps
	}
	ctx.emitOp(ifOp)

	ctx.sm.push(bindingName)
	ctx.trackDepth()

	if thenCtx.maxDepth > ctx.maxDepth {
		ctx.maxDepth = thenCtx.maxDepth
	}
	if elseCtx.maxDepth > ctx.maxDepth {
		ctx.maxDepth = elseCtx.maxDepth
	}
}

func (ctx *loweringContext) lowerLoop(bindingName string, count int, body []ir.ANFBinding, iterVar string) {
	// Collect outer-scope param names referenced in the loop body.
	// These must not be consumed in non-final iterations.
	outerParams := make(map[string]bool)
	for _, b := range body {
		if b.Value.Kind == "load_param" && b.Value.Name != iterVar {
			outerParams[b.Value.Name] = true
		}
	}

	for i := 0; i < count; i++ {
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(i))})
		ctx.sm.push(iterVar)

		lastUses := computeLastUses(body)

		// In non-final iterations, prevent outer-scope params from being
		// consumed by setting their last-use beyond any body binding index.
		if i < count-1 {
			for paramName := range outerParams {
				lastUses[paramName] = len(body)
			}
		}

		for j, binding := range body {
			ctx.lowerBinding(&binding, j, lastUses)
		}

		// Clean up the iteration variable if it was not consumed by the body.
		// The body may not reference iterVar at all, leaving it on the stack.
		if ctx.sm.has(iterVar) {
			depth := ctx.sm.findDepth(iterVar)
			if depth == 0 {
				ctx.emitOp(StackOp{Op: "drop"})
				ctx.sm.pop()
			}
		}
	}
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerAssert(valueRef string, bindingIndex int, lastUses map[string]int, terminal bool) {
	isLast := ctx.isLastUse(valueRef, bindingIndex, lastUses)
	ctx.bringToTop(valueRef, isLast)
	if terminal {
		// Terminal assert: leave value on stack for Bitcoin Script's
		// final truthiness check (no OP_VERIFY).
	} else {
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	}
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerUpdateProp(propName, valueRef string, bindingIndex int, lastUses map[string]int) {
	isLast := ctx.isLastUse(valueRef, bindingIndex, lastUses)
	ctx.bringToTop(valueRef, isLast)
	ctx.sm.pop()
	ctx.sm.push(propName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerGetStateScript(bindingName string) {
	var stateProps []ir.ANFProperty
	for _, p := range ctx.properties {
		if !p.Readonly {
			stateProps = append(stateProps, p)
		}
	}

	if len(stateProps) == 0 {
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{}}})
		ctx.sm.push(bindingName)
		return
	}

	first := true
	for _, prop := range stateProps {
		if ctx.sm.has(prop.Name) {
			ctx.bringToTop(prop.Name, false)
		} else if prop.InitialValue != nil {
			ctx.pushPropertyValue(prop.InitialValue)
			ctx.sm.push("")
		} else {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
			ctx.sm.push("")
		}

		// Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
		if prop.Type == "bigint" {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
			ctx.sm.push("")
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
			ctx.sm.pop() // pop the width
		} else if prop.Type == "boolean" {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
			ctx.sm.push("")
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
			ctx.sm.pop() // pop the width
		}
		// Byte-typed properties (ByteString, PubKey, Sig, etc.) need no
		// conversion — they are already byte sequences on the stack.

		if !first {
			ctx.sm.pop()
			ctx.sm.pop()
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
			ctx.sm.push("")
		}
		first = false
	}

	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerAddOutput(bindingName, satoshis string, stateValues []string, bindingIndex int, lastUses map[string]int) {
	// Serialize a transaction output: <8-byte LE satoshis> <serialized state values>
	// This mirrors lowerGetStateScript but uses the provided value refs instead
	// of loading from the stack, and prepends the satoshis amount.

	var stateProps []ir.ANFProperty
	for _, p := range ctx.properties {
		if !p.Readonly {
			stateProps = append(stateProps, p)
		}
	}

	// Step 1: Serialize satoshis as 8-byte LE
	isLastSatoshis := ctx.isLastUse(satoshis, bindingIndex, lastUses)
	ctx.bringToTop(satoshis, isLastSatoshis)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop() // pop the width

	// Step 2: Serialize each state value and concatenate
	for i := 0; i < len(stateValues) && i < len(stateProps); i++ {
		valueRef := stateValues[i]
		prop := stateProps[i]

		isLast := ctx.isLastUse(valueRef, bindingIndex, lastUses)
		ctx.bringToTop(valueRef, isLast)

		// Convert numeric/boolean values to fixed-width bytes
		if prop.Type == "bigint" {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
			ctx.sm.push("")
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
			ctx.sm.pop()
		} else if prop.Type == "boolean" {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
			ctx.sm.push("")
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
			ctx.sm.pop()
		}
		// Byte types used as-is

		// Concatenate with accumulator
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
		ctx.sm.push("")
	}

	// Rename top to binding name
	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerCheckPreimage(bindingName, preimage string, bindingIndex int, lastUses map[string]int) {
	// OP_PUSH_TX: verify the sighash preimage matches the current spending
	// transaction.  See https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
	//
	// The technique uses a well-known ECDSA keypair where private key = 1
	// (so the public key is the secp256k1 generator point G, compressed:
	//   0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798).
	//
	// At spending time the SDK must:
	//   1. Serialise the BIP-143 sighash preimage for the current input.
	//   2. Compute sighash = SHA256(SHA256(preimage)).
	//   3. Derive an ECDSA signature (r, s) with privkey = 1:
	//        r = Gx  (x-coordinate of the generator point, constant)
	//        s = (sighash + r) mod n
	//   4. DER-encode (r, s) and append the SIGHASH_ALL|FORKID byte (0x41).
	//   5. Push <sig> <preimage> (plus any other method args) as the
	//      unlocking script.
	//
	// The locking script sequence:
	//   [bring preimage to top]     -- via PICK or ROLL
	//   [bring _opPushTxSig to top] -- via ROLL (consuming)
	//   <G>                         -- push compressed generator point
	//   OP_CHECKSIG                 -- verify sig over SHA256(SHA256(preimage))
	//   OP_VERIFY                   -- abort if invalid
	//   -- preimage remains on stack for field extractors
	//
	// Stack map trace:
	//   After bringToTop(preimage):  [..., preimage]
	//   After bringToTop(sig, true): [..., preimage, _opPushTxSig]
	//   After push G:                [..., preimage, _opPushTxSig, null(G)]
	//   After OP_CHECKSIG:           [..., preimage, null(result)]
	//   After OP_VERIFY:             [..., preimage]

	// Step 1: Bring preimage to top.
	isLast := ctx.isLastUse(preimage, bindingIndex, lastUses)
	ctx.bringToTop(preimage, isLast)

	// Step 2: Bring the implicit _opPushTxSig to top (consuming).
	ctx.bringToTop("_opPushTxSig", true)

	// Step 3: Push compressed secp256k1 generator point G (33 bytes).
	G := []byte{
		0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
		0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
		0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
		0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
		0x98,
	}
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: G}})
	ctx.sm.push("") // G on stack

	// Step 4: OP_CHECKSIG -- pops pubkey (G) and sig, pushes boolean result.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CHECKSIG"})
	ctx.sm.pop() // G consumed
	ctx.sm.pop() // _opPushTxSig consumed
	ctx.sm.push("") // boolean result

	// Step 5: OP_VERIFY -- abort if false, removes result from stack.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	ctx.sm.pop() // result consumed

	// The preimage is now on top (from Step 1). Rename to binding name
	// so field extractors can reference it.
	ctx.sm.pop()
	ctx.sm.push(bindingName)

	ctx.trackDepth()
}

// lowerExtractor handles preimage field extractor calls.
//
// The SigHashPreimage follows BIP-143 format:
//
//	Offset  Bytes  Field
//	0       4      nVersion (LE uint32)
//	4       32     hashPrevouts
//	36      32     hashSequence
//	68      36     outpoint (txid 32 + vout 4)
//	104     var    scriptCode (varint-prefixed)
//	var     8      amount (satoshis, LE int64)
//	var     4      nSequence
//	var     32     hashOutputs
//	var     4      nLocktime
//	var     4      sighashType
//
// Fixed-offset fields use absolute OP_SPLIT positions.
// Variable-offset fields use end-relative positions via OP_SIZE.
func (ctx *loweringContext) lowerExtractor(bindingName, funcName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic(fmt.Sprintf("%s requires 1 argument", funcName))
	}
	arg := args[0]
	isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
	ctx.bringToTop(arg, isLast)

	// The preimage is now on top of the stack.
	ctx.sm.pop() // consume the preimage from stack map

	switch funcName {
	case "extractVersion":
		// <preimage> 4 OP_SPLIT OP_DROP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	case "extractHashPrevouts":
		// <preimage> 4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(32)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

	case "extractHashSequence":
		// <preimage> 36 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(36)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(32)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

	case "extractOutpoint":
		// <preimage> 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(68)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(36)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

	case "extractSigHashType":
		// End-relative: last 4 bytes, converted to number.
		// <preimage> OP_SIZE 4 OP_SUB OP_SPLIT OP_NIP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	case "extractLocktime":
		// End-relative: 4 bytes before the last 4 (sighashType).
		// <preimage> OP_SIZE 8 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	case "extractOutputHash", "extractOutputs":
		// End-relative: 32 bytes before the last 8 (nLocktime 4 + sighashType 4).
		// hashOutputs(32) + nLocktime(4) + sighashType(4) = 40 bytes from end.
		// <preimage> OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(40)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(32)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

	case "extractAmount":
		// End-relative: 8 bytes (LE int64) at offset -(nSequence(4) + hashOutputs(32) + nLocktime(4) + sighashType(4) + amount(8)) = -52 from end.
		// <preimage> OP_SIZE 52 OP_SUB OP_SPLIT OP_NIP 8 OP_SPLIT OP_DROP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(52)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	case "extractSequence":
		// End-relative: 4 bytes (nSequence) before hashOutputs(32) + nLocktime(4) + sighashType(4) = 44 from end.
		// <preimage> OP_SIZE 44 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(44)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	case "extractScriptCode":
		// Variable-length field at offset 104. End-relative tail = 52 bytes.
		// <preimage> 104 OP_SPLIT OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_DROP
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(104)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(52)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

	case "extractInputIndex":
		// Input index = vout field of outpoint, at offset 100, 4 bytes.
		// <preimage> 100 OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(100)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	default:
		panic(fmt.Sprintf("unknown extractor: %s", funcName))
	}

	// Rename top of stack to the binding name
	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerReverseBytes(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic("reverseBytes requires 1 argument")
	}
	arg := args[0]
	isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
	ctx.bringToTop(arg, isLast)

	// Variable-length byte reversal using bounded unrolled loop.
	// Algorithm: split off first byte repeatedly, prepend each to accumulator.
	ctx.sm.pop()

	// Push empty result (OP_0), swap so data is on top
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
	ctx.emitOp(StackOp{Op: "swap"})

	// 520 iterations (max BSV element size)
	for i := 0; i < 520; i++ {
		// Stack: [result, data]
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.emitOp(StackOp{
			Op: "if",
			Then: []StackOp{
				{Op: "push", Value: bigIntPush(1)},
				{Op: "opcode", Code: "OP_SPLIT"},
				{Op: "swap"},
				{Op: "rot"},
				{Op: "opcode", Code: "OP_CAT"},
				{Op: "swap"},
			},
		})
	}

	// Drop empty remainder
	ctx.emitOp(StackOp{Op: "drop"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerArrayAccess handles __array_access(data, index) — ByteString byte-level indexing.
//
// Compiled to:
//
//	<data> <index> OP_SPLIT OP_NIP 1 OP_SPLIT OP_DROP OP_BIN2NUM
//
// Stack trace:
//
//	[..., data, index]
//	OP_SPLIT  → [..., left, right]       (split at index)
//	OP_NIP    → [..., right]             (discard left)
//	push 1    → [..., right, 1]
//	OP_SPLIT  → [..., firstByte, rest]   (split off first byte)
//	OP_DROP   → [..., firstByte]         (discard rest)
//	OP_BIN2NUM → [..., numericValue]     (convert byte to bigint)
func (ctx *loweringContext) lowerArrayAccess(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("__array_access requires 2 arguments (object, index)")
	}

	obj, index := args[0], args[1]

	// Push the data (ByteString) onto the stack
	objIsLast := ctx.isLastUse(obj, bindingIndex, lastUses)
	ctx.bringToTop(obj, objIsLast)

	// Push the index onto the stack
	indexIsLast := ctx.isLastUse(index, bindingIndex, lastUses)
	ctx.bringToTop(index, indexIsLast)

	// OP_SPLIT at index: stack = [..., left, right]
	ctx.sm.pop()  // index consumed
	ctx.sm.pop()  // data consumed
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.push("") // left part (discard)
	ctx.sm.push("") // right part (keep)

	// OP_NIP: discard left, keep right: stack = [..., right]
	ctx.emitOp(StackOp{Op: "nip"})
	ctx.sm.pop()
	rightPart := ctx.sm.pop()
	ctx.sm.push(rightPart)

	// Push 1 for the next split (extract 1 byte)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
	ctx.sm.push("")

	// OP_SPLIT: split off first byte: stack = [..., firstByte, rest]
	ctx.sm.pop()  // 1 consumed
	ctx.sm.pop()  // right consumed
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.push("") // first byte (keep)
	ctx.sm.push("") // rest (discard)

	// OP_DROP: discard rest: stack = [..., firstByte]
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")

	// OP_BIN2NUM: convert single byte to numeric value
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerSubstr(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("substr requires 3 arguments")
	}

	data, start, length := args[0], args[1], args[2]

	dataIsLast := ctx.isLastUse(data, bindingIndex, lastUses)
	ctx.bringToTop(data, dataIsLast)

	startIsLast := ctx.isLastUse(start, bindingIndex, lastUses)
	ctx.bringToTop(start, startIsLast)

	// Split at start position.
	// Before: stack map has [..., data, start]. Pop both because OP_SPLIT
	// consumes them and produces two new values.
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// After OP_SPLIT: Bitcoin stack is [..., left, right].
	// Push two entries onto the stack map to mirror this.
	ctx.sm.push("") // left (discard)
	ctx.sm.push("") // right (keep)

	// NIP removes the second-from-top element (left part) from the Bitcoin
	// stack, leaving [..., right]. The stack map still has two entries from
	// the OP_SPLIT above. We pop both entries (removing the "left" and
	// "right" placeholders) and push one back for the surviving right part.
	// Net effect on stack map: 2 entries become 1, matching the Bitcoin stack.
	ctx.emitOp(StackOp{Op: "nip"})
	ctx.sm.pop()
	rightPart := ctx.sm.pop()
	ctx.sm.push(rightPart)

	// Push length
	lenIsLast := ctx.isLastUse(length, bindingIndex, lastUses)
	ctx.bringToTop(length, lenIsLast)

	// Split at length to extract the substring.
	// Before: stack map has [..., rightPart, length]. Pop both for OP_SPLIT.
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// After OP_SPLIT: Bitcoin stack is [..., result, remainder].
	ctx.sm.push("") // result (keep)
	ctx.sm.push("") // remainder (discard)

	// DROP removes the top element (remainder) from the Bitcoin stack,
	// leaving [..., result]. Pop both stack map entries (the remainder and
	// the result placeholders) so the caller can push the final binding name.
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.sm.pop()

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerVerifyRabinSig(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 4 {
		panic("verifyRabinSig requires 4 arguments")
	}

	// Stack input: <msg> <sig> <padding> <pubKey>
	// Computation: (sig^2 + padding) mod pubKey == SHA256(msg)
	// Opcode sequence: OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
	msg, sig, padding, pubKey := args[0], args[1], args[2], args[3]

	msgIsLast := ctx.isLastUse(msg, bindingIndex, lastUses)
	ctx.bringToTop(msg, msgIsLast)

	sigIsLast := ctx.isLastUse(sig, bindingIndex, lastUses)
	ctx.bringToTop(sig, sigIsLast)

	paddingIsLast := ctx.isLastUse(padding, bindingIndex, lastUses)
	ctx.bringToTop(padding, paddingIsLast)

	pubKeyIsLast := ctx.isLastUse(pubKey, bindingIndex, lastUses)
	ctx.bringToTop(pubKey, pubKeyIsLast)

	// Pop all 4 args from stack map
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.pop()

	// Emit the Rabin signature verification opcode sequence
	// Stack: msg(3) sig(2) padding(1) pubKey(0)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SWAP"})  // msg sig pubKey padding
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})   // msg pubKey padding sig
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MUL"})   // msg pubKey padding sig^2
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ADD"})   // msg pubKey (sig^2+padding)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SWAP"})  // msg (sig^2+padding) pubKey
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})   // msg ((sig^2+padding) mod pubKey)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SWAP"})  // ((sig^2+padding) mod pubKey) msg
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SHA256"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_EQUAL"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerSign lowers sign(x) to Script that avoids division by zero for x == 0.
// Stack: <x>
// OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF
// If x == 0, the duplicated 0 is consumed by OP_IF (falsy) and original 0 stays.
func (ctx *loweringContext) lowerSign(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic("sign requires 1 argument")
	}
	x := args[0]

	xIsLast := ctx.isLastUse(x, bindingIndex, lastUses)
	ctx.bringToTop(x, xIsLast)
	ctx.sm.pop()

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
	ctx.emitOp(StackOp{
		Op: "if",
		Then: []StackOp{
			{Op: "opcode", Code: "OP_DUP"},
			{Op: "opcode", Code: "OP_ABS"},
			{Op: "swap"},
			{Op: "opcode", Code: "OP_DIV"},
		},
	})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerRight lowers right(data, len) to Script.
// right() returns the rightmost `len` bytes of `data`.
// Stack: <data> <len>
// OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP
func (ctx *loweringContext) lowerRight(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("right requires 2 arguments")
	}
	data, length := args[0], args[1]

	dataIsLast := ctx.isLastUse(data, bindingIndex, lastUses)
	ctx.bringToTop(data, dataIsLast)

	lengthIsLast := ctx.isLastUse(length, bindingIndex, lastUses)
	ctx.bringToTop(length, lengthIsLast)

	ctx.sm.pop() // len
	ctx.sm.pop() // data

	ctx.emitOp(StackOp{Op: "swap"})                          // <len> <data>
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})       // <len> <data> <size>
	ctx.emitOp(StackOp{Op: "rot"})                            // <data> <size> <len>
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})        // <data> <size-len>
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})      // <left> <right>
	ctx.emitOp(StackOp{Op: "nip"})                            // <right>

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// ---------------------------------------------------------------------------
// New math/utility builtin lowering
// ---------------------------------------------------------------------------

// lowerSafeDivMod lowers safediv(a, b) or safemod(a, b).
// Asserts b != 0, then performs OP_DIV or OP_MOD.
// Opcodes: <a> <b> OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV (or OP_MOD)
func (ctx *loweringContext) lowerSafeDivMod(bindingName, funcName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic(fmt.Sprintf("%s requires 2 arguments", funcName))
	}
	a, b := args[0], args[1]

	aIsLast := ctx.isLastUse(a, bindingIndex, lastUses)
	ctx.bringToTop(a, aIsLast)

	bIsLast := ctx.isLastUse(b, bindingIndex, lastUses)
	ctx.bringToTop(b, bIsLast)

	// Stack: ... a b
	// DUP b, check non-zero, then divide/mod
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"}) // ... a b b
	ctx.sm.push("")                                     // extra b copy
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"}) // ... a b (b!=0)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_VERIFY"})    // ... a b (aborts if zero)
	ctx.sm.pop() // remove the check result

	// Pop both operands, emit div or mod
	ctx.sm.pop() // b
	ctx.sm.pop() // a
	opcode := "OP_DIV"
	if funcName == "safemod" {
		opcode = "OP_MOD"
	}
	ctx.emitOp(StackOp{Op: "opcode", Code: opcode})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerClamp lowers clamp(val, lo, hi) — clamp value to [lo, hi].
// Opcodes: <val> <lo> OP_MAX <hi> OP_MIN
func (ctx *loweringContext) lowerClamp(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("clamp requires 3 arguments")
	}
	val, lo, hi := args[0], args[1], args[2]

	valIsLast := ctx.isLastUse(val, bindingIndex, lastUses)
	ctx.bringToTop(val, valIsLast)

	loIsLast := ctx.isLastUse(lo, bindingIndex, lastUses)
	ctx.bringToTop(lo, loIsLast)

	// Stack: ... val lo -> OP_MAX -> max(val, lo)
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MAX"})
	ctx.sm.push("") // intermediate

	hiIsLast := ctx.isLastUse(hi, bindingIndex, lastUses)
	ctx.bringToTop(hi, hiIsLast)

	// Stack: ... max(val,lo) hi -> OP_MIN -> min(max(val,lo), hi)
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MIN"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerPow lowers pow(base, exp) — exponentiation with bounded 32-iteration
// conditional multiply loop.
// Strategy: <base> <exp> OP_SWAP push(1), then 32 rounds of:
//
//	2 OP_PICK (get exp), push(i+1), OP_GREATERTHAN, OP_IF, OP_OVER, OP_MUL, OP_ENDIF
//
// After iterations: OP_NIP OP_NIP to get result.
func (ctx *loweringContext) lowerPow(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("pow requires 2 arguments")
	}
	base, exp := args[0], args[1]

	baseIsLast := ctx.isLastUse(base, bindingIndex, lastUses)
	ctx.bringToTop(base, baseIsLast)

	expIsLast := ctx.isLastUse(exp, bindingIndex, lastUses)
	ctx.bringToTop(exp, expIsLast)

	// Pop both args from stack map
	ctx.sm.pop() // exp
	ctx.sm.pop() // base

	// Stack: base exp
	ctx.emitOp(StackOp{Op: "swap"})                          // exp base
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})    // exp base 1(acc)

	const maxPowIterations = 32
	for i := 0; i < maxPowIterations; i++ {
		// Stack: exp base acc
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_PICK"})              // exp base acc exp
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(i + 1))})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_GREATERTHAN"})       // exp base acc (exp > i)
		ctx.emitOp(StackOp{
			Op: "if",
			Then: []StackOp{
				{Op: "over"},                            // exp base acc base
				{Op: "opcode", Code: "OP_MUL"},          // exp base (acc*base)
			},
		})
	}
	// Stack: exp base result
	ctx.emitOp(StackOp{Op: "nip"}) // exp result
	ctx.emitOp(StackOp{Op: "nip"}) // result

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerMulDiv lowers mulDiv(a, b, c) — (a * b) / c.
// Opcodes: <a> <b> OP_MUL <c> OP_DIV
func (ctx *loweringContext) lowerMulDiv(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("mulDiv requires 3 arguments")
	}
	a, b, c := args[0], args[1], args[2]

	aIsLast := ctx.isLastUse(a, bindingIndex, lastUses)
	ctx.bringToTop(a, aIsLast)
	bIsLast := ctx.isLastUse(b, bindingIndex, lastUses)
	ctx.bringToTop(b, bIsLast)

	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MUL"})
	ctx.sm.push("") // intermediate

	cIsLast := ctx.isLastUse(c, bindingIndex, lastUses)
	ctx.bringToTop(c, cIsLast)

	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerPercentOf lowers percentOf(amount, bps) — (amount * bps) / 10000.
// Opcodes: <amount> <bps> OP_MUL <10000> OP_DIV
func (ctx *loweringContext) lowerPercentOf(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("percentOf requires 2 arguments")
	}
	amount, bps := args[0], args[1]

	amountIsLast := ctx.isLastUse(amount, bindingIndex, lastUses)
	ctx.bringToTop(amount, amountIsLast)
	bpsIsLast := ctx.isLastUse(bps, bindingIndex, lastUses)
	ctx.bringToTop(bps, bpsIsLast)

	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MUL"})
	ctx.sm.push("") // intermediate

	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(10000)})
	ctx.sm.push("")

	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerSqrt lowers sqrt(n) — integer square root via Newton's method.
// 16 iterations: guess = n, then guess = (guess + n/guess) / 2
// Guarded for n == 0: if n is 0, skip Newton iteration (avoid division by zero).
func (ctx *loweringContext) lowerSqrt(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic("sqrt requires 1 argument")
	}
	n := args[0]

	nIsLast := ctx.isLastUse(n, bindingIndex, lastUses)
	ctx.bringToTop(n, nIsLast)
	ctx.sm.pop()

	// Stack: <n>
	// Guard: OP_DUP OP_IF <newton> OP_ENDIF
	// If n == 0, the duplicated 0 is consumed by OP_IF (falsy) and original 0 stays.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"}) // n n

	// Build the Newton iteration ops for the then-branch
	var newtonOps []StackOp
	// Inside the if: stack is <n> (the OP_IF consumed the dup'd copy)
	// DUP to get initial guess = n
	newtonOps = append(newtonOps, StackOp{Op: "opcode", Code: "OP_DUP"}) // n guess(=n)

	// 16 Newton iterations: guess = (guess + n/guess) / 2
	const sqrtIterations = 16
	for i := 0; i < sqrtIterations; i++ {
		// Stack: n guess
		newtonOps = append(newtonOps, StackOp{Op: "over"})                       // n guess n
		newtonOps = append(newtonOps, StackOp{Op: "over"})                       // n guess n guess
		newtonOps = append(newtonOps, StackOp{Op: "opcode", Code: "OP_DIV"})     // n guess (n/guess)
		newtonOps = append(newtonOps, StackOp{Op: "opcode", Code: "OP_ADD"})     // n (guess + n/guess)
		newtonOps = append(newtonOps, StackOp{Op: "push", Value: bigIntPush(2)}) // n (guess + n/guess) 2
		newtonOps = append(newtonOps, StackOp{Op: "opcode", Code: "OP_DIV"})     // n new_guess
	}
	// Stack: n result
	newtonOps = append(newtonOps, StackOp{Op: "nip"}) // result (drop n)

	ctx.emitOp(StackOp{
		Op:   "if",
		Then: newtonOps,
		// Else: empty — if n == 0, original 0 stays on stack
	})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerGcd lowers gcd(a, b) — Euclidean algorithm, bounded to 256 iterations.
// Algorithm: while (b != 0) { temp = b; b = a % b; a = temp; } return a;
func (ctx *loweringContext) lowerGcd(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("gcd requires 2 arguments")
	}
	a, b := args[0], args[1]

	aIsLast := ctx.isLastUse(a, bindingIndex, lastUses)
	ctx.bringToTop(a, aIsLast)
	bIsLast := ctx.isLastUse(b, bindingIndex, lastUses)
	ctx.bringToTop(b, bIsLast)

	ctx.sm.pop()
	ctx.sm.pop()

	// Stack: a b
	// Both should be absolute values
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ABS"})
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ABS"})
	ctx.emitOp(StackOp{Op: "swap"})
	// Stack: |a| |b|

	const gcdIterations = 256
	for i := 0; i < gcdIterations; i++ {
		// Stack: a b
		// if b != 0: a b -> b (a%b)
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})        // a b b
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})  // a b (b!=0)
		ctx.emitOp(StackOp{
			Op: "if",
			Then: []StackOp{
				// a b -> b (a%b)
				{Op: "opcode", Code: "OP_TUCK"}, // b a b
				{Op: "opcode", Code: "OP_MOD"},   // b (a%b)
			},
		})
	}
	// Stack: result 0 (or result if b was already 0)
	ctx.emitOp(StackOp{Op: "drop"}) // drop the 0

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerDivmod lowers divmod(a, b) — returns quotient.
// Opcodes: <a> <b> OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP
func (ctx *loweringContext) lowerDivmod(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("divmod requires 2 arguments")
	}
	a, b := args[0], args[1]

	aIsLast := ctx.isLastUse(a, bindingIndex, lastUses)
	ctx.bringToTop(a, aIsLast)
	bIsLast := ctx.isLastUse(b, bindingIndex, lastUses)
	ctx.bringToTop(b, bIsLast)

	ctx.sm.pop()
	ctx.sm.pop()

	// Stack: a b
	// OP_2DUP: a b a b
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_2DUP"})
	// OP_DIV: a b (a/b)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})
	// OP_ROT OP_ROT: (a/b) a b
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})
	// OP_MOD: (a/b) (a%b)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})
	// Drop the remainder, keep quotient
	ctx.emitOp(StackOp{Op: "drop"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerLog2 lowers log2(n) — exact floor(log2(n)) via bit-scanning.
//
// Uses a bounded unrolled loop (64 iterations for bigint range):
//
//	counter = 0
//	while input > 1: input >>= 1, counter++
//	result = counter
//
// Stack layout during loop: <input> <counter>
// Each iteration: OP_SWAP OP_DUP OP_1 OP_GREATERTHAN OP_IF OP_1 OP_RSHIFT OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
func (ctx *loweringContext) lowerLog2(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic("log2 requires 1 argument")
	}
	n := args[0]

	nIsLast := ctx.isLastUse(n, bindingIndex, lastUses)
	ctx.bringToTop(n, nIsLast)
	ctx.sm.pop()

	// Stack: <n>
	// Push counter = 0
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)}) // n 0

	// 64 iterations (sufficient for Bitcoin Script bigint range)
	const log2Iterations = 64
	for i := 0; i < log2Iterations; i++ {
		// Stack: input counter
		ctx.emitOp(StackOp{Op: "swap"})                                  // counter input
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})               // counter input input
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})            // counter input input 1
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_GREATERTHAN"})        // counter input (input>1)
		ctx.emitOp(StackOp{
			Op: "if",
			Then: []StackOp{
				{Op: "push", Value: bigIntPush(1)},       // counter input 1
				{Op: "opcode", Code: "OP_RSHIFT"},        // counter (input>>1)
				{Op: "swap"},                             // (input>>1) counter
				{Op: "opcode", Code: "OP_1ADD"},          // (input>>1) (counter+1)
				{Op: "swap"},                             // (counter+1) (input>>1)
			},
		})
		// Stack: counter input (or input counter if swapped back)
		// After the if: stack is counter input (swap at start, then if-branch swaps back)
		ctx.emitOp(StackOp{Op: "swap"}) // input counter
	}
	// Stack: input counter
	// Drop input, keep counter
	ctx.emitOp(StackOp{Op: "nip"}) // counter

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// LowerToStack converts an ANF program to a slice of StackMethods.
// Private methods are inlined at call sites rather than compiled separately.
// The constructor is skipped since it's not emitted to Bitcoin Script.
func LowerToStack(program *ir.ANFProgram) (result []StackMethod, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("stack lowering failed: %v", r)
		}
	}()

	// Build map of private methods for inlining
	privateMethods := make(map[string]*ir.ANFMethod)
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic && m.Name != "constructor" {
			privateMethods[m.Name] = m
		}
	}

	var methods []StackMethod

	for i := range program.Methods {
		method := &program.Methods[i]
		// Skip constructor and private methods
		if method.Name == "constructor" || (!method.IsPublic && method.Name != "constructor") {
			continue
		}
		sm, err := lowerMethodWithPrivateMethods(method, program.Properties, privateMethods)
		if err != nil {
			return nil, err
		}
		methods = append(methods, *sm)
	}

	return methods, nil
}

// methodUsesCheckPreimage scans a method's bindings for check_preimage usage.
// If found, the unlocking script will push an implicit <sig> parameter before
// all declared parameters (OP_PUSH_TX pattern).
func methodUsesCheckPreimage(bindings []ir.ANFBinding) bool {
	for _, b := range bindings {
		if b.Value.Kind == "check_preimage" {
			return true
		}
	}
	return false
}

func lowerMethodWithPrivateMethods(method *ir.ANFMethod, properties []ir.ANFProperty, privateMethods map[string]*ir.ANFMethod) (*StackMethod, error) {
	paramNames := make([]string, len(method.Params))
	for i, p := range method.Params {
		paramNames[i] = p.Name
	}

	// If the method uses checkPreimage, the unlocking script pushes an
	// implicit <sig> before all declared parameters (OP_PUSH_TX pattern).
	// Insert _opPushTxSig at the base of the stack so it can be consumed
	// by lowerCheckPreimage later.
	if methodUsesCheckPreimage(method.Body) {
		paramNames = append([]string{"_opPushTxSig"}, paramNames...)
	}

	ctx := newLoweringContext(paramNames, properties)
	ctx.privateMethods = privateMethods
	// Pass terminalAssert=true for public methods so the last assert leaves
	// its value on the stack (Bitcoin Script requires a truthy top-of-stack).
	ctx.lowerBindings(method.Body, method.IsPublic)

	if ctx.maxDepth > maxStackDepth {
		return nil, fmt.Errorf(
			"method '%s' exceeds maximum stack depth of %d (actual: %d). Simplify the contract logic",
			method.Name, maxStackDepth, ctx.maxDepth,
		)
	}

	return &StackMethod{
		Name:          method.Name,
		Ops:           ctx.ops,
		MaxStackDepth: ctx.maxDepth,
	}, nil
}

func lowerMethod(method *ir.ANFMethod, properties []ir.ANFProperty) (*StackMethod, error) {
	paramNames := make([]string, len(method.Params))
	for i, p := range method.Params {
		paramNames[i] = p.Name
	}

	// If the method uses checkPreimage, insert the implicit _opPushTxSig param.
	if methodUsesCheckPreimage(method.Body) {
		paramNames = append([]string{"_opPushTxSig"}, paramNames...)
	}

	ctx := newLoweringContext(paramNames, properties)
	// Pass terminalAssert=true for public methods so the last assert leaves
	// its value on the stack (Bitcoin Script requires a truthy top-of-stack).
	ctx.lowerBindings(method.Body, method.IsPublic)

	if ctx.maxDepth > maxStackDepth {
		return nil, fmt.Errorf(
			"method '%s' exceeds maximum stack depth of %d (actual: %d). Simplify the contract logic",
			method.Name, maxStackDepth, ctx.maxDepth,
		)
	}

	return &StackMethod{
		Name:          method.Name,
		Ops:           ctx.ops,
		MaxStackDepth: ctx.maxDepth,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bigIntPush(n int64) PushValue {
	return PushValue{Kind: "bigint", BigInt: big.NewInt(n)}
}

func hexToBytes(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string: %s", err))
	}
	return b
}

// lowerVerifyWOTS emits the WOTS+ signature verification script.
// Parameters: w=16, n=32 (SHA-256), len=67 chains.
// emitWOTSOneChain emits one WOTS+ chain verification.
// Input: sig(0) csum(1) endpt(2) digit(3) → sigRest(0) newCsum(1) newEndpt(2)
func (ctx *loweringContext) emitWOTSOneChain(chainIndex int) {
	// Entry stack: pubSeed(bottom) sig csum endpt digit(top)
	// Save steps_copy = 15 - digit to alt (for checksum accumulation later)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(15)})
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#1: steps_copy

	// Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#2: endpt
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#3: csum
	// main: pubSeed sig digit

	// Split 32B sig element
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(32)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // push#4: sigRest
	ctx.emitOp(StackOp{Op: "swap"})
	// main: pubSeed sigElem digit

	// Hash loop: skip first `digit` iterations, then apply F for the rest.
	// When digit > 0: decrement (skip). When digit == 0: hash at step j.
	// Stack: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
	for j := 0; j < 15; j++ {
		adrsBytes := []byte{byte(chainIndex), byte(j)}
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		ctx.emitOp(StackOp{Op: "if",
			Then: []StackOp{
				{Op: "opcode", Code: "OP_1SUB"}, // skip: digit--
			},
			Else: []StackOp{
				{Op: "swap"},                                                             // pubSeed digit X
				{Op: "push", Value: bigIntPush(2)},
				{Op: "opcode", Code: "OP_PICK"},                                          // copy pubSeed
				{Op: "push", Value: PushValue{Kind: "bytes", Bytes: adrsBytes}},           // ADRS [chainIndex, j]
				{Op: "opcode", Code: "OP_CAT"},                                            // pubSeed || adrs
				{Op: "swap"},                                                               // bring X to top
				{Op: "opcode", Code: "OP_CAT"},                                            // pubSeed || adrs || X
				{Op: "opcode", Code: "OP_SHA256"},                                         // F result
				{Op: "swap"},                                                               // pubSeed new_X digit(=0)
			},
		})
	}
	ctx.emitOp(StackOp{Op: "drop"}) // drop digit (now 0)

	// Restore: sigRest, csum, endpt_acc, steps_copy
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})

	// csum += steps_copy
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ADD"})

	// Concat endpoint to endpt_acc
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(3)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROLL"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
}

func (ctx *loweringContext) lowerVerifyWOTS(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("verifyWOTS requires 3 arguments: msg, sig, pubkey")
	}

	// Bring args to top: msg, sig, pubkey
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 3; i++ {
		ctx.sm.pop()
	}
	// main: msg sig pubkey(64B: pubSeed||pkRoot)

	// Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(32)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})          // msg sig pubSeed pkRoot
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})    // pkRoot → alt

	// Rearrange: put pubSeed at bottom, hash msg
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})            // sig pubSeed msg
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROT"})            // pubSeed msg sig
	ctx.emitOp(StackOp{Op: "swap"})                                // pubSeed sig msg
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SHA256"})         // pubSeed sig msgHash

	// Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_0"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(3)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ROLL"})

	// Process 32 bytes → 64 message chains
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		if byteIdx < 31 {
			ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			ctx.emitOp(StackOp{Op: "swap"})
		}
		// Unsigned byte conversion
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		// Extract nibbles
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})
		ctx.emitOp(StackOp{Op: "swap"})
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})

		if byteIdx < 31 {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			ctx.emitOp(StackOp{Op: "swap"})
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		}

		ctx.emitWOTSOneChain(byteIdx * 2) // high nibble chain

		if byteIdx < 31 {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			ctx.emitOp(StackOp{Op: "swap"})
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}

		ctx.emitWOTSOneChain(byteIdx*2 + 1) // low nibble chain

		if byteIdx < 31 {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}
	}

	// Checksum digits
	ctx.emitOp(StackOp{Op: "swap"})
	// d66
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// d65
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DUP"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// d64
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(256)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_DIV"})
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(16)})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_MOD"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	// 3 checksum chains (indices 64, 65, 66)
	for ci := 0; ci < 3; ci++ {
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		ctx.emitWOTSOneChain(64 + ci)
		ctx.emitOp(StackOp{Op: "swap"})
		ctx.emitOp(StackOp{Op: "drop"})
	}

	// Final comparison
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "drop"})
	// main: pubSeed endptAcc
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SHA256"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // pkRoot
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	// Clean up pubSeed
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.emitOp(StackOp{Op: "drop"})

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerVerifySLHDSA emits the SLH-DSA (FIPS 205) signature verification script.
func (ctx *loweringContext) lowerVerifySLHDSA(bindingName, paramKey string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("verifySLHDSA requires 3 arguments: msg, sig, pubkey")
	}

	// Bring args to top: msg, sig, pubkey
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 3; i++ {
		ctx.sm.pop()
	}

	EmitVerifySLHDSA(func(op StackOp) { ctx.emitOp(op) }, paramKey)

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}
