// Package codegen implements the Stack IR lowering and Bitcoin Script emission
// passes of the Rúnar Go compiler. It mirrors the TypeScript compiler's Pass 5
// (stack lowering) and Pass 6 (emit).
package codegen

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
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

func (s *stackMap) renameAtDepth(depthFromTop int, newName string) {
	idx := len(s.slots) - 1 - depthFromTop
	if idx < 0 || idx >= len(s.slots) {
		panic(fmt.Sprintf("invalid stack depth for rename: %d", depthFromTop))
	}
	s.slots[idx] = newName
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

// namedSlots returns the set of all non-empty slot names.
func (s *stackMap) namedSlots() map[string]bool {
	names := make(map[string]bool)
	for _, slot := range s.slots {
		if slot != "" {
			names[slot] = true
		}
	}
	return names
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
	case "deserialize_state":
		refs = append(refs, value.Preimage)
	case "add_output":
		refs = append(refs, value.Satoshis)
		refs = append(refs, value.StateValues...)
		if value.Preimage != "" {
			refs = append(refs, value.Preimage)
		}
	case "add_raw_output":
		refs = append(refs, value.Satoshis)
		refs = append(refs, value.ScriptBytes)
	case "array_literal":
		refs = append(refs, value.Elements...)
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
	localBindings      map[string]bool // binding names in current lowerBindings scope; used by @ref: handler
	outerProtectedRefs map[string]bool // parent-scope refs that must not be consumed (used after current if-branch)
	insideBranch       bool            // true when executing inside an if-branch; update_prop skips old-value removal
}

func newLoweringContext(params []string, properties []ir.ANFProperty) *loweringContext {
	ctx := &loweringContext{
		sm:             newStackMap(params),
		properties:     properties,
		privateMethods: make(map[string]*ir.ANFMethod),
		localBindings:  make(map[string]bool),
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

// emitVarintEncoding emits opcodes to convert a script number length on
// the stack into a Bitcoin varint byte sequence.
//
// Expects stack: [..., script, len]
// Leaves stack:  [..., script, varint_bytes]
//
// OP_NUM2BIN uses sign-magnitude encoding where values 128-255 need 2 bytes
// (sign bit). To produce a correct 1-byte unsigned varint, we use
// OP_NUM2BIN 2 then SPLIT to extract only the low byte.
// Similarly for 2-byte unsigned varint, we use OP_NUM2BIN 4 then SPLIT.
func (ctx *loweringContext) emitVarintEncoding() {
	// Stack: [..., script, len]
	ctx.emitOp(StackOp{Op: "dup"}) // [script, len, len]
	ctx.sm.dup()
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(253)}) // [script, len, len, 253]
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_LESSTHAN"}) // [script, len, isSmall]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
	ctx.sm.pop() // pop condition

	// Then: 1-byte varint (len < 253)
	// Use NUM2BIN 2 to avoid sign-magnitude issue for values 128-252,
	// then take only the first (low) byte via SPLIT.
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"}) // [script, len_2bytes]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)}) // [script, len_2bytes, 1]
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"}) // [script, lowByte, highByte]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("") // lowByte
	ctx.sm.push("") // highByte
	ctx.emitOp(StackOp{Op: "drop"}) // [script, lowByte]
	ctx.sm.pop()

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})

	// Else: 0xfd + 2-byte LE varint (len >= 253)
	// Use NUM2BIN 4 to avoid sign-magnitude issue for values >= 32768,
	// then take only the first 2 (low) bytes via SPLIT.
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"}) // [script, len_4bytes]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)}) // [script, len_4bytes, 2]
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"}) // [script, low2bytes, high2bytes]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("") // low2bytes
	ctx.sm.push("") // high2bytes
	ctx.emitOp(StackOp{Op: "drop"}) // [script, low2bytes]
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0xfd}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})
	// --- Stack: [..., script, varint] ---
}

// emitPushDataEncode emits opcodes to encode a ByteString value on top of the
// stack with a Bitcoin Script push-data length prefix.
//
// Expects stack: [..., bs_value]
// Leaves stack:  [..., pushdata_encoded_value]
func (ctx *loweringContext) emitPushDataEncode() {
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "dup"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(76)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
	ctx.sm.pop()
	smAfterOuterIf := ctx.sm.clone()

	// THEN: len <= 75
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop(); ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	smEndTarget := ctx.sm.clone()

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})
	ctx.sm = smAfterOuterIf.clone()

	ctx.emitOp(StackOp{Op: "dup"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(256)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
	ctx.sm.pop()
	smAfterInnerIf := ctx.sm.clone()

	// THEN: 76-255 → 0x4c + 1-byte
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x4c}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop(); ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop(); ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})
	ctx.sm = smAfterInnerIf.clone()

	// ELSE: >= 256 → 0x4d + 2-byte LE
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(4)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x4d}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop(); ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop(); ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})
	ctx.sm = smEndTarget
}

// emitPushDataDecode emits opcodes to decode a push-data encoded ByteString
// from the state bytes on top of the stack.
//
// Expects stack: [..., state_bytes]
// Leaves stack:  [..., data, remaining_state]
func (ctx *loweringContext) emitPushDataDecode() {
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	ctx.emitOp(StackOp{Op: "dup"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(76)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
	ctx.sm.pop()
	smAfterOuterIf := ctx.sm.clone()

	// THEN: fb < 76 → direct length
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	smEndTarget := ctx.sm.clone()

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})
	ctx.sm = smAfterOuterIf.clone()

	ctx.emitOp(StackOp{Op: "dup"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(77)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
	ctx.sm.pop()
	smAfterInnerIf := ctx.sm.clone()

	// THEN: fb == 77 → 2-byte LE
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})
	ctx.sm = smAfterInnerIf.clone()

	// ELSE: fb == 76 → 1-byte
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	ctx.sm.pop(); ctx.sm.pop()
	ctx.sm.push(""); ctx.sm.push("")

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})
	ctx.sm = smEndTarget
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
	ctx.localBindings = make(map[string]bool, len(bindings))
	for _, b := range bindings {
		ctx.localBindings[b.Name] = true
	}
	lastUses := computeLastUses(bindings)

	// Protect parent-scope refs that are still needed after this scope
	if ctx.outerProtectedRefs != nil {
		for ref := range ctx.outerProtectedRefs {
			lastUses[ref] = len(bindings)
		}
	}

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
		ctx.lowerLoadConst(name, value, bindingIndex, lastUses)
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
	case "deserialize_state":
		ctx.lowerDeserializeState(value.Preimage, bindingIndex, lastUses)
	case "add_output":
		ctx.lowerAddOutput(name, value.Satoshis, value.StateValues, value.Preimage, bindingIndex, lastUses)
	case "add_raw_output":
		ctx.lowerAddRawOutput(name, value.Satoshis, value.ScriptBytes, bindingIndex, lastUses)
	case "array_literal":
		ctx.lowerArrayLiteral(name, value.Elements, bindingIndex, lastUses)
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

	if ctx.sm.has(propName) {
		// Property has been updated (via update_prop) — use the stack value.
		// Must check this BEFORE InitialValue — after update_prop, we need the
		// updated value, not the original constant.
		ctx.bringToTop(propName, false)
		ctx.sm.pop()
	} else if prop != nil && prop.InitialValue != nil {
		ctx.pushPropertyValue(prop.InitialValue)
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

func (ctx *loweringContext) lowerLoadConst(bindingName string, value *ir.ANFValue, bindingIndex int, lastUses map[string]int) {
	// Handle @ref: aliases (ANF variable aliasing)
	// When a load_const has a string value starting with "@ref:", it's an alias
	// to another binding. We bring that value to the top via PICK (non-consuming)
	// unless this is the last use, in which case we consume it via ROLL.
	if value.ConstString != nil && len(*value.ConstString) > 5 && (*value.ConstString)[:5] == "@ref:" {
		refName := (*value.ConstString)[5:]
		if ctx.sm.has(refName) {
			// Only consume (ROLL) if the ref target is a local binding in the
			// current scope. Outer-scope refs must be copied (PICK) so that the
			// parent stackMap stays in sync (critical for IfElse branches and
			// BoundedLoop iterations).
			consume := ctx.localBindings[refName] && ctx.isLastUse(refName, bindingIndex, lastUses)
			ctx.bringToTop(refName, consume)
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

	// For byte-typed operands, override certain operators.
	if resultType == "bytes" && (op == "===" || op == "!==") {
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_EQUAL"})
		if op == "!==" {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NOT"})
		}
	} else if resultType == "bytes" && op == "+" {
		// ByteString concatenation: + on byte types emits OP_CAT, not OP_ADD.
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
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

	// checkMultiSig(sigs, pks) — special handling for OP_CHECKMULTISIG.
	// The two args are array_literal bindings whose individual elements are already
	// on the stack from lowerArrayLiteral. We emit:
	//   OP_0 <sig1> ... <sigN> <nSigs> <pk1> ... <pkM> <nPKs> OP_CHECKMULTISIG
	if funcName == "checkMultiSig" && len(args) == 2 {
		ctx.lowerCheckMultiSig(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "reverseBytes" {
		ctx.lowerReverseBytes(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "__array_access" {
		ctx.lowerArrayAccess(bindingName, args, bindingIndex, lastUses)
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

	if funcName == "sha256Compress" {
		ctx.lowerSha256Compress(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "sha256Finalize" {
		ctx.lowerSha256Finalize(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "blake3Compress" {
		ctx.lowerBlake3Compress(bindingName, args, bindingIndex, lastUses)
		return
	}

	if funcName == "blake3Hash" {
		ctx.lowerBlake3Hash(bindingName, args, bindingIndex, lastUses)
		return
	}

	if isEcBuiltin(funcName) {
		ctx.lowerEcBuiltin(bindingName, funcName, args, bindingIndex, lastUses)
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

	// computeStateOutputHash(preimage, stateBytes) — builds full BIP-143 output
	// serialization for single-output stateful continuation, then hashes it.
	if funcName == "computeStateOutputHash" {
		ctx.lowerComputeStateOutputHash(bindingName, args, bindingIndex, lastUses)
		return
	}

	// computeStateOutput(preimage, stateBytes) — same as computeStateOutputHash
	// but returns raw output bytes WITHOUT hashing. Used when the output bytes
	// need to be concatenated with a change output before hashing.
	if funcName == "computeStateOutput" {
		ctx.lowerComputeStateOutput(bindingName, args, bindingIndex, lastUses)
		return
	}

	// buildChangeOutput(pkh, amount) — builds a P2PKH output serialization:
	//   amount(8LE) + varint(25) + OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
	//   = amount(8LE) + 0x19 + 76a914 <pkh:20> 88ac
	if funcName == "buildChangeOutput" {
		ctx.lowerBuildChangeOutput(bindingName, args, bindingIndex, lastUses)
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

func (ctx *loweringContext) lowerMethodCall(bindingName, object string, method string, args []string, bindingIndex int, lastUses map[string]int) {
	// Consume the @this object reference before dispatching — without this,
	// a stale 0n sits on the stack and desyncs subsequent depths.
	if ctx.sm.has(object) {
		ctx.bringToTop(object, true)
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
	}

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
	type shadowEntry struct {
		paramName    string
		shadowedName string
	}
	var shadowed []shadowEntry

	// Bind call arguments to private method params.
	for i, arg := range args {
		if i < len(method.Params) {
			isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
			ctx.bringToTop(arg, isLast)
			ctx.sm.pop()

			paramName := method.Params[i].Name

			// If paramName already exists on the stack, temporarily rename
			// the existing entry to prevent duplicate-name issues.
			if ctx.sm.has(paramName) {
				existingDepth := ctx.sm.findDepth(paramName)
				shadowedName := fmt.Sprintf("__shadowed_%d_%s", bindingIndex, paramName)
				ctx.sm.renameAtDepth(existingDepth, shadowedName)
				shadowed = append(shadowed, shadowEntry{paramName: paramName, shadowedName: shadowedName})
			}

			ctx.sm.push(paramName)
		}
	}

	// Lower the method body
	ctx.lowerBindings(method.Body, false)

	// Restore shadowed names so the caller's scope sees its original entries.
	for _, s := range shadowed {
		if ctx.sm.has(s.shadowedName) {
			depth := ctx.sm.findDepth(s.shadowedName)
			ctx.sm.renameAtDepth(depth, s.paramName)
		}
	}

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

	// Identify parent-scope items still needed after this if-expression.
	protectedRefs := make(map[string]bool)
	for ref, lastIdx := range lastUses {
		if lastIdx > bindingIndex && ctx.sm.has(ref) {
			protectedRefs[ref] = true
		}
	}

	// Snapshot parent stackMap names before branches run
	preIfNames := ctx.sm.namedSlots()

	// Lower then-branch
	thenCtx := newLoweringContext(nil, ctx.properties)
	thenCtx.sm = ctx.sm.clone()
	thenCtx.outerProtectedRefs = protectedRefs
	thenCtx.insideBranch = true
	thenCtx.lowerBindings(thenBindings, ta)

	if ta && thenCtx.sm.depth() > 1 {
		excess := thenCtx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			thenCtx.emitOp(StackOp{Op: "nip"})
			thenCtx.sm.removeAtDepth(1)
		}
	}

	// Lower else-branch
	elseCtx := newLoweringContext(nil, ctx.properties)
	elseCtx.sm = ctx.sm.clone()
	elseCtx.outerProtectedRefs = protectedRefs
	elseCtx.insideBranch = true
	elseCtx.lowerBindings(elseBindings, ta)

	if ta && elseCtx.sm.depth() > 1 {
		excess := elseCtx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			elseCtx.emitOp(StackOp{Op: "nip"})
			elseCtx.sm.removeAtDepth(1)
		}
	}

	// Balance stack between branches so both end at the same depth.
	// When addOutput is inside an if-then with no else, the then-branch
	// consumes stack items and pushes a serialized output, while the
	// else-branch leaves the stack unchanged. Both must end at the same
	// depth for correct execution after OP_ENDIF.
	//
	// Fix: identify items consumed by the then-branch (present in parent
	// but gone after then). Emit targeted ROLL+DROP in the else-branch
	// to remove those same items, then push empty bytes as placeholder.
	// OP_CAT with empty bytes is identity (no-op for output hashing).
	// Identify items consumed asymmetrically between branches.
	// Phase 1: collect consumed names from both directions.
	postThenNames := thenCtx.sm.namedSlots()
	var consumedNames []string
	for name := range preIfNames {
		if !postThenNames[name] && elseCtx.sm.has(name) {
			consumedNames = append(consumedNames, name)
		}
	}
	postElseNames := elseCtx.sm.namedSlots()
	var elseConsumedNames []string
	for name := range preIfNames {
		if !postElseNames[name] && thenCtx.sm.has(name) {
			elseConsumedNames = append(elseConsumedNames, name)
		}
	}

	// Phase 2: perform ALL drops before any placeholder pushes.
	// This prevents double-placeholder when bilateral drops balance each other.
	if len(consumedNames) > 0 {
		depths := make([]int, 0, len(consumedNames))
		for _, n := range consumedNames {
			depths = append(depths, elseCtx.sm.findDepth(n))
		}
		sort.Sort(sort.Reverse(sort.IntSlice(depths)))
		for _, depth := range depths {
			if depth == 0 {
				elseCtx.emitOp(StackOp{Op: "drop"})
				elseCtx.sm.pop()
			} else if depth == 1 {
				elseCtx.emitOp(StackOp{Op: "nip"})
				elseCtx.sm.removeAtDepth(1)
			} else {
				elseCtx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(depth))})
				elseCtx.sm.push("")
				elseCtx.emitOp(StackOp{Op: "roll", Depth: depth})
				elseCtx.sm.pop()
				removed := elseCtx.sm.removeAtDepth(depth)
				elseCtx.sm.push(removed)
				elseCtx.emitOp(StackOp{Op: "drop"})
				elseCtx.sm.pop()
			}
		}
	}
	if len(elseConsumedNames) > 0 {
		depths := make([]int, 0, len(elseConsumedNames))
		for _, n := range elseConsumedNames {
			depths = append(depths, thenCtx.sm.findDepth(n))
		}
		sort.Sort(sort.Reverse(sort.IntSlice(depths)))
		for _, depth := range depths {
			if depth == 0 {
				thenCtx.emitOp(StackOp{Op: "drop"})
				thenCtx.sm.pop()
			} else if depth == 1 {
				thenCtx.emitOp(StackOp{Op: "nip"})
				thenCtx.sm.removeAtDepth(1)
			} else {
				thenCtx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(depth))})
				thenCtx.sm.push("")
				thenCtx.emitOp(StackOp{Op: "roll", Depth: depth})
				thenCtx.sm.pop()
				removed := thenCtx.sm.removeAtDepth(depth)
				thenCtx.sm.push(removed)
				thenCtx.emitOp(StackOp{Op: "drop"})
				thenCtx.sm.pop()
			}
		}
	}

	// Phase 3: single depth-balance check after ALL drops.
	// Push placeholder only if one branch is still deeper than the other.
	if thenCtx.sm.depth() > elseCtx.sm.depth() {
		// When the then-branch reassigned a local variable (if-without-else),
		// push a COPY of that variable in the else-branch instead of a generic
		// placeholder. This ensures the else-branch preserves the correct value
		// when post-ENDIF stale removal (NIP) removes the old entry.
		thenTopP3 := thenCtx.sm.peekAtDepth(0)
		if len(elseBindings) == 0 && thenTopP3 != "" && elseCtx.sm.has(thenTopP3) {
			varDepth := elseCtx.sm.findDepth(thenTopP3)
			if varDepth == 0 {
				elseCtx.emitOp(StackOp{Op: "dup"})
			} else {
				elseCtx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(varDepth))})
				elseCtx.sm.push("")
				elseCtx.emitOp(StackOp{Op: "pick", Depth: varDepth})
				elseCtx.sm.pop()
			}
			elseCtx.sm.push(thenTopP3)
		} else {
			elseCtx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{}}})
			elseCtx.sm.push("")
		}
	} else if elseCtx.sm.depth() > thenCtx.sm.depth() {
		thenCtx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{}}})
		thenCtx.sm.push("")
	}

	thenOps := thenCtx.ops
	elseOps := elseCtx.ops

	ifOp := StackOp{
		Op:   "if",
		Then: thenOps,
	}
	if len(elseOps) > 0 {
		ifOp.Else = elseOps
	}
	ctx.emitOp(ifOp)

	// Reconcile parent stackMap: remove items consumed by the branches.
	postBranchNames := thenCtx.sm.namedSlots()
	for name := range preIfNames {
		if !postBranchNames[name] && ctx.sm.has(name) {
			depth := ctx.sm.findDepth(name)
			ctx.sm.removeAtDepth(depth)
		}
	}

	// The if expression may produce a result value on top.
	if thenCtx.sm.depth() > ctx.sm.depth() {
		// Branches increased depth — check if both updated the same property.
		thenTop := thenCtx.sm.peekAtDepth(0)
		elseTop := ""
		if elseCtx.sm.depth() > 0 {
			elseTop = elseCtx.sm.peekAtDepth(0)
		}
		isProperty := false
		for _, p := range ctx.properties {
			if p.Name == thenTop {
				isProperty = true
				break
			}
		}
		if isProperty && thenTop != "" && thenTop == elseTop && thenTop != bindingName && ctx.sm.has(thenTop) {
			// Both branches did update_prop for the same property (e.g., turn flip).
			ctx.sm.push(thenTop)
			for d := 1; d < ctx.sm.depth(); d++ {
				if ctx.sm.peekAtDepth(d) == thenTop {
					if d == 1 {
						ctx.emitOp(StackOp{Op: "nip"})
						ctx.sm.removeAtDepth(1)
					} else {
						ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(d))})
						ctx.sm.push("")
						ctx.emitOp(StackOp{Op: "roll", Depth: d + 1})
						ctx.sm.pop()
						rolled := ctx.sm.removeAtDepth(d)
						ctx.sm.push(rolled)
						ctx.emitOp(StackOp{Op: "drop"})
						ctx.sm.pop()
					}
					break
				}
			}
		} else if thenTop != "" && !isProperty && len(elseBindings) == 0 && thenTop != bindingName && ctx.sm.has(thenTop) {
			// If-without-else: the then-branch reassigned a local variable that
			// was PICKed (outer-protected), leaving a stale copy on the stack.
			// Push the local name and remove the stale entry.
			ctx.sm.push(thenTop)
			for d := 1; d < ctx.sm.depth(); d++ {
				if ctx.sm.peekAtDepth(d) == thenTop {
					if d == 1 {
						ctx.emitOp(StackOp{Op: "nip"})
						ctx.sm.removeAtDepth(1)
					} else {
						ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(d))})
						ctx.sm.push("")
						ctx.emitOp(StackOp{Op: "roll", Depth: d + 1})
						ctx.sm.pop()
						rolled := ctx.sm.removeAtDepth(d)
						ctx.sm.push(rolled)
						ctx.emitOp(StackOp{Op: "drop"})
						ctx.sm.pop()
					}
					break
				}
			}
		} else {
			ctx.sm.push(bindingName)
		}
	} else if elseCtx.sm.depth() > ctx.sm.depth() {
		ctx.sm.push(bindingName)
	} else {
		// Void if — don't push phantom
	}
	ctx.trackDepth()

	if thenCtx.maxDepth > ctx.maxDepth {
		ctx.maxDepth = thenCtx.maxDepth
	}
	if elseCtx.maxDepth > ctx.maxDepth {
		ctx.maxDepth = elseCtx.maxDepth
	}
}

func (ctx *loweringContext) lowerLoop(bindingName string, count int, body []ir.ANFBinding, iterVar string) {
	// Collect body binding names (values defined inside the loop body).
	bodyBindingNames := make(map[string]bool, len(body))
	for _, b := range body {
		bodyBindingNames[b.Name] = true
	}

	// Collect outer-scope names referenced in the loop body.
	// These must not be consumed in non-final iterations.
	outerRefs := make(map[string]bool)
	for _, b := range body {
		if b.Value.Kind == "load_param" && b.Value.Name != iterVar {
			outerRefs[b.Value.Name] = true
		}
		// Also protect @ref: targets from outer scope (not redefined in body)
		if b.Value.Kind == "load_const" && b.Value.ConstString != nil &&
			len(*b.Value.ConstString) > 5 && (*b.Value.ConstString)[:5] == "@ref:" {
			refName := (*b.Value.ConstString)[5:]
			if !bodyBindingNames[refName] {
				outerRefs[refName] = true
			}
		}
	}

	// Temporarily extend localBindings with body binding names so
	// @ref: to body-internal values can consume on last use.
	prevLocalBindings := ctx.localBindings
	newLocalBindings := make(map[string]bool, len(prevLocalBindings)+len(bodyBindingNames))
	for k, v := range prevLocalBindings {
		newLocalBindings[k] = v
	}
	for k, v := range bodyBindingNames {
		newLocalBindings[k] = v
	}
	ctx.localBindings = newLocalBindings

	for i := 0; i < count; i++ {
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(i))})
		ctx.sm.push(iterVar)

		lastUses := computeLastUses(body)

		// In non-final iterations, prevent outer-scope refs from being
		// consumed by setting their last-use beyond any body binding index.
		if i < count-1 {
			for refName := range outerRefs {
				lastUses[refName] = len(body)
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
	// Restore localBindings
	ctx.localBindings = prevLocalBindings
	// Note: loops are statements, not expressions — they don't produce a
	// physical stack value. Do NOT push a dummy stackMap entry, as it would
	// desync the stackMap depth from the physical stack.
	_ = bindingName
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

	// When NOT inside an if-branch, remove the old property entry from
	// the stack. After liftBranchUpdateProps transforms conditional
	// property updates into flat if-expressions + top-level update_prop,
	// the old value is dead and must be removed to keep stack depth correct.
	// Inside branches, the old value is kept for lowerIf's same-property
	// detection to handle correctly.
	if !ctx.insideBranch {
		for d := 1; d < ctx.sm.depth(); d++ {
			if ctx.sm.peekAtDepth(d) == propName {
				if d == 1 {
					ctx.emitOp(StackOp{Op: "nip"})
					ctx.sm.removeAtDepth(1)
				} else {
					ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(d))})
					ctx.sm.push("")
					ctx.emitOp(StackOp{Op: "roll", Depth: d + 1})
					ctx.sm.pop()
					rolled := ctx.sm.removeAtDepth(d)
					ctx.sm.push(rolled)
					ctx.emitOp(StackOp{Op: "drop"})
					ctx.sm.pop()
				}
				break
			}
		}
	}

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
			ctx.bringToTop(prop.Name, true) // consume: raw value dead after serialization
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
		} else if prop.Type == "ByteString" {
			// Prepend push-data length prefix (matching SDK format)
			ctx.emitPushDataEncode()
		}
		// Other byte-typed properties (PubKey, Sig, etc.) need no conversion.

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

// lowerComputeStateOutputHash builds the full BIP-143 output serialization for
// a single-output stateful continuation and hashes it with SHA256d.
// Uses _codePart implicit parameter for the code portion and extracts
// the amount from the preimage's scriptCode field.
func (ctx *loweringContext) lowerComputeStateOutputHash(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	preimageRef := args[0]
	stateBytesRef := args[1]

	// Bring stateBytes to stack first.
	stateLast := ctx.isLastUse(stateBytesRef, bindingIndex, lastUses)
	ctx.bringToTop(stateBytesRef, stateLast)

	// Extract amount from preimage for the continuation output.
	preLast := ctx.isLastUse(preimageRef, bindingIndex, lastUses)
	ctx.bringToTop(preimageRef, preLast)

	// Extract amount: last 52 bytes from end, take 8 bytes at offset 0.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(52)}) // 8 (amount) + 44 (tail)
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"}) // [prefix, amountAndTail]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("") // prefix
	ctx.sm.push("") // amountAndTail
	ctx.emitOp(StackOp{Op: "nip"}) // drop prefix
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"}) // [amount(8), tail(44)]
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("") // amount
	ctx.sm.push("") // tail
	ctx.emitOp(StackOp{Op: "drop"}) // drop tail
	ctx.sm.pop()
	// --- Stack: [..., stateBytes, amount(8LE)] ---

	// Save amount to altstack
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	ctx.sm.pop()

	// Bring _codePart to top (PICK — never consume, reused across outputs)
	ctx.bringToTop("_codePart", false)
	// --- Stack: [..., stateBytes, codePart] ---

	// Append OP_RETURN + stateBytes
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x6a}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

	// Compute varint prefix for script length
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
	ctx.sm.push("")
	ctx.emitVarintEncoding()

	// Prepend varint to script
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	// --- Stack: [..., varint+script] ---

	// Prepend amount from altstack
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., amount+varint+script] ---

	// Hash with SHA256d
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_HASH256"})

	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerComputeStateOutput builds the full BIP-143 output serialization for
// a single-output stateful continuation WITHOUT the final hash. This allows
// the caller to concatenate additional outputs (e.g., change output) before hashing.
// Uses _codePart implicit parameter instead of extracting from preimage.
func (ctx *loweringContext) lowerComputeStateOutput(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	// computeStateOutput(preimage, stateBytes, newAmount)
	// Builds the continuation output using _newAmount instead of sourceSatoshis.
	// Uses _codePart implicit parameter instead of extracting from preimage.

	preimageRef := args[0]
	stateBytesRef := args[1]
	newAmountRef := args[2]

	// Consume preimage ref (no longer needed — we use _codePart and _newAmount).
	preLast := ctx.isLastUse(preimageRef, bindingIndex, lastUses)
	ctx.bringToTop(preimageRef, preLast)
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()

	// Step 1: Convert _newAmount to 8-byte LE and save to altstack.
	amountLast := ctx.isLastUse(newAmountRef, bindingIndex, lastUses)
	ctx.bringToTop(newAmountRef, amountLast)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	ctx.sm.pop()

	// Step 2: Bring stateBytes to stack.
	stateLast := ctx.isLastUse(stateBytesRef, bindingIndex, lastUses)
	ctx.bringToTop(stateBytesRef, stateLast)

	// Step 3: Bring _codePart to top (PICK — never consume, reused across outputs)
	ctx.bringToTop("_codePart", false)
	// --- Stack: [..., stateBytes, codePart] ---

	// Step 4: Append OP_RETURN + stateBytes
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x6a}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

	// Step 5: Compute varint prefix for script length
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
	ctx.sm.push("")
	ctx.emitVarintEncoding()

	// Prepend varint to script
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	// --- Stack: [..., varint+script] ---

	// Step 6: Prepend _newAmount (8-byte LE) from altstack.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., amount(8LE)+varint+script] --- (NO hash)

	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerBuildChangeOutput builds a P2PKH output serialization:
//
//	amount(8LE) + 0x19 + 76a914 <pkh:20bytes> 88ac
//
// Total: 34 bytes (8 + 1 + 25).
func (ctx *loweringContext) lowerBuildChangeOutput(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	pkhRef := args[0]
	amountRef := args[1]

	// Step 1: Build the P2PKH locking script with length prefix.
	// Push prefix: varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 = 0x1976a914
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x19, 0x76, 0xa9, 0x14}}})
	ctx.sm.push("")

	// Push the 20-byte PKH
	ctx.bringToTop(pkhRef, ctx.isLastUse(pkhRef, bindingIndex, lastUses))
	// CAT: prefix || pkh
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")

	// Push suffix: OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x88, 0xac}}})
	ctx.sm.push("")
	// CAT: (prefix || pkh) || suffix
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., 0x1976a914{pkh}88ac] ---

	// Step 2: Prepend amount as 8-byte LE.
	ctx.bringToTop(amountRef, ctx.isLastUse(amountRef, bindingIndex, lastUses))
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop() // pop width
	// Stack: [..., script, amount(8LE)]
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	// Stack: [..., amount(8LE), script]
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., amount(8LE)+0x1976a914{pkh}88ac] ---

	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerDeserializeState extracts mutable property values from the BIP-143
// preimage's scriptCode field. The state is stored as the last `stateLen`
// bytes of the scriptCode (after OP_RETURN).
//
// For each mutable property, the value is extracted, converted to the
// correct type (BIN2NUM for bigint/boolean), and pushed onto the stack
// with the property name in the stackMap. This allows load_prop to
// find the deserialized values instead of using hardcoded initial values.
func (ctx *loweringContext) lowerDeserializeState(preimageRef string, bindingIndex int, lastUses map[string]int) {
	var stateProps []ir.ANFProperty
	var propSizes []int
	hasVariableLength := false
	for _, p := range ctx.properties {
		if p.Readonly {
			continue
		}
		stateProps = append(stateProps, p)
		var sz int
		switch p.Type {
		case "bigint":
			sz = 8
		case "boolean":
			sz = 1
		case "PubKey":
			sz = 33
		case "Addr":
			sz = 20
		case "Sha256":
			sz = 32
		case "Point":
			sz = 64
		case "ByteString":
			sz = -1
			hasVariableLength = true
		default:
			panic("deserialize_state: unsupported type: " + p.Type)
		}
		propSizes = append(propSizes, sz)
	}
	if len(stateProps) == 0 {
		return
	}

	isLast := ctx.isLastUse(preimageRef, bindingIndex, lastUses)
	ctx.bringToTop(preimageRef, isLast)

	// 1. Skip first 104 bytes (header), drop prefix
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(104)})
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

	// 2. Drop tail 44 bytes
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
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
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()

	// 3. Drop amount (last 8 bytes)
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
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
	ctx.emitOp(StackOp{Op: "drop"})
	ctx.sm.pop()

	if !hasVariableLength {
		// All fields fixed-size — existing code path (backward compatible)
		stateLen := 0
		for _, sz := range propSizes {
			stateLen += sz
		}

		// 4. Extract last stateLen bytes (the state section)
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(stateLen))})
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

		// 5. Split fixed-size state fields
		ctx.splitFixedStateFields(stateProps, propSizes)
	} else if !ctx.sm.has("_codePart") {
		// Variable-length state but _codePart not available (terminal method).
		// Skip deserialization — the method body doesn't use mutable state.
		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
	} else {
		// Variable-length path: strip varint, use _codePart to find state
		// Strip varint prefix from varint+scriptCode
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(1)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("") // firstByte
		ctx.sm.push("") // rest
		ctx.emitOp(StackOp{Op: "swap"})
		ctx.sm.swap()
		ctx.emitOp(StackOp{Op: "dup"})
		ctx.sm.push(ctx.sm.peekAtDepth(0))
		// Zero-pad before BIN2NUM to prevent sign-bit misinterpretation (0xfd → -125 without pad)
		ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0}}})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
		ctx.sm.pop(); ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(253)})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")

		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_IF"})
		ctx.sm.pop()
		smAtVarintIf := ctx.sm.clone()

		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()

		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ELSE"})
		ctx.sm = smAtVarintIf.clone()

		ctx.emitOp(StackOp{Op: "drop"})
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(2)})
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

		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_ENDIF"})

		// Compute skip = SIZE(_codePart) - codeSepIdx
		ctx.bringToTop("_codePart", false)
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "push_codesep_index"})
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SUB"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")

		// Split scriptCode at skip to get state
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")
		ctx.sm.push("")
		ctx.emitOp(StackOp{Op: "nip"})
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.sm.push("")

		// Parse state fields left-to-right
		ctx.parseVariableLengthStateFields(stateProps, propSizes)
	}
	ctx.trackDepth()
}

// splitFixedStateFields splits fixed-size state bytes into individual properties.
func (ctx *loweringContext) splitFixedStateFields(stateProps []ir.ANFProperty, propSizes []int) {
	if len(stateProps) == 1 {
		prop := stateProps[0]
		if prop.Type == "bigint" || prop.Type == "boolean" {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		}
		ctx.sm.pop()
		ctx.sm.push(prop.Name)
	} else {
		for i, prop := range stateProps {
			sz := propSizes[i]
			if i < len(stateProps)-1 {
				ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(sz))})
				ctx.sm.push("")
				ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
				ctx.sm.pop()
				ctx.sm.pop()
				ctx.sm.push("")
				ctx.sm.push("")
				ctx.emitOp(StackOp{Op: "swap"})
				ctx.sm.swap()
				if prop.Type == "bigint" || prop.Type == "boolean" {
					ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
				}
				ctx.emitOp(StackOp{Op: "swap"})
				ctx.sm.swap()
				ctx.sm.pop()
				ctx.sm.pop()
				ctx.sm.push(prop.Name)
				ctx.sm.push("")
			} else {
				if prop.Type == "bigint" || prop.Type == "boolean" {
					ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
				}
				ctx.sm.pop()
				ctx.sm.push(prop.Name)
			}
		}
	}
}

// parseVariableLengthStateFields parses state fields left-to-right, handling ByteString.
func (ctx *loweringContext) parseVariableLengthStateFields(stateProps []ir.ANFProperty, propSizes []int) {
	if len(stateProps) == 1 {
		prop := stateProps[0]
		if prop.Type == "ByteString" {
			// Single ByteString field: decode push-data prefix, drop trailing empty
			ctx.emitPushDataDecode() // [..., data, remaining]
			ctx.emitOp(StackOp{Op: "drop"})
			ctx.sm.pop()
		} else if prop.Type == "bigint" || prop.Type == "boolean" {
			ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		}
		ctx.sm.pop()
		ctx.sm.push(prop.Name)
	} else {
		for i, prop := range stateProps {
			if i < len(stateProps)-1 {
				if prop.Type == "ByteString" {
					// ByteString: decode push-data prefix, extract data
					ctx.emitPushDataDecode() // [..., data, rest]
					ctx.sm.pop(); ctx.sm.pop()
					ctx.sm.push(prop.Name)
					ctx.sm.push("") // rest on top
				} else {
					ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(propSizes[i]))})
					ctx.sm.push("")
					ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SPLIT"})
					ctx.sm.pop(); ctx.sm.pop()
					ctx.sm.push(""); ctx.sm.push("")
					ctx.emitOp(StackOp{Op: "swap"})
					ctx.sm.swap()
					if prop.Type == "bigint" || prop.Type == "boolean" {
						ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
					}
					ctx.emitOp(StackOp{Op: "swap"})
					ctx.sm.swap()
					ctx.sm.pop(); ctx.sm.pop()
					ctx.sm.push(prop.Name)
					ctx.sm.push("")
				}
			} else {
				if prop.Type == "ByteString" {
					// Last ByteString: decode push-data prefix, drop trailing empty
					ctx.emitPushDataDecode() // [..., data, remaining]
					ctx.emitOp(StackOp{Op: "drop"})
					ctx.sm.pop()
				} else if prop.Type == "bigint" || prop.Type == "boolean" {
					ctx.emitOp(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
				}
				ctx.sm.pop()
				ctx.sm.push(prop.Name)
			}
		}
	}
}

func (ctx *loweringContext) lowerAddOutput(bindingName, satoshis string, stateValues []string, _ string, bindingIndex int, lastUses map[string]int) {
	// Build a full BIP-143 output serialization:
	//   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
	// Uses _codePart implicit parameter (passed by SDK) instead of extracting
	// codePart from the preimage. This is simpler and works with OP_CODESEPARATOR.

	stateProps := make([]ir.ANFProperty, 0)
	for _, p := range ctx.properties {
		if !p.Readonly {
			stateProps = append(stateProps, p)
		}
	}

	// Step 1: Bring _codePart to top (PICK — never consume, reused across outputs)
	ctx.bringToTop("_codePart", false)
	// --- Stack: [..., codePart] ---

	// Step 2: Append OP_RETURN byte (0x6a).
	ctx.emitOp(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x6a}}})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.sm.push("")
	// --- Stack: [..., codePart+OP_RETURN] ---

	// Step 3: Serialize each state value and concatenate.
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
		} else if prop.Type == "ByteString" {
			// Prepend push-data length prefix (matching SDK format)
			ctx.emitPushDataEncode()
		}
		// Other byte types used as-is

		// Concatenate with accumulator
		ctx.sm.pop()
		ctx.sm.pop()
		ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
		ctx.sm.push("")
	}
	// --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

	// Step 4: Compute varint prefix for the full script length.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"}) // [script, len]
	ctx.sm.push("")
	ctx.emitVarintEncoding()
	// --- Stack: [..., script, varint] ---

	// Step 5: Prepend varint to script: SWAP CAT
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"})
	ctx.sm.push("")
	// --- Stack: [..., varint+script] ---

	// Step 6: Prepend satoshis as 8-byte LE.
	isLastSatoshis := ctx.isLastUse(satoshis, bindingIndex, lastUses)
	ctx.bringToTop(satoshis, isLastSatoshis)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop() // pop the width
	// Stack: [..., varint+script, satoshis(8LE)]
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"}) // satoshis || varint+script
	ctx.sm.push("")
	// --- Stack: [..., amount(8LE)+varint+scriptPubKey] ---

	// Rename top to binding name
	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// lowerAddRawOutput builds a raw output serialization:
//
//	amount(8LE) + varint(scriptLen) + scriptBytes
//
// The scriptBytes are used as-is (no codePart/state insertion).
func (ctx *loweringContext) lowerAddRawOutput(bindingName, satoshis, scriptBytes string, bindingIndex int, lastUses map[string]int) {
	// Step 1: Bring scriptBytes to top
	scriptIsLast := ctx.isLastUse(scriptBytes, bindingIndex, lastUses)
	ctx.bringToTop(scriptBytes, scriptIsLast)

	// Step 2: Compute varint prefix for script length
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_SIZE"}) // [script, len]
	ctx.sm.push("")
	ctx.emitVarintEncoding()
	// --- Stack: [..., script, varint] ---

	// Step 3: Prepend varint to script: SWAP CAT
	ctx.emitOp(StackOp{Op: "swap"}) // [varint, script]
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"}) // [varint+script]
	ctx.sm.push("")

	// Step 4: Prepend satoshis as 8-byte LE
	satIsLast := ctx.isLastUse(satoshis, bindingIndex, lastUses)
	ctx.bringToTop(satoshis, satIsLast)
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(8)})
	ctx.sm.push("")
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ctx.sm.pop() // pop width
	// Stack: [..., varint+script, satoshis(8LE)]
	ctx.emitOp(StackOp{Op: "swap"})
	ctx.sm.swap()
	ctx.sm.pop()
	ctx.sm.pop()
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CAT"}) // satoshis || varint+script
	ctx.sm.push("")

	// Rename top to binding name
	ctx.sm.pop()
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerArrayLiteral(bindingName string, elements []string, bindingIndex int, lastUses map[string]int) {
	// An array_literal brings each element to the top of the stack.
	// The elements remain as individual stack entries — the binding name tracks
	// the last element so that callers (e.g. checkMultiSig) can find them.
	for _, elem := range elements {
		isLast := ctx.isLastUse(elem, bindingIndex, lastUses)
		ctx.bringToTop(elem, isLast)
		ctx.sm.pop()
		ctx.sm.push("") // anonymous stack entry for intermediate elements
	}
	// Rename the topmost entry to the binding name
	if len(elements) > 0 {
		ctx.sm.pop()
	}
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerCheckMultiSig(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	// checkMultiSig(sigs, pks) — emits the OP_CHECKMULTISIG sequence.
	// Bitcoin Script stack layout:
	//   OP_0 <sig1> ... <sigN> <nSigs> <pk1> ... <pkM> <nPKs> OP_CHECKMULTISIG
	//
	// The two args reference array_literal bindings. Each array_literal has
	// already placed its individual elements on the stack. Here we:
	// 1. Push OP_0 dummy (Bitcoin CHECKMULTISIG off-by-one bug workaround)
	// 2. Bring the sigs ref to top
	// 3. Bring the pks ref to top
	// 4. Emit OP_CHECKMULTISIG

	// Push OP_0 dummy
	ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(0)})
	ctx.sm.push("")

	// Bring sigs array ref to top
	sigsIsLast := ctx.isLastUse(args[0], bindingIndex, lastUses)
	ctx.bringToTop(args[0], sigsIsLast)

	// Bring pks array ref to top
	pksIsLast := ctx.isLastUse(args[1], bindingIndex, lastUses)
	ctx.bringToTop(args[1], pksIsLast)

	// Pop all args + dummy
	ctx.sm.pop() // pks
	ctx.sm.pop() // sigs
	ctx.sm.pop() // OP_0 dummy

	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CHECKMULTISIG"})
	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerCheckPreimage(bindingName, preimage string, bindingIndex int, lastUses map[string]int) {
	// OP_PUSH_TX: verify the sighash preimage matches the current spending
	// transaction using on-chain signature derivation (BSV Academy pattern).
	//
	// The unlocking script pushes ONLY <preimage>. The locking script derives
	// the ECDSA signature on-chain:
	//   1. DUP preimage
	//   2. HASH256 → sighash
	//   3. BIN2NUM → strip leading zeros
	//   4. 1ADD → s = sighash_int + 1
	//   5. NUM2BIN 32 → pad to 32 bytes
	//   6. Prepend DER prefix (header + known R = Gx)
	//   7. Append SIGHASH_ALL|FORKID (0x41)
	//   8. Push known pubkey
	//   9. CHECKSIGVERIFY

	// Step 0: Emit OP_CODESEPARATOR so that the scriptCode in the BIP-143
	// preimage is only the code after this point. This reduces preimage size
	// for large scripts and is required for scripts > ~32KB.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CODESEPARATOR"})

	// Step 1: Bring preimage to top (non-consuming).
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

	// Step 4: OP_CHECKSIGVERIFY — verify and remove sig + pubkey.
	ctx.emitOp(StackOp{Op: "opcode", Code: "OP_CHECKSIGVERIFY"})
	ctx.sm.pop() // G consumed
	ctx.sm.pop() // _opPushTxSig consumed

	// Preimage remains on top. Rename for field extractors.
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
		ctx.sm.pop() // pop position (32)
		ctx.sm.pop() // pop data being split
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
		ctx.sm.pop() // pop position (32)
		ctx.sm.pop() // pop data being split
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
		ctx.sm.pop() // pop position (36)
		ctx.sm.pop() // pop data being split
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
		ctx.sm.pop() // pop position (4)
		ctx.sm.pop() // pop value being split
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
		ctx.sm.pop() // pop position (8)
		ctx.sm.pop() // pop value being split
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
		ctx.sm.pop() // pop position (4)
		ctx.sm.pop() // pop value being split
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
		ctx.sm.pop() // pop position (4)
		ctx.sm.pop() // pop value being split
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
		ctx.emitOp(StackOp{Op: "push", Value: bigIntPush(int64(i))})
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
// Each iteration: OP_SWAP OP_DUP OP_1 OP_GREATERTHAN OP_IF OP_2 OP_DIV OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
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
				{Op: "push", Value: bigIntPush(2)},       // counter input 2
				{Op: "opcode", Code: "OP_DIV"},           // counter (input/2)
				{Op: "swap"},                             // (input/2) counter
				{Op: "opcode", Code: "OP_1ADD"},          // (input/2) (counter+1)
				{Op: "swap"},                             // (counter+1) (input/2)
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

// methodUsesCodePart checks whether a method has add_output, add_raw_output,
// or computeStateOutput/computeStateOutputHash calls (recursively).
// Only methods that construct continuation outputs need the _codePart implicit parameter.
func methodUsesCodePart(bindings []ir.ANFBinding) bool {
	for _, b := range bindings {
		if b.Value.Kind == "add_output" || b.Value.Kind == "add_raw_output" {
			return true
		}
		// Single-output stateful continuation uses computeStateOutput/computeStateOutputHash
		if b.Value.Kind == "call" && (b.Value.Func == "computeStateOutput" || b.Value.Func == "computeStateOutputHash") {
			return true
		}
		// Recurse into if-else branches and loops
		if b.Value.Kind == "if" {
			if methodUsesCodePart(b.Value.Then) || methodUsesCodePart(b.Value.Else) {
				return true
			}
		}
		if b.Value.Kind == "loop" && methodUsesCodePart(b.Value.Body) {
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

	// If the method uses checkPreimage, the unlocking script pushes implicit
	// params before all declared parameters (OP_PUSH_TX pattern).
	// _codePart: full code script (locking script minus state) as ByteString
	// _opPushTxSig: ECDSA signature for OP_PUSH_TX verification
	// These are inserted at the base of the stack so they can be consumed later.
	if methodUsesCheckPreimage(method.Body) {
		paramNames = append([]string{"_opPushTxSig"}, paramNames...)
		// _codePart is needed when the method has add_output or add_raw_output
		// (it provides the code script for continuation output construction),
		// or when deserializing variable-length (ByteString) state fields.
		if methodUsesCodePart(method.Body) {
			paramNames = append([]string{"_codePart"}, paramNames...)
		}
	}

	ctx := newLoweringContext(paramNames, properties)
	ctx.privateMethods = privateMethods
	// Pass terminalAssert=true for public methods so the last assert leaves
	// its value on the stack (Bitcoin Script requires a truthy top-of-stack).
	ctx.lowerBindings(method.Body, method.IsPublic)

	// Clean up excess stack items left by deserialize_state.
	hasDeserializeState := false
	for _, b := range method.Body {
		if b.Value.Kind == "deserialize_state" {
			hasDeserializeState = true
			break
		}
	}
	if method.IsPublic && hasDeserializeState && ctx.sm.depth() > 1 {
		excess := ctx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			ctx.emitOp(StackOp{Op: "nip"})
			ctx.sm.removeAtDepth(1)
		}
	}

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

	// OP_PUSH_TX no longer requires an implicit _opPushTxSig parameter.

	ctx := newLoweringContext(paramNames, properties)
	// Pass terminalAssert=true for public methods so the last assert leaves
	// its value on the stack (Bitcoin Script requires a truthy top-of-stack).
	ctx.lowerBindings(method.Body, method.IsPublic)

	// Clean up excess stack items left by deserialize_state.
	// Stateful methods that deserialize state from the preimage leave the
	// deserialized property values on the stack. These must be removed so
	// only the final assertion result remains (CLEANSTACK policy).
	hasDeserializeState := false
	for _, b := range method.Body {
		if b.Value.Kind == "deserialize_state" {
			hasDeserializeState = true
			break
		}
	}
	if method.IsPublic && hasDeserializeState && ctx.sm.depth() > 1 {
		excess := ctx.sm.depth() - 1
		for i := 0; i < excess; i++ {
			ctx.emitOp(StackOp{Op: "nip"})
			ctx.sm.removeAtDepth(1)
		}
	}

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

// ---------------------------------------------------------------------------
// SHA-256 compression — delegates to sha256.go
// ---------------------------------------------------------------------------

func (ctx *loweringContext) lowerSha256Compress(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("sha256Compress requires 2 arguments: state, block")
	}
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 2; i++ {
		ctx.sm.pop()
	}

	EmitSha256Compress(func(op StackOp) { ctx.emitOp(op) })

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerSha256Finalize(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 3 {
		panic("sha256Finalize requires 3 arguments: state, remaining, msgBitLen")
	}
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 3; i++ {
		ctx.sm.pop()
	}

	EmitSha256Finalize(func(op StackOp) { ctx.emitOp(op) })

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// ---------------------------------------------------------------------------
// BLAKE3 compression — delegates to blake3.go
// ---------------------------------------------------------------------------

func (ctx *loweringContext) lowerBlake3Compress(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 2 {
		panic("blake3Compress requires 2 arguments: chainingValue, block")
	}
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	for i := 0; i < 2; i++ {
		ctx.sm.pop()
	}

	EmitBlake3Compress(func(op StackOp) { ctx.emitOp(op) })

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

func (ctx *loweringContext) lowerBlake3Hash(bindingName string, args []string, bindingIndex int, lastUses map[string]int) {
	if len(args) < 1 {
		panic("blake3Hash requires 1 argument: message")
	}
	for _, arg := range args {
		ctx.bringToTop(arg, ctx.isLastUse(arg, bindingIndex, lastUses))
	}
	ctx.sm.pop()

	EmitBlake3Hash(func(op StackOp) { ctx.emitOp(op) })

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}

// ---------------------------------------------------------------------------
// EC builtin helpers
// ---------------------------------------------------------------------------

var ecBuiltinNames = map[string]bool{
	"ecAdd": true, "ecMul": true, "ecMulGen": true,
	"ecNegate": true, "ecOnCurve": true, "ecModReduce": true,
	"ecEncodeCompressed": true, "ecMakePoint": true,
	"ecPointX": true, "ecPointY": true,
}

func isEcBuiltin(name string) bool {
	return ecBuiltinNames[name]
}

func (ctx *loweringContext) lowerEcBuiltin(bindingName, funcName string, args []string, bindingIndex int, lastUses map[string]int) {
	// Bring args to top in order
	for _, arg := range args {
		isLast := ctx.isLastUse(arg, bindingIndex, lastUses)
		ctx.bringToTop(arg, isLast)
	}
	for range args {
		ctx.sm.pop()
	}

	emitFn := func(op StackOp) { ctx.emitOp(op) }

	switch funcName {
	case "ecAdd":
		EmitEcAdd(emitFn)
	case "ecMul":
		EmitEcMul(emitFn)
	case "ecMulGen":
		EmitEcMulGen(emitFn)
	case "ecNegate":
		EmitEcNegate(emitFn)
	case "ecOnCurve":
		EmitEcOnCurve(emitFn)
	case "ecModReduce":
		EmitEcModReduce(emitFn)
	case "ecEncodeCompressed":
		EmitEcEncodeCompressed(emitFn)
	case "ecMakePoint":
		EmitEcMakePoint(emitFn)
	case "ecPointX":
		EmitEcPointX(emitFn)
	case "ecPointY":
		EmitEcPointY(emitFn)
	default:
		panic(fmt.Sprintf("unknown EC builtin: %s", funcName))
	}

	ctx.sm.push(bindingName)
	ctx.trackDepth()
}
