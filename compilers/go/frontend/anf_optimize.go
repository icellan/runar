package frontend

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// EC constants — secp256k1 curve parameters
// ---------------------------------------------------------------------------

var (
	curveN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	genXHex   = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	genYHex   = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	gHex      = genXHex + genYHex // 128 hex chars = 64 bytes
)

// infinityHex is 128 zero hex chars (64 zero bytes), representing the point at infinity.
var infinityHex = strings.Repeat("0", 128)

// ---------------------------------------------------------------------------
// OptimizeEC applies algebraic EC optimizations to the ANF program.
// ---------------------------------------------------------------------------

// OptimizeEC walks the ANF program and rewrites EC calls using algebraic
// identities (identity element, scalar simplifications, double-negate, etc.).
// It mutates the program in-place and returns it.
func OptimizeEC(program *ir.ANFProgram) *ir.ANFProgram {
	for mi := range program.Methods {
		optimizeMethodEC(&program.Methods[mi])
	}
	return program
}

func optimizeMethodEC(method *ir.ANFMethod) {
	// Build a lookup map from binding name to its value.
	lookup := make(map[string]*ir.ANFValue)
	for i := range method.Body {
		lookup[method.Body[i].Name] = &method.Body[i].Value
	}

	anyChanged := false
	changed := true
	for changed {
		changed = false
		for i := range method.Body {
			b := &method.Body[i]
			if optimizeBindingEC(b, lookup) {
				changed = true
				anyChanged = true
			}
		}
	}

	// Only run dead binding elimination if we actually rewrote something,
	// to avoid incorrectly pruning bindings in non-EC methods.
	if anyChanged {
		eliminateDeadBindings(method)
	}
}

func optimizeBindingEC(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	v := &b.Value
	if v.Kind != "call" {
		return false
	}

	switch v.Func {
	case "ecAdd":
		return optimizeECAdd(b, lookup)
	case "ecMul":
		return optimizeECMul(b, lookup)
	case "ecMulGen":
		return optimizeECMulGen(b, lookup)
	case "ecNegate":
		return optimizeECNegate(b, lookup)
	}
	return false
}

// ---------------------------------------------------------------------------
// ecAdd optimizations
// ---------------------------------------------------------------------------

func optimizeECAdd(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	v := &b.Value
	if len(v.Args) != 2 {
		return false
	}

	arg0 := v.Args[0]
	arg1 := v.Args[1]

	// Rule 1: ecAdd(x, INFINITY) -> alias to x
	if isInfinityRef(arg1, lookup) {
		makeAlias(b, arg0)
		return true
	}

	// Rule 2: ecAdd(INFINITY, x) -> alias to x
	if isInfinityRef(arg0, lookup) {
		makeAlias(b, arg1)
		return true
	}

	// Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
	neg1 := resolveValue(arg1, lookup)
	if neg1 != nil && neg1.Kind == "call" && neg1.Func == "ecNegate" && len(neg1.Args) == 1 && neg1.Args[0] == arg0 {
		makeInfinityConst(b)
		return true
	}
	// Also check reversed: ecAdd(ecNegate(x), x)
	neg0 := resolveValue(arg0, lookup)
	if neg0 != nil && neg0.Kind == "call" && neg0.Func == "ecNegate" && len(neg0.Args) == 1 && neg0.Args[0] == arg1 {
		makeInfinityConst(b)
		return true
	}

	// Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2)
	v0 := resolveValue(arg0, lookup)
	v1 := resolveValue(arg1, lookup)
	if v0 != nil && v1 != nil &&
		v0.Kind == "call" && v0.Func == "ecMulGen" && len(v0.Args) == 1 &&
		v1.Kind == "call" && v1.Func == "ecMulGen" && len(v1.Args) == 1 {
		k1 := resolveConstBigInt(v0.Args[0], lookup)
		k2 := resolveConstBigInt(v1.Args[0], lookup)
		if k1 != nil && k2 != nil {
			sum := new(big.Int).Add(k1, k2)
			sum.Mod(sum, curveN)
			// Create a new const binding name for the sum, reusing the binding
			b.Value = ir.ANFValue{
				Kind: "call",
				Func: "ecMulGen",
				Args: []string{v0.Args[0]}, // placeholder, we need a new const
			}
			// Actually, we need to create a temp const. Since we can't easily
			// add bindings, fold if both args are const by rewriting the call
			// to use one of the existing args. For now, just use arg addition
			// if both are already const references.
			// The cleaner approach: rewrite this binding to ecMulGen with a
			// new arg that sums the two. But since we can't add bindings here,
			// skip this optimization unless we can find a simpler form.
			// Revert and skip for now — this needs binding insertion support.
			b.Value = ir.ANFValue{
				Kind: "call",
				Func: "ecAdd",
				Args: []string{arg0, arg1},
			}
			// We'll skip this complex optimization that requires new bindings.
			return false
		}
	}

	// Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) -> ecMul(k1+k2, p)
	// Same issue — requires creating new bindings for k1+k2. Skip.

	return false
}

// ---------------------------------------------------------------------------
// ecMul optimizations
// ---------------------------------------------------------------------------

func optimizeECMul(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	v := &b.Value
	if len(v.Args) != 2 {
		return false
	}

	point := v.Args[0]
	scalar := v.Args[1]

	// Rule 3: ecMul(x, 1) -> alias to x
	if isConstBigInt(scalar, lookup, 1) {
		makeAlias(b, point)
		return true
	}

	// Rule 4: ecMul(x, 0) -> INFINITY
	if isConstBigInt(scalar, lookup, 0) {
		makeInfinityConst(b)
		return true
	}

	// Rule 12: ecMul(k, G) -> ecMulGen(k)
	if isGRef(point, lookup) {
		b.Value = ir.ANFValue{
			Kind: "call",
			Func: "ecMulGen",
			Args: []string{scalar},
		}
		return true
	}

	// Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2)
	// Requires creating a new const binding for k1*k2. Skip unless both are const.
	innerVal := resolveValue(point, lookup)
	if innerVal != nil && innerVal.Kind == "call" && innerVal.Func == "ecMul" && len(innerVal.Args) == 2 {
		k1 := resolveConstBigInt(innerVal.Args[1], lookup)
		k2 := resolveConstBigInt(scalar, lookup)
		if k1 != nil && k2 != nil {
			product := new(big.Int).Mul(k1, k2)
			product.Mod(product, curveN)
			// We can't easily add new bindings. Skip.
			_ = product
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// ecMulGen optimizations
// ---------------------------------------------------------------------------

func optimizeECMulGen(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	v := &b.Value
	if len(v.Args) != 1 {
		return false
	}

	scalar := v.Args[0]

	// Rule 5: ecMulGen(0) -> INFINITY
	if isConstBigInt(scalar, lookup, 0) {
		makeInfinityConst(b)
		return true
	}

	// Rule 6: ecMulGen(1) -> G constant
	if isConstBigInt(scalar, lookup, 1) {
		makeGConst(b)
		return true
	}

	return false
}

// ---------------------------------------------------------------------------
// ecNegate optimizations
// ---------------------------------------------------------------------------

func optimizeECNegate(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	v := &b.Value
	if len(v.Args) != 1 {
		return false
	}

	arg := v.Args[0]

	// Rule 7: ecNegate(ecNegate(x)) -> alias to x
	inner := resolveValue(arg, lookup)
	if inner != nil && inner.Kind == "call" && inner.Func == "ecNegate" && len(inner.Args) == 1 {
		makeAlias(b, inner.Args[0])
		return true
	}

	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveValue looks up the ANFValue for a binding name.
func resolveValue(name string, lookup map[string]*ir.ANFValue) *ir.ANFValue {
	return lookup[name]
}

// resolveConstBigInt returns the big.Int value if the named binding is a load_const bigint.
func resolveConstBigInt(name string, lookup map[string]*ir.ANFValue) *big.Int {
	v := lookup[name]
	if v == nil || v.Kind != "load_const" {
		return nil
	}
	return v.ConstBigInt
}

// isConstBigInt checks if the named binding is a constant with the given int64 value.
func isConstBigInt(name string, lookup map[string]*ir.ANFValue, n int64) bool {
	v := resolveConstBigInt(name, lookup)
	if v == nil {
		return false
	}
	return v.Cmp(big.NewInt(n)) == 0
}

// isInfinityRef checks if the named binding is a constant equal to the INFINITY point.
func isInfinityRef(name string, lookup map[string]*ir.ANFValue) bool {
	v := lookup[name]
	if v == nil || v.Kind != "load_const" || v.ConstString == nil {
		return false
	}
	return *v.ConstString == infinityHex
}

// isGRef checks if the named binding is a constant equal to the generator point G.
func isGRef(name string, lookup map[string]*ir.ANFValue) bool {
	v := lookup[name]
	if v == nil || v.Kind != "load_const" || v.ConstString == nil {
		return false
	}
	return *v.ConstString == gHex
}

// makeAlias rewrites a binding to be a load_param referencing another binding via @ref:.
func makeAlias(b *ir.ANFBinding, target string) {
	b.Value = ir.ANFValue{
		Kind: "load_param",
		Name: "@ref:" + target,
	}
}

// makeInfinityConst rewrites a binding to be a load_const with the INFINITY point value.
func makeInfinityConst(b *ir.ANFBinding) {
	infHex := infinityHex
	infBytes, _ := hex.DecodeString(infHex)
	b.Value = ir.ANFValue{
		Kind:        "load_const",
		ConstString: &infHex,
		ConstBigInt: nil,
		ConstBool:   nil,
	}
	_ = infBytes
}

// makeGConst rewrites a binding to be a load_const with the generator point G value.
func makeGConst(b *ir.ANFBinding) {
	g := gHex
	b.Value = ir.ANFValue{
		Kind:        "load_const",
		ConstString: &g,
	}
}

// ---------------------------------------------------------------------------
// Dead binding elimination
// ---------------------------------------------------------------------------

// eliminateDeadBindings removes bindings that are not referenced by any other
// binding, iteratively until no more can be removed.
func eliminateDeadBindings(method *ir.ANFMethod) {
	for {
		refs := collectAllRefs(method.Body)
		var kept []ir.ANFBinding
		removed := false
		for _, b := range method.Body {
			if _, used := refs[b.Name]; used || hasSideEffect(&b.Value) {
				kept = append(kept, b)
			} else {
				removed = true
			}
		}
		method.Body = kept
		if !removed {
			break
		}
	}
}

// collectAllRefs collects all binding names referenced in a list of bindings.
func collectAllRefs(bindings []ir.ANFBinding) map[string]bool {
	refs := make(map[string]bool)
	for _, b := range bindings {
		collectValueRefs(&b.Value, refs)
	}
	return refs
}

// collectValueRefs collects all name references from an ANFValue.
func collectValueRefs(v *ir.ANFValue, refs map[string]bool) {
	switch v.Kind {
	case "load_param":
		name := v.Name
		if strings.HasPrefix(name, "@ref:") {
			name = strings.TrimPrefix(name, "@ref:")
		}
		refs[name] = true
	case "load_prop":
		// references the property by name, not a binding
	case "load_const":
		// no references
	case "bin_op":
		refs[v.Left] = true
		refs[v.Right] = true
	case "unary_op":
		refs[v.Operand] = true
	case "call":
		for _, arg := range v.Args {
			refs[arg] = true
		}
	case "method_call":
		refs[v.Object] = true
		for _, arg := range v.Args {
			refs[arg] = true
		}
	case "if":
		refs[v.Cond] = true
		for _, tb := range v.Then {
			collectValueRefs(&tb.Value, refs)
		}
		for _, eb := range v.Else {
			collectValueRefs(&eb.Value, refs)
		}
	case "loop":
		for _, lb := range v.Body {
			collectValueRefs(&lb.Value, refs)
		}
	case "assert":
		if v.ValueRef != "" {
			refs[v.ValueRef] = true
		}
	case "update_prop":
		if v.ValueRef != "" {
			refs[v.ValueRef] = true
		}
	case "check_preimage":
		if v.Preimage != "" {
			refs[v.Preimage] = true
		}
	case "add_output":
		if v.Satoshis != "" {
			refs[v.Satoshis] = true
		}
		for _, sv := range v.StateValues {
			refs[sv] = true
		}
	}
}

// hasSideEffect returns true if the binding has side effects and should not be eliminated.
func hasSideEffect(v *ir.ANFValue) bool {
	switch v.Kind {
	case "assert", "update_prop", "check_preimage", "add_output", "deserialize_state":
		return true
	case "if":
		// If any branch has side effects, keep it
		for _, tb := range v.Then {
			if hasSideEffect(&tb.Value) {
				return true
			}
		}
		for _, eb := range v.Else {
			if hasSideEffect(&eb.Value) {
				return true
			}
		}
	case "loop":
		for _, lb := range v.Body {
			if hasSideEffect(&lb.Value) {
				return true
			}
		}
	}
	return false
}
