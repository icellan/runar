package frontend

// Dead Code Elimination pass for ANF IR.
//
// Removes bindings whose results are never referenced by other bindings,
// preserving bindings with observable side effects (assert, update_prop,
// check_preimage, deserialize_state, add_output, add_raw_output,
// add_data_output, call, method_call, raw_script). Iterates to a fixed point
// so transitively dead bindings are also removed.
//
// "Results" is plural on purpose (N-140). A binding does not only define its
// own Name: an `if` that merges branch locals also defines every name in
// Results, and both an `if` and a `loop` define the names their nested
// bindings bind. Liveness used to test refs[b.Name] alone, so an `if` named
// `t9` carrying Results ["a","b"] — a name nothing ever references, because
// callers reference `a` and `b` — was deleted whenever its arms happened to be
// pure, and the merged locals kept their pre-branch values. See
// conformance/dce/live-if.test.ts.
//
// This module is the canonical, standalone DCE pass for the Go compiler.
// It mirrors the Zig reference implementation in
// `compilers/zig/src/passes/dce.zig`. The earlier inline implementation in
// `anf_optimize.go` has been surgically extracted here.
//
// Behaviour: byte-for-byte identical, at the time of that extraction, to the
// previous inline DCE in anf_optimize.go. Verified by the conformance suite
// (cross-tier hex parity) and the unknown-kind exhaustiveness tests.
//
// N-140 is the one deliberate behaviour change since: liveness considers the
// names a binding DEFINES, not only its own Name.

import (
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// EliminateDeadCode walks every method in the program and removes
// unreferenced pure bindings. Mutates the program in place and returns it.
func EliminateDeadCode(program *ir.ANFProgram) *ir.ANFProgram {
	for mi := range program.Methods {
		EliminateDeadBindings(&program.Methods[mi])
	}
	return program
}

// EliminateDeadBindings removes bindings that are not referenced by any other
// binding, iteratively until no more can be removed.
func EliminateDeadBindings(method *ir.ANFMethod) {
	for {
		ownRefs := make([]map[string]bool, len(method.Body))
		refCount := make(map[string]int)
		for i := range method.Body {
			own := make(map[string]bool)
			collectValueRefs(&method.Body[i].Value, own)
			ownRefs[i] = own
			for name := range own {
				refCount[name]++
			}
		}
		var kept []ir.ANFBinding
		removed := false
		for i, b := range method.Body {
			if isReferencedExternally(&method.Body[i], ownRefs[i], refCount) || HasSideEffect(&b.Value) {
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

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

// collectDefinedNames collects every SSA name a binding brings into scope: its
// own Name, plus — for the two nesting kinds — an `if`'s declared Results (the
// merged branch locals / property slots both arms leave behind) and the names
// bound inside Then, Else and a loop Body, recursively.
//
// IterVar is deliberately absent: it is the loop's own induction variable,
// referenced only from inside the body, so counting it as defined would make
// every non-trivial loop unconditionally live.
func collectDefinedNames(b *ir.ANFBinding, out map[string]bool) {
	out[b.Name] = true
	collectDefinedNamesFromValue(&b.Value, out)
}

func collectDefinedNamesFromValue(v *ir.ANFValue, out map[string]bool) {
	switch v.Kind {
	case "if":
		for _, r := range v.Results {
			out[r] = true
		}
		for i := range v.Then {
			collectDefinedNames(&v.Then[i], out)
		}
		for i := range v.Else {
			collectDefinedNames(&v.Else[i], out)
		}
	case "loop":
		for i := range v.Body {
			collectDefinedNames(&v.Body[i], out)
		}
	}
}

// isReferencedExternally reports whether any name the binding defines is
// referenced by some OTHER binding.
//
// refCount maps a name to the number of DISTINCT bindings referencing it;
// ownRefs is this binding's own contribution. Subtracting it is what keeps the
// rule from degenerating into "never delete an `if` or a `loop`": an arm's
// bindings almost always reference each other, and counting those
// self-references would make every nesting node immortal.
//
// For a non-nesting binding this is exactly the old refs[b.Name]: ANF has no
// self-reference, so ownRefs never holds the binding's own name.
func isReferencedExternally(b *ir.ANFBinding, ownRefs map[string]bool, refCount map[string]int) bool {
	defined := make(map[string]bool)
	collectDefinedNames(b, defined)
	for name := range defined {
		own := 0
		if ownRefs[name] {
			own = 1
		}
		if refCount[name]-own > 0 {
			return true
		}
	}
	return false
}

// collectValueRefs collects all name references from an ANFValue.
func collectValueRefs(v *ir.ANFValue, refs map[string]bool) {
	switch v.Kind {
	case "load_param":
		// Do NOT track @ref: targets here — matches TS collectRefsFromValue
		// which breaks on load_param without collecting refs.
	case "load_prop":
		// references the property by name, not a binding
	case "load_const":
		// Track @ref: aliases as references to prevent DCE
		if v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
			refs[strings.TrimPrefix(*v.ConstString, "@ref:")] = true
		}
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
		// Preimage completes parity with the TS reference. Both frontends
		// emit add_output with preimage="" today, so this is latent — but
		// the --ir path deserializes the field, and codegen/stack.go
		// (collectRefs / lowerAddOutput) reads it, so a non-empty preimage
		// arriving that way would dangle exactly like deserialize_state's.
		if v.Preimage != "" {
			refs[v.Preimage] = true
		}
	case "add_raw_output", "add_data_output":
		// Both operands are read by codegen/stack.go lowerAddRawOutput, so
		// their producing bindings must be kept live — matches the TS
		// reference (optimizer/dce.ts collectRefsFromValue). Without this the
		// add_raw_output binding (now correctly retained by HasSideEffect)
		// would survive with its operand producers deleted, and stack
		// lowering would resolve a binding that no longer exists.
		if v.Satoshis != "" {
			refs[v.Satoshis] = true
		}
		if v.ScriptBytes != "" {
			refs[v.ScriptBytes] = true
		}
	case "deserialize_state":
		// The binding itself is kept by HasSideEffect, but codegen
		// (stack.go lowerDeserializeState) brings the preimage to TOS, so
		// its producer must stay live too — otherwise the consumer outlives
		// its producer and stack lowering panics with
		// `value "…" not found on stack`. Matches the TS reference
		// (optimizer/dce.ts collectRefsFromValue).
		if v.Preimage != "" {
			refs[v.Preimage] = true
		}
	case "array_literal":
		// array_literal is pure, but it survives whenever a consumer
		// (checkMultiSig) references it. lowerCheckMultiSig pulls each
		// element to TOS at the use site, so the element producers must
		// stay live — same dangling shape as above. Matches the TS
		// reference (optimizer/dce.ts collectRefsFromValue).
		for _, elem := range v.Elements {
			refs[elem] = true
		}
	case "get_state_script", "raw_script":
		// no SSA operand refs.
	default:
		// Exhaustiveness guard. A silent fall-through here would cause
		// DCE to drop a live binding because its refs go uncollected.
		panic(&ir.UnknownANFKindError{Kind: v.Kind, Location: "anf-optimize.collectValueRefs"})
	}
}

// HasSideEffect returns true if the binding has side effects and should not
// be eliminated. Both polarities of the discriminant are enumerated
// explicitly so an unknown kind cannot silently default to "no side effect"
// — that would let DCE eliminate a newly-added side-effecting ANF kind and
// produce scripts that omit observable behavior.
func HasSideEffect(v *ir.ANFValue) bool {
	switch v.Kind {
	case "assert", "update_prop", "check_preimage", "add_output", "deserialize_state",
		"add_raw_output", "add_data_output", // author-written transaction outputs
		"call", "method_call", // a callee body may assert / write props
		"raw_script": // opaque byte span — DCE must never eliminate it
		return true
	case "load_prop":
		// Issue #109 (`@embedAlways`): a load_prop injected to force a readonly
		// field into the deployed locking script carries Preserve = true, so DCE
		// must keep it even though nothing references it. Ordinary load_props
		// (Preserve = false) remain freely eliminable. Mirrors
		// compilers/zig/src/passes/dce.zig.
		return v.Preserve
	case "load_param", "load_const", "bin_op", "unary_op",
		"get_state_script", "array_literal":
		// Pure ANF kinds — no observable effect, safe to DCE if unreferenced.
		return false
	case "if":
		// If any branch has side effects, keep it
		for _, tb := range v.Then {
			if HasSideEffect(&tb.Value) {
				return true
			}
		}
		for _, eb := range v.Else {
			if HasSideEffect(&eb.Value) {
				return true
			}
		}
		return false
	case "loop":
		for _, lb := range v.Body {
			if HasSideEffect(&lb.Value) {
				return true
			}
		}
		return false
	default:
		// Exhaustiveness guard. A silent default to false here would
		// let DCE eliminate a newly-added side-effecting ANF kind.
		panic(&ir.UnknownANFKindError{Kind: v.Kind, Location: "anf-optimize.hasSideEffect"})
	}
}
