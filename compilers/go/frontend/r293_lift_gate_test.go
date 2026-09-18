package frontend

import (
	"fmt"
	"sort"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-293 — `liftBranchUpdateProps` hoists an arm's value-prefix bindings under
// FRESH names and rewrites their refs with `remapValueRefs`. That remapper
// rewrites an `if`'s `cond` and nothing else: it never descends into `Then` /
// `Else`, and for a `loop` it rewrites nothing at all.
//
// Six tiers never hand it one. Their purity predicate for the lift gate is a
// five-kind list — load_prop, load_param, load_const, bin_op, unary_op — so an
// arm whose prefix contains a nested `if` or `loop` simply is not lifted.
//
// This tier's `isSideEffectFree` also returned true for "if", "loop",
// "get_state_script" and "array_literal", so exactly the kinds that need
// recursion were admitted. A nested `if` in the prefix got hoisted, its body's
// references to the renamed prefix temps were left pointing at names that no
// longer existed, and the method died in pass 5:
//
//	go   Compilation error: stack lowering failed: value "t" not found on stack
//	rust <compiles, 1463 bytes of hex>
//
// So it is not a miscompile — it is a Go-only refusal of a contract the other
// six tiers accept, i.e. a seven-tier parity break. "array_literal" is worse
// still: it is admitted by the gate and has NO case in `remapValueRefs`, so it
// reaches that function's exhaustiveness panic.
//
// The fix narrows the gate to the same five kinds the peers use.
// `isSideEffectFree` has exactly one caller, `allBindingsSideEffectFree`, which
// in turn is called only at the two lift gates — DCE uses `HasSideEffect` in
// dce.go, which IS properly recursive and is untouched.

// A dispatch chain whose FIRST arm computes its value with a nested `if`. The
// prefix is [load_const 10, if(...), merge temps], which the old gate let
// through.
const r293NestedIfInArm = `
class R293NestedIf extends StatefulSmartContract {
  x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public go(k: bigint, m: bigint) {
    if (k === 1n) {
      let t: bigint = 10n;
      if (m > 0n) {
        t = t + 1n;
      } else {
        t = t + 2n;
      }
      this.x = t;
    } else if (k === 2n) {
      this.x = 20n;
    } else {
      this.x = 30n;
    }
    this.addOutput(1000n, this.x);
  }
}
`

// Same, with a `loop` in the prefix instead of an `if`. `remapValueRefs`
// rewrites nothing at all for a loop, so its body's refs go stale wholesale.
const r293LoopInArm = `
class R293Loop extends StatefulSmartContract {
  x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public go(k: bigint, m: bigint) {
    if (k === 1n) {
      let t: bigint = m;
      for (let i = 0n; i < 3n; i++) {
        t = t + i;
      }
      this.x = t;
    } else if (k === 2n) {
      this.x = 20n;
    } else {
      this.x = 30n;
    }
    this.addOutput(1000n, this.x);
  }
}
`

// Positive control: the shape the lift exists FOR — a dispatch chain whose
// arms carry only pure prefix bindings. Narrowing the gate must not switch
// this off; without this control, deleting the lift entirely would pass every
// test above.
const r293ControlLiftableChain = `
class R293Control extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;
  turn: bigint;

  constructor(c0: bigint, c1: bigint, turn: bigint) {
    super(c0, c1, turn);
    this.c0 = c0;
    this.c1 = c1;
    this.turn = turn;
  }

  public poke(position: bigint) {
    if (position == 0n) { this.c0 = this.turn; }
    else if (position == 1n) { this.c1 = this.turn; }
    else { assert(false); }
  }
}
`

// ownRefsOf returns a binding value's OWN refs — the ones it reads at its own
// position — without descending into an `if` / `loop` body. Those nested
// bodies are checked separately, in their own scope.
func ownRefsOf(v *ir.ANFValue) map[string]bool {
	refs := map[string]bool{}
	switch v.Kind {
	case "if":
		refs[v.Cond] = true
	case "loop":
		// A loop reads nothing at its own position.
	default:
		collectValueRefs(v, refs)
	}
	return refs
}

// danglingRefs returns every ref that names no binding IN SCOPE at the point
// it is read: defined earlier in the same body, or earlier in an enclosing
// one. "Defined somewhere in the method" is not enough — the defect this test
// exists for produces a read of `t` that sits BEFORE the `t` binding in the
// same arm, which a set-membership check cannot see.
func danglingRefs(method *ir.ANFMethod) []string {
	bad := map[string]bool{}

	var walk func(bindings []ir.ANFBinding, enclosing map[string]bool)
	walk = func(bindings []ir.ANFBinding, enclosing map[string]bool) {
		scope := map[string]bool{}
		for k := range enclosing {
			scope[k] = true
		}
		for i := range bindings {
			b := &bindings[i]
			for r := range ownRefsOf(&b.Value) {
				if r != "" && !scope[r] {
					bad[r] = true
				}
			}
			if b.Value.Kind == "if" {
				walk(b.Value.Then, scope)
				walk(b.Value.Else, scope)
			}
			if b.Value.Kind == "loop" {
				walk(b.Value.Body, scope)
			}
			scope[b.Name] = true
		}
	}
	walk(method.Body, map[string]bool{})

	var out []string
	for r := range bad {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func lowerOrRefuse(t *testing.T, source string) (program *ir.ANFProgram, refusal string) {
	t.Helper()
	contract, _ := mustLowerToANF(t, source)
	defer func() {
		if r := recover(); r != nil {
			refusal = fmt.Sprint(r)
		}
	}()
	return LowerToANF(contract), ""
}

func TestR293NestedControlFlowInArmDoesNotStrandRefs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"nested if in the arm's value prefix", r293NestedIfInArm},
		{"loop in the arm's value prefix", r293LoopInArm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, refusal := lowerOrRefuse(t, tc.source)
			if refusal != "" {
				t.Fatalf("ANF lowering refused a contract the peer tiers compile: %s", refusal)
			}
			for i := range program.Methods {
				if got := danglingRefs(&program.Methods[i]); len(got) > 0 {
					t.Fatalf("method %q reads %v, which no binding defines in scope at "+
						"that point — the branch lift hoisted a nested body without "+
						"remapping the refs inside it",
						program.Methods[i].Name, got)
				}
			}
		})
	}
}

// The lift must still fire for the shape it exists for: a dispatch chain is
// flattened into one top-level update_prop per property whose value is an `if`.
func TestR293LiftStillFiresForAPureChain(t *testing.T) {
	program, refusal := lowerOrRefuse(t, r293ControlLiftableChain)
	if refusal != "" {
		t.Fatalf("control refused: %s", refusal)
	}

	var method *ir.ANFMethod
	for i := range program.Methods {
		if program.Methods[i].Name == "poke" {
			method = &program.Methods[i]
			break
		}
	}
	if method == nil {
		t.Fatal("method poke not found")
	}

	byName := map[string]ir.ANFValue{}
	for _, b := range method.Body {
		byName[b.Name] = b.Value
	}
	lifted := 0
	for _, b := range method.Body {
		if b.Value.Kind != "update_prop" {
			continue
		}
		if producer, ok := byName[b.Value.ValueRef]; ok && producer.Kind == "if" {
			lifted++
		}
	}
	if lifted < 2 {
		t.Fatalf("the branch lift no longer fires for a pure dispatch chain: "+
			"%d lifted update_props, want >= 2", lifted)
	}
}
