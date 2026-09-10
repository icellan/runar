package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// Regression test: the branch-lift must not zero the matched arm.
//
// liftBranchUpdateProps flattens a dispatch chain
//
//	if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
//	else { assert(false); }
//
// into one single-valued `if` per property plus a top-level update_prop. The
// `if`'s then-arm must evaluate to the assigned value and its else-arm to the
// property's old value.
//
// The defect: the then-arm was built from branch.valueBindings — everything
// BEFORE the update_prop in the original arm. That ends on the assigned value
// only when the value was computed INSIDE the arm. When the arm assigns
// something bound outside it, valueBindings is empty, the arm was emitted
// EMPTY, and stack lowering padded it with a zero push
// (OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF): the MATCHED branch wrote 0.
//
// examples/ts/tic-tac-toe escapes it only because `this.cN = this.turn` puts a
// load_prop inside the arm — covered by the second test below as a control.

const branchLiftLocalValueSource = `
class LocalValueDispatch extends StatefulSmartContract {
  c0: bigint;
  c1: bigint;

  constructor(c0: bigint, c1: bigint) {
    super(c0, c1);
    this.c0 = c0;
    this.c1 = c1;
  }

  public poke(position: bigint, value: bigint) {
    const doubled: bigint = value + value;
    if (position == 0n) { this.c0 = doubled; }
    else if (position == 1n) { this.c1 = doubled; }
    else { assert(false); }
  }
}
`

const branchLiftInArmValueSource = `
class InArmValueDispatch extends StatefulSmartContract {
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

// liftedAssignments returns, for each top-level update_prop whose value is an
// `if` binding, the property name and that `if`'s two arms.
func liftedAssignments(t *testing.T, source string) []struct {
	Prop string
	Then []ir.ANFBinding
	Else []ir.ANFBinding
} {
	t.Helper()

	contract, _ := mustLowerToANF(t, source)
	program := LowerToANF(contract)

	var method *ir.ANFMethod
	for i := range program.Methods {
		if program.Methods[i].Name == "poke" {
			method = &program.Methods[i]
			break
		}
	}
	if method == nil {
		t.Fatal("method poke not found in lowered program")
	}

	byName := map[string]ir.ANFValue{}
	for _, b := range method.Body {
		byName[b.Name] = b.Value
	}

	var out []struct {
		Prop string
		Then []ir.ANFBinding
		Else []ir.ANFBinding
	}
	for _, b := range method.Body {
		if b.Value.Kind != "update_prop" {
			continue
		}
		producer, ok := byName[b.Value.ValueRef]
		if !ok || producer.Kind != "if" {
			continue
		}
		out = append(out, struct {
			Prop string
			Then []ir.ANFBinding
			Else []ir.ANFBinding
		}{b.Value.Name, producer.Then, producer.Else})
	}
	return out
}

func TestBranchLift_ThenArmCarriesValueBoundOutsideTheArm(t *testing.T) {
	lifted := liftedAssignments(t, branchLiftLocalValueSource)

	// Both properties in the chain must be lifted. If this is 0 the pass has
	// stopped recognising the shape and the arm assertions below would pass
	// vacuously.
	if len(lifted) != 2 {
		t.Fatalf("expected 2 lifted conditional assignments, got %d", len(lifted))
	}

	for _, l := range lifted {
		if len(l.Then) == 0 {
			t.Errorf("then-arm for this.%s is empty; stack lowering pads it with OP_0, "+
				"so the MATCHED branch writes zero instead of the assigned value", l.Prop)
			continue
		}
		last := l.Then[len(l.Then)-1]
		if last.Value.Kind != "load_const" || last.Value.ConstString == nil ||
			*last.Value.ConstString != "@ref:doubled" {
			t.Errorf("then-arm for this.%s must end on the assigned local; got %+v",
				l.Prop, last.Value)
		}
		if len(l.Else) == 0 {
			t.Errorf("else-arm for this.%s is empty", l.Prop)
		}
	}
}

// Control: the TicTacToe shape already computed its value inside the arm and
// was always correct. The fix must add nothing here — a second binding would
// move the checked-in goldens.
func TestBranchLift_InArmValueShapeIsUnchanged(t *testing.T) {
	lifted := liftedAssignments(t, branchLiftInArmValueSource)

	if len(lifted) != 2 {
		t.Fatalf("expected 2 lifted conditional assignments, got %d", len(lifted))
	}
	for _, l := range lifted {
		if len(l.Then) != 1 {
			t.Errorf("then-arm for this.%s should hold exactly the in-arm load_prop, got %d bindings",
				l.Prop, len(l.Then))
		}
		if l.Then[0].Value.Kind != "load_prop" || l.Then[0].Value.Name != "turn" {
			t.Errorf("then-arm for this.%s should be load_prop turn, got %+v", l.Prop, l.Then[0].Value)
		}
	}
}
