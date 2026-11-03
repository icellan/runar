package frontend

// F-024 (CL-BUG-079, user decision R14) — Go-tier port of
// packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.
//
// Proves (Go tier, TS surface): every default single-output continuation
// carries the injected `assert(_newAmount >= extractAmount(txPreimage))`
// ANF (load_param txPreimage; call extractAmount; load_param _newAmount;
// bin_op >=; assert) after the body, addOutput and terminal methods do not;
// `continuationAmount()` lowers to load_param _newAmount where that witness
// exists and is refused everywhere else; a write to it is refused.
// Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
// cross-tier byte parity (conformance).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

const f024Counter = `
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count = this.count + 1n; }
  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
  public close() { assert(this.count > 0n); }
  public log(payload: ByteString) { this.addDataOutput(0n, payload); }
}
`

// f024Compile runs parse -> validate -> typecheck -> ANF and returns the
// program, or every error message (an ANF-lowering refusal is a panic that
// the compiler package turns into an error; it is recovered here the same way).
func f024Compile(source string) (prog *ir.ANFProgram, errs []string) {
	result := ParseSource([]byte(source), "C.runar.ts")
	errs = append(errs, result.ErrorStrings()...)
	if result.Contract == nil {
		return nil, errs
	}
	errs = append(errs, Validate(result.Contract).ErrorStrings()...)
	errs = append(errs, TypeCheck(result.Contract).ErrorStrings()...)
	if len(errs) > 0 {
		return nil, errs
	}
	defer func() {
		if r := recover(); r != nil {
			prog = nil
			errs = append(errs, fmt.Sprint(r))
		}
	}()
	return LowerToANF(result.Contract), nil
}

func f024PublicMethod(t *testing.T, p *ir.ANFProgram, name string) *ir.ANFMethod {
	t.Helper()
	for i := range p.Methods {
		if p.Methods[i].Name == name && p.Methods[i].IsPublic {
			return &p.Methods[i]
		}
	}
	t.Fatalf("no public method %q", name)
	return nil
}

func f024InjectedCheckAt(body []ir.ANFBinding) []int {
	var hits []int
	for i := 0; i+4 < len(body); i++ {
		a, b, c, d, e := body[i], body[i+1], body[i+2], body[i+3], body[i+4]
		if a.Value.Kind == "load_param" && a.Value.Name == "txPreimage" &&
			b.Value.Kind == "call" && b.Value.Func == "extractAmount" &&
			len(b.Value.Args) == 1 && b.Value.Args[0] == a.Name &&
			c.Value.Kind == "load_param" && c.Value.Name == "_newAmount" &&
			d.Value.Kind == "bin_op" && d.Value.Op == ">=" && d.Value.Left == c.Name && d.Value.Right == b.Name &&
			e.Value.Kind == "assert" && e.Value.ValueRef == d.Name {
			hits = append(hits, i)
		}
	}
	return hits
}

func f024Kinds(body []ir.ANFBinding) []string {
	out := make([]string, len(body))
	for i, b := range body {
		if b.Value.Kind == "call" {
			out[i] = "call:" + b.Value.Func
		} else {
			out[i] = b.Value.Kind
		}
	}
	return out
}

func f024Contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestF024_DefaultContinuationCarriesTheValueCheck(t *testing.T) {
	p, errs := f024Compile(f024Counter)
	if len(errs) > 0 {
		t.Fatalf("compile failed: %v", errs)
	}
	body := f024PublicMethod(t, p, "increment").Body
	hits := f024InjectedCheckAt(body)
	if len(hits) != 1 {
		t.Fatalf("increment: want exactly 1 injected check, got %d: %v", len(hits), f024Kinds(body))
	}
	kinds := f024Kinds(body)
	if !f024Contains(kinds[:hits[0]], "update_prop") {
		t.Errorf("the check must follow the method body: %v", kinds)
	}
	after := kinds[hits[0]+5:]
	for _, k := range []string{"if", "get_state_script", "call:computeStateOutput"} {
		if !f024Contains(after, k) {
			t.Errorf("%s must follow the check: %v", k, kinds)
		}
	}
	if body[hits[0]+4].Value.IsAutoInjectedStateCheck {
		t.Errorf("the value check is an ordinary assert, not the on-chain-only hashOutputs check")
	}
	if got := f024InjectedCheckAt(f024PublicMethod(t, p, "log").Body); len(got) != 1 {
		t.Errorf("data-output-only method: want 1 check, got %d", len(got))
	}
	for _, name := range []string{"addTo", "close"} {
		m := f024PublicMethod(t, p, name)
		if f024Contains(paramNamesOf(m), "_newAmount") || f024Contains(f024Kinds(m.Body), "call:extractAmount") {
			t.Errorf("%s must not get _newAmount or the check: %v", name, f024Kinds(m.Body))
		}
	}
}

const f024Pot = `
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  %s
}
`

func TestF024_ContinuationAmountReadLowersToNewAmount(t *testing.T) {
	p, errs := f024Compile(fmt.Sprintf(f024Pot, `public join(bet: bigint) {
    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);
    this.count = this.count + 1n;
  }`))
	if len(errs) > 0 {
		t.Fatalf("compile failed: %v", errs)
	}
	body := f024PublicMethod(t, p, "join").Body
	hits := f024InjectedCheckAt(body)
	if len(hits) != 1 {
		t.Fatalf("want 1 injected check, got %d", len(hits))
	}
	first := -1
	for i, b := range body {
		if b.Value.Kind == "load_param" && b.Value.Name == "_newAmount" {
			first = i
			break
		}
	}
	if first < 0 || first >= hits[0] {
		t.Errorf("the author's read must be its own load_param _newAmount before the check (first=%d, check=%d)", first, hits[0])
	}
}

func TestF024_ContinuationAmountRefusals(t *testing.T) {
	const readOnly = "continuationAmount() is read-only and cannot be assigned"
	const unavailable = "continuationAmount() is only available in a public StatefulSmartContract method whose state continues through the default single-output continuation"
	cases := []struct{ name, src, want string }{
		// This tier's .runar.ts parser already refuses a call as an assignment
		// target (a syntax error); the typecheck guard covers parsers that
		// accept it. Either way the write must not compile.
		{"write", fmt.Sprintf(f024Pot, `public join() { continuationAmount() = 5n; this.count = this.count + 1n; }`), ""},
		{"increment", fmt.Sprintf(f024Pot, `public join() { continuationAmount()++; this.count = this.count + 1n; }`), readOnly},
		{"stateless", `
class P extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public unlock() { assert(continuationAmount() > this.x); }
}
`, "continuationAmount() is only available in StatefulSmartContract methods"},
		{"terminal", fmt.Sprintf(f024Pot, `public close() { assert(continuationAmount() > 0n); }`), unavailable},
		{"addOutput", fmt.Sprintf(f024Pot, `public split() { this.addOutput(continuationAmount(), this.count); }`), unavailable},
		{"private", fmt.Sprintf(f024Pot, `private amt(): bigint { return continuationAmount(); }
  public bump() { this.count = this.count + this.amt(); }`), unavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, errs := f024Compile(c.src)
			if c.want == "" {
				if len(errs) == 0 {
					t.Fatal("want the write refused, it compiled")
				}
				return
			}
			if !strings.Contains(strings.Join(errs, " | "), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, errs)
			}
		})
	}
}
