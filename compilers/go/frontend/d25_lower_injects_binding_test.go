package frontend

import "testing"

// D25: LowerToANF is a public entry point. Callers that assemble their own
// pipeline (the integration helpers, the end2end webapp compilers,
// dump-compiled) call Validate/TypeCheck/LowerToANF directly and never ran
// InjectContinuationBinding, so a mixed ("bind") contract lowered through them
// carried no _spentOutpointHash: its continuations were not bound to the
// spent outpoint, which is the twin-input theft D25 closes.
const d25LowerMixedSrc = `import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`

func TestD25_LowerToANFInjectsBindingWithoutCallerInjection(t *testing.T) {
	pr := ParseSource([]byte(d25LowerMixedSrc), "MixedPot.runar.ts")
	if len(pr.Errors) > 0 || pr.Contract == nil {
		t.Fatalf("parse: %v", pr.Errors)
	}
	if v := Validate(pr.Contract); len(v.Errors) > 0 {
		t.Fatalf("validate: %v", v.Errors)
	}
	if tc := TypeCheck(pr.Contract); len(tc.Errors) > 0 {
		t.Fatalf("typecheck: %v", tc.Errors)
	}
	program := LowerToANF(pr.Contract)
	props := program.Properties
	if len(props) == 0 || props[len(props)-1].Name != TwinBindingField {
		t.Fatalf("last ANF property = %+v, want %s (binding not injected)", props[len(props)-1], TwinBindingField)
	}
}

func TestD25_LowerToANFDoesNotInjectTwice(t *testing.T) {
	pr := ParseSource([]byte(d25LowerMixedSrc), "MixedPot.runar.ts")
	Validate(pr.Contract)
	TypeCheck(pr.Contract)
	program := LowerToANF(InjectContinuationBinding(pr.Contract))
	n := 0
	for _, p := range program.Properties {
		if p.Name == TwinBindingField {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%s appears %d times, want 1", TwinBindingField, n)
	}
}
