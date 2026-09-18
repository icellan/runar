package frontend

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// R-002: subContext() must carry sideEffects and paramAliasStack.
//
// subContext() builds the lowering context used for every nested block — an
// `if` arm, a `for` body, a ternary arm. It copied most of the parent's state
// but dropped two fields, producing two distinct miscompilations:
//
//   (a) sideEffects was nil in every nested context, so shouldInlinePrivate
//       returned false there. A private helper that calls this.addOutput was
//       therefore ANF-inlined only when the call sat at method top level. From
//       inside an `if` arm the same call stayed a `method_call`, its
//       add_output ref never entered the caller's binding stream, and the
//       public method fell back to the SINGLE-output continuation
//       (get_state_script + computeStateOutput). The declared payment output
//       is then absent from hashOutputs, so a spending transaction is free to
//       omit it.
//
//   (b) paramAliasStack was nil in every nested context. inlinePrivateMethodCall
//       pushes the caller's arg refs as aliases for the private's parameter
//       names on the CURRENT context, then lowers the private's body. Any
//       if/for/ternary inside that body lowered in a subContext with no alias
//       map, so the lookup missed and the identifier fell through to
//       `load_param <privateParamName>` — naming a parameter the public
//       method's ABI does not declare.
//
// What these tests prove: at the ANF level, nesting no longer changes the
// inlining decision, and no inlined body leaks a private parameter name into a
// load_param. What they do NOT prove: anything about the emitted Bitcoin
// Script bytes, the stack-lowering treatment of the resulting bindings, or
// cross-tier parity — those are the conformance suite's job.
// ---------------------------------------------------------------------------

// walkANFBindingsR002 visits every binding, recursing into if arms and loop bodies.
func walkANFBindingsR002(bindings []ir.ANFBinding, visit func(ir.ANFBinding)) {
	for _, b := range bindings {
		visit(b)
		walkANFBindingsR002(b.Value.Then, visit)
		walkANFBindingsR002(b.Value.Else, visit)
		walkANFBindingsR002(b.Value.Body, visit)
	}
}

func lowerContractSourceR002(t *testing.T, source, fileName string) *ir.ANFProgram {
	t.Helper()
	res := ParseSource([]byte(source), fileName)
	if len(res.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(res.ErrorStrings(), "; "))
	}
	if res.Contract == nil {
		t.Fatal("parse returned nil contract")
	}
	if v := Validate(res.Contract); len(v.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(v.ErrorStrings(), "; "))
	}
	if tc := TypeCheck(res.Contract); len(tc.Errors) > 0 {
		t.Fatalf("type check errors: %s", strings.Join(tc.ErrorStrings(), "; "))
	}
	return LowerToANF(res.Contract)
}

func findANFMethodR002(t *testing.T, prog *ir.ANFProgram, name string) ir.ANFMethod {
	t.Helper()
	for _, m := range prog.Methods {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("method %q not found in ANF program", name)
	return ir.ANFMethod{}
}

// R-002 (a): a private helper that emits a state output must be ANF-inlined
// regardless of whether the call site sits at method top level or inside an
// `if` arm.
func TestSubContextCarriesSideEffects_NestedPrivateOutputCallIsInlined(t *testing.T) {
	const source = `
import { StatefulSmartContract, assert } from 'runar-lang';

class NestedPay extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private pay(amt: bigint): void {
    this.addOutput(amt, this.count);
  }

  public topLevel(amt: bigint): void {
    this.pay(amt);
    this.count = this.count + 1n;
  }

  public nested(amt: bigint, flag: bigint): void {
    if (flag === 1n) {
      this.pay(amt);
    }
    this.count = this.count + 1n;
  }
}
`
	prog := lowerContractSourceR002(t, source, "NestedPay.runar.ts")

	// Control: the top-level call site is inlined today.
	control := findANFMethodR002(t, prog, "topLevel")
	var controlAddOutputs, controlPayCalls int
	walkANFBindingsR002(control.Body, func(b ir.ANFBinding) {
		if b.Value.Kind == "add_output" {
			controlAddOutputs++
		}
		if b.Value.Kind == "method_call" && b.Value.Method == "pay" {
			controlPayCalls++
		}
	})
	if controlAddOutputs != 1 || controlPayCalls != 0 {
		t.Fatalf("control broken: topLevel expected 1 add_output / 0 method_call pay, got %d / %d",
			controlAddOutputs, controlPayCalls)
	}

	// Subject: the same call inside an `if` arm must inline identically.
	subject := findANFMethodR002(t, prog, "nested")
	var addOutputs, payCalls int
	walkANFBindingsR002(subject.Body, func(b ir.ANFBinding) {
		if b.Value.Kind == "add_output" {
			addOutputs++
		}
		if b.Value.Kind == "method_call" && b.Value.Method == "pay" {
			payCalls++
		}
	})
	if payCalls != 0 {
		t.Errorf("nested: private output helper was not inlined — found %d method_call to pay; "+
			"subContext() dropped sideEffects so shouldInlinePrivate returned false", payCalls)
	}
	if addOutputs != 1 {
		t.Errorf("nested: expected 1 add_output binding in the caller's stream, got %d", addOutputs)
	}

	// The continuation must be the multi-output path. The single-output path is
	// identified by get_state_script + the computeStateOutput call; a method
	// that declares its own outputs must not take it.
	var sawGetStateScript, sawComputeStateOutput bool
	walkANFBindingsR002(subject.Body, func(b ir.ANFBinding) {
		if b.Value.Kind == "get_state_script" {
			sawGetStateScript = true
		}
		if b.Value.Kind == "call" && b.Value.Func == "computeStateOutput" {
			sawComputeStateOutput = true
		}
	})
	if sawGetStateScript || sawComputeStateOutput {
		t.Errorf("nested: took the single-output continuation path "+
			"(get_state_script=%v computeStateOutput=%v); the helper's declared output "+
			"is not committed by hashOutputs", sawGetStateScript, sawComputeStateOutput)
	}
}

// R-002 (b): an inlined private body must not emit load_param naming one of
// the private method's own parameters — the public method's ABI does not
// declare it.
func TestSubContextCarriesParamAliases_NoPrivateParamLeaksIntoLoadParam(t *testing.T) {
	const source = `
import { StatefulSmartContract, assert } from 'runar-lang';

class NestedAlias extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private payIf(amt: bigint, flag: bigint): void {
    if (flag === 1n) {
      this.addOutput(amt, this.count);
    } else {
      this.addOutput(amt + 1n, this.count);
    }
  }

  public go(a: bigint, f: bigint): void {
    this.payIf(a, f);
    this.count = this.count + 1n;
  }
}
`
	prog := lowerContractSourceR002(t, source, "NestedAlias.runar.ts")
	method := findANFMethodR002(t, prog, "go")

	declared := make(map[string]bool, len(method.Params))
	for _, p := range method.Params {
		declared[p.Name] = true
	}

	var leaked []string
	walkANFBindingsR002(method.Body, func(b ir.ANFBinding) {
		if b.Value.Kind == "load_param" && !declared[b.Value.Name] {
			leaked = append(leaked, b.Name+": load_param "+b.Value.Name)
		}
	})
	if len(leaked) > 0 {
		t.Errorf("go: %d load_param binding(s) name a parameter the method's ABI does not declare "+
			"(declared: %v): %v; subContext() dropped paramAliasStack so the alias lookup missed "+
			"inside the inlined helper's if arms",
			len(leaked), method.Params, leaked)
	}
}
