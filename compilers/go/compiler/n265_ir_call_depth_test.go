package compiler

import (
	"strconv"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

// N-265 — the --ir path bypasses N-180's MAX_CALL_DEPTH bound.
//
// F-071's checkIRNoRecursion (ir_frontend_rules.go) refused a CYCLE in the
// method_call graph but had no depth counter at all: an ACYCLIC chain of
// private helpers supplied through CompileFromIRBytes recursed
// inlineMethodCall (codegen/stack.go) exactly as deep as the chain, unbounded,
// with no diagnostic — the same crash N-180 closed on the source path
// (--source), reopened on --ir because the source validator never runs there.
//
// What this proves: CompileFromIRBytes now refuses a chain one past
// frontend.MaxCallDepth, naming the first offending method in DECLARATION
// ORDER with frontend.CallDepthMessage, accepts a chain right at the bound,
// and refuses a 20000-link chain promptly (no runtime stack-overflow signal,
// no multi-second hang).
//
// What this does NOT prove: that the other six tiers' --ir loaders agree
// (conformance/negatives/n265-ir-call-depth-parity.test.ts does); call graphs
// other than a chain; or that 128 is the right number (N-180 measured that).

// chainIR builds a program whose public verify(a) calls m0(a); m_i calls
// m_{i+1} for i < n; m_{n-1} returns its argument unchanged. Declaration
// order is m0..m(n-1) THEN verify, matching N-180's own chain fixture
// (conformance/negatives/n180-call-depth-parity.test.ts): at n=128 only
// `verify` exceeds the bound, but at n=20000 `m0` is declared first and
// already exceeds it, so `m0` is reported.
func chainIR(n int) string {
	var b strings.Builder
	b.WriteString(`{"contractName": "Chain", "properties": [], "methods": [`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(`,`)
		}
		if i == n-1 {
			b.WriteString(`{"name": "m` + strconv.Itoa(i) + `", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "x"}}
			]}`)
		} else {
			b.WriteString(`{"name": "m` + strconv.Itoa(i) + `", "isPublic": false, "params": [{"name": "x", "type": "bigint"}], "body": [
				{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
				{"name": "t1", "value": {"kind": "load_param", "name": "x"}},
				{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "m` + strconv.Itoa(i+1) + `", "args": ["t1"]}}
			]}`)
		}
	}
	if n > 0 {
		b.WriteString(`,`)
	}
	b.WriteString(`{"name": "verify", "isPublic": true, "params": [{"name": "a", "type": "bigint"}], "body": [
		{"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
		{"name": "t1", "value": {"kind": "load_param", "name": "a"}},
		{"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "m0", "args": ["t1"]}},
		{"name": "t3", "value": {"kind": "load_const", "value": 0}},
		{"name": "t4", "value": {"kind": "bin_op", "op": ">=", "left": "t2", "right": "t3"}},
		{"name": "t5", "value": {"kind": "assert", "value": "t4"}}
	]}`)
	b.WriteString(`]}`)
	return b.String()
}

func TestN265_IRChainAtMaxCallDepthCompiles(t *testing.T) {
	if _, err := CompileFromIRBytes([]byte(chainIR(frontend.MaxCallDepth))); err != nil {
		t.Fatalf("chain at MaxCallDepth must compile, got: %v", err)
	}
}

func TestN265_IRChainOnePastMaxCallDepthRefused(t *testing.T) {
	_, err := CompileFromIRBytes([]byte(chainIR(frontend.MaxCallDepth + 1)))
	if err == nil {
		t.Fatalf("expected a call-depth refusal, got a compiled artifact")
	}
	want := frontend.CallDepthMessage("verify")
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected the shared diagnostic %q, got: %v", want, err)
	}
}

func TestN265_IR20000LinkChainRefusedPromptly(t *testing.T) {
	_, err := CompileFromIRBytes([]byte(chainIR(20000)))
	if err == nil {
		t.Fatalf("expected a call-depth refusal, got a compiled artifact")
	}
	want := frontend.CallDepthMessage("m0")
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected the shared diagnostic %q, got: %v", want, err)
	}
}
