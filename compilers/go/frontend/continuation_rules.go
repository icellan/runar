package frontend

import "fmt"

// Two rules about where a StatefulSmartContract's satoshis can go, both read
// off the side-effect summary, so they see exactly the effects the
// continuation is injected from. Mirrors
// packages/runar-compiler/src/passes/continuation-rules.ts (same texts in all
// seven tiers).
//
// #199 (warning, validator): no public method is terminal and none sizes its
// own outputs (addOutput / addRawOutput, directly or via a private helper), so
// every spend takes the default continuation whose F-024 floor never lets the
// value shrink: the satoshis can never leave.
//
// D18 (error, typecheck): a public method that writes state and calls
// addRawOutput but never addOutput gets no auto-injected continuation, so the
// state write is dropped and the contract's value leaves with the spend.

// ReleaseTrapMessage is the shared #199 warning text.
func ReleaseTrapMessage(contract string) string {
	return fmt.Sprintf(
		"contract '%s' has no terminal method and no public method that calls "+
			"addOutput/addRawOutput; its satoshis can never leave instances of '%s'",
		contract, contract)
}

// DroppedContinuationMessage is the shared D18 error text.
func DroppedContinuationMessage(method string) string {
	return fmt.Sprintf(
		"method '%s' writes contract state but emits no state continuation: it calls "+
			"addRawOutput() without addOutput(), and a method that declares its own outputs gets no "+
			"auto-injected continuation, so the state write would be lost and the contract's satoshis "+
			"would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or "+
			"stop writing state in a method meant to end the contract",
		method)
}

// DropsContinuation is the D18 predicate on a method's (transitive) effects.
func DropsContinuation(eff MethodEffects) bool {
	return eff.MutatesState && eff.HasStateOutput && !eff.CallsAddOutput
}

// releaseTrapWarning returns the #199 warning text when it applies.
func releaseTrapWarning(contract *ContractNode, summary SideEffectSummary) (string, bool) {
	if contract.ParentClass != "StatefulSmartContract" {
		return "", false
	}
	publics := 0
	for _, m := range contract.Methods {
		if m.Visibility != "public" {
			continue
		}
		publics++
		eff, ok := summary[m.Name]
		if !ok || ContinuationShapeFor(eff).IsTerminal || eff.HasStateOutput {
			return "", false
		}
	}
	if publics == 0 {
		return "", false
	}
	return ReleaseTrapMessage(contract.Name), true
}
