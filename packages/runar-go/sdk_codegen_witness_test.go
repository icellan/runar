package runar

// ---------------------------------------------------------------------------
// sdk_codegen_witness_test.go
//
// F-245 — the typed wrapper GenerateGo emits must not forward the
// intent-intrinsic witness params (`_prevOutScript_<i>`, `_serialisedOutputs`)
// as call args. PrepareCall supplies them from SetPrevOutScript /
// SetSerialisedOutputs and excludes them from its arity check.
//
// Proves: an args slice shaped exactly like the codegen's SDK-arg list
// (getSdkArgParams, which builds the wrapper's args expression) is accepted by
// Call() on a MockProvider — no "expects N args" error.
// Does NOT prove: on-chain validity of the resulting spend (the artifact's
// script is a bare OP_TRUE and the provider is always-ack), nor anything about
// the rendered wrapper text: GenerateGo's mustache renderer currently resolves
// nested method sections against the root context and emits empty method
// bodies for every artifact (separate pre-existing defect, out of scope here).
// ---------------------------------------------------------------------------

import (
	"testing"
)

func TestCodegenWitness_SdkArgParamsMatchPrepareCallArity(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0, 1}, true)
	sdkArgs := getSdkArgParams(art.ABI.Methods[0].Params, isStatefulArtifact(art))

	contract, provider, signer := setupContractAndDeploy(t, art)
	if err := contract.SetPrevOutScript(0, "aa"); err != nil {
		t.Fatal(err)
	}
	if err := contract.SetPrevOutScript(1, "bb"); err != nil {
		t.Fatal(err)
	}
	if err := contract.SetSerialisedOutputs("cc"); err != nil {
		t.Fatal(err)
	}

	// One value per codegen SDK arg, exactly as the generated wrapper builds it.
	args := make([]interface{}, len(sdkArgs))
	for i := range args {
		args[i] = int64(123)
	}
	if _, _, err := contract.Call("move", args, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	}); err != nil {
		t.Fatalf("Call with codegen-shaped args (%d) rejected: %v", len(args), err)
	}
}
