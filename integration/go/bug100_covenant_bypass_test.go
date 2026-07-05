//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// deployFreshCounter deploys a new stateful Counter (count=0) with `sats`
// satoshis and returns the contract + provider + funder signer.
func deployFreshCounter(t *testing.T, sats int64) (*runar.RunarContract, runar.Provider, runar.Signer) {
	t.Helper()
	artifact := getCounterArtifact(t)
	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	w := helpers.NewWallet()
	helpers.RPCCall("importaddress", w.Address, "", false)
	if _, err := helpers.FundWallet(w, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(w)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: sats}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return contract, provider, signer
}

// recoverCodeSep finds the adjusted OP_CODESEPARATOR offset the SDK used for a
// stateful spend, by matching the deterministic BIP-143 preimage it produced.
// Uses only exported SDK functions — no reliance on internal codesep math.
func recoverCodeSep(t *testing.T, txHex, subscript string, sats int64, wantPreimageHex string) int {
	t.Helper()
	for cand := -1; cand <= len(subscript)/2; cand++ {
		_, pre, err := runar.ComputeOpPushTxWithCodeSep(txHex, 0, subscript, sats, cand)
		if err == nil && hex.EncodeToString(pre) == wantPreimageHex {
			return cand
		}
	}
	t.Fatalf("could not recover codesep for stateful spend")
	return -2
}

// TestBug100_DecoupledPreimage_StatefulCovenantBypass is the Step-0 PoC for the
// v1 remediation. It demonstrates BUG-100: the compiler-injected checkPreimage
// for a StatefulSmartContract never binds the pushed BIP-143 preimage to the
// spending transaction. A spender can pay themselves — signing the real tx under
// the *public* OP_PUSH_TX key k=1 — while presenting a decoupled continuation
// preimage that still satisfies the auto-injected state-continuation check.
//
// The attack and its naive control spend an identical 1-in/1-out transaction
// that pays the attacker, with an identical OP_PUSH_TX signature over it. They
// differ in ONE field — the pushed preimage:
//
//	control-legit : a normal increment continuation is ACCEPTED (harness works).
//	control-naive : attacker-paying tx + the tx's OWN (attacker) preimage is
//	                REJECTED — the continuation check defends against naive theft.
//	attack        : the SAME tx + signature, but with a continuation preimage
//	                swapped in, is ACCEPTED. Only the preimage bytes differ, so
//	                the check is provably not bound to the transaction.
//
// ACCEPT of the attack => BUG-100 confirmed (Step 1 fix required).
// REJECT => the node enforces a binding the audit missed; re-scope BUG-100.
func TestBug100_DecoupledPreimage_StatefulCovenantBypass(t *testing.T) {
	attacker := helpers.NewWallet()

	// control-legit: a normal continuation increment must be accepted.
	{
		contract, provider, signer := deployFreshCounter(t, 5000)
		if _, _, err := contract.Call("increment", nil, provider, signer, nil); err != nil {
			t.Fatalf("control-legit: a normal increment must be accepted, got: %v", err)
		}
		t.Log("control-legit: normal increment ACCEPTED (harness + deploy + codesep OK)")
	}

	// buildDecoupledSpend deploys a fresh counter and returns a prepared call
	// whose TxHex is a clean 1-in/1-out tx paying the attacker, with a valid
	// OP_PUSH_TX signature over that tx. The `useContinuationPreimage` flag picks
	// which preimage to present: the tx's own (naive) or the state-continuation
	// one (the attack). Everything else — signature, tx, unlock structure — is
	// identical between the two.
	buildDecoupledSpend := func(t *testing.T, useContinuationPreimage bool) (*runar.RunarContract, runar.Provider, *runar.PreparedCall) {
		contract, provider, signer := deployFreshCounter(t, 5000)
		utxo := contract.GetCurrentUtxo()

		// Continuation prepare: its preimage's hashOutputs commits to the
		// counter@1 state continuation the injected check reconstructs.
		pCont, err := contract.PrepareCall("increment", nil, provider, signer, nil)
		if err != nil {
			t.Fatalf("continuation PrepareCall: %v", err)
		}
		codesep := recoverCodeSep(t, pCont.TxHex, utxo.Script, utxo.Satoshis, pCont.Preimage)

		// Clean 1-in/1-out attacker-paying tx (no funding input to re-sign).
		attackTx, err := helpers.BuildSpendTx(helpers.SDKUtxoToHelper(utxo), attacker.P2PKHScript(), 4000)
		if err != nil {
			t.Fatalf("build attack tx: %v", err)
		}
		sigAttack, preAttack, err := runar.ComputeOpPushTxWithCodeSep(attackTx.Hex(), 0, utxo.Script, utxo.Satoshis, codesep)
		if err != nil {
			t.Fatalf("attack OP_PUSH_TX: %v", err)
		}

		// Reuse the correct continuation-path unlock assembly (codePart + selector
		// + change witness) via FinalizeCall, but point it at the attacker tx and
		// the attacker signature. Swap the preimage per the flag.
		pCont.OpPushTxSig = hex.EncodeToString(sigAttack)
		pCont.TxHex = attackTx.Hex()
		if !useContinuationPreimage {
			pCont.Preimage = hex.EncodeToString(preAttack) // naive: preimage matches the real (attacker) outputs
		}
		// else: keep pCont.Preimage (state continuation) — the decoupling.
		return contract, provider, pCont
	}

	// control-naive: attacker tx carrying its OWN preimage — continuation check
	// must reject it (hash256(continuation) != preimage.hashOutputs).
	{
		contract, provider, prepared := buildDecoupledSpend(t, false)
		if _, _, err := contract.FinalizeCall(prepared, nil, provider); err == nil {
			t.Fatalf("control-naive: naive theft (matching preimage) was ACCEPTED — the continuation check is absent, not merely unbound")
		} else {
			t.Logf("control-naive: naive theft correctly REJECTED: %v", err)
		}
	}

	// attack: the SAME attacker-paying tx, continuation preimage swapped in.
	// After the BUG-100 fix the on-chain signature is derived from the pushed
	// preimage, so OP_CHECKSIG fails when the preimage is decoupled from the real
	// tx — this decoupled spend MUST now be rejected. (Pre-fix it was accepted;
	// this is the node-level regression guard for the fix.)
	{
		contract, provider, prepared := buildDecoupledSpend(t, true)
		txid, _, err := contract.FinalizeCall(prepared, nil, provider)
		if err == nil {
			t.Fatalf("BUG-100 REGRESSION: decoupled-preimage spend was ACCEPTED (txid=%s) — the on-chain preimage binding is not enforced; attacker %s would receive the contract's funds", txid, attacker.Address)
		}
		t.Logf("BUG-100 fix verified: decoupled-preimage spend correctly REJECTED: %v", err)
	}
}
