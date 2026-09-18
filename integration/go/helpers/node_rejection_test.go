package helpers

import (
	"errors"
	"fmt"
	"testing"
)

// oldShape is the assertion integration/go/bug100_covenant_bypass_test.go used
// to make: any error at all from FinalizeCall counted as proof that the node
// enforced the covenant.
func oldShape(err error) bool { return err != nil }

// TestCheckNodeRejected_AssemblyFailureIsNotANodeRejection is the vacuity proof.
//
// RunarContract.FinalizeCall returns "parsing tx: ..." before it ever reaches
// provider.Broadcast, and the BUG-100 guard hand-mutates a PreparedCall
// (TxHex, OpPushTxSig, a swapped preimage). Any SDK change that makes a
// hand-modified PreparedCall fail assembly therefore turns that guard
// permanently green while proving nothing about consensus.
func TestCheckNodeRejected_AssemblyFailureIsNotANodeRejection(t *testing.T) {
	p := NewRPCProvider()
	p.BroadcastAttempts = 3 // the deploy and the control legs already broadcast

	before := p.BroadcastAttempts
	// FinalizeCall fails during assembly: no transaction is handed to the node,
	// so the counter does not move.
	err := fmt.Errorf("RunarContract.FinalizeCall: parsing tx: %w", errors.New("bad hex"))

	if !oldShape(err) {
		t.Fatal("setup is wrong: the old assertion must accept this error")
	}
	if got := CheckNodeRejected(p, before, err); got == nil {
		t.Fatal("CheckNodeRejected accepted an assembly failure as a node rejection")
	}
}

// TestCheckNodeRejected_TransportFailureIsNotANodeRejection: the tx was handed
// to the provider, but the node never answered. The counter alone cannot tell
// this from a consensus rejection, so the reason has to be read too.
func TestCheckNodeRejected_TransportFailureIsNotANodeRejection(t *testing.T) {
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	p.BroadcastAttempts++ // Broadcast was entered

	err := fmt.Errorf("RunarContract.FinalizeCall: broadcasting: %w",
		errors.New("RPC connection failed: dial tcp 127.0.0.1:18332: connect: connection refused"))

	if !oldShape(err) {
		t.Fatal("setup is wrong: the old assertion must accept this error")
	}
	if got := CheckNodeRejected(p, before, err); got == nil {
		t.Fatal("CheckNodeRejected accepted an unreachable node as a node rejection")
	}
}

// TestCheckNodeRejected_SuccessIsNotARejection: no error at all.
func TestCheckNodeRejected_SuccessIsNotARejection(t *testing.T) {
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	p.BroadcastAttempts++
	if got := CheckNodeRejected(p, before, nil); got == nil {
		t.Fatal("CheckNodeRejected accepted a SUCCESSFUL spend as a rejection")
	}
}

// TestCheckNodeRejected_GenuineConsensusRejectionPasses is the control with
// teeth: an over-strict guard that reddens a real node rejection reddens here.
// The error text is the one SV Node actually produces for a script failure,
// routed through RPCCall's "RPC error <code>: <message>" wrapper.
func TestCheckNodeRejected_GenuineConsensusRejectionPasses(t *testing.T) {
	for _, nodeMsg := range []string{
		"RPC error -26: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
		"RPC error -26: mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)",
		"RPC error -26: 16: bad-txns-inputs-missingorspent",
		"RPC error -25: Missing inputs",
	} {
		p := NewRPCProvider()
		p.BroadcastAttempts = 2
		before := p.BroadcastAttempts
		p.BroadcastAttempts++ // the attack tx reached the node

		err := fmt.Errorf("RunarContract.FinalizeCall: broadcasting: %w", errors.New(nodeMsg))
		if got := CheckNodeRejected(p, before, err); got != nil {
			t.Fatalf("CheckNodeRejected rejected a genuine consensus rejection %q: %v", nodeMsg, got)
		}
	}
}

// TestCheckNodeRejected_UtxoFetchFailureIsNotANodeRejection: the SDK gave up
// before building the spend, and the error it surfaced is the NODE's own
// "RPC error ..." text — from a UTXO lookup, not from broadcasting the attack.
// Only the broadcast counter separates this from a consensus rejection.
func TestCheckNodeRejected_UtxoFetchFailureIsNotANodeRejection(t *testing.T) {
	p := NewRPCProvider()
	p.BroadcastAttempts = 1 // the deploy
	before := p.BroadcastAttempts

	err := fmt.Errorf("RunarContract.FinalizeCall: fetching utxos: %w",
		errors.New("RPC error -5: No information available about address"))

	if !oldShape(err) {
		t.Fatal("setup is wrong: the old assertion must accept this error")
	}
	if got := CheckNodeRejected(p, before, err); got == nil {
		t.Fatal("CheckNodeRejected accepted a pre-broadcast UTXO-fetch failure as a node rejection")
	}
}
