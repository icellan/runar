package helpers

import (
	"fmt"
	"strings"
)

// ScriptVerifyFailed is the reason SV Node gives for a spend whose unlocking
// script fails (a false assert, a failed checkSig, a script error such as
// OP_SPLIT out of range). The Rust, Java and Zig suites pin the same text.
const ScriptVerifyFailed = "mandatory-script-verify-flag-failed"

// broadcastStateSource is satisfied by *RPCProvider and, through embedding,
// by *BatchRPCProvider, so a negative passes whichever provider it used.
type broadcastStateSource interface {
	broadcastState() *RPCProvider
}

func (p *RPCProvider) broadcastState() *RPCProvider { return p }

// CheckNodeRejected reports whether `err`, returned by an SDK call made against
// `p`, is evidence that the NODE rejected the spend for `reason` — as opposed
// to the SDK failing to assemble it, the node never answering, or the node
// ACCEPTING it and the confirming mine failing afterwards.
//
// `before` is p.BroadcastAttempts sampled immediately before the call.
//
// It reads what each broadcast of the call came to (p.BroadcastLog), not the
// error's text: since a failed confirming mine is an error (GK-BUG-004 /
// R3-GO-BROADCAST-MINE), an accepted spend also errors after an attempt, and
// its error carries the node's own "RPC error ..." reply from the mine RPC.
// Returns nil when, and only when:
//
//  1. there is an error (a spend that was ACCEPTED is not a rejection);
//  2. the call broadcast at least once (an error with no broadcast is an
//     SDK-side refusal, e.g. FinalizeCall's "parsing tx: ...", not consensus);
//  3. the node accepted NONE of the call's broadcasts — including an accepted
//     tx whose confirming mine then failed;
//  4. the last one was refused by the node at sendrawtransaction with a message
//     containing `reason`.
//
// The reason is pinned because a refusal for a different reason (a
// double-spend, a missing input) never ran the script the test is about.
func CheckNodeRejected(src broadcastStateSource, before int, err error, reason string) error {
	p := src.broadcastState()
	if reason == "" {
		return fmt.Errorf("CheckNodeRejected needs the rejection reason the test is about")
	}
	if err == nil {
		return fmt.Errorf(
			"the spend was ACCEPTED (no error), so nothing was rejected; broadcasts %d -> %d",
			before, p.BroadcastAttempts)
	}
	if p.BroadcastAttempts <= before {
		return fmt.Errorf(
			"the SDK never handed a transaction to the node (broadcasts %d -> %d), "+
				"so this error is an assembly/build failure and NOT a consensus rejection: %w",
			before, p.BroadcastAttempts, err)
	}
	if len(p.BroadcastLog) != p.BroadcastAttempts || before < 0 {
		return fmt.Errorf("broadcast log out of sync: %d entries for %d attempts (before=%d)",
			len(p.BroadcastLog), p.BroadcastAttempts, before)
	}
	added := p.BroadcastLog[before:]
	for _, o := range added {
		if o.Kind == BroadcastAccepted || o.Kind == BroadcastAcceptedMineFailed {
			return fmt.Errorf("the node ACCEPTED a transaction from this call (%s: %s): %w", o.Kind, o.Detail, err)
		}
	}
	last := added[len(added)-1]
	if last.Kind != BroadcastNodeRejected {
		return fmt.Errorf("the node never ruled on the spend (%s: %s): %w", last.Kind, last.Detail, err)
	}
	if !strings.Contains(last.Detail, reason) {
		return fmt.Errorf("the node rejected the spend for the wrong reason: expected %q, got %q",
			reason, last.Detail)
	}
	return nil
}
