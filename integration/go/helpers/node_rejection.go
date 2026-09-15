package helpers

import (
	"fmt"
	"strings"
)

// CheckNodeRejected reports whether `err`, returned by an SDK call made against
// `p`, is evidence that the NODE rejected the spend — as opposed to the SDK
// failing to assemble it, or the node never answering at all.
//
// `before` is p.BroadcastAttempts sampled immediately before the call.
//
// Three things have to hold, and none of them is implied by `err != nil`:
//
//  1. There is an error. A spend that was ACCEPTED is not a rejection.
//  2. The counter moved. RunarContract.FinalizeCall returns "parsing tx: ..."
//     before it ever reaches provider.Broadcast, so a guard that hand-mutates a
//     PreparedCall can fail assembly and look identical to a consensus
//     rejection from the outside. A moved counter proves assembly finished and
//     a transaction was handed to the node.
//  3. The node answered with a rejection. RPCCall reports a node-side refusal
//     as "RPC error <code>: <message>" and a transport failure as "RPC
//     connection failed: ...". Only the first is consensus speaking.
//
// Conditions 2 and 3 are independent, and each catches a case the other misses:
// a UTXO-fetch failure surfaces the node's own "RPC error ..." text without any
// transaction ever being broadcast, and an unreachable node moves the counter
// without consensus ever ruling on the spend.
//
// It deliberately does NOT match on a particular rejection message: an
// assertion that pins the exact consensus reason reddens on a legitimate
// rejection the day a node changes its wording, which is the failure mode of
// an over-strict guard rather than of a vacuous one.
//
// Returns nil when the rejection is genuine, and an error describing which of
// the three conditions failed otherwise.
func CheckNodeRejected(p *RPCProvider, before int, err error) error {
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
	if !strings.Contains(err.Error(), "RPC error ") {
		return fmt.Errorf(
			"the transaction reached the broadcast path but the node never ruled on it: a "+
				"consensus rejection arrives as the node's own \"RPC error <code>: <message>\" "+
				"reply, an unreachable node as \"RPC connection failed\": %w", err)
	}
	return nil
}
