package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ConditionalDataOutput -- Audit regression: a stateful method that
// emits a data output on a conditional branch must keep the canonical
// single-output computeStateOutput state continuation on every path.
//
// See conformance/tests/conditional-data-output-stateful/ for the full
// rationale; the cross-format ports must produce identical Bitcoin Script.
type ConditionalDataOutput struct {
	runar.StatefulSmartContract
	Amount runar.Bigint
}

// Pay -- the canonical bug: AddDataOutput is wrapped in a branch.
// The compiler must register the if's value as a DATA output ref
// (not a state output ref) so that the parent method's continuation
// hash keeps computeStateOutput.
func (c *ConditionalDataOutput) Pay(flag runar.Bool, payload runar.ByteString) {
	c.Amount = c.Amount + 1
	if flag {
		c.AddDataOutput(0, payload)
	}
	runar.Assert(true)
}
