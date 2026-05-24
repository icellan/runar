//go:build ignore

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// AllReadonlyCleanstack — regression fixture for issue #44.
//
// A StatefulSmartContract with ZERO mutable fields (only a readonly Owner)
// plus a readonly-field-binding in a terminal method. The ownerCopy := c.Owner
// binding force-embeds the readonly field onto the stack; it is not consumed by
// the terminal CheckSig assertion, leaving an excess stack item below the
// top-of-stack boolean. Before the fix, the leftover survived and the spend was
// rejected on mainnet with "Script did not clean its stack". The fix runs the
// stack cleanup for every public method, emitting the trailing OP_NIP.
type AllReadonlyCleanstack struct {
	runar.StatefulSmartContract
	Owner runar.PubKey `runar:"readonly"`
}

func (c *AllReadonlyCleanstack) Claim(sig runar.Sig) {
	ownerCopy := c.Owner
	runar.Assert(runar.CheckSig(sig, c.Owner))
}
